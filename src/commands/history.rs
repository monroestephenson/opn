use std::collections::{HashMap, VecDeque};
use std::fs::OpenOptions;
use std::io::Write;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::time::Duration;

use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};
use serde_json::json;

use crate::agent::{self, AgentResponse, AgentSocket};
use crate::cli::HistoryAction;
use crate::model::{LiveSocketActivity, LiveSocketActivityKind, QueryFilter};
use crate::platform::Platform;
use crate::render::RenderOutcome;

const HISTORY_SCHEMA: &str = "opn-history/1";
const PID_FILE: &str = "recorder.pid";
const STATE_FILE: &str = "state.json";
const EVENTS_FILE: &str = "events.jsonl";

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
enum EventKind {
    Appeared,
    Disappeared,
    StateChanged,
    Listen,
    Accept,
    Connect,
    Close,
    Retransmit,
}

impl EventKind {
    fn as_str(&self) -> &'static str {
        match self {
            EventKind::Appeared => "appeared",
            EventKind::Disappeared => "disappeared",
            EventKind::StateChanged => "state_changed",
            EventKind::Listen => "listen",
            EventKind::Accept => "accept",
            EventKind::Connect => "connect",
            EventKind::Close => "close",
            EventKind::Retransmit => "retransmit",
        }
    }
}

#[derive(Clone, Serialize, Deserialize)]
struct HistoryEvent {
    ts: u64,
    kind: EventKind,
    socket: AgentSocket,
    #[serde(skip_serializing_if = "Option::is_none")]
    previous_state: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    current_state: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    rx_bytes: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    tx_bytes: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    retransmits: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    rtt_us: Option<u32>,
}

#[derive(Clone, Serialize, Deserialize)]
struct RecorderState {
    schema: String,
    updated_at: u64,
    sockets: Vec<AgentSocket>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct RecorderPid {
    pid: u32,
    started_at: u64,
    interval_secs: u64,
    capacity: usize,
}

#[derive(Debug, Serialize)]
struct StatusPayload {
    schema: &'static str,
    running: bool,
    pid: Option<u32>,
    started_at: Option<u64>,
    interval_secs: Option<u64>,
    capacity: Option<usize>,
    last_updated_at: Option<u64>,
    retained_events: usize,
    tracked_sockets: usize,
    data_dir: String,
}

struct RecordOptions<'a> {
    interval: u64,
    capacity: usize,
    foreground: bool,
    iterations: Option<usize>,
    data_dir_override: Option<&'a Path>,
    filter: &'a QueryFilter,
    as_json: bool,
    llm: bool,
}

struct EventFilter<'a> {
    since: Option<u64>,
    until: Option<u64>,
    port: Option<u16>,
    pid: Option<u32>,
    process: Option<&'a str>,
    kind: Option<&'a str>,
    state: Option<&'a str>,
}

pub fn run(
    platform: &dyn Platform,
    action: &HistoryAction,
    as_json: bool,
    llm: bool,
) -> Result<RenderOutcome> {
    match action {
        HistoryAction::Start {
            interval,
            capacity,
            data_dir,
        } => run_start(*interval, *capacity, data_dir.as_deref(), as_json, llm),
        HistoryAction::Record {
            interval,
            capacity,
            foreground,
            iterations,
            data_dir,
            filter,
        } => run_record(
            platform,
            RecordOptions {
                interval: *interval,
                capacity: *capacity,
                foreground: *foreground,
                iterations: *iterations,
                data_dir_override: data_dir.as_deref(),
                filter: &QueryFilter::from(filter),
                as_json,
                llm,
            },
        ),
        HistoryAction::Stop { data_dir } => run_stop(data_dir.as_deref(), as_json, llm),
        HistoryAction::Status { data_dir } => run_status(data_dir.as_deref(), as_json, llm),
        HistoryAction::Events {
            limit,
            since,
            until,
            port,
            pid,
            process,
            kind,
            state,
            data_dir,
        } => {
            let events_path = history_dir(data_dir.as_deref())?.join(EVENTS_FILE);
            let events = read_events(&events_path)?;
            let filtered: Vec<HistoryEvent> = events
                .into_iter()
                .filter(|event| {
                    event_matches(
                        event,
                        &EventFilter {
                            since: *since,
                            until: *until,
                            port: *port,
                            pid: *pid,
                            process: process.as_deref(),
                            kind: kind.as_deref(),
                            state: state.as_deref(),
                        },
                    )
                })
                .rev()
                .take(*limit)
                .collect::<Vec<_>>()
                .into_iter()
                .rev()
                .collect();
            print_events(filtered, as_json, llm)
        }
    }
}

fn run_start(
    interval: u64,
    capacity: usize,
    data_dir_override: Option<&Path>,
    as_json: bool,
    llm: bool,
) -> Result<RenderOutcome> {
    let data_dir = history_dir(data_dir_override)?;
    ensure_history_dir(&data_dir)?;
    if let Some(pid_meta) = read_pid_file(&data_dir)? {
        if pid_is_running(pid_meta.pid) {
            return render_message(
                json!({
                    "schema": HISTORY_SCHEMA,
                    "started": false,
                    "running": true,
                    "pid": pid_meta.pid,
                    "data_dir": data_dir.display().to_string(),
                }),
                format!("history recorder already running (pid {})", pid_meta.pid),
                as_json,
                llm,
            );
        }
    }

    let exe = std::env::current_exe().context("failed to locate current executable")?;
    let mut cmd = Command::new(exe);
    cmd.arg("history")
        .arg("record")
        .arg("--foreground")
        .arg("--interval")
        .arg(interval.to_string())
        .arg("--capacity")
        .arg(capacity.to_string())
        .arg("--data-dir")
        .arg(&data_dir)
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null());
    let child = cmd.spawn().context("failed to spawn history recorder")?;

    let pid_meta = RecorderPid {
        pid: child.id(),
        started_at: agent::current_ts(),
        interval_secs: interval,
        capacity,
    };
    write_pid_file(&data_dir, &pid_meta)?;

    render_message(
        json!({
            "schema": HISTORY_SCHEMA,
            "started": true,
            "running": true,
            "pid": pid_meta.pid,
            "interval_secs": interval,
            "capacity": capacity,
            "data_dir": data_dir.display().to_string(),
        }),
        format!(
            "history recorder started (pid {}, interval={}s, capacity={})",
            pid_meta.pid, interval, capacity
        ),
        as_json,
        llm,
    )
}

fn run_record(platform: &dyn Platform, opts: RecordOptions<'_>) -> Result<RenderOutcome> {
    if !opts.foreground {
        return run_start(
            opts.interval,
            opts.capacity,
            opts.data_dir_override,
            opts.as_json,
            opts.llm,
        );
    }

    let data_dir = history_dir(opts.data_dir_override)?;
    ensure_history_dir(&data_dir)?;
    let pid_meta = RecorderPid {
        pid: std::process::id(),
        started_at: agent::current_ts(),
        interval_secs: opts.interval,
        capacity: opts.capacity,
    };
    write_pid_file(&data_dir, &pid_meta)?;

    let result = (|| -> Result<()> {
        let mut remaining = opts.iterations.unwrap_or(usize::MAX);
        loop {
            let live_wait = platform.supports_live_socket_activity();
            let saw_activity = if live_wait {
                platform.wait_for_socket_activity(Duration::from_secs(opts.interval))?
            } else {
                false
            };
            if live_wait && !saw_activity && opts.interval > 0 {
                if remaining == 1 {
                    break;
                }
                remaining = remaining.saturating_sub(1);
                continue;
            }

            let now = agent::current_ts();
            let live_events = if live_wait {
                platform.drain_live_socket_activity().unwrap_or_default()
            } else {
                Vec::new()
            };
            let previous = read_state(&data_dir)?.unwrap_or_else(empty_state);
            let (current, events) = if live_wait && !live_events.is_empty() {
                // Live eBPF path: skip the procfs snapshot and use live events directly.
                // Carry previous sockets forward as the current state so the next
                // diff_state fallback iteration has a valid baseline.
                let events = live_activity_to_history_events(platform, &live_events, opts.filter);
                (previous.sockets.clone(), events)
            } else {
                let current = collect_agent_sockets(platform, opts.filter)?;
                let events = diff_state(previous.sockets, current.clone(), now);
                (current, events)
            };
            append_events(&data_dir.join(EVENTS_FILE), &events, opts.capacity)?;
            write_state(
                &data_dir,
                &RecorderState {
                    schema: HISTORY_SCHEMA.to_string(),
                    updated_at: now,
                    sockets: current,
                },
            )?;

            if remaining == 1 {
                break;
            }
            remaining = remaining.saturating_sub(1);
            if !live_wait {
                std::thread::sleep(Duration::from_secs(opts.interval));
            }
        }
        Ok(())
    })();

    if let Err(err) = std::fs::remove_file(data_dir.join(PID_FILE)) {
        if err.kind() != std::io::ErrorKind::NotFound {
            return Err(err).context("failed to remove history pid file");
        }
    }
    result?;

    render_message(
        json!({
            "schema": HISTORY_SCHEMA,
            "recorded": true,
            "data_dir": data_dir.display().to_string(),
        }),
        "history recording iteration completed".to_string(),
        opts.as_json,
        opts.llm,
    )
}

fn run_stop(data_dir_override: Option<&Path>, as_json: bool, llm: bool) -> Result<RenderOutcome> {
    let data_dir = history_dir(data_dir_override)?;
    let pid_meta = read_pid_file(&data_dir)?.context("history recorder is not running")?;
    if !pid_is_running(pid_meta.pid) {
        remove_pid_file_if_present(&data_dir)?;
        return render_message(
            json!({
                "schema": HISTORY_SCHEMA,
                "stopped": false,
                "running": false,
                "pid": pid_meta.pid,
                "data_dir": data_dir.display().to_string(),
            }),
            format!(
                "history recorder was not running; removed stale pid {}",
                pid_meta.pid
            ),
            as_json,
            llm,
        );
    }

    stop_pid(pid_meta.pid)?;
    remove_pid_file_if_present(&data_dir)?;

    render_message(
        json!({
            "schema": HISTORY_SCHEMA,
            "stopped": true,
            "pid": pid_meta.pid,
            "data_dir": data_dir.display().to_string(),
        }),
        format!("history recorder stopped (pid {})", pid_meta.pid),
        as_json,
        llm,
    )
}

fn run_status(data_dir_override: Option<&Path>, as_json: bool, llm: bool) -> Result<RenderOutcome> {
    let data_dir = history_dir(data_dir_override)?;
    ensure_history_dir(&data_dir)?;
    let pid_meta = read_pid_file(&data_dir)?;
    let state = read_state(&data_dir)?.unwrap_or_else(empty_state);
    let retained_events = read_events(&data_dir.join(EVENTS_FILE))?.len();
    let running = pid_meta
        .as_ref()
        .map(|meta| pid_is_running(meta.pid))
        .unwrap_or(false);

    let payload = StatusPayload {
        schema: HISTORY_SCHEMA,
        running,
        pid: pid_meta.as_ref().map(|meta| meta.pid),
        started_at: pid_meta.as_ref().map(|meta| meta.started_at),
        interval_secs: pid_meta.as_ref().map(|meta| meta.interval_secs),
        capacity: pid_meta.as_ref().map(|meta| meta.capacity),
        last_updated_at: if state.updated_at == 0 {
            None
        } else {
            Some(state.updated_at)
        },
        retained_events,
        tracked_sockets: state.sockets.len(),
        data_dir: data_dir.display().to_string(),
    };

    if llm {
        let resp = AgentResponse {
            schema: "opn-agent/1".to_string(),
            ok: true,
            ts: agent::current_ts(),
            cmd: "history status".to_string(),
            caps: agent::caps(false),
            data: Some(serde_json::to_value(&payload)?),
            hints: vec![],
            warnings: vec![],
            actions: agent::build_actions(false),
        };
        agent::print_agent_response(&resp);
    } else if as_json {
        println!("{}", serde_json::to_string_pretty(&payload)?);
    } else if running {
        println!(
            "history recorder running pid={} interval={}s capacity={} tracked_sockets={} retained_events={} last_updated_at={}",
            payload.pid.unwrap_or(0),
            payload.interval_secs.unwrap_or(0),
            payload.capacity.unwrap_or(0),
            payload.tracked_sockets,
            payload.retained_events,
            payload.last_updated_at.unwrap_or(0)
        );
    } else {
        println!(
            "history recorder stopped tracked_sockets={} retained_events={} last_updated_at={}",
            payload.tracked_sockets,
            payload.retained_events,
            payload.last_updated_at.unwrap_or(0)
        );
    }

    Ok(if payload.retained_events == 0 {
        RenderOutcome::NoResults
    } else {
        RenderOutcome::HasResults
    })
}

fn print_events(events: Vec<HistoryEvent>, as_json: bool, llm: bool) -> Result<RenderOutcome> {
    if llm {
        let resp = AgentResponse {
            schema: "opn-agent/1".to_string(),
            ok: true,
            ts: agent::current_ts(),
            cmd: "history events".to_string(),
            caps: agent::caps(false),
            data: Some(serde_json::to_value(&events)?),
            hints: vec![],
            warnings: vec![],
            actions: agent::build_actions(false),
        };
        agent::print_agent_response(&resp);
    } else if as_json {
        println!("{}", serde_json::to_string_pretty(&events)?);
    } else if events.is_empty() {
        println!("No matching history events.");
    } else {
        for event in &events {
            println!(
                "{} {} {} {} -> {} [{}] pid={} proc={}",
                event.ts,
                event.kind.as_str(),
                event.socket.protocol,
                event.socket.local,
                event.socket.remote,
                event
                    .current_state
                    .as_deref()
                    .or(event.previous_state.as_deref())
                    .unwrap_or(event.socket.state.as_str()),
                event.socket.pid,
                event.socket.process
            );
        }
    }

    Ok(if events.is_empty() {
        RenderOutcome::NoResults
    } else {
        RenderOutcome::HasResults
    })
}

fn render_message(
    payload: serde_json::Value,
    text: String,
    as_json: bool,
    llm: bool,
) -> Result<RenderOutcome> {
    if llm {
        let resp = AgentResponse {
            schema: "opn-agent/1".to_string(),
            ok: true,
            ts: agent::current_ts(),
            cmd: "history".to_string(),
            caps: agent::caps(false),
            data: Some(payload),
            hints: vec![],
            warnings: vec![],
            actions: agent::build_actions(false),
        };
        agent::print_agent_response(&resp);
    } else if as_json {
        println!("{}", serde_json::to_string_pretty(&payload)?);
    } else {
        println!("{text}");
    }
    Ok(RenderOutcome::HasResults)
}

fn history_dir(override_dir: Option<&Path>) -> Result<PathBuf> {
    if let Some(path) = override_dir {
        return Ok(path.to_path_buf());
    }
    let home = std::env::var("HOME").unwrap_or_else(|_| String::from("/tmp"));
    Ok(PathBuf::from(home)
        .join(".local")
        .join("share")
        .join("opn")
        .join("history"))
}

fn ensure_history_dir(path: &Path) -> Result<()> {
    std::fs::create_dir_all(path)
        .with_context(|| format!("failed to create history dir {}", path.display()))?;
    Ok(())
}

fn collect_agent_sockets(
    platform: &dyn Platform,
    filter: &QueryFilter,
) -> Result<Vec<AgentSocket>> {
    let sockets = platform.list_sockets(filter)?;
    let mut agent_sockets: Vec<_> = sockets
        .iter()
        .map(|socket| {
            let ancestry = platform
                .process_ancestry(socket.process.pid)
                .unwrap_or_default();
            agent::socket_to_agent(socket, ancestry, false)
        })
        .collect();
    agent_sockets.sort_by_key(socket_identity);
    Ok(agent_sockets)
}

fn empty_state() -> RecorderState {
    RecorderState {
        schema: HISTORY_SCHEMA.to_string(),
        updated_at: 0,
        sockets: Vec::new(),
    }
}

fn diff_state(previous: Vec<AgentSocket>, current: Vec<AgentSocket>, ts: u64) -> Vec<HistoryEvent> {
    let prev_map: HashMap<String, AgentSocket> = previous
        .into_iter()
        .map(|socket| (socket_identity(&socket), socket))
        .collect();
    let curr_map: HashMap<String, AgentSocket> = current
        .into_iter()
        .map(|socket| (socket_identity(&socket), socket))
        .collect();

    let mut events = Vec::new();
    for (key, socket) in &curr_map {
        match prev_map.get(key) {
            None => events.push(HistoryEvent {
                ts,
                kind: EventKind::Appeared,
                socket: socket.clone(),
                previous_state: None,
                current_state: Some(socket.state.clone()),
                rx_bytes: None,
                tx_bytes: None,
                retransmits: None,
                rtt_us: None,
            }),
            Some(previous_socket) if previous_socket.state != socket.state => {
                events.push(HistoryEvent {
                    ts,
                    kind: EventKind::StateChanged,
                    socket: socket.clone(),
                    previous_state: Some(previous_socket.state.clone()),
                    current_state: Some(socket.state.clone()),
                    rx_bytes: None,
                    tx_bytes: None,
                    retransmits: None,
                    rtt_us: None,
                })
            }
            _ => {}
        }
    }
    for (key, socket) in &prev_map {
        if !curr_map.contains_key(key) {
            events.push(HistoryEvent {
                ts,
                kind: EventKind::Disappeared,
                socket: socket.clone(),
                previous_state: Some(socket.state.clone()),
                current_state: None,
                rx_bytes: None,
                tx_bytes: None,
                retransmits: None,
                rtt_us: None,
            });
        }
    }
    events.sort_by(|a, b| {
        (a.ts, socket_identity(&a.socket), a.kind.as_str()).cmp(&(
            b.ts,
            socket_identity(&b.socket),
            b.kind.as_str(),
        ))
    });
    events
}

fn socket_identity(socket: &AgentSocket) -> String {
    format!(
        "{}|{}|{}|{}|{}",
        socket.protocol, socket.local, socket.remote, socket.pid, socket.process
    )
}

fn live_activity_to_history_events(
    platform: &dyn Platform,
    events: &[LiveSocketActivity],
    filter: &QueryFilter,
) -> Vec<HistoryEvent> {
    let mut history_events = Vec::new();
    for event in events {
        if let Some(history_event) = live_activity_to_history_event(platform, event, filter) {
            history_events.push(history_event);
        }
    }
    history_events.sort_by(|a, b| {
        (a.ts, socket_identity(&a.socket), a.kind.as_str()).cmp(&(
            b.ts,
            socket_identity(&b.socket),
            b.kind.as_str(),
        ))
    });
    history_events
}

fn live_activity_to_history_event(
    platform: &dyn Platform,
    event: &LiveSocketActivity,
    filter: &QueryFilter,
) -> Option<HistoryEvent> {
    if let Some(pid) = filter.pid {
        if event.pid != pid {
            return None;
        }
    }
    if let Some(process_name) = &filter.process_name {
        if &event.process != process_name {
            return None;
        }
    }
    if filter.tcp && !event.protocol.eq_ignore_ascii_case("tcp") {
        return None;
    }
    if filter.udp && !event.protocol.eq_ignore_ascii_case("udp") {
        return None;
    }
    if filter.ipv4 && event.local_addr.starts_with('[') {
        return None;
    }
    if filter.ipv6 && !event.local_addr.starts_with('[') {
        return None;
    }
    if let Some(state) = &filter.state {
        let event_state = live_activity_state(event);
        if !event_state.eq_ignore_ascii_case(state) {
            return None;
        }
    }

    let proc_info = platform.process_info(event.pid).ok();
    let socket = AgentSocket {
        protocol: event.protocol.clone(),
        local: event.local_addr.clone(),
        remote: event.remote_addr.clone(),
        state: live_activity_state(event).to_string(),
        pid: event.pid,
        process: event.process.clone(),
        user: proc_info
            .as_ref()
            .map(|p| p.user.clone())
            .unwrap_or_default(),
        cmd: proc_info
            .as_ref()
            .map(|p| p.command.clone())
            .unwrap_or_else(|| event.process.clone()),
        ancestry: Vec::new(),
        rdns: None,
        service: None,
        container: crate::container::detect(event.pid),
    };

    let (kind, previous_state, current_state) = match event.kind {
        LiveSocketActivityKind::Listen => (EventKind::Listen, None, Some(String::from("LISTEN"))),
        LiveSocketActivityKind::Accept => {
            (EventKind::Accept, None, Some(String::from("ESTABLISHED")))
        }
        LiveSocketActivityKind::Connect => {
            (EventKind::Connect, None, Some(String::from("ESTABLISHED")))
        }
        LiveSocketActivityKind::Close => (
            // TODO: previous_state should come from the eBPF flow table (could be
            // LISTEN, SYN_SENT, TIME_WAIT, etc.); ESTABLISHED is a best-effort default
            // until the eBPF event carries prior state.
            EventKind::Close,
            Some(String::from("ESTABLISHED")),
            Some(String::from("CLOSED")),
        ),
        LiveSocketActivityKind::StateChange => {
            (EventKind::StateChanged, None, Some(String::from("ACTIVE")))
        }
        LiveSocketActivityKind::Retransmit => (
            EventKind::Retransmit,
            None,
            Some(String::from("ESTABLISHED")),
        ),
    };

    Some(HistoryEvent {
        ts: event.ts_ns / 1_000_000_000,
        kind,
        socket,
        previous_state,
        current_state,
        rx_bytes: Some(event.rx_bytes),
        tx_bytes: Some(event.tx_bytes),
        retransmits: Some(event.retransmits),
        rtt_us: event.rtt_us,
    })
}

fn live_activity_state(event: &LiveSocketActivity) -> &'static str {
    match event.kind {
        LiveSocketActivityKind::Listen => "LISTEN",
        LiveSocketActivityKind::Accept | LiveSocketActivityKind::Connect => "ESTABLISHED",
        LiveSocketActivityKind::Close => "CLOSED",
        LiveSocketActivityKind::StateChange => "ACTIVE",
        LiveSocketActivityKind::Retransmit => "ESTABLISHED",
    }
}

fn append_events(path: &Path, new_events: &[HistoryEvent], capacity: usize) -> Result<()> {
    if new_events.is_empty() && path.exists() {
        return Ok(());
    }
    let mut all = VecDeque::from(read_events(path)?);
    for event in new_events {
        all.push_back(event.clone());
    }
    while all.len() > capacity {
        all.pop_front();
    }

    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent)?;
    }
    let mut file = OpenOptions::new()
        .create(true)
        .write(true)
        .truncate(true)
        .open(path)
        .with_context(|| format!("failed to open history events file {}", path.display()))?;
    for event in all {
        writeln!(file, "{}", serde_json::to_string(&event)?)?;
    }
    Ok(())
}

fn read_events(path: &Path) -> Result<Vec<HistoryEvent>> {
    if !path.exists() {
        return Ok(Vec::new());
    }
    let content = std::fs::read_to_string(path)
        .with_context(|| format!("failed to read history events {}", path.display()))?;
    content
        .lines()
        .filter(|line| !line.trim().is_empty())
        .map(|line| {
            serde_json::from_str::<HistoryEvent>(line).context("failed to parse history event")
        })
        .collect()
}

fn write_state(data_dir: &Path, state: &RecorderState) -> Result<()> {
    let path = data_dir.join(STATE_FILE);
    std::fs::write(&path, serde_json::to_vec_pretty(state)?)
        .with_context(|| format!("failed to write history state {}", path.display()))?;
    Ok(())
}

fn read_state(data_dir: &Path) -> Result<Option<RecorderState>> {
    let path = data_dir.join(STATE_FILE);
    if !path.exists() {
        return Ok(None);
    }
    let content = std::fs::read_to_string(&path)
        .with_context(|| format!("failed to read history state {}", path.display()))?;
    Ok(Some(serde_json::from_str(&content)?))
}

fn write_pid_file(data_dir: &Path, pid_meta: &RecorderPid) -> Result<()> {
    let path = data_dir.join(PID_FILE);
    std::fs::write(&path, serde_json::to_vec_pretty(pid_meta)?)
        .with_context(|| format!("failed to write history pid file {}", path.display()))?;
    Ok(())
}

fn read_pid_file(data_dir: &Path) -> Result<Option<RecorderPid>> {
    let path = data_dir.join(PID_FILE);
    if !path.exists() {
        return Ok(None);
    }
    let content = std::fs::read_to_string(&path)
        .with_context(|| format!("failed to read history pid file {}", path.display()))?;
    Ok(Some(serde_json::from_str(&content)?))
}

fn remove_pid_file_if_present(data_dir: &Path) -> Result<()> {
    let path = data_dir.join(PID_FILE);
    if let Err(err) = std::fs::remove_file(&path) {
        if err.kind() != std::io::ErrorKind::NotFound {
            return Err(err).with_context(|| format!("failed to remove {}", path.display()));
        }
    }
    Ok(())
}

fn pid_is_running(pid: u32) -> bool {
    unsafe { libc::kill(pid as i32, 0) == 0 }
}

fn stop_pid(pid: u32) -> Result<()> {
    if unsafe { libc::kill(pid as i32, libc::SIGTERM) } != 0 {
        return Err(std::io::Error::last_os_error()).context("failed to stop history recorder");
    }
    Ok(())
}

fn event_matches(event: &HistoryEvent, filter: &EventFilter<'_>) -> bool {
    if let Some(since_ts) = filter.since {
        if event.ts < since_ts {
            return false;
        }
    }
    if let Some(until_ts) = filter.until {
        if event.ts > until_ts {
            return false;
        }
    }
    if let Some(expected_pid) = filter.pid {
        if event.socket.pid != expected_pid {
            return false;
        }
    }
    if let Some(expected_process) = filter.process {
        if event.socket.process != expected_process {
            return false;
        }
    }
    if let Some(expected_kind) = filter.kind {
        if event.kind.as_str() != expected_kind {
            return false;
        }
    }
    if let Some(expected_state) = filter.state {
        let prev_matches = event
            .previous_state
            .as_ref()
            .map(|value| value.eq_ignore_ascii_case(expected_state))
            .unwrap_or(false);
        let curr_matches = event
            .current_state
            .as_ref()
            .map(|value| value.eq_ignore_ascii_case(expected_state))
            .unwrap_or(false);
        if !prev_matches
            && !curr_matches
            && !event.socket.state.eq_ignore_ascii_case(expected_state)
        {
            return false;
        }
    }
    if let Some(expected_port) = filter.port {
        if !addr_has_port(&event.socket.local, expected_port)
            && !addr_has_port(&event.socket.remote, expected_port)
        {
            return false;
        }
    }
    true
}

fn addr_has_port(addr: &str, expected_port: u16) -> bool {
    addr.rsplit(':')
        .next()
        .and_then(|raw| raw.parse::<u16>().ok())
        .map(|port| port == expected_port)
        .unwrap_or(false)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn socket(local: &str, remote: &str, state: &str, pid: u32) -> AgentSocket {
        AgentSocket {
            protocol: "TCP".to_string(),
            local: local.to_string(),
            remote: remote.to_string(),
            state: state.to_string(),
            pid,
            process: format!("p{pid}"),
            user: "me".to_string(),
            cmd: format!("cmd-{pid}"),
            ancestry: vec![],
            rdns: None,
            service: None,
            container: None,
        }
    }

    #[test]
    fn diff_state_detects_appearance_disappearance_and_state_change() {
        let previous = vec![
            socket("127.0.0.1:80", "0.0.0.0:0", "LISTEN", 10),
            socket("127.0.0.1:443", "1.2.3.4:50000", "ESTABLISHED", 11),
            socket("127.0.0.1:8080", "0.0.0.0:0", "LISTEN", 13),
        ];
        let current = vec![
            socket("127.0.0.1:80", "0.0.0.0:0", "LISTEN", 10),
            socket("127.0.0.1:443", "1.2.3.4:50000", "CLOSE_WAIT", 11),
            socket("127.0.0.1:53", "0.0.0.0:0", "LISTEN", 12),
        ];

        let events = diff_state(previous, current, 123);
        assert_eq!(events.len(), 3);
        assert!(events.iter().any(|event| event.kind == EventKind::Appeared));
        assert!(events
            .iter()
            .any(|event| event.kind == EventKind::Disappeared));
        assert!(events
            .iter()
            .any(|event| event.kind == EventKind::StateChanged));
    }

    #[test]
    fn append_events_enforces_capacity() {
        let dir = std::env::temp_dir().join(format!(
            "opn-history-test-{}-{}",
            std::process::id(),
            agent::current_ts()
        ));
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join(EVENTS_FILE);
        let events = [
            HistoryEvent {
                ts: 1,
                kind: EventKind::Appeared,
                socket: socket("127.0.0.1:1", "0.0.0.0:0", "LISTEN", 1),
                previous_state: None,
                current_state: Some("LISTEN".to_string()),
                rx_bytes: None,
                tx_bytes: None,
                retransmits: None,
                rtt_us: None,
            },
            HistoryEvent {
                ts: 2,
                kind: EventKind::Appeared,
                socket: socket("127.0.0.1:2", "0.0.0.0:0", "LISTEN", 2),
                previous_state: None,
                current_state: Some("LISTEN".to_string()),
                rx_bytes: None,
                tx_bytes: None,
                retransmits: None,
                rtt_us: None,
            },
            HistoryEvent {
                ts: 3,
                kind: EventKind::Appeared,
                socket: socket("127.0.0.1:3", "0.0.0.0:0", "LISTEN", 3),
                previous_state: None,
                current_state: Some("LISTEN".to_string()),
                rx_bytes: None,
                tx_bytes: None,
                retransmits: None,
                rtt_us: None,
            },
        ];
        append_events(&path, &events[..2], 2).unwrap();
        append_events(&path, &events[2..], 2).unwrap();
        let stored = read_events(&path).unwrap();
        assert_eq!(stored.len(), 2);
        assert_eq!(stored[0].ts, 2);
        assert_eq!(stored[1].ts, 3);
        let _ = std::fs::remove_dir_all(dir);
    }

    #[test]
    fn event_matches_applies_filters() {
        let event = HistoryEvent {
            ts: 100,
            kind: EventKind::StateChanged,
            socket: socket("127.0.0.1:4444", "10.0.0.2:55000", "ESTABLISHED", 22),
            previous_state: Some("SYN_RECV".to_string()),
            current_state: Some("ESTABLISHED".to_string()),
            rx_bytes: None,
            tx_bytes: None,
            retransmits: None,
            rtt_us: None,
        };
        assert!(event_matches(
            &event,
            &EventFilter {
                since: Some(90),
                until: Some(110),
                port: Some(4444),
                pid: Some(22),
                process: Some("p22"),
                kind: Some("state_changed"),
                state: Some("ESTABLISHED"),
            },
        ));
        assert!(!event_matches(
            &event,
            &EventFilter {
                since: Some(101),
                until: None,
                port: None,
                pid: None,
                process: None,
                kind: None,
                state: None,
            },
        ));
    }
}
