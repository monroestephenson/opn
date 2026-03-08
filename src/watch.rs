#[cfg(feature = "watch")]
pub fn run(
    platform: &dyn crate::platform::Platform,
    target: crate::cli::WatchTarget,
    port: Option<u16>,
    file: Option<&str>,
    interval_secs: u64,
    filter: &crate::model::QueryFilter,
    as_json: bool,
) -> anyhow::Result<()> {
    use crate::cli::WatchTarget;
    use anyhow::Context;
    use crossterm::event::{self, Event, KeyCode};
    use crossterm::execute;
    use crossterm::terminal::{
        disable_raw_mode, enable_raw_mode, EnterAlternateScreen, LeaveAlternateScreen,
    };
    use ratatui::backend::CrosstermBackend;
    use ratatui::layout::{Constraint, Direction, Layout};
    use ratatui::style::{Modifier, Style};
    use ratatui::widgets::{Block, Borders, Cell, Paragraph, Row, Table, TableState};
    use ratatui::Terminal;
    use std::io::stdout;
    use std::time::{Duration, Instant};

    if as_json {
        anyhow::bail!("watch mode does not support --json");
    }
    if target == WatchTarget::Port && port.is_none() {
        anyhow::bail!("watch --target port requires --port <PORT>");
    }
    if target == WatchTarget::File && file.is_none() {
        anyhow::bail!("watch --target file requires --file <PATH>");
    }

    #[derive(Clone, Copy, PartialEq, Eq)]
    enum SortKey {
        Protocol,
        Local,
        Pid,
    }
    impl SortKey {
        fn next(self) -> Self {
            match self {
                SortKey::Protocol => SortKey::Local,
                SortKey::Local => SortKey::Pid,
                SortKey::Pid => SortKey::Protocol,
            }
        }
        fn label(self) -> &'static str {
            match self {
                SortKey::Protocol => "protocol",
                SortKey::Local => "local",
                SortKey::Pid => "pid",
            }
        }
    }

    enable_raw_mode().context("failed to enable raw mode")?;
    let mut out = stdout();
    execute!(out, EnterAlternateScreen).context("failed to enter alternate screen")?;
    let backend = CrosstermBackend::new(out);
    let mut terminal = Terminal::new(backend).context("failed to create terminal")?;
    let mut paused = false;
    let mut sort_key = SortKey::Local;
    let mut last_tick = Instant::now();
    let tick_rate = Duration::from_secs(interval_secs);
    let mut rows = snapshot_rows(platform, target, port, file, filter)?;
    let mut selected = 0usize;
    let mut table_state = TableState::default();
    let mut status_msg = String::new();
    let title = match target {
        WatchTarget::Sockets => "Sockets",
        WatchTarget::Port => "Port",
        WatchTarget::File => "File",
    };
    let headers = headers_for(target);

    let result: anyhow::Result<()> = (|| loop {
        rows.sort_by(|a, b| match sort_key {
            SortKey::Protocol => a.cols[0].cmp(&b.cols[0]).then(a.cols[1].cmp(&b.cols[1])),
            SortKey::Local => a.cols[1].cmp(&b.cols[1]).then(a.cols[4].cmp(&b.cols[4])),
            SortKey::Pid => a.cols[4].cmp(&b.cols[4]).then(a.cols[1].cmp(&b.cols[1])),
        });
        clamp_selection(&mut selected, rows.len());
        if rows.is_empty() {
            table_state.select(None);
        } else {
            table_state.select(Some(selected));
        }

        terminal.draw(|frame| {
            let area = frame.area();
            let chunks = Layout::default()
                .direction(Direction::Vertical)
                .constraints([Constraint::Length(2), Constraint::Min(1)])
                .split(area);

            let status = format!(
                "opn watch {} | {} | sort={} | interval={}s | rows={} | j/k move, g/G top/bottom, x terminate, q quit",
                title.to_ascii_lowercase(),
                if paused { "paused" } else { "running" },
                sort_key.label(),
                interval_secs,
                rows.len()
            );
            let full_status = if status_msg.is_empty() {
                status
            } else {
                format!("{status} | {status_msg}")
            };
            frame.render_widget(Paragraph::new(full_status), chunks[0]);

            let header = Row::new(headers)
                .style(Style::default().add_modifier(Modifier::BOLD));
            let rows_view = rows.iter().map(|e| {
                Row::new(vec![
                    Cell::from(e.cols[0].clone()),
                    Cell::from(e.cols[1].clone()),
                    Cell::from(e.cols[2].clone()),
                    Cell::from(e.cols[3].clone()),
                    Cell::from(e.cols[4].clone()),
                    Cell::from(e.cols[5].clone()),
                ])
            });
            let table = Table::new(
                rows_view,
                [
                    Constraint::Length(12),
                    Constraint::Length(24),
                    Constraint::Length(24),
                    Constraint::Length(16),
                    Constraint::Length(8),
                    Constraint::Min(8),
                ],
            )
            .header(header)
            .block(Block::default().borders(Borders::ALL).title(title))
            .row_highlight_style(Style::default().add_modifier(Modifier::REVERSED));
            frame.render_stateful_widget(table, chunks[1], &mut table_state);
        })?;

        let timeout = tick_rate.saturating_sub(last_tick.elapsed());
        if event::poll(timeout)? {
            if let Event::Key(key) = event::read()? {
                match key.code {
                    KeyCode::Char('q') => break Ok(()),
                    KeyCode::Char(' ') => paused = !paused,
                    KeyCode::Char('s') => sort_key = sort_key.next(),
                    KeyCode::Down | KeyCode::Char('j') => {
                        if selected + 1 < rows.len() {
                            selected += 1;
                        }
                    }
                    KeyCode::Up | KeyCode::Char('k') => {
                        selected = selected.saturating_sub(1);
                    }
                    KeyCode::Char('g') => selected = 0,
                    KeyCode::Char('G') => {
                        if !rows.is_empty() {
                            selected = rows.len() - 1;
                        }
                    }
                    KeyCode::Char('x') => {
                        if let Some(row) = rows.get(selected) {
                            match terminate_pid(row.pid) {
                                Ok(()) => {
                                    status_msg = format!("sent SIGTERM to pid {}", row.pid);
                                    if !paused {
                                        rows = snapshot_rows(platform, target, port, file, filter)?;
                                        clamp_selection(&mut selected, rows.len());
                                        last_tick = Instant::now();
                                    }
                                }
                                Err(err) => {
                                    status_msg = err.to_string();
                                }
                            }
                        } else {
                            status_msg = String::from("no row selected");
                        }
                    }
                    _ => {}
                }
            }
        }

        if !paused && last_tick.elapsed() >= tick_rate {
            rows = snapshot_rows(platform, target, port, file, filter)?;
            clamp_selection(&mut selected, rows.len());
            last_tick = Instant::now();
        }
    })();

    disable_raw_mode().ok();
    execute!(terminal.backend_mut(), LeaveAlternateScreen).ok();
    terminal.show_cursor().ok();
    result
}

#[cfg(feature = "watch")]
#[derive(Clone)]
struct WatchRow {
    cols: [String; 6],
    pid: u32,
}

#[cfg(feature = "watch")]
fn headers_for(target: crate::cli::WatchTarget) -> [&'static str; 6] {
    use crate::cli::WatchTarget;
    match target {
        WatchTarget::Sockets | WatchTarget::Port => {
            ["PROTO", "LOCAL", "REMOTE", "STATE", "PID", "PROCESS"]
        }
        WatchTarget::File => ["PID", "PROCESS", "USER", "FD", "TYPE", "PATH"],
    }
}

#[cfg(feature = "watch")]
fn clamp_selection(selected: &mut usize, len: usize) {
    if len == 0 {
        *selected = 0;
    } else if *selected >= len {
        *selected = len - 1;
    }
}

#[cfg(feature = "watch")]
fn terminate_pid(pid: u32) -> anyhow::Result<()> {
    use anyhow::Context;

    if pid == std::process::id() {
        anyhow::bail!("refusing to terminate current opn process (pid {pid})");
    }

    let rc = unsafe { libc::kill(pid as i32, libc::SIGTERM) };
    if rc == 0 {
        Ok(())
    } else {
        let err = std::io::Error::last_os_error();
        Err(err).with_context(|| format!("failed to terminate pid {pid}"))
    }
}

#[cfg(feature = "watch")]
fn socket_rows(entries: &[crate::model::SocketEntry]) -> Vec<WatchRow> {
    entries
        .iter()
        .map(|e| WatchRow {
            cols: [
                e.protocol.to_string(),
                e.local_addr.clone(),
                e.remote_addr.clone(),
                e.state.clone(),
                e.process.pid.to_string(),
                e.process.name.clone(),
            ],
            pid: e.process.pid,
        })
        .collect()
}

#[cfg(feature = "watch")]
fn file_rows(entries: &[crate::model::OpenFile]) -> Vec<WatchRow> {
    entries
        .iter()
        .map(|e| WatchRow {
            cols: [
                e.process.pid.to_string(),
                e.process.name.clone(),
                e.process.user.clone(),
                e.fd.map(|f| f.to_string()).unwrap_or_else(|| "-".into()),
                e.fd_type.to_string(),
                if e.deleted {
                    format!("{} (deleted)", e.path)
                } else {
                    e.path.clone()
                },
            ],
            pid: e.process.pid,
        })
        .collect()
}

#[cfg(feature = "watch")]
fn snapshot_rows(
    platform: &dyn crate::platform::Platform,
    target: crate::cli::WatchTarget,
    port: Option<u16>,
    file: Option<&str>,
    filter: &crate::model::QueryFilter,
) -> anyhow::Result<Vec<WatchRow>> {
    use crate::cli::WatchTarget;

    match target {
        WatchTarget::Sockets => {
            let entries = platform.list_sockets(filter)?;
            Ok(socket_rows(&entries))
        }
        WatchTarget::Port => {
            let p = port.expect("validated by caller");
            let entries = platform.find_by_port(p, filter)?;
            Ok(socket_rows(&entries))
        }
        WatchTarget::File => {
            let path = file.expect("validated by caller");
            let entries = platform.find_by_file(path, filter)?;
            Ok(file_rows(&entries))
        }
    }
}
