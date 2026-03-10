#[cfg(feature = "watch")]
use ratatui::style::{Color, Modifier, Style};

#[cfg(feature = "watch")]
#[derive(Clone, Copy)]
pub struct WatchRunOptions<'a> {
    pub target: crate::cli::WatchTarget,
    pub theme: crate::cli::WatchTheme,
    pub port: Option<u16>,
    pub file: Option<&'a str>,
    pub interval_secs: u64,
    pub filter: &'a crate::model::QueryFilter,
    pub as_json: bool,
}

#[cfg(feature = "watch")]
struct DrillDownData {
    entry: crate::model::SocketEntry,
    resources: Option<crate::model::ProcessResources>,
    ancestry: Vec<crate::model::ProcessAncestor>,
}

#[cfg(feature = "watch")]
enum AppState {
    List,
    DrillDown(DrillDownData),
}

#[cfg(feature = "watch")]
pub fn run(
    platform: &dyn crate::platform::Platform,
    opts: WatchRunOptions<'_>,
) -> anyhow::Result<()> {
    use crate::cli::WatchTarget;
    use anyhow::Context;
    use crossterm::event::{self, Event, KeyCode};
    use crossterm::execute;
    use crossterm::terminal::{
        disable_raw_mode, enable_raw_mode, EnterAlternateScreen, LeaveAlternateScreen,
    };
    use ratatui::backend::CrosstermBackend;
    use ratatui::layout::{Alignment, Constraint, Direction, Layout};
    use ratatui::widgets::{Block, Borders, Cell, Clear, Paragraph, Row, Table, TableState};
    use ratatui::Terminal;
    use std::io::stdout;
    use std::time::{Duration, Instant};

    let WatchRunOptions {
        target,
        theme,
        port,
        file,
        interval_secs,
        filter,
        as_json,
    } = opts;

    if as_json {
        anyhow::bail!("watch mode does not support --json");
    }
    if target == WatchTarget::Port && port.is_none() {
        anyhow::bail!("watch --target port requires --port <PORT>");
    }
    if target == WatchTarget::File && file.is_none() {
        anyhow::bail!("watch --target file requires --file <PATH>");
    }
    if target == WatchTarget::File {
        crate::path_safety::validate_user_path(file.expect("validated above"))?;
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
    let mut app_state = AppState::List;
    let mut paused = false;
    let mut sort_key = SortKey::Local;
    let mut last_tick = Instant::now();
    let tick_rate = Duration::from_secs(interval_secs);
    let mut rows = snapshot_rows(platform, target, port, file, filter)?;
    let mut selected = 0usize;
    let mut table_state = TableState::default();
    let mut status_msg = String::new();
    let mut confirm_kill: Option<(u32, String)> = None;
    let title = match target {
        WatchTarget::Sockets => "Sockets",
        WatchTarget::Port => "Port",
        WatchTarget::File => "File",
    };
    let headers = headers_for(target);
    let show_socket_totals = matches!(target, WatchTarget::Sockets | WatchTarget::Port);
    let palette = theme_palette(theme);

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
                "opn watch {} | {} | sort={} | interval={}s | {} | j/k move, g/G top/bottom, enter drill-down, x terminate, q quit",
                title.to_ascii_lowercase(),
                if paused { "paused" } else { "running" },
                sort_key.label(),
                interval_secs,
                if show_socket_totals {
                    socket_state_totals(&rows)
                } else {
                    format!("rows={}", rows.len())
                }
            );
            let full_status = if status_msg.is_empty() {
                status
            } else {
                format!("{status} | {status_msg}")
            };
            frame.render_widget(
                Paragraph::new(full_status).style(status_bar_style(paused, &palette)),
                chunks[0],
            );

            let header = Row::new(headers).style(header_style(&palette));
            let rows_view = rows.iter().map(|e| {
                Row::new(vec![
                    Cell::from(e.cols[0].clone()),
                    Cell::from(e.cols[1].clone()),
                    Cell::from(e.cols[2].clone()),
                    Cell::from(e.cols[3].clone()),
                    Cell::from(e.cols[4].clone()),
                    Cell::from(e.cols[5].clone()),
                ])
                .style(row_style(e, target, &palette))
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
            .block(
                Block::default()
                    .borders(Borders::ALL)
                    .title(title)
                    .style(block_style(&palette)),
            )
            .row_highlight_style(selected_row_style(&palette))
            .highlight_symbol(">> ");
            frame.render_stateful_widget(table, chunks[1], &mut table_state);

            if let Some((pid, process_name)) = &confirm_kill {
                let popup = centered_rect(60, 30, area);
                frame.render_widget(Clear, popup);
                let block = Block::default()
                    .title("Confirm Termination")
                    .borders(Borders::ALL)
                    .style(Style::default().fg(palette.header));
                let text = format!(
                    "Terminate PID {} ({})?\n\nPress y/Enter to confirm, n/Esc to cancel.",
                    pid, process_name
                );
                let paragraph = Paragraph::new(text)
                    .alignment(Alignment::Center)
                    .block(block)
                    .style(Style::default().fg(palette.normal));
                frame.render_widget(paragraph, popup);
            }

            if let AppState::DrillDown(ref dd) = app_state {
                let popup = centered_rect(85, 88, area);
                frame.render_widget(Clear, popup);
                let text = drill_down_text(dd, &palette);
                let block = Block::default()
                    .title(" opn · drill-down ")
                    .borders(Borders::ALL)
                    .style(Style::default().fg(palette.header));
                let paragraph = Paragraph::new(text)
                    .block(block)
                    .style(Style::default().fg(palette.normal));
                frame.render_widget(paragraph, popup);
            }
        })?;

        let timeout = tick_rate.saturating_sub(last_tick.elapsed());
        if event::poll(timeout)? {
            if let Event::Key(key) = event::read()? {
                if let Some((pid, _)) = confirm_kill.clone() {
                    match key.code {
                        KeyCode::Char('y') | KeyCode::Enter => {
                            match terminate_pid(pid) {
                                Ok(()) => {
                                    status_msg = format!("sent SIGTERM to pid {}", pid);
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
                            confirm_kill = None;
                        }
                        KeyCode::Char('n') | KeyCode::Esc => {
                            confirm_kill = None;
                            status_msg = String::from("termination cancelled");
                        }
                        _ => {}
                    }
                } else if matches!(app_state, AppState::DrillDown(_)) {
                    match key.code {
                        KeyCode::Esc | KeyCode::Char('q') => {
                            app_state = AppState::List;
                            status_msg = String::new();
                        }
                        KeyCode::Char('x') => {
                            if let AppState::DrillDown(ref dd) = app_state {
                                confirm_kill =
                                    Some((dd.entry.process.pid, dd.entry.process.name.clone()));
                            }
                        }
                        _ => {}
                    }
                } else {
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
                        KeyCode::Enter => {
                            if let Some(row) = rows.get(selected) {
                                if let Some(ref entry) = row.socket_entry {
                                    let pid = entry.process.pid;
                                    let resources = platform.process_resources(pid).ok();
                                    let ancestry =
                                        platform.process_ancestry(pid).unwrap_or_default();
                                    app_state = AppState::DrillDown(DrillDownData {
                                        entry: entry.clone(),
                                        resources,
                                        ancestry,
                                    });
                                    status_msg = String::from("esc back · x kill");
                                }
                            }
                        }
                        KeyCode::Char('x') => {
                            if let Some(row) = rows.get(selected) {
                                confirm_kill = Some((row.pid, row.cols[5].clone()));
                            } else {
                                status_msg = String::from("no row selected");
                            }
                        }
                        _ => {}
                    }
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
    socket_entry: Option<crate::model::SocketEntry>,
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
        .map(|e| {
            let local_port = e
                .local_addr
                .rsplit(':')
                .next()
                .and_then(|p| p.parse::<u16>().ok())
                .unwrap_or(0);
            let service = crate::proto_detect::detect(local_port, &e.process.name);
            let container = crate::container::detect(e.process.pid);

            let mut tags: Vec<String> = Vec::new();
            if let Some(s) = service {
                tags.push(s.to_string());
            }
            if let Some(c) = container {
                tags.push(c);
            }
            let process_col = if tags.is_empty() {
                e.process.name.clone()
            } else {
                format!("{} [{}]", e.process.name, tags.join(" · "))
            };

            WatchRow {
                cols: [
                    e.protocol.to_string(),
                    crate::socket_display::display_local_addr(e),
                    crate::socket_display::display_remote_addr(e),
                    e.state.clone(),
                    e.process.pid.to_string(),
                    process_col,
                ],
                pid: e.process.pid,
                socket_entry: Some(e.clone()),
            }
        })
        .collect()
}

#[cfg(feature = "watch")]
fn socket_state_totals(rows: &[WatchRow]) -> String {
    let listen = rows
        .iter()
        .filter(|r| r.cols[3].eq_ignore_ascii_case("LISTEN"))
        .count();
    let established = rows
        .iter()
        .filter(|r| r.cols[3].eq_ignore_ascii_case("ESTABLISHED"))
        .count();
    format!(
        "{} sockets | {} listening | {} established",
        rows.len(),
        listen,
        established
    )
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
            socket_entry: None,
        })
        .collect()
}

#[cfg(feature = "watch")]
#[derive(Clone, Copy)]
struct ThemePalette {
    status_running: Color,
    status_paused: Color,
    header: Color,
    border: Color,
    selected_fg: Color,
    selected_bg: Color,
    listen: Color,
    established: Color,
    wait: Color,
    udp: Color,
    normal: Color,
    deleted: Color,
}

#[cfg(feature = "watch")]
fn theme_palette(theme: crate::cli::WatchTheme) -> ThemePalette {
    use crate::cli::WatchTheme;
    match theme {
        WatchTheme::CatppuccinLatte => ThemePalette {
            status_running: Color::Rgb(30, 102, 245),
            status_paused: Color::Rgb(223, 142, 29),
            header: Color::Rgb(4, 165, 229),
            border: Color::Rgb(124, 127, 147),
            selected_fg: Color::Rgb(76, 79, 105),
            selected_bg: Color::Rgb(204, 208, 218),
            listen: Color::Rgb(64, 160, 43),
            established: Color::Rgb(30, 102, 245),
            wait: Color::Rgb(223, 142, 29),
            udp: Color::Rgb(234, 118, 203),
            normal: Color::Rgb(76, 79, 105),
            deleted: Color::Rgb(210, 15, 57),
        },
        WatchTheme::Catppuccin => ThemePalette {
            status_running: Color::Rgb(137, 180, 250),
            status_paused: Color::Rgb(249, 226, 175),
            header: Color::Rgb(116, 199, 236),
            border: Color::Rgb(88, 91, 112),
            selected_fg: Color::Rgb(17, 17, 27),
            selected_bg: Color::Rgb(166, 173, 200),
            listen: Color::Rgb(166, 227, 161),
            established: Color::Rgb(137, 180, 250),
            wait: Color::Rgb(249, 226, 175),
            udp: Color::Rgb(245, 194, 231),
            normal: Color::Rgb(205, 214, 244),
            deleted: Color::Rgb(243, 139, 168),
        },
        WatchTheme::Ethereal => ThemePalette {
            status_running: Color::Rgb(164, 196, 255),
            status_paused: Color::Rgb(245, 215, 155),
            header: Color::Rgb(168, 224, 204),
            border: Color::Rgb(96, 110, 140),
            selected_fg: Color::Rgb(232, 237, 255),
            selected_bg: Color::Rgb(67, 77, 102),
            listen: Color::Rgb(176, 220, 170),
            established: Color::Rgb(155, 195, 255),
            wait: Color::Rgb(236, 203, 140),
            udp: Color::Rgb(213, 178, 235),
            normal: Color::Rgb(214, 220, 235),
            deleted: Color::Rgb(235, 149, 167),
        },
        WatchTheme::Everforest => ThemePalette {
            status_running: Color::Rgb(167, 192, 128),
            status_paused: Color::Rgb(230, 195, 132),
            header: Color::Rgb(127, 187, 179),
            border: Color::Rgb(75, 85, 90),
            selected_fg: Color::Rgb(220, 215, 186),
            selected_bg: Color::Rgb(58, 68, 58),
            listen: Color::Rgb(167, 192, 128),
            established: Color::Rgb(127, 187, 179),
            wait: Color::Rgb(219, 188, 127),
            udp: Color::Rgb(214, 153, 182),
            normal: Color::Rgb(211, 198, 170),
            deleted: Color::Rgb(230, 126, 128),
        },
        WatchTheme::FlexokiLight => ThemePalette {
            status_running: Color::Rgb(32, 94, 166),
            status_paused: Color::Rgb(188, 110, 0),
            header: Color::Rgb(36, 131, 123),
            border: Color::Rgb(148, 132, 113),
            selected_fg: Color::Rgb(16, 15, 15),
            selected_bg: Color::Rgb(230, 220, 202),
            listen: Color::Rgb(102, 128, 11),
            established: Color::Rgb(32, 94, 166),
            wait: Color::Rgb(188, 110, 0),
            udp: Color::Rgb(160, 47, 111),
            normal: Color::Rgb(16, 15, 15),
            deleted: Color::Rgb(175, 48, 41),
        },
        WatchTheme::Gruvbox => ThemePalette {
            status_running: Color::Rgb(184, 187, 38),
            status_paused: Color::Rgb(250, 189, 47),
            header: Color::Rgb(131, 165, 152),
            border: Color::Rgb(102, 92, 84),
            selected_fg: Color::Rgb(235, 219, 178),
            selected_bg: Color::Rgb(60, 56, 54),
            listen: Color::Rgb(184, 187, 38),
            established: Color::Rgb(131, 165, 152),
            wait: Color::Rgb(250, 189, 47),
            udp: Color::Rgb(211, 134, 155),
            normal: Color::Rgb(213, 196, 161),
            deleted: Color::Rgb(251, 73, 52),
        },
        WatchTheme::Hackerman => ThemePalette {
            status_running: Color::Rgb(126, 255, 126),
            status_paused: Color::Rgb(190, 255, 126),
            header: Color::Rgb(112, 235, 112),
            border: Color::Rgb(52, 95, 52),
            selected_fg: Color::Rgb(190, 255, 170),
            selected_bg: Color::Rgb(22, 44, 22),
            listen: Color::Rgb(126, 255, 126),
            established: Color::Rgb(90, 220, 150),
            wait: Color::Rgb(190, 220, 110),
            udp: Color::Rgb(150, 205, 135),
            normal: Color::Rgb(120, 195, 120),
            deleted: Color::Rgb(240, 110, 110),
        },
        WatchTheme::Kanagawa => ThemePalette {
            status_running: Color::Rgb(152, 187, 215),
            status_paused: Color::Rgb(223, 188, 118),
            header: Color::Rgb(126, 156, 216),
            border: Color::Rgb(84, 92, 126),
            selected_fg: Color::Rgb(223, 223, 212),
            selected_bg: Color::Rgb(54, 63, 84),
            listen: Color::Rgb(152, 187, 108),
            established: Color::Rgb(126, 156, 216),
            wait: Color::Rgb(223, 188, 118),
            udp: Color::Rgb(149, 127, 184),
            normal: Color::Rgb(201, 206, 219),
            deleted: Color::Rgb(228, 104, 118),
        },
        WatchTheme::MatteBlack => ThemePalette {
            status_running: Color::Rgb(170, 178, 189),
            status_paused: Color::Rgb(208, 162, 109),
            header: Color::Rgb(131, 146, 168),
            border: Color::Rgb(70, 74, 82),
            selected_fg: Color::Rgb(223, 226, 230),
            selected_bg: Color::Rgb(44, 47, 54),
            listen: Color::Rgb(143, 187, 129),
            established: Color::Rgb(131, 146, 168),
            wait: Color::Rgb(208, 162, 109),
            udp: Color::Rgb(173, 142, 181),
            normal: Color::Rgb(185, 189, 198),
            deleted: Color::Rgb(221, 97, 97),
        },
        WatchTheme::Miasma => ThemePalette {
            status_running: Color::Rgb(152, 170, 98),
            status_paused: Color::Rgb(198, 163, 94),
            header: Color::Rgb(124, 153, 143),
            border: Color::Rgb(93, 86, 77),
            selected_fg: Color::Rgb(205, 196, 169),
            selected_bg: Color::Rgb(63, 58, 52),
            listen: Color::Rgb(152, 170, 98),
            established: Color::Rgb(124, 153, 143),
            wait: Color::Rgb(198, 163, 94),
            udp: Color::Rgb(174, 133, 150),
            normal: Color::Rgb(190, 179, 151),
            deleted: Color::Rgb(198, 107, 97),
        },
        WatchTheme::Nord => ThemePalette {
            status_running: Color::Rgb(136, 192, 208),
            status_paused: Color::Rgb(235, 203, 139),
            header: Color::Rgb(129, 161, 193),
            border: Color::Rgb(76, 86, 106),
            selected_fg: Color::Rgb(236, 239, 244),
            selected_bg: Color::Rgb(59, 66, 82),
            listen: Color::Rgb(163, 190, 140),
            established: Color::Rgb(129, 161, 193),
            wait: Color::Rgb(235, 203, 139),
            udp: Color::Rgb(180, 142, 173),
            normal: Color::Rgb(216, 222, 233),
            deleted: Color::Rgb(191, 97, 106),
        },
        WatchTheme::OsakaJade => ThemePalette {
            status_running: Color::Rgb(120, 176, 154),
            status_paused: Color::Rgb(216, 182, 116),
            header: Color::Rgb(109, 173, 162),
            border: Color::Rgb(70, 95, 95),
            selected_fg: Color::Rgb(214, 226, 218),
            selected_bg: Color::Rgb(46, 70, 67),
            listen: Color::Rgb(138, 184, 123),
            established: Color::Rgb(109, 173, 162),
            wait: Color::Rgb(216, 182, 116),
            udp: Color::Rgb(183, 144, 171),
            normal: Color::Rgb(188, 205, 196),
            deleted: Color::Rgb(217, 112, 118),
        },
        WatchTheme::Ristretto => ThemePalette {
            status_running: Color::Rgb(150, 178, 132),
            status_paused: Color::Rgb(212, 169, 111),
            header: Color::Rgb(128, 162, 184),
            border: Color::Rgb(88, 76, 73),
            selected_fg: Color::Rgb(226, 214, 205),
            selected_bg: Color::Rgb(63, 53, 50),
            listen: Color::Rgb(150, 178, 132),
            established: Color::Rgb(128, 162, 184),
            wait: Color::Rgb(212, 169, 111),
            udp: Color::Rgb(186, 138, 170),
            normal: Color::Rgb(204, 190, 180),
            deleted: Color::Rgb(215, 108, 108),
        },
        WatchTheme::RosePine => ThemePalette {
            status_running: Color::Rgb(156, 207, 216),
            status_paused: Color::Rgb(246, 193, 119),
            header: Color::Rgb(196, 167, 231),
            border: Color::Rgb(82, 79, 103),
            selected_fg: Color::Rgb(224, 222, 244),
            selected_bg: Color::Rgb(57, 53, 82),
            listen: Color::Rgb(156, 207, 216),
            established: Color::Rgb(196, 167, 231),
            wait: Color::Rgb(246, 193, 119),
            udp: Color::Rgb(234, 154, 151),
            normal: Color::Rgb(224, 222, 244),
            deleted: Color::Rgb(235, 111, 146),
        },
        WatchTheme::TokyoNight => ThemePalette {
            status_running: Color::Rgb(125, 207, 255),
            status_paused: Color::Rgb(224, 175, 104),
            header: Color::Rgb(187, 154, 247),
            border: Color::Rgb(65, 72, 104),
            selected_fg: Color::Rgb(192, 202, 245),
            selected_bg: Color::Rgb(41, 46, 66),
            listen: Color::Rgb(158, 206, 106),
            established: Color::Rgb(125, 207, 255),
            wait: Color::Rgb(224, 175, 104),
            udp: Color::Rgb(187, 154, 247),
            normal: Color::Rgb(169, 177, 214),
            deleted: Color::Rgb(247, 118, 142),
        },
        WatchTheme::Vantablack => ThemePalette {
            status_running: Color::Rgb(165, 190, 165),
            status_paused: Color::Rgb(198, 176, 131),
            header: Color::Rgb(145, 170, 190),
            border: Color::Rgb(58, 58, 58),
            selected_fg: Color::Rgb(220, 220, 220),
            selected_bg: Color::Rgb(34, 34, 34),
            listen: Color::Rgb(145, 190, 145),
            established: Color::Rgb(145, 170, 190),
            wait: Color::Rgb(198, 176, 131),
            udp: Color::Rgb(175, 150, 180),
            normal: Color::Rgb(185, 185, 185),
            deleted: Color::Rgb(210, 112, 112),
        },
        WatchTheme::White => ThemePalette {
            status_running: Color::Rgb(34, 97, 162),
            status_paused: Color::Rgb(170, 110, 20),
            header: Color::Rgb(26, 119, 116),
            border: Color::Rgb(162, 166, 172),
            selected_fg: Color::Rgb(24, 24, 24),
            selected_bg: Color::Rgb(225, 225, 225),
            listen: Color::Rgb(64, 140, 47),
            established: Color::Rgb(34, 97, 162),
            wait: Color::Rgb(170, 110, 20),
            udp: Color::Rgb(162, 85, 135),
            normal: Color::Rgb(24, 24, 24),
            deleted: Color::Rgb(180, 38, 38),
        },
    }
}

#[cfg(feature = "watch")]
fn status_bar_style(paused: bool, p: &ThemePalette) -> Style {
    let fg = if paused {
        p.status_paused
    } else {
        p.status_running
    };
    Style::default().fg(fg).add_modifier(Modifier::BOLD)
}

#[cfg(feature = "watch")]
fn header_style(p: &ThemePalette) -> Style {
    Style::default().fg(p.header).add_modifier(Modifier::BOLD)
}

#[cfg(feature = "watch")]
fn block_style(p: &ThemePalette) -> Style {
    Style::default().fg(p.border)
}

#[cfg(feature = "watch")]
fn selected_row_style(p: &ThemePalette) -> Style {
    Style::default()
        .fg(p.selected_fg)
        .bg(p.selected_bg)
        .add_modifier(Modifier::BOLD)
}

#[cfg(feature = "watch")]
fn row_style(row: &WatchRow, target: crate::cli::WatchTarget, p: &ThemePalette) -> Style {
    use crate::cli::WatchTarget;
    match target {
        WatchTarget::Sockets | WatchTarget::Port => socket_row_style(row, p),
        WatchTarget::File => file_row_style(row, p),
    }
}

#[cfg(feature = "watch")]
fn socket_row_style(row: &WatchRow, p: &ThemePalette) -> Style {
    let proto = row.cols[0].as_str();
    let state = row.cols[3].as_str();
    if state.eq_ignore_ascii_case("LISTEN") {
        return Style::default().fg(p.listen);
    }
    if state.eq_ignore_ascii_case("ESTABLISHED") {
        return Style::default().fg(p.established);
    }
    if state.eq_ignore_ascii_case("TIME_WAIT") || state.eq_ignore_ascii_case("CLOSE_WAIT") {
        return Style::default().fg(p.wait);
    }
    if proto.eq_ignore_ascii_case("UDP") {
        return Style::default().fg(p.udp);
    }
    Style::default().fg(p.normal)
}

#[cfg(feature = "watch")]
fn file_row_style(row: &WatchRow, p: &ThemePalette) -> Style {
    let fd_type = row.cols[4].as_str();
    let path = row.cols[5].as_str();
    if path.ends_with("(deleted)") {
        return Style::default().fg(p.deleted);
    }
    if fd_type.eq_ignore_ascii_case("SOCK") {
        return Style::default().fg(p.established);
    }
    if fd_type.eq_ignore_ascii_case("PIPE") {
        return Style::default().fg(p.wait);
    }
    Style::default().fg(p.normal)
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

#[cfg(feature = "watch")]
fn drill_down_text(dd: &DrillDownData, palette: &ThemePalette) -> ratatui::text::Text<'static> {
    use ratatui::style::Stylize;
    use ratatui::text::{Line, Span, Text};

    let e = &dd.entry;
    let local_port = e
        .local_addr
        .rsplit(':')
        .next()
        .and_then(|p: &str| p.parse::<u16>().ok())
        .unwrap_or(0);
    let service = crate::proto_detect::detect(local_port, &e.process.name)
        .unwrap_or("-")
        .to_string();
    let container = crate::container::detect(e.process.pid).unwrap_or_else(|| "-".to_string());

    let hl = palette.header;
    let dim = palette.border;

    let label = |s: &str| Span::styled(s.to_string(), ratatui::style::Style::default().fg(hl));
    let val = |s: String| Span::raw(s);
    let sep = || Span::styled("  ", ratatui::style::Style::default().fg(dim));

    let mut lines: Vec<Line> = vec![
        Line::from(""),
        Line::from(vec![Span::styled(
            " CONNECTION",
            ratatui::style::Style::default().fg(hl).bold(),
        )]),
        Line::from(vec![
            label("   Protocol "),
            val(format!("{:<18}", e.protocol)),
            label("Service  "),
            val(service.clone()),
        ]),
        Line::from(vec![
            label("   Local    "),
            val(format!("{:<18}", e.local_addr)),
            label("Remote   "),
            val(e.remote_addr.clone()),
        ]),
        Line::from(vec![label("   State    "), val(e.state.clone())]),
        Line::from(""),
        Line::from(vec![Span::styled(
            " PROCESS",
            ratatui::style::Style::default().fg(hl).bold(),
        )]),
        Line::from(vec![
            label("   PID      "),
            val(format!("{:<18}", e.process.pid)),
            label("User     "),
            val(e.process.user.clone()),
        ]),
        Line::from(vec![
            label("   Name     "),
            val(format!("{:<18}", e.process.name)),
            label("Container"),
            val(container),
        ]),
        Line::from(vec![label("   Command  "), val(e.process.command.clone())]),
        Line::from(""),
    ];

    // Resources section
    lines.push(Line::from(vec![Span::styled(
        " RESOURCES",
        ratatui::style::Style::default().fg(hl).bold(),
    )]));
    if let Some(ref r) = dd.resources {
        let mem_mb = r.mem_rss_kb as f64 / 1024.0;
        lines.push(Line::from(vec![
            label("   CPU      "),
            val(format!("{:<18}", format!("{:.1}%", r.cpu_pct))),
            label("Memory   "),
            val(format!("{:.1} MB RSS", mem_mb)),
        ]));
        lines.push(Line::from(vec![
            label("   Threads  "),
            val(format!("{:<18}", r.threads)),
            label("Open FDs "),
            val(r.open_fds.to_string()),
        ]));
    } else {
        lines.push(Line::from(vec![
            sep(),
            Span::styled(
                "(unavailable — may need elevated privileges)",
                ratatui::style::Style::default().fg(dim),
            ),
        ]));
    }
    lines.push(Line::from(""));

    // Process tree section
    lines.push(Line::from(vec![Span::styled(
        " PROCESS TREE",
        ratatui::style::Style::default().fg(hl).bold(),
    )]));
    if dd.ancestry.is_empty() {
        lines.push(Line::from(vec![
            label("   "),
            val(format!("{} ({})", e.process.name, e.process.pid)),
        ]));
    } else {
        for (i, ancestor) in dd.ancestry.iter().enumerate() {
            let indent = "  ".repeat(i + 1);
            let connector = if i == 0 {
                "".to_string()
            } else {
                "└─ ".to_string()
            };
            lines.push(Line::from(vec![Span::styled(
                format!(
                    "  {}{}{} ({})",
                    indent, connector, ancestor.name, ancestor.pid
                ),
                ratatui::style::Style::default().fg(dim),
            )]));
        }
        let depth = dd.ancestry.len();
        let indent = "  ".repeat(depth + 1);
        lines.push(Line::from(vec![
            Span::styled(
                format!("  {}└─ ", indent),
                ratatui::style::Style::default().fg(dim),
            ),
            Span::styled(
                format!("{} ({}) ←", e.process.name, e.process.pid),
                ratatui::style::Style::default().fg(hl).bold(),
            ),
        ]));
    }

    lines.push(Line::from(""));
    lines.push(Line::from(vec![Span::styled(
        "  esc back · x kill",
        ratatui::style::Style::default().fg(dim),
    )]));

    Text::from(lines)
}

#[cfg(feature = "watch")]
fn centered_rect(
    percent_x: u16,
    percent_y: u16,
    r: ratatui::layout::Rect,
) -> ratatui::layout::Rect {
    let popup_layout = ratatui::layout::Layout::default()
        .direction(ratatui::layout::Direction::Vertical)
        .constraints([
            ratatui::layout::Constraint::Percentage((100 - percent_y) / 2),
            ratatui::layout::Constraint::Percentage(percent_y),
            ratatui::layout::Constraint::Percentage((100 - percent_y) / 2),
        ])
        .split(r);
    ratatui::layout::Layout::default()
        .direction(ratatui::layout::Direction::Horizontal)
        .constraints([
            ratatui::layout::Constraint::Percentage((100 - percent_x) / 2),
            ratatui::layout::Constraint::Percentage(percent_x),
            ratatui::layout::Constraint::Percentage((100 - percent_x) / 2),
        ])
        .split(popup_layout[1])[1]
}
