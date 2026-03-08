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
    use anyhow::Context;
    use crate::cli::WatchTarget;
    use crossterm::event::{self, Event, KeyCode};
    use crossterm::execute;
    use crossterm::terminal::{
        disable_raw_mode, enable_raw_mode, EnterAlternateScreen, LeaveAlternateScreen,
    };
    use ratatui::backend::CrosstermBackend;
    use ratatui::layout::{Constraint, Direction, Layout};
    use ratatui::style::{Modifier, Style};
    use ratatui::widgets::{Block, Borders, Cell, Paragraph, Row, Table};
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
    let title = match target {
        WatchTarget::Sockets => "Sockets",
        WatchTarget::Port => "Port",
        WatchTarget::File => "File",
    };

    let result: anyhow::Result<()> = (|| loop {
        rows.sort_by(|a, b| match sort_key {
            SortKey::Protocol => a[0].cmp(&b[0]).then(a[1].cmp(&b[1])),
            SortKey::Local => a[1].cmp(&b[1]).then(a[4].cmp(&b[4])),
            SortKey::Pid => a[4].cmp(&b[4]).then(a[1].cmp(&b[1])),
        });

        terminal.draw(|frame| {
            let area = frame.area();
            let chunks = Layout::default()
                .direction(Direction::Vertical)
                .constraints([Constraint::Length(2), Constraint::Min(1)])
                .split(area);

            let status = format!(
                "opn watch {} | {} | sort={} | interval={}s | rows={} | q quit, space pause, s sort",
                title.to_ascii_lowercase(),
                if paused { "paused" } else { "running" },
                sort_key.label(),
                interval_secs,
                rows.len()
            );
            frame.render_widget(Paragraph::new(status), chunks[0]);

            let header = Row::new(["COL1", "COL2", "COL3", "COL4", "COL5", "COL6"])
                .style(Style::default().add_modifier(Modifier::BOLD));
            let rows_view = rows.iter().map(|e| {
                Row::new(vec![
                    Cell::from(e[0].clone()),
                    Cell::from(e[1].clone()),
                    Cell::from(e[2].clone()),
                    Cell::from(e[3].clone()),
                    Cell::from(e[4].clone()),
                    Cell::from(e[5].clone()),
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
            .block(Block::default().borders(Borders::ALL).title(title));
            frame.render_widget(table, chunks[1]);
        })?;

        let timeout = tick_rate.saturating_sub(last_tick.elapsed());
        if event::poll(timeout)? {
            if let Event::Key(key) = event::read()? {
                match key.code {
                    KeyCode::Char('q') => break Ok(()),
                    KeyCode::Char(' ') => paused = !paused,
                    KeyCode::Char('s') => sort_key = sort_key.next(),
                    _ => {}
                }
            }
        }

        if !paused && last_tick.elapsed() >= tick_rate {
            rows = snapshot_rows(platform, target, port, file, filter)?;
            last_tick = Instant::now();
        }
    })();

    disable_raw_mode().ok();
    execute!(terminal.backend_mut(), LeaveAlternateScreen).ok();
    terminal.show_cursor().ok();
    result
}

#[cfg(feature = "watch")]
fn socket_rows(entries: &[crate::model::SocketEntry]) -> Vec<[String; 6]> {
    entries
        .iter()
        .map(|e| {
            [
                e.protocol.to_string(),
                e.local_addr.clone(),
                e.remote_addr.clone(),
                e.state.clone(),
                e.process.pid.to_string(),
                e.process.name.clone(),
            ]
        })
        .collect()
}

#[cfg(feature = "watch")]
fn file_rows(entries: &[crate::model::OpenFile]) -> Vec<[String; 6]> {
    entries
        .iter()
        .map(|e| {
            [
                e.process.pid.to_string(),
                e.process.name.clone(),
                e.process.user.clone(),
                e.fd.to_string(),
                e.fd_type.to_string(),
                if e.deleted {
                    format!("{} (deleted)", e.path)
                } else {
                    e.path.clone()
                },
            ]
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
) -> anyhow::Result<Vec<[String; 6]>> {
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
