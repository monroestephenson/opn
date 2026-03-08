#[cfg(feature = "watch")]
pub fn run(
    platform: &dyn crate::platform::Platform,
    filter: &crate::model::QueryFilter,
    as_json: bool,
) -> anyhow::Result<()> {
    use anyhow::Context;
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
    let tick_rate = Duration::from_secs(2);
    let mut entries = platform.list_sockets(filter)?;

    let result: anyhow::Result<()> = (|| loop {
        entries.sort_by(|a, b| match sort_key {
            SortKey::Protocol => a
                .protocol
                .to_string()
                .cmp(&b.protocol.to_string())
                .then(a.local_addr.cmp(&b.local_addr)),
            SortKey::Local => a
                .local_addr
                .cmp(&b.local_addr)
                .then(a.process.pid.cmp(&b.process.pid)),
            SortKey::Pid => a
                .process
                .pid
                .cmp(&b.process.pid)
                .then(a.local_addr.cmp(&b.local_addr)),
        });

        terminal.draw(|frame| {
            let area = frame.area();
            let chunks = Layout::default()
                .direction(Direction::Vertical)
                .constraints([Constraint::Length(2), Constraint::Min(1)])
                .split(area);

            let status = format!(
                "opn watch sockets | {} | sort={} | rows={} | q quit, space pause, s sort",
                if paused { "paused" } else { "running" },
                sort_key.label(),
                entries.len()
            );
            frame.render_widget(Paragraph::new(status), chunks[0]);

            let header = Row::new(["PROTO", "LOCAL", "REMOTE", "STATE", "PID", "PROCESS"])
                .style(Style::default().add_modifier(Modifier::BOLD));
            let rows = entries.iter().map(|e| {
                Row::new(vec![
                    Cell::from(e.protocol.to_string()),
                    Cell::from(e.local_addr.clone()),
                    Cell::from(e.remote_addr.clone()),
                    Cell::from(e.state.clone()),
                    Cell::from(e.process.pid.to_string()),
                    Cell::from(e.process.name.clone()),
                ])
            });
            let table = Table::new(
                rows,
                [
                    Constraint::Length(6),
                    Constraint::Length(24),
                    Constraint::Length(24),
                    Constraint::Length(12),
                    Constraint::Length(8),
                    Constraint::Min(8),
                ],
            )
            .header(header)
            .block(Block::default().borders(Borders::ALL).title("Sockets"));
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
            entries = platform.list_sockets(filter)?;
            last_tick = Instant::now();
        }
    })();

    disable_raw_mode().ok();
    execute!(terminal.backend_mut(), LeaveAlternateScreen).ok();
    terminal.show_cursor().ok();
    result
}
