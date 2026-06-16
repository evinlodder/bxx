//! Bottom bar: status line + message/command line.

use ratatui::Frame;
use ratatui::layout::{Constraint, Layout, Rect};
use ratatui::style::{Color, Modifier, Style};
use ratatui::text::{Line, Span};
use ratatui::widgets::Paragraph;

use crate::app::{App, Mode};

pub fn render(frame: &mut Frame, area: Rect, app: &App) {
    let [status_area, msg_area] =
        Layout::vertical([Constraint::Length(1), Constraint::Length(1)]).areas(area);

    let (mode_txt, mode_color) = match app.mode {
        Mode::Normal => ("NORMAL", Color::Blue),
        Mode::Visual => ("VISUAL", Color::Magenta),
        Mode::Edit { ascii: false } => ("EDIT:hex", Color::Red),
        Mode::Edit { ascii: true } => ("EDIT:ascii", Color::Red),
        Mode::Command => ("COMMAND", Color::Yellow),
        Mode::Search => ("SEARCH", Color::Green),
        Mode::StrFilter => ("FILTER", Color::Green),
    };

    let mut spans = vec![
        Span::styled(
            format!(" {mode_txt} "),
            Style::default()
                .bg(mode_color)
                .fg(Color::Black)
                .add_modifier(Modifier::BOLD),
        ),
        Span::raw(format!(" 0x{:X}/0x{:X}", app.cursor, app.buf.len())),
    ];
    if app.docs.len() > 1 {
        spans.push(Span::styled(
            format!("  [{}/{}]", app.active + 1, app.docs.len()),
            Style::default().fg(Color::Cyan),
        ));
    }
    if let Some((s, e)) = app.selection() {
        spans.push(Span::styled(
            format!("  sel 0x{s:X}..0x{e:X} ({} B)", e - s),
            Style::default().fg(Color::Magenta),
        ));
    }
    if let Some(g) = &app.pending_g {
        spans.push(Span::styled(
            format!("  g{g}…"),
            Style::default().fg(Color::Yellow),
        ));
    }
    spans.push(Span::styled(
        format!(
            "  {} | H={:.2} | md5 {}",
            app.file_info.detected_type,
            app.file_info.entropy,
            &app.file_info.md5[..12.min(app.file_info.md5.len())]
        ),
        Style::default().fg(Color::DarkGray),
    ));
    if app.diff_buf.is_some() {
        let hunks = app.diff_hunks.len() + app.diff_hunks_b.len();
        spans.push(Span::styled(
            format!(
                "  DIFF {:.0}% {hunks}h{}",
                app.diff_similarity * 100.0,
                if app.diff_aligned { "" } else { "~" }
            ),
            Style::default().fg(Color::Yellow),
        ));
    }
    if !app.search.query.is_empty() {
        spans.push(Span::styled(
            format!("  /{}", app.search.query),
            Style::default().fg(Color::Green),
        ));
    }
    frame.render_widget(Paragraph::new(Line::from(spans)), status_area);

    let msg = match app.mode {
        Mode::Command => Line::from(vec![
            Span::styled(":", Style::default().fg(Color::Yellow)),
            Span::raw(app.cmdline.clone()),
            Span::styled("█", Style::default().fg(Color::Yellow)),
        ]),
        Mode::Search => Line::from(vec![
            Span::styled("/", Style::default().fg(Color::Green)),
            Span::raw(app.cmdline.clone()),
            Span::styled("█", Style::default().fg(Color::Green)),
        ]),
        Mode::StrFilter => Line::from(vec![
            Span::styled("strings filter: ", Style::default().fg(Color::Green)),
            Span::raw(app.cmdline.clone()),
            Span::styled("█", Style::default().fg(Color::Green)),
        ]),
        _ => Line::from(app.message.clone()),
    };
    frame.render_widget(Paragraph::new(msg), msg_area);
}
