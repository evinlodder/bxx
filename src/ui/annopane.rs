//! Side pane: tabbed Marks / Analysis / Entropy / Output views.

use ratatui::Frame;
use ratatui::layout::{Constraint, Layout, Rect};
use ratatui::style::{Color, Modifier, Style};
use ratatui::text::{Line, Span};
use ratatui::widgets::{Block, Paragraph, Wrap};

use crate::analysis::{entropy, strings};
use crate::app::{App, SideTab};
use crate::inspector;

pub fn render(frame: &mut Frame, area: Rect, app: &mut App) {
    let block = Block::bordered();
    let inner = block.inner(area);
    frame.render_widget(block, area);

    let titles = ["Marks", "Inspect", "Strings", "Analysis", "Entropy", "Output"];
    let selected = match app.side_tab {
        SideTab::Marks => 0,
        SideTab::Inspect => 1,
        SideTab::Strings => 2,
        SideTab::Analysis => 3,
        SideTab::Entropy => 4,
        SideTab::Output => 5,
    };
    // Tabs wrap onto as many rows as the pane width needs.
    let tab_rows = tab_lines(&titles, selected, inner.width);
    let tab_height = tab_rows.len() as u16;
    let [tab_area, body] =
        Layout::vertical([Constraint::Length(tab_height), Constraint::Min(0)]).areas(inner);
    frame.render_widget(Paragraph::new(tab_rows), tab_area);

    // The Strings list is pre-windowed for speed, so it manages its own scroll.
    let (lines, scroll): (Vec<Line>, u16) = match app.side_tab {
        SideTab::Marks => (marks_lines(app), app.side_scroll),
        SideTab::Inspect => (inspect_lines(app), app.side_scroll),
        SideTab::Strings => (strings_lines(app, body), 0),
        SideTab::Analysis => (
            app.info_lines().into_iter().map(Line::from).collect(),
            app.side_scroll,
        ),
        SideTab::Entropy => (entropy_lines(app, body), app.side_scroll),
        SideTab::Output => (
            app.output_lines.iter().cloned().map(Line::from).collect(),
            app.side_scroll,
        ),
    };
    frame.render_widget(
        Paragraph::new(lines).scroll((scroll, 0)).wrap(Wrap { trim: false }),
        body,
    );
}

/// Lay tab labels across as many rows as `width` requires (poor-man's wrap,
/// since ratatui's `Tabs` is single-line).
fn tab_lines(titles: &[&str], selected: usize, width: u16) -> Vec<Line<'static>> {
    let width = width.max(1) as usize;
    let mut rows: Vec<Vec<Span<'static>>> = vec![Vec::new()];
    let mut row_w = 0usize;
    for (i, t) in titles.iter().enumerate() {
        let label = format!(" {t} ");
        let w = label.chars().count();
        if row_w > 0 && row_w + w > width {
            rows.push(Vec::new());
            row_w = 0;
        }
        let style = if i == selected {
            Style::default()
                .bg(Color::Yellow)
                .fg(Color::Black)
                .add_modifier(Modifier::BOLD)
        } else {
            Style::default().fg(Color::Gray)
        };
        rows.last_mut().unwrap().push(Span::styled(label, style));
        row_w += w;
    }
    rows.into_iter().map(Line::from).collect()
}

fn marks_lines(app: &App) -> Vec<Line<'static>> {
    if app.annotations.is_empty() {
        return vec![
            Line::from("no annotations"),
            Line::from(""),
            Line::from(":mark <start> <end> <label> <type>"),
            Line::from("or select with v then press m"),
        ];
    }
    let mut lines = Vec::new();
    for r in &app.annotations {
        let here = r.contains(app.cursor);
        let head_style = if here {
            Style::default()
                .fg(app.config.color_annotation)
                .add_modifier(Modifier::BOLD | Modifier::REVERSED)
        } else {
            Style::default().fg(app.config.color_annotation)
        };
        lines.push(Line::from(vec![
            Span::styled(format!("{} ", r.label), head_style),
            Span::styled(
                format!("{} 0x{:X}..0x{:X}", r.rtype, r.start, r.end),
                Style::default().fg(Color::DarkGray),
            ),
        ]));
        lines.push(Line::from(format!("  = {}", r.decode(&app.buf))));
    }
    lines
}

fn inspect_lines(app: &App) -> Vec<Line<'static>> {
    inspector::lines(&app.buf, app.cursor)
        .into_iter()
        .map(|(label, value)| {
            Line::from(vec![
                Span::styled(format!("{label:<11}"), Style::default().fg(Color::DarkGray)),
                Span::styled(value, Style::default().fg(app.config.color_annotation)),
            ])
        })
        .collect()
}

fn strings_lines(app: &mut App, body: Rect) -> Vec<Line<'static>> {
    app.ensure_strings();
    let cursor = app.cursor;
    let offset_w = format!("{:X}", app.buf.len().max(0x100)).len().max(8);
    let q = app.strings_filter.to_lowercase();
    let (list, trunc) = app.strings_cache.as_ref().unwrap();

    // Apply the live filter (substring, case-insensitive).
    let filtered: Vec<&(u64, String)> = if q.is_empty() {
        list.iter().collect()
    } else {
        list.iter()
            .filter(|(_, s)| s.to_lowercase().contains(&q))
            .collect()
    };

    let mut lines: Vec<Line<'static>> = Vec::new();
    if !app.strings_filter.is_empty() {
        lines.push(Line::from(vec![
            Span::styled("filter ", Style::default().fg(Color::DarkGray)),
            Span::styled(
                app.strings_filter.clone(),
                Style::default().fg(Color::Green).add_modifier(Modifier::BOLD),
            ),
            Span::styled(
                format!("  ({} match)", filtered.len()),
                Style::default().fg(Color::DarkGray),
            ),
        ]));
    }
    if filtered.is_empty() {
        lines.push(Line::from(if app.strings_filter.is_empty() {
            format!("no strings ≥{} bytes  ( :strings <min> [utf16] )", app.strings_min)
        } else {
            "no matches  (\\ to edit, Esc to clear)".to_string()
        }));
        return lines;
    }

    let textw = (body.width as usize).saturating_sub(offset_w + 3).max(8);
    let height = (body.height as usize).saturating_sub(lines.len()).max(1);
    let near = filtered.iter().rposition(|(o, _)| *o <= cursor).unwrap_or(0);
    let start = (app.side_scroll as usize).min(filtered.len().saturating_sub(1));

    for (i, (off, s)) in filtered.iter().enumerate().skip(start).take(height) {
        let shown: String = s.chars().take(textw).collect();
        let text_style = if i == near {
            Style::default()
                .fg(Color::Yellow)
                .add_modifier(Modifier::BOLD)
        } else {
            Style::default().fg(app.config.color_annotation)
        };
        lines.push(Line::from(vec![
            Span::styled(
                format!("{off:0offset_w$X}  "),
                Style::default().fg(Color::DarkGray),
            ),
            Span::styled(shown, text_style),
        ]));
    }
    if *trunc && q.is_empty() {
        lines.push(Line::from(Span::styled(
            format!("… truncated at {}", strings::MAX_STRINGS),
            Style::default().fg(Color::DarkGray),
        )));
    }
    lines
}

fn entropy_lines(app: &mut App, body: Rect) -> Vec<Line<'static>> {
    let buckets = body.height.max(1) as usize;
    // Cache: the whole-file pass is too expensive to redo every keystroke.
    let recompute = app
        .entropy_cache
        .as_ref()
        .is_none_or(|(b, _)| *b != buckets);
    if recompute {
        let computed = entropy::bucketed(app.buf.raw(), buckets);
        app.entropy_cache = Some((buckets, computed));
    }
    let (_, rows) = app.entropy_cache.as_ref().unwrap();
    let offset_w = format!("{:X}", app.buf.len().max(0x100)).len().max(8);
    let bar_w = (body.width as usize).saturating_sub(offset_w + 8).max(4);
    const PARTIAL: [char; 8] = ['▏', '▎', '▍', '▌', '▋', '▊', '▉', '█'];
    let cursor_bucket = rows
        .iter()
        .rposition(|&(off, _)| app.cursor >= off)
        .unwrap_or(0);
    rows.iter()
        .enumerate()
        .map(|(i, &(off, h))| {
            let filled = h / 8.0 * bar_w as f64;
            let full = filled as usize;
            let frac = ((filled - full as f64) * 8.0) as usize;
            let mut bar = "█".repeat(full.min(bar_w));
            if full < bar_w && frac > 0 {
                bar.push(PARTIAL[frac.min(7)]);
            }
            let style = if i == cursor_bucket {
                Style::default()
                    .fg(Color::Yellow)
                    .add_modifier(Modifier::BOLD)
            } else if h > 7.2 {
                Style::default().fg(Color::Red) // likely compressed/encrypted
            } else {
                Style::default().fg(Color::Green)
            };
            Line::from(vec![
                Span::styled(
                    format!("{off:0offset_w$X} "),
                    Style::default().fg(Color::DarkGray),
                ),
                Span::styled(bar, style),
                Span::raw(format!(" {h:.2}")),
            ])
        })
        .collect()
}
