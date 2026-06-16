//! File-overview minimap: a thin vertical strip on the right of the hex view
//! (010-style). The whole file is mapped to the column height, each row tinted
//! by that region's entropy, with annotations highlighted and a bracket marking
//! the currently-visible window plus an arrow at the cursor.

use ratatui::Frame;
use ratatui::layout::Rect;
use ratatui::style::{Color, Modifier, Style};
use ratatui::text::{Line, Span};
use ratatui::widgets::Paragraph;

use crate::analysis::entropy;
use crate::app::App;

/// Columns the minimap occupies (marker + 1-wide colour bar).
pub const WIDTH: u16 = 2;

fn entropy_color(h: f64) -> Color {
    if h > 7.2 {
        Color::Red // compressed / encrypted
    } else if h > 5.5 {
        Color::Yellow
    } else if h > 2.0 {
        Color::Green
    } else {
        Color::DarkGray // sparse / zero-ish
    }
}

pub fn render(frame: &mut Frame, area: Rect, app: &mut App) {
    let rows = area.height as usize;
    let file_len = app.buf.len();
    if rows == 0 || file_len == 0 {
        return;
    }

    // One entropy bucket per minimap row; cached by row count.
    let stale = app
        .minimap_cache
        .as_ref()
        .is_none_or(|(r, _)| *r != rows);
    if stale {
        let computed = entropy::bucketed(app.buf.raw(), rows);
        app.minimap_cache = Some((rows, computed));
    }
    let buckets = &app.minimap_cache.as_ref().unwrap().1;

    let cols = app.columns();
    let view_start = app.view_top;
    let view_end = view_start + (app.view_rows as u64) * cols;
    let cursor = app.cursor;
    let bucket_sz = (file_len as f64 / rows as f64).max(1.0) as u64 + 1;

    let mut lines: Vec<Line> = Vec::with_capacity(rows);
    for &(off, h) in buckets.iter() {
        let b_end = off + bucket_sz;
        let in_view = b_end > view_start && off < view_end;
        let has_cursor = cursor >= off && cursor < b_end;
        let has_anno = app
            .annotations
            .iter()
            .any(|r| r.start < b_end && r.end > off);

        // marker column: cursor > viewport bracket > blank
        let (mk, mk_style) = if has_cursor {
            ("▶", Style::default().fg(Color::Yellow).add_modifier(Modifier::BOLD))
        } else if in_view {
            ("┃", Style::default().fg(Color::White))
        } else {
            (" ", Style::default())
        };

        // colour bar: annotations tint over entropy
        let bar_color = if has_anno {
            app.config.color_annotation
        } else {
            entropy_color(h)
        };

        lines.push(Line::from(vec![
            Span::styled(mk, mk_style),
            Span::styled("█", Style::default().fg(bar_color)),
        ]));
    }

    frame.render_widget(Paragraph::new(lines), area);
}
