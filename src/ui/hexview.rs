//! Hex pane: offset column | hex bytes | ASCII sidebar, with layered
//! highlighting (cursor, selection, search, diff, annotations, heuristics).

use ratatui::Frame;
use ratatui::layout::Rect;
use ratatui::style::{Color, Modifier, Style};
use ratatui::text::{Line, Span};
use ratatui::widgets::{Block, Paragraph};

use crate::analysis::arch::ArchHitKind;
use crate::app::{App, Mode};
use crate::diff::{self, HunkKind};

#[derive(PartialEq, Clone, Copy)]
pub enum Side {
    Main,
    DiffRight,
}

pub fn render(frame: &mut Frame, area: Rect, app: &App, side: Side) {
    let buf = match side {
        Side::Main => &app.buf,
        Side::DiffRight => app.diff_buf.as_ref().expect("diff buffer present"),
    };
    let name = buf
        .path
        .file_name()
        .map(|n| n.to_string_lossy().into_owned())
        .unwrap_or_default();
    let modified = if buf.has_unsaved_changes() {
        " [+]"
    } else {
        ""
    };
    let block = Block::bordered().title(format!(" {name}{modified} "));
    let inner_rows = area.height.saturating_sub(2) as usize;
    let cols = app.columns();
    let offset_w = format!("{:X}", app.buf.len().max(0x100)).len().max(8);

    // Pre-slice annotation/heuristic intervals overlapping the window so the
    // per-byte style check stays cheap even with thousands of hits.
    let win_start = app.view_top;
    let win_end = win_start + (inner_rows as u64) * cols;
    let annos: Vec<(u64, u64)> = if side == Side::Main {
        app.annotations
            .iter()
            .filter(|r| r.start < win_end && r.end > win_start)
            .map(|r| (r.start, r.end))
            .collect()
    } else {
        Vec::new()
    };
    let arch: Vec<(u64, u64, ArchHitKind)> = if side == Side::Main {
        let lo = app
            .arch_hits
            .partition_point(|h| h.start < win_start.saturating_sub(64));
        app.arch_hits[lo..]
            .iter()
            .take_while(|h| h.start < win_end)
            .filter(|h| h.end > win_start)
            .map(|h| (h.start, h.end, h.kind))
            .collect()
    } else {
        Vec::new()
    };
    let selection = app.selection();
    let diff_active = app.diff_buf.is_some();

    let style_for = |off: u64| -> Style {
        let mut style = Style::default();
        if side == Side::Main {
            if annos.iter().any(|&(s, e)| off >= s && off < e) {
                style = style.fg(app.config.color_annotation);
            } else if let Some(&(_, _, kind)) = arch.iter().find(|&&(s, e, _)| off >= s && off < e)
            {
                // Padding/fill is muted; code-looking signatures get the
                // heuristic color.
                style = match kind {
                    ArchHitKind::ZeroPad => style.fg(Color::DarkGray),
                    _ => style.fg(app.config.color_heuristic),
                };
            }
            if buf.is_modified_at(off) {
                style = style
                    .fg(app.config.color_modified)
                    .add_modifier(Modifier::BOLD);
            }
        }
        if diff_active {
            // Each pane is coloured by its own file's hunks (alignment-aware).
            let hunks = match side {
                Side::DiffRight => &app.diff_hunks_b,
                Side::Main => &app.diff_hunks,
            };
            if let Some(h) = diff::hunk_at(hunks, off) {
                let bg = match h.kind {
                    HunkKind::Changed => app.config.color_diff_changed,
                    HunkKind::Added => app.config.color_diff_added,
                    HunkKind::Removed => app.config.color_diff_removed,
                };
                style = style.bg(bg).fg(Color::Black);
            }
        }
        if side == Side::Main {
            if app.search.hit_at(off) {
                style = style.bg(app.config.color_search).fg(Color::Black);
            }
            if let Some((s, e)) = selection
                && off >= s
                && off < e
            {
                style = style.bg(app.config.color_selection).fg(Color::White);
            }
        }
        if off == app.cursor {
            style = if side == Side::Main {
                style.bg(app.config.color_cursor).fg(Color::Black)
            } else {
                style.add_modifier(Modifier::REVERSED)
            };
        }
        style
    };

    let mut lines: Vec<Line> = Vec::with_capacity(inner_rows);
    if buf.is_empty() {
        lines.push(Line::from("  <empty file>"));
    }
    for row in 0..inner_rows {
        let base = win_start + row as u64 * cols;
        if base >= buf.len() {
            break;
        }
        let row_bytes = buf.get_range(base, cols as usize);
        let mut spans: Vec<Span> = vec![Span::styled(
            format!("{base:0offset_w$X}  "),
            Style::default().fg(Color::DarkGray),
        )];
        for i in 0..cols as usize {
            if i > 0 && i % 8 == 0 {
                spans.push(Span::raw(" "));
            }
            match row_bytes.get(i) {
                Some(&b) => {
                    let off = base + i as u64;
                    let mut st = style_for(off);
                    // In hex-edit mode show which nibble is pending.
                    if off == app.cursor
                        && app.mode == (Mode::Edit { ascii: false })
                        && app.nibble_low
                    {
                        st = st.add_modifier(Modifier::UNDERLINED);
                    }
                    spans.push(Span::styled(format!("{b:02X}"), st));
                    spans.push(Span::raw(" "));
                }
                None => spans.push(Span::raw("   ")),
            }
        }
        spans.push(Span::raw(" "));
        for (i, &b) in row_bytes.iter().enumerate() {
            let ch = if (0x20..0x7f).contains(&b) {
                b as char
            } else {
                '·'
            };
            spans.push(Span::styled(ch.to_string(), style_for(base + i as u64)));
        }
        lines.push(Line::from(spans));
    }

    frame.render_widget(Paragraph::new(lines).block(block), area);
}
