//! Root layout: hex pane(s) + annotation/analysis side pane + info bar.

mod annopane;
mod hexview;
mod infobar;
mod minimap;

use ratatui::Frame;
use ratatui::layout::{Constraint, Layout, Rect};
use ratatui::style::{Color, Modifier, Style};
use ratatui::text::{Line, Span};
use ratatui::widgets::Paragraph;

use crate::app::App;
use crate::config::AnnoPanePos;

pub fn draw(frame: &mut Frame, app: &mut App) {
    let [mut main, info] =
        Layout::vertical([Constraint::Min(3), Constraint::Length(2)]).areas(frame.area());

    // When several files are open, reserve a tab strip at the very top.
    if app.docs.len() > 1 {
        let [tabs, rest] =
            Layout::vertical([Constraint::Length(1), Constraint::Min(2)]).areas(main);
        render_file_tabs(frame, tabs, app);
        main = rest;
    }

    let pane = app.config.anno_pane;
    let want_side = pane != AnnoPanePos::Off && main.width > app.config.anno_width + 40;
    let (hex_area, side_area) = if want_side {
        let w = app.config.anno_width;
        match pane {
            AnnoPanePos::Right => {
                let [h, s] =
                    Layout::horizontal([Constraint::Min(20), Constraint::Length(w)]).areas(main);
                (h, Some(s))
            }
            _ => {
                let [s, h] =
                    Layout::horizontal([Constraint::Length(w), Constraint::Min(20)]).areas(main);
                (h, Some(s))
            }
        }
    } else {
        (main, None)
    };

    // Carve a thin minimap strip off the right of the hex area (not in diff
    // mode, and only when there's room to spare).
    let want_minimap =
        app.config.minimap && app.diff_buf.is_none() && hex_area.width > minimap::WIDTH + 50;
    let (hex_area, minimap_area) = if want_minimap {
        let [h, m] = Layout::horizontal([
            Constraint::Min(20),
            Constraint::Length(minimap::WIDTH),
        ])
        .areas(hex_area);
        (h, Some(m))
    } else {
        (hex_area, None)
    };

    app.view_rows = hex_area.height.saturating_sub(2).max(1) as usize;

    if app.diff_buf.is_some() {
        let [left, right] =
            Layout::horizontal([Constraint::Percentage(50), Constraint::Percentage(50)])
                .areas(hex_area);
        hexview::render(frame, left, app, hexview::Side::Main);
        hexview::render(frame, right, app, hexview::Side::DiffRight);
    } else {
        hexview::render(frame, hex_area, app, hexview::Side::Main);
    }

    if let Some(mut m) = minimap_area {
        // Align the strip with the hex rows (inside the hex view's border).
        m.y += 1;
        m.height = m.height.saturating_sub(2);
        minimap::render(frame, m, app);
    }

    if let Some(side) = side_area {
        annopane::render(frame, side, app);
    }

    infobar::render(frame, info, app);
}

/// Tab strip listing the open files, active one highlighted.
fn render_file_tabs(frame: &mut Frame, area: Rect, app: &App) {
    let mut spans = Vec::new();
    for (i, doc) in app.docs.iter().enumerate() {
        let dirty = if doc.buf.has_unsaved_changes() { "+" } else { "" };
        let label = format!(" {}:{}{} ", i + 1, doc.title(), dirty);
        let style = if i == app.active {
            Style::default()
                .bg(Color::Blue)
                .fg(Color::Black)
                .add_modifier(Modifier::BOLD)
        } else {
            Style::default().fg(Color::Gray)
        };
        spans.push(Span::styled(label, style));
        spans.push(Span::raw(" "));
    }
    frame.render_widget(Paragraph::new(Line::from(spans)), area);
}
