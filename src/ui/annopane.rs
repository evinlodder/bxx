//! Side pane: tabbed Marks / Analysis / Entropy / Output views.

use ratatui::Frame;
use ratatui::layout::{Constraint, Layout, Rect};
use ratatui::style::{Color, Modifier, Style};
use ratatui::text::{Line, Span};
use ratatui::widgets::{Block, Paragraph, Wrap};

use crate::analysis::{entropy, strings, triage};
use crate::app::{App, SideTab};
use crate::inspector;

pub fn render(frame: &mut Frame, area: Rect, app: &mut App) {
    let block = Block::bordered();
    let inner = block.inner(area);
    frame.render_widget(block, area);

    let titles: Vec<&str> = SideTab::ORDER.iter().map(|t| tab_title(*t)).collect();
    let selected = SideTab::ORDER
        .iter()
        .position(|&t| t == app.side_tab)
        .unwrap_or(0);
    // Single-row carousel: scrolls to keep the active tab centred, with </>
    // edge hints when more tabs exist off-screen.
    let [tab_area, body] =
        Layout::vertical([Constraint::Length(1), Constraint::Min(0)]).areas(inner);
    frame.render_widget(
        Paragraph::new(tab_header_line(&titles, selected, inner.width)),
        tab_area,
    );

    // Marks and Strings are pre-windowed for speed, so they manage their own
    // scroll; the rest use the shared scroll offset with wrapping.
    let (lines, scroll, wrap): (Vec<Line>, u16, bool) = match app.side_tab {
        SideTab::Marks => (marks_lines(app, body), 0, false),
        SideTab::Template => (template_lines(app), app.side_scroll, false),
        SideTab::Inspect => (inspect_lines(app), app.side_scroll, true),
        SideTab::Strings => (strings_lines(app, body), 0, false),
        SideTab::Triage => (triage_lines(app, body), 0, false),
        SideTab::Transform => (transform_lines(app, body), app.side_scroll, true),
        SideTab::Analysis => (
            app.info_lines().into_iter().map(Line::from).collect(),
            app.side_scroll,
            true,
        ),
        SideTab::Entropy => (entropy_lines(app, body), app.side_scroll, false),
        SideTab::Output => (
            app.output_lines.iter().cloned().map(Line::from).collect(),
            app.side_scroll,
            true,
        ),
    };
    let para = Paragraph::new(lines).scroll((scroll, 0));
    let para = if wrap { para.wrap(Wrap { trim: false }) } else { para };
    frame.render_widget(para, body);
}

fn tab_title(t: SideTab) -> &'static str {
    match t {
        SideTab::Marks => "Marks",
        SideTab::Template => "Template",
        SideTab::Inspect => "Inspect",
        SideTab::Strings => "Strings",
        SideTab::Triage => "Triage",
        SideTab::Transform => "Transform",
        SideTab::Analysis => "Analysis",
        SideTab::Entropy => "Entropy",
        SideTab::Output => "Output",
    }
}

/// A single-row tab strip that scrolls to keep the selected tab centred,
/// clamped at both ends (no wrap-around), with `<`/`>` edge indicators.
fn tab_header_line(titles: &[&str], selected: usize, width: u16) -> Line<'static> {
    let dim = Style::default().fg(Color::Gray);
    let hot = Style::default()
        .bg(Color::Yellow)
        .fg(Color::Black)
        .add_modifier(Modifier::BOLD);
    let arrow = Style::default().fg(Color::Yellow);

    // Flatten the whole strip into styled characters, tracking the selection.
    let mut chars: Vec<(char, Style)> = Vec::new();
    let (mut sel_start, mut sel_len) = (0usize, 0usize);
    for (i, t) in titles.iter().enumerate() {
        let label = format!(" {t} ");
        if i == selected {
            sel_start = chars.len();
            sel_len = label.chars().count();
        }
        let style = if i == selected { hot } else { dim };
        for c in label.chars() {
            chars.push((c, style));
        }
    }

    let total = chars.len();
    let content_w = (width as usize).saturating_sub(2).max(1); // edges hold arrows
    let scroll = if total <= content_w {
        0
    } else {
        let center = sel_start + sel_len / 2;
        center
            .saturating_sub(content_w / 2)
            .min(total - content_w)
    };
    let left = scroll > 0;
    let right = scroll + content_w < total;

    let mut spans = vec![Span::styled(if left { "<" } else { " " }.to_string(), arrow)];
    for &(c, st) in chars.iter().skip(scroll).take(content_w) {
        spans.push(Span::styled(c.to_string(), st));
    }
    spans.push(Span::styled(if right { ">" } else { " " }.to_string(), arrow));
    Line::from(spans)
}

fn triage_lines(app: &App, body: Rect) -> Vec<Line<'static>> {
    let Some(rep) = &app.triage else {
        return vec![
            Line::from("not a recognized executable"),
            Line::from(""),
            Line::from("works on ELF — :triage to (re)scan"),
        ];
    };
    let dim = Style::default().fg(Color::DarkGray);
    let mut rows: Vec<Line<'static>> = Vec::new();
    let mut sel_line = 0usize;

    rows.push(Line::from(vec![
        Span::styled(
            rep.format.clone(),
            Style::default()
                .fg(app.config.color_annotation)
                .add_modifier(Modifier::BOLD),
        ),
        Span::styled(
            format!("  ({} items · J/K select · ⏎ jump)", rep.entries.len()),
            dim,
        ),
    ]));

    let mut last_kind: Option<triage::Kind> = None;
    for (i, e) in rep.entries.iter().enumerate() {
        if Some(e.kind) != last_kind {
            rows.push(Line::from(Span::styled(
                e.kind.label(),
                Style::default()
                    .fg(Color::Yellow)
                    .add_modifier(Modifier::BOLD),
            )));
            last_kind = Some(e.kind);
        }
        let selected = i == app.triage_sel;
        if selected {
            sel_line = rows.len();
        }
        let name_style = if selected {
            Style::default()
                .fg(app.config.color_annotation)
                .add_modifier(Modifier::BOLD | Modifier::REVERSED)
        } else {
            Style::default().fg(app.config.color_annotation)
        };
        let mut spans = vec![
            Span::styled(if selected { "▸ " } else { "  " }.to_string(), dim),
            Span::styled(e.name.clone(), name_style),
        ];
        if !e.detail.is_empty() {
            spans.push(Span::styled(format!("  {}", e.detail), dim));
        }
        if let Some(a) = e.addr {
            spans.push(Span::styled(format!("  @0x{a:X}"), Style::default().fg(Color::Cyan)));
        }
        if let Some(o) = e.offset {
            spans.push(Span::styled(format!("  off 0x{o:X}"), dim));
        }
        if e.size > 0 {
            spans.push(Span::styled(format!("  {}B", e.size), dim));
        }
        rows.push(Line::from(spans));
    }

    // window so the selected row stays on screen
    let height = (body.height as usize).max(1);
    let max_start = rows.len().saturating_sub(height);
    let start = sel_line.saturating_sub(height / 2).min(max_start);
    rows.into_iter().skip(start).take(height).collect()
}

fn transform_lines(app: &App, body: Rect) -> Vec<Line<'static>> {
    let Some((s, e)) = app.tx_input else {
        return vec![
            Line::from("no transform input"),
            Line::from(""),
            Line::from("select bytes (v), press T — or :transform"),
            Line::from("then :t <op> (e.g. :t unbase64, :t xor 5a)"),
            Line::from(":pipelines lists named recipes (~/.bxpipes)"),
        ];
    };
    let mut out = Vec::new();
    let dim = Style::default().fg(Color::DarkGray);
    out.push(Line::from(vec![
        Span::styled("input ", dim),
        Span::styled(
            format!("0x{s:X}..0x{e:X} ({} B)", e - s),
            Style::default().fg(app.config.color_annotation),
        ),
    ]));

    out.push(Line::from(Span::styled("recipe:", dim)));
    if app.tx_recipe.is_empty() {
        out.push(Line::from(Span::styled("  (empty — :t <op> to add)", dim)));
    } else {
        for (i, op) in app.tx_recipe.iter().enumerate() {
            out.push(Line::from(vec![
                Span::styled(format!("  {}. ", i + 1), dim),
                Span::styled(
                    op.clone(),
                    Style::default().fg(Color::Cyan).add_modifier(Modifier::BOLD),
                ),
            ]));
        }
    }
    out.push(Line::from(""));

    match &app.tx_output {
        Some(Ok(bytes)) => {
            out.push(Line::from(Span::styled(
                format!("output: {} byte(s)", bytes.len()),
                Style::default().fg(Color::Green),
            )));
            // hex preview, sized to the pane
            let cols = ((body.width as usize).saturating_sub(2) / 4).clamp(4, 16);
            let rows = (body.height as usize).saturating_sub(out.len() + 2).max(2);
            for chunk in bytes.chunks(cols).take(rows) {
                let hex: Vec<String> = chunk.iter().map(|b| format!("{b:02X}")).collect();
                let ascii: String = chunk
                    .iter()
                    .map(|&b| if (0x20..0x7f).contains(&b) { b as char } else { '·' })
                    .collect();
                out.push(Line::from(vec![
                    Span::raw(format!("{:<width$} ", hex.join(" "), width = cols * 3)),
                    Span::styled(ascii, dim),
                ]));
            }
            if bytes.len() > cols * rows {
                out.push(Line::from(Span::styled("  …", dim)));
            }
            // text rendering, if it looks textual
            let printable = bytes
                .iter()
                .filter(|&&b| (0x20..0x7f).contains(&b) || b == b'\n' || b == b'\t')
                .count();
            if !bytes.is_empty() && printable * 100 / bytes.len() >= 90 {
                out.push(Line::from(Span::styled("── as text ──", dim)));
                let text: String = bytes
                    .iter()
                    .take(2048)
                    .map(|&b| if b == b'\n' { ' ' } else { b as char })
                    .collect();
                out.push(Line::from(Span::styled(
                    text,
                    Style::default().fg(Color::White),
                )));
            }
        }
        Some(Err(msg)) => out.push(Line::from(Span::styled(
            format!("error: {msg}"),
            Style::default().fg(Color::Red).add_modifier(Modifier::BOLD),
        ))),
        None => out.push(Line::from(Span::styled("(no output)", dim))),
    }
    out
}

fn template_lines(app: &App) -> Vec<Line<'static>> {
    let desc = app.template.describe();
    if desc.is_empty() {
        return vec![
            Line::from("no .bxs template loaded"),
            Line::from(""),
            Line::from("auto-loads <file>.bxs, or :loadstructs <file>"),
            Line::from("then :applystruct <name> at the cursor"),
        ];
    }
    desc.into_iter()
        .map(|s| {
            // Definition headers (struct/enum/bitfield/}) start in column 0.
            let header = s
                .starts_with("struct ")
                || s.starts_with("enum ")
                || s.starts_with("bitfield ")
                || s == "}";
            let style = if header {
                Style::default()
                    .fg(app.config.color_annotation)
                    .add_modifier(Modifier::BOLD)
            } else {
                Style::default().fg(Color::Gray)
            };
            Line::from(Span::styled(s, style))
        })
        .collect()
}

fn marks_lines(app: &App, body: Rect) -> Vec<Line<'static>> {
    if app.annotations.is_empty() {
        return vec![
            Line::from("no annotations"),
            Line::from(""),
            Line::from(":mark <start> <end> <label> <type>"),
            Line::from("or select with v then press m"),
            Line::from(":applystruct <name> to parse a struct"),
        ];
    }
    let forest = crate::marks::build(&app.annotations);
    let mut rows: Vec<Line<'static>> = Vec::new();
    render_nodes(&forest, 0, app, &mut rows);

    // Window the (possibly long, when expanded) list to what fits.
    let height = (body.height as usize).max(1);
    let start = (app.side_scroll as usize).min(rows.len().saturating_sub(1));
    rows.into_iter().skip(start).take(height).collect()
}

fn render_nodes(
    level: &[crate::marks::MarkNode],
    depth: usize,
    app: &App,
    out: &mut Vec<Line<'static>>,
) {
    let indent = "  ".repeat(depth);
    for n in level {
        let here = app.cursor >= n.start && app.cursor < n.end;
        if n.is_group() {
            let collapsed = app.collapsed.contains(&n.path);
            // Highlight a collapsed group that holds the cursor (deepest visible).
            let hl = here && collapsed;
            let glyph = if collapsed { "▸" } else { "▾" };
            let name_style = base_style(app, hl);
            out.push(Line::from(vec![
                Span::styled(format!("{indent}{glyph} "), Style::default().fg(Color::DarkGray)),
                Span::styled(format!("{} ", n.name), name_style),
                Span::styled(n.summary(), Style::default().fg(Color::DarkGray)),
            ]));
            if !collapsed {
                render_nodes(&n.children, depth + 1, app, out);
            }
        } else if let Some(ri) = n.region {
            let r = &app.annotations[ri];
            let mut spans = vec![
                Span::styled(format!("{indent}  "), Style::default()),
                Span::styled(format!("{} ", n.name), base_style(app, here)),
                Span::raw(format!("= {}", r.decode(&app.buf))),
            ];
            if let Some(note) = &r.note {
                spans.push(Span::styled(
                    format!("  {note}"),
                    Style::default().fg(Color::Green).add_modifier(Modifier::BOLD),
                ));
            }
            out.push(Line::from(spans));
        }
    }
}

fn base_style(app: &App, highlight: bool) -> Style {
    let s = Style::default().fg(app.config.color_annotation);
    if highlight {
        s.add_modifier(Modifier::BOLD | Modifier::REVERSED)
    } else {
        s
    }
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
