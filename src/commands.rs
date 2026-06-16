//! `:` command parsing and execution.

use std::path::{Path, PathBuf};

use crate::annotations::{Region, RegionType};
use crate::app::{App, SideTab, YankFmt};
use crate::export;

/// Jump-target syntax: annotation label, `0x` hex, `0d` decimal, bare hex.
pub fn parse_offset(s: &str, regions: &[Region]) -> Option<u64> {
    if let Some(r) = regions.iter().find(|r| r.label == s) {
        return Some(r.start);
    }
    if let Some(h) = s.strip_prefix("0x").or_else(|| s.strip_prefix("0X")) {
        u64::from_str_radix(h, 16).ok()
    } else if let Some(d) = s.strip_prefix("0d") {
        d.parse().ok()
    } else {
        u64::from_str_radix(s, 16).ok()
    }
}

pub fn execute(app: &mut App, line: &str) {
    let line = line.trim();
    if line.is_empty() {
        return;
    }
    let mut parts = line.split_whitespace();
    let cmd = parts.next().unwrap();
    let args: Vec<&str> = parts.collect();
    match cmd {
        "seek" => cmd_seek(app, &args),
        "mark" => cmd_mark(app, &args),
        "unmark" => cmd_unmark(app, &args),
        "xor" => match app.last_selection {
            Some((s, e)) => app.run_xor(s, e),
            None => app.message = "xor: no selection (use v to select first)".into(),
        },
        "cyclic" => match app.last_selection {
            Some((s, e)) => app.run_cyclic(s, e),
            None => app.message = "cyclic: no selection".into(),
        },
        "diff" => match args.first() {
            Some(f) => {
                if let Err(e) = app.start_diff(Path::new(f)) {
                    app.message = format!("diff: {e}");
                }
            }
            None => app.message = "usage: :diff <file>".into(),
        },
        "diffoff" => {
            app.diff_buf = None;
            app.diff_hunks.clear();
            app.diff_hunks_b.clear();
            app.message = "diff closed".into();
        }
        "applystruct" => cmd_applystruct(app, &args),
        "loadstructs" => cmd_loadstructs(app, &args),
        "reloadstructs" | "reload" => cmd_reload(app),
        "export" => cmd_export(app, &args),
        "export-ghidra" | "ghidra" => cmd_bridge(app, &args, true),
        "export-r2" | "r2" => cmd_bridge(app, &args, false),
        "checksum" | "cksum" | "hash" => cmd_checksum(app, &args),
        "yank" | "y" => cmd_yank(app, &args),
        "paste" => app.paste(),
        "fill" => cmd_fill(app, &args),
        "transform" | "tx" => app.start_transform(None, args.first().copied()),
        "t" => {
            if args.is_empty() {
                app.message = "usage: :t <op> [args]  (e.g. :t xor 5a, :t pipe zcat)".into();
            } else {
                app.transform_push(&args.join(" "));
            }
        }
        "tpop" => app.transform_pop(),
        "tclear" => app.transform_clear(),
        "tsave" => cmd_tsave(app, &args),
        "tpatch" => cmd_tpatch(app),
        "pipelines" | "tlist" => cmd_pipelines(app),
        "reloadpipes" | "pipereload" => cmd_reloadpipes(app),
        "triage" => {
            app.ensure_triage();
            if app.triage.is_some() {
                app.side_tab = SideTab::Triage;
                app.side_scroll = 0;
                app.message = "triage — J/K select · Enter jump to offset".into();
            } else {
                app.message = "triage: not a recognized executable (ELF supported)".into();
            }
        }
        "follow" => cmd_follow(app, &args),
        "xref" | "xrefs" => cmd_xref(app, &args),
        "strings" => cmd_strings(app, &args),
        "sfind" | "strfind" | "sgrep" => {
            app.strings_filter = args.join(" ");
            app.jump_to_string_match();
        }
        "base" => cmd_base(app, &args),
        "endian" => cmd_endian(app, &args),
        "bookmarks" | "bm" | "marks" => cmd_bookmarks(app),
        "jumps" => cmd_jumps(app),
        "e" | "edit" | "open" => cmd_open(app, &args),
        "bn" | "bnext" => app.switch_file(1),
        "bp" | "bprev" => app.switch_file(-1),
        "b" | "buffer" => cmd_buffer(app, &args),
        "ls" | "files" | "buffers" => cmd_files(app),
        "close" | "bd" => app.request_close(false),
        "bd!" => app.request_close(true),
        "w" | "wq" => {
            let target = args.first().map(PathBuf::from);
            match app.buf.save(target.as_deref()) {
                Ok(path) => {
                    if target.is_none() {
                        // In-place patch changes hash/entropy/magic landscape.
                        app.reanalyze();
                    }
                    app.save_annotations();
                    app.message = format!("wrote {}", path.display());
                    if cmd == "wq" {
                        app.request_close(false);
                    }
                }
                Err(e) => app.message = format!("write failed: {e}"),
            }
        }
        "revert" => {
            if app.buf.has_unsaved_changes() {
                app.buf.discard_edits();
                app.message = "reverted unsaved edits".into();
            } else {
                app.message = "no unsaved edits".into();
            }
        }
        "q" => app.request_close(false),
        "q!" => app.request_close(true),
        "qa" | "qall" => {
            if app.docs.iter().any(|d| d.buf.has_unsaved_changes()) {
                app.message = "unsaved changes in some files (:qa! to discard all)".into();
            } else {
                app.quit = true;
            }
        }
        "qa!" | "qall!" => app.quit = true,
        "info" => {
            app.side_tab = SideTab::Analysis;
            app.side_scroll = 0;
        }
        "inspect" => {
            app.side_tab = SideTab::Inspect;
            app.side_scroll = 0;
        }
        "template" | "defs" | "schema" => {
            app.side_tab = SideTab::Template;
            app.side_scroll = 0;
        }
        "entropy" => {
            app.side_tab = SideTab::Entropy;
            app.side_scroll = 0;
        }
        "help" => {
            app.output_lines = HELP.lines().map(String::from).collect();
            app.side_tab = SideTab::Output;
            app.side_scroll = 0;
        }
        _ => app.message = format!("unknown command :{cmd} (:help)"),
    }
}

fn cmd_seek(app: &mut App, args: &[&str]) {
    let Some(target) = args.first() else {
        app.message = "usage: :seek <hex|0d<dec>|label>".into();
        return;
    };
    match parse_offset(target, &app.annotations) {
        Some(off) if off < app.buf.len() => {
            app.jump_to(off);
            app.message = format!("seek 0x{:X}", app.cursor);
        }
        Some(off) => app.message = format!("0x{off:X} is past EOF (size 0x{:X})", app.buf.len()),
        None => app.message = format!("can't parse offset or label '{target}'"),
    }
}

fn cmd_mark(app: &mut App, args: &[&str]) {
    if args.len() != 4 {
        app.message = "usage: :mark <start> <end> <label> <type>  (end exclusive)".into();
        return;
    }
    let (start, end) = match (
        parse_offset(args[0], &app.annotations),
        parse_offset(args[1], &app.annotations),
    ) {
        (Some(s), Some(e)) => (s, e),
        _ => {
            app.message = format!("bad offsets '{} {}'", args[0], args[1]);
            return;
        }
    };
    if start >= end || end > app.buf.len() {
        app.message = format!(
            "bad range 0x{start:X}..0x{end:X} (file size 0x{:X})",
            app.buf.len()
        );
        return;
    }
    let label = args[2].to_string();
    let Some(rtype) = RegionType::parse(args[3]) else {
        app.message = format!(
            "unknown type '{}' (u8 u16le u16be u32le u32be u64le u64be float str raw)",
            args[3]
        );
        return;
    };
    if let Some(size) = rtype.fixed_size()
        && end - start != size
    {
        app.message = format!(
            "{rtype} needs exactly {size} byte(s), range is {}",
            end - start
        );
        return;
    }
    app.annotations.retain(|r| r.label != label);
    app.annotations.push(Region {
        start,
        end,
        label: label.clone(),
        rtype,
        note: None,
    });
    app.annotations.sort_by_key(|r| r.start);
    app.save_annotations();
    app.side_tab = SideTab::Marks;
    app.message = format!("marked {label} @ 0x{start:X}..0x{end:X}");
}

/// True if `label` is `ns` itself or a field/element beneath it, e.g.
/// `Elf64` matches `Elf64`, `Elf64.magic`, `Elf64.phdrs[0].p_type`.
fn in_namespace(label: &str, ns: &str) -> bool {
    label == ns
        || label.starts_with(&format!("{ns}."))
        || label.starts_with(&format!("{ns}["))
}

fn cmd_unmark(app: &mut App, args: &[&str]) {
    let Some(label) = args.first() else {
        app.message = "usage: :unmark <label>  (also removes a struct's fields)".into();
        return;
    };
    let before = app.annotations.len();
    app.annotations.retain(|r| !in_namespace(&r.label, label));
    let removed = before - app.annotations.len();
    if removed > 0 {
        app.save_annotations();
        app.message = format!("unmarked {removed} region(s) under '{label}'");
    } else {
        app.message = format!("no annotation '{label}'");
    }
}

fn cmd_applystruct(app: &mut App, args: &[&str]) {
    let Some(name) = args.first() else {
        let mut known = app.template.struct_names();
        known.sort_unstable();
        app.message = format!(
            "usage: :applystruct <name> [offset]; loaded: {}",
            known.join(", ")
        );
        return;
    };
    if !app.template.has_struct(name) {
        app.message = format!("no struct '{name}' (load via <file>.bxs or :loadstructs)");
        return;
    }
    // Optional second arg: apply at a hex offset / decimal / mark label.
    let at = match args.get(1) {
        None => app.cursor,
        Some(s) => match parse_offset(s, &app.annotations) {
            Some(o) if o < app.buf.len() => o,
            Some(o) => {
                app.message = format!("0x{o:X} is past EOF (size 0x{:X})", app.buf.len());
                return;
            }
            None => {
                app.message = format!("can't parse offset or label '{s}'");
                return;
            }
        },
    };
    let (regions, warn) = app.template.apply(name, at, &app.buf);
    let n = regions.len();
    // Clear the struct's whole namespace first, so a re-apply (e.g. with a
    // smaller array) never leaves orphan fields behind.
    app.annotations.retain(|x| !in_namespace(&x.label, name));
    app.annotations.extend(regions);
    app.annotations.sort_by_key(|r| r.start);
    app.save_annotations();
    app.autocollapse_marks();
    app.jump_to(at);
    app.side_tab = SideTab::Marks;
    app.message = match warn {
        Some(w) => format!("applied {name}: {n} field(s) @ 0x{at:X} — {w}"),
        None => format!("applied {name}: {n} field(s) @ 0x{at:X}"),
    };
}

fn cmd_loadstructs(app: &mut App, args: &[&str]) {
    let Some(arg) = args.first() else {
        app.message = "usage: :loadstructs <file.bxs | directory>".into();
        return;
    };
    let path = Path::new(arg);
    // Gather the .bxs files to load (a directory loads all of its .bxs files).
    let files: Vec<PathBuf> = if path.is_dir() {
        match std::fs::read_dir(path) {
            Ok(rd) => {
                let mut v: Vec<PathBuf> = rd
                    .flatten()
                    .map(|e| e.path())
                    .filter(|p| p.is_file() && p.extension().is_some_and(|x| x == "bxs"))
                    .collect();
                v.sort();
                v
            }
            Err(e) => {
                app.message = format!("{arg}: {e}");
                return;
            }
        }
    } else {
        vec![path.to_path_buf()]
    };
    if files.is_empty() {
        app.message = format!("{arg}: no .bxs files found");
        return;
    }

    let (mut loaded, mut total_defs, mut errors) = (0usize, 0usize, Vec::new());
    for f in &files {
        match std::fs::read_to_string(f) {
            Ok(text) => match crate::structs::parse(&text) {
                Ok(mut tpl) => {
                    tpl.set_source(&f.file_name().unwrap_or(f.as_os_str()).to_string_lossy());
                    total_defs += tpl.struct_names().len();
                    app.template.merge(tpl);
                    loaded += 1;
                }
                Err(e) => errors.push(format!("{}: {e}", f.display())),
            },
            Err(e) => errors.push(format!("{}: {e}", f.display())),
        }
    }
    if !errors.is_empty() {
        for e in &errors {
            app.output_lines.push(e.clone());
        }
    }
    app.message = if files.len() > 1 {
        format!(
            "loaded {loaded}/{} file(s), {total_defs} struct(s){}",
            files.len(),
            if errors.is_empty() {
                String::new()
            } else {
                format!(" — {} error(s), see Output", errors.len())
            }
        )
    } else if let Some(e) = errors.first() {
        e.clone()
    } else {
        format!("loaded {total_defs} struct(s)")
    };
    app.autocollapse_template();
    app.side_tab = SideTab::Template;
    app.side_scroll = 0;
}

/// Re-read the `<binary>.bxs` sidecar from scratch (picks up edits, drops
/// removed definitions). Note: definitions added via `:loadstructs <other>`
/// are not retained — re-run those if needed.
fn cmd_reload(app: &mut App) {
    let mut os = app.buf.path.as_os_str().to_owned();
    os.push(".bxs");
    let path = std::path::PathBuf::from(os);
    match std::fs::read_to_string(&path) {
        Ok(text) => match crate::structs::parse(&text) {
            Ok(mut tpl) => {
                let n = tpl.struct_names().len();
                tpl.set_source(&path.file_name().unwrap_or(path.as_os_str()).to_string_lossy());
                // Rebuild from the built-ins so they survive the reload.
                let mut base = crate::structs::Template::default();
                if let Ok(mut b) = crate::structs::parse(crate::builtins::BUILTINS) {
                    b.set_source("built-in");
                    base.merge(b);
                }
                base.merge(tpl);
                app.template = base;
                app.autocollapse_template();
                app.message = format!("reloaded {} ({n} struct(s))", path.display());
            }
            Err(e) => app.message = format!("{}: {e}", path.display()),
        },
        Err(e) => app.message = format!("{}: {e}", path.display()),
    }
}

fn cmd_checksum(app: &mut App, args: &[&str]) {
    let range = if args.is_empty() {
        // last visual selection, else whole file
        app.last_selection
    } else if args.len() == 2 {
        match (
            parse_offset(args[0], &app.annotations),
            parse_offset(args[1], &app.annotations),
        ) {
            (Some(s), Some(e)) if s < e && e <= app.buf.len() => Some((s, e)),
            _ => {
                app.message = format!("bad range '{} {}'", args[0], args[1]);
                return;
            }
        }
    } else {
        app.message = "usage: :checksum [start end]  (default: selection or whole file)".into();
        return;
    };
    app.run_checksum(range);
}

fn cmd_tsave(app: &mut App, args: &[&str]) {
    let Some(out) = args.first() else {
        app.message = "usage: :tsave <file>".into();
        return;
    };
    match app.transform_output() {
        Some(bytes) => match std::fs::write(out, bytes) {
            Ok(()) => app.message = format!("wrote {} byte(s) to {out}", bytes.len()),
            Err(e) => app.message = format!("{out}: {e}"),
        },
        None => app.message = "no transform output to save (fix the recipe?)".into(),
    }
}

/// Overwrite the transform output back into the buffer at the input offset.
fn cmd_tpatch(app: &mut App) {
    let Some((start, _)) = app.tx_input else {
        app.message = "no transform input (press T on a selection)".into();
        return;
    };
    let Some(bytes) = app.transform_output().map(<[u8]>::to_vec) else {
        app.message = "no transform output to apply".into();
        return;
    };
    let max = app.buf.len().saturating_sub(start) as usize;
    let n = bytes.len().min(max);
    for (i, &b) in bytes.iter().take(n).enumerate() {
        app.buf.set(start + i as u64, b);
    }
    app.buf.commit_group();
    app.jump_to(start);
    app.message = format!(
        "patched {n} byte(s) @ 0x{start:X}{} (:w to save)",
        if n < bytes.len() { " (clamped to EOF)" } else { "" }
    );
}

fn cmd_pipelines(app: &mut App) {
    let mut lines = if app.pipelines.is_empty() {
        vec![
            "no named pipelines.".to_string(),
            "define them in ~/.bxpipes:  name = op | op | …".to_string(),
        ]
    } else {
        let mut v = vec![format!("{} pipeline(s) (~/.bxpipes):", app.pipelines.len())];
        let mut names: Vec<&String> = app.pipelines.keys().collect();
        names.sort();
        for name in names {
            v.push(format!("  {name} = {}", app.pipelines[name].join(" | ")));
        }
        v
    };
    lines.push(String::new());
    lines.push(format!("ops: {}", crate::transform::OP_NAMES.join(" ")));
    app.output_lines = lines;
    app.side_tab = SideTab::Output;
    app.side_scroll = 0;
}

/// Re-read `~/.bxpipes` so edits take effect without restarting, then show the
/// refreshed list in the Output panel.
fn cmd_reloadpipes(app: &mut App) {
    let (pipes, warnings) = crate::transform::load_pipelines();
    let n = pipes.len();
    app.pipelines = pipes;
    cmd_pipelines(app); // repaints the Output panel with the new list
    for w in &warnings {
        app.output_lines.push(w.clone());
    }
    app.message = format!("reloaded ~/.bxpipes: {n} pipeline(s)");
}

fn cmd_yank(app: &mut App, args: &[&str]) {
    let Some(range) = app.last_selection else {
        app.message = "yank: no selection (v to select first)".into();
        return;
    };
    let fmt = match args.first().map(|s| s.to_ascii_lowercase()).as_deref() {
        None | Some("hex") => YankFmt::Hex,
        Some("c") | Some("carray") => YankFmt::CArray,
        Some("raw") => YankFmt::Raw,
        Some("base64") | Some("b64") => YankFmt::Base64,
        Some(o) => {
            app.message = format!("yank: unknown format '{o}' (hex|c|raw|base64)");
            return;
        }
    };
    app.yank(range, fmt);
}

fn cmd_fill(app: &mut App, args: &[&str]) {
    let Some(range) = app.last_selection else {
        app.message = "fill: no selection (v to select first)".into();
        return;
    };
    let Some(pattern) = parse_hex_bytes(&args.join("")) else {
        app.message = "usage: :fill <hex>  (e.g. :fill 00, :fill deadbeef)".into();
        return;
    };
    app.fill(range, &pattern);
}

/// Parse a run-together / spaced hex string into bytes (`de ad`, `0xdead`).
fn parse_hex_bytes(s: &str) -> Option<Vec<u8>> {
    let h: String = s
        .chars()
        .filter(|c| !c.is_whitespace())
        .collect::<String>()
        .replace("0x", "")
        .replace("0X", "");
    if h.is_empty() || !h.len().is_multiple_of(2) {
        return None;
    }
    let hexval = |c: u8| -> Option<u8> {
        match c {
            b'0'..=b'9' => Some(c - b'0'),
            b'a'..=b'f' => Some(c - b'a' + 10),
            b'A'..=b'F' => Some(c - b'A' + 10),
            _ => None,
        }
    };
    h.as_bytes()
        .chunks(2)
        .map(|p| Some((hexval(p[0])? << 4) | hexval(p[1])?))
        .collect()
}

/// Parse `u32le` / `u32be` / `u64le` / `u64be` into `(width, little_endian)`.
fn parse_ptr_type(s: &str) -> Option<(u8, bool)> {
    match s.to_ascii_lowercase().as_str() {
        "u32le" | "32le" => Some((4, true)),
        "u32be" | "32be" => Some((4, false)),
        "u64le" | "64le" => Some((8, true)),
        "u64be" | "64be" => Some((8, false)),
        _ => None,
    }
}

fn cmd_follow(app: &mut App, args: &[&str]) {
    let (w, le) = match args.first() {
        None => (app.ptr_width, app.endian_le),
        Some(t) => match parse_ptr_type(t) {
            Some(v) => v,
            None => {
                app.message = "usage: :follow [u32le|u32be|u64le|u64be]".into();
                return;
            }
        },
    };
    app.follow_pointer(w, le);
}

fn cmd_xref(app: &mut App, args: &[&str]) {
    let (w, le) = match args.first() {
        None => (app.ptr_width, app.endian_le),
        Some(t) => match parse_ptr_type(t) {
            Some(v) => v,
            None => {
                app.message = "usage: :xref [u32le|u32be|u64le|u64be]".into();
                return;
            }
        },
    };
    app.find_xrefs(w, le);
}

fn cmd_strings(app: &mut App, args: &[&str]) {
    let mut min = app.strings_min;
    let mut utf16 = false;
    for a in args {
        if a.eq_ignore_ascii_case("utf16") || a.eq_ignore_ascii_case("u16") {
            utf16 = true;
        } else if let Ok(m) = a.parse::<usize>() {
            min = m;
        } else {
            app.message = "usage: :strings [min-len] [utf16]".into();
            return;
        }
    }
    app.run_strings(min, utf16);
}

fn cmd_base(app: &mut App, args: &[&str]) {
    match args.first() {
        None => app.message = format!("pointer base = 0x{:X}", app.ptr_base),
        Some(v) => match parse_offset(v, &[]) {
            Some(b) => {
                app.ptr_base = b;
                app.message = format!("pointer base = 0x{b:X} (follow/xref subtract this)");
            }
            None => app.message = format!("can't parse base '{v}'"),
        },
    }
}

fn cmd_endian(app: &mut App, args: &[&str]) {
    match args.first().map(|s| s.to_ascii_lowercase()) {
        Some(s) if s == "le" || s == "little" => {
            app.endian_le = true;
            app.message = "pointer endian = little".into();
        }
        Some(s) if s == "be" || s == "big" => {
            app.endian_le = false;
            app.message = "pointer endian = big".into();
        }
        _ => {
            app.message = format!(
                "endian = {} (usage: :endian le|be)",
                if app.endian_le { "little" } else { "big" }
            );
        }
    }
}

fn cmd_bookmarks(app: &mut App) {
    let mut lines = if app.bookmarks.is_empty() {
        vec!["no bookmarks (m<key> to set, `<key> to jump)".to_string()]
    } else {
        vec![format!("{} bookmark(s):", app.bookmarks.len())]
    };
    for (key, off) in &app.bookmarks {
        lines.push(format!("  '{key}'  0x{off:X}"));
    }
    app.output_lines = lines;
    app.side_tab = SideTab::Output;
    app.side_scroll = 0;
}

fn cmd_jumps(app: &mut App) {
    let mut lines = vec![format!(
        "jump list: {} back, {} forward (Ctrl-o / Ctrl-p)",
        app.jump_back.len(),
        app.jump_fwd.len()
    )];
    for off in app.jump_back.iter().rev().take(20) {
        lines.push(format!("  0x{off:X}"));
    }
    app.output_lines = lines;
    app.side_tab = SideTab::Output;
    app.side_scroll = 0;
}

fn cmd_open(app: &mut App, args: &[&str]) {
    let Some(file) = args.first() else {
        app.message = "usage: :e <file>".into();
        return;
    };
    if let Err(e) = app.open_file(Path::new(file)) {
        app.message = format!("open: {e}");
    }
}

fn cmd_buffer(app: &mut App, args: &[&str]) {
    let Some(n) = args.first().and_then(|s| s.parse::<usize>().ok()) else {
        app.message = "usage: :b <n>".into();
        return;
    };
    app.goto_file(n.saturating_sub(1));
}

fn cmd_files(app: &mut App) {
    let mut lines = vec![format!("{} open file(s):", app.docs.len())];
    for (i, d) in app.docs.iter().enumerate() {
        let marker = if i == app.active { '>' } else { ' ' };
        let dirty = if d.buf.has_unsaved_changes() { " [+]" } else { "" };
        lines.push(format!("{marker} {}: {}{}", i + 1, d.buf.path.display(), dirty));
    }
    app.output_lines = lines;
    app.side_tab = SideTab::Output;
    app.side_scroll = 0;
}

fn cmd_export(app: &mut App, args: &[&str]) {
    let Some(out) = args.first() else {
        app.message = "usage: :export <report.json>".into();
        return;
    };
    match export::write_report(Path::new(out), &app.buf, &app.file_info, &app.annotations) {
        Ok(()) => app.message = format!("exported {} region(s) to {out}", app.annotations.len()),
        Err(e) => app.message = format!("export: {e}"),
    }
}

/// Export marks + bookmarks as a Ghidra (`ghidra=true`) or radare2 script.
fn cmd_bridge(app: &mut App, args: &[&str], ghidra: bool) {
    let tool = if ghidra { "ghidra" } else { "r2" };
    let Some(out) = args.first() else {
        app.message = format!("usage: :export-{tool} <file>");
        return;
    };
    if app.annotations.is_empty() && app.bookmarks.is_empty() {
        app.message = "nothing to export (no marks or bookmarks)".into();
        return;
    }
    app.ensure_triage(); // for offset→vaddr mapping
    let path = Path::new(out);
    let res = if ghidra {
        crate::bridge::write_ghidra(
            path,
            &app.buf,
            &app.annotations,
            &app.bookmarks,
            app.triage.as_ref(),
        )
    } else {
        crate::bridge::write_r2(
            path,
            &app.buf,
            &app.annotations,
            &app.bookmarks,
            app.triage.as_ref(),
        )
    };
    match res {
        Ok((n, 0)) => app.message = format!("wrote {n} item(s) to {out} ({tool})"),
        Ok((n, skip)) => {
            app.message = format!("wrote {n} item(s) to {out} ({tool}); {skip} unmapped, skipped")
        }
        Err(e) => app.message = format!("export: {e}"),
    }
}

const HELP: &str = "\
bxx commands:
  :seek <hex|0d<dec>|label>     jump (also g<hex>g, gg, G)
  :mark <start> <end> <label> <type>   annotate region (end exclusive)
  :unmark <label>               remove a mark, or a whole applied struct
  :applystruct <name> [off]     parse a struct at cursor or offset/label
  :loadstructs <file|dir> / :reloadstructs   load .bxs (or all in a dir) / re-read sidecar
  :diff <file> / :diffoff       side-by-side diff (n/N jump hunks)
  :xor / :cyclic                analyze last visual selection (also x / c)
  :checksum [start end]         CRC/MD5/SHA of selection or file (also #)
  :strings [min] [utf16]        list strings (Strings tab) · \\ or :sfind to filter
  :triage                       sections/symbols/imports (Triage tab; J/K, ⏎ jump)
  :transform [pipe] (also T)    pipe a selection through transforms (Transform tab)
  :t <op>  :tpop :tclear        add/remove recipe steps · :tsave <f> · :tpatch
  :pipelines / :reloadpipes     list / re-read named recipes (~/.bxpipes)
  :follow / :xref [u32le|…]     follow pointer (f/F) · find pointers here (X)
  :base <hex> / :endian le|be   pointer load base / byte order for follow+xref
  :bookmarks / :jumps           list bookmarks · jump-list state
  :export <file.json>           JSON report of annotations
  :export-ghidra / :export-r2   marks+bookmarks as a Ghidra / r2 script
  files: :e <f> open · :bn/:bp/:b<n> switch · :ls list · :close · gt/gT
  :w [file] | :q | :q! | :wq | :qa    write / quit
  :info :template :inspect :entropy :help   side-pane tabs
keys: hjkl move · v select · i edit · u undo · C-r redo · C-o/C-p jump back/fwd
      m<k> set bookmark · `<k> jump · f/F follow ptr 32/64 · X xrefs-to-here
      za toggle fold · zR expand all · zM collapse all (Marks tree / Template tab)
      Triage & Template tabs: J/K move selection · Enter jump / fold
      / search: ?? wildcard · \"text\" str · i\"text\" caseless · re: regex · v/ scoped
      n/N next/prev · ↑/↓ history · {/} magic · y yank · p paste · :fill <hex>
      Tab/S-Tab cycle side pane · J/K scroll · >/< resize · # checksum · e entropy";
