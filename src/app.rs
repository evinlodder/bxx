//! Application state and vim-style key handling.
//!
//! Per-file state lives in [`Document`]; [`App`] owns a stack of open documents
//! plus global UI state (mode, command line, side-pane tab) and derefs to the
//! active document so the rest of the code can keep saying `app.buf` etc.

use std::borrow::Cow;
use std::collections::HashSet;
use std::ops::{Deref, DerefMut};
use std::path::Path;

use crossterm::event::{Event, KeyCode, KeyEvent, KeyEventKind, KeyModifiers};

use crate::analysis::arch::{self, ArchHit};
use crate::analysis::magic::{self, MagicHit};
use crate::analysis::{checksum, cyclic, entropy, headers, xor};
use crate::annotations::{self, Region};
use crate::buffer::FileBuffer;
use crate::config::Config;
use crate::diff::{self, Hunk};
use crate::export::FileInfo;
use crate::search::SearchState;
use crate::structs::Template;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Mode {
    Normal,
    Visual,
    /// Overwrite editing; `ascii` selects the ASCII column, else hex nibbles.
    Edit {
        ascii: bool,
    },
    Command,
    Search,
    /// Live incremental filter of the Strings tab.
    StrFilter,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SideTab {
    Marks,
    Template,
    Inspect,
    Strings,
    Triage,
    Transform,
    Analysis,
    Entropy,
    Output,
}

impl SideTab {
    /// Display order, for the tab strip and next/prev cycling.
    pub const ORDER: [SideTab; 9] = [
        Self::Marks,
        Self::Template,
        Self::Inspect,
        Self::Strings,
        Self::Triage,
        Self::Transform,
        Self::Analysis,
        Self::Entropy,
        Self::Output,
    ];

    fn index(self) -> usize {
        Self::ORDER.iter().position(|&t| t == self).unwrap_or(0)
    }

    pub fn next(self) -> Self {
        Self::ORDER[(self.index() + 1) % Self::ORDER.len()]
    }

    pub fn prev(self) -> Self {
        Self::ORDER[(self.index() + Self::ORDER.len() - 1) % Self::ORDER.len()]
    }
}

/// Selections larger than this are truncated before brute-force analysis.
const XOR_CAP: usize = 1 << 20;
const CYCLIC_CAP: usize = 4 << 20;

/// Everything tied to one open file.
pub struct Document {
    pub buf: FileBuffer,
    pub diff_buf: Option<FileBuffer>,
    pub diff_hunks: Vec<Hunk>,
    pub annotations: Vec<Region>,
    pub template: Template,
    pub search: SearchState,
    pub magic_hits: Vec<MagicHit>,
    pub magic_truncated: bool,
    pub arch_hits: Vec<ArchHit>,
    pub arch_truncated: bool,
    pub header_details: Vec<String>,
    pub file_info: FileInfo,
    pub cursor: u64,
    pub view_top: u64,
    /// Waiting for the low nibble of a hex edit.
    pub nibble_low: bool,
    pub visual_anchor: Option<u64>,
    pub last_selection: Option<(u64, u64)>,
    pub output_lines: Vec<String>,
    /// Bucketed whole-file entropy, keyed by bucket count (pane height).
    pub entropy_cache: Option<(usize, Vec<(u64, f64)>)>,
    /// Cursor positions for the jump list (Ctrl-o / Ctrl-p history).
    pub jump_back: Vec<u64>,
    pub jump_fwd: Vec<u64>,
    /// Named bookmarks (`m<key>` to set, `` `<key> `` to jump).
    pub bookmarks: std::collections::BTreeMap<char, u64>,
    /// Pointer interpretation for follow / xref: load base, endian, width.
    pub ptr_base: u64,
    pub endian_le: bool,
    pub ptr_width: u8,
    /// Cached extracted strings + whether the list was truncated.
    pub strings_cache: Option<(Vec<(u64, String)>, bool)>,
    pub strings_min: usize,
    pub strings_utf16: bool,
    /// Case-insensitive substring filter applied to the Strings tab.
    pub strings_filter: String,
    /// Paths of collapsed groups in the Marks tree.
    pub collapsed: HashSet<String>,
    /// Transform pipeline: input range, recipe (op strings), cached output.
    pub tx_input: Option<(u64, u64)>,
    pub tx_recipe: Vec<String>,
    pub tx_output: Option<Result<Vec<u8>, String>>,
    /// Structural triage (sections/symbols/imports), cached; `triage_sel` is
    /// the highlighted row in the Triage tab.
    pub triage: Option<crate::analysis::triage::Report>,
    pub triage_sel: usize,
    /// Whole-file entropy bucketed to the minimap height, keyed by row count.
    pub minimap_cache: Option<(usize, Vec<(u64, f64)>)>,
}

impl Document {
    pub fn open(path: &Path) -> Result<Self, String> {
        let buf = FileBuffer::open(path).map_err(|e| format!("{}: {e}", path.display()))?;
        let mut doc = Self {
            buf,
            diff_buf: None,
            diff_hunks: Vec::new(),
            annotations: Vec::new(),
            template: Template::default(),
            search: SearchState::default(),
            magic_hits: Vec::new(),
            magic_truncated: false,
            arch_hits: Vec::new(),
            arch_truncated: false,
            header_details: Vec::new(),
            file_info: FileInfo {
                size: 0,
                md5: String::new(),
                entropy: 0.0,
                detected_type: "data".into(),
            },
            cursor: 0,
            view_top: 0,
            nibble_low: false,
            visual_anchor: None,
            last_selection: None,
            output_lines: Vec::new(),
            entropy_cache: None,
            jump_back: Vec::new(),
            jump_fwd: Vec::new(),
            bookmarks: std::collections::BTreeMap::new(),
            ptr_base: 0,
            endian_le: true,
            ptr_width: 4,
            strings_cache: None,
            strings_min: 4,
            strings_utf16: false,
            strings_filter: String::new(),
            collapsed: HashSet::new(),
            tx_input: None,
            tx_recipe: Vec::new(),
            tx_output: None,
            triage: None,
            triage_sel: 0,
            minimap_cache: None,
        };
        doc.reanalyze();
        doc.detect_ptr_defaults();
        doc.load_sidecars();
        Ok(doc)
    }

    /// Pick sensible pointer width/endian from an ELF header at offset 0.
    fn detect_ptr_defaults(&mut self) {
        let h = self.buf.get_range(0, 6);
        if h.len() == 6 && &h[..4] == b"\x7fELF" {
            self.ptr_width = if h[4] == 2 { 8 } else { 4 }; // EI_CLASS
            self.endian_le = h[5] != 2; // EI_DATA: 2 = big-endian
        }
    }

    /// Short name for the file-tab strip.
    pub fn title(&self) -> String {
        self.buf
            .path
            .file_name()
            .map(|n| n.to_string_lossy().into_owned())
            .unwrap_or_else(|| "?".into())
    }

    /// Whole-file passes: hash, entropy, magic scan, arch heuristics, headers.
    pub fn reanalyze(&mut self) {
        let raw = self.buf.raw();
        let (magic_hits, magic_trunc) = magic::scan(raw);
        let (arch_hits, arch_trunc) = arch::scan(raw);
        self.file_info = FileInfo {
            size: raw.len() as u64,
            md5: format!("{:x}", md5::compute(raw)),
            entropy: entropy::shannon(raw),
            detected_type: magic::detect_type(&magic_hits),
        };
        self.header_details.clear();
        let mut parsed = 0;
        for hit in &magic_hits {
            if parsed >= 6 {
                break;
            }
            if let Some(lines) = headers::parse_for(hit.name, raw, hit.offset as usize) {
                self.header_details
                    .push(format!("── {} @ 0x{:X}", hit.name, hit.offset));
                self.header_details.extend(lines);
                parsed += 1;
            }
        }
        self.magic_hits = magic_hits;
        self.magic_truncated = magic_trunc;
        self.arch_hits = arch_hits;
        self.arch_truncated = arch_trunc;
        self.entropy_cache = None;
        self.strings_cache = None;
        self.triage = None;
        self.triage_sel = 0;
        self.minimap_cache = None;
    }

    fn load_sidecars(&mut self) {
        match annotations::load_sidecar(&self.buf.path) {
            Ok(Some(bxa)) => {
                if bxa.file_md5 != self.file_info.md5 {
                    self.output_lines.push(
                        "warning: .bxa md5 differs from file (annotations may be stale)".into(),
                    );
                }
                self.annotations = bxa.regions;
                self.annotations.sort_by_key(|r| r.start);
                self.bookmarks = bxa.bookmarks;
            }
            Ok(None) => {}
            Err(e) => self.output_lines.push(format!("bxa load failed: {e}")),
        }
        let bxs = {
            let mut os = self.buf.path.as_os_str().to_owned();
            os.push(".bxs");
            std::path::PathBuf::from(os)
        };
        if let Ok(text) = std::fs::read_to_string(&bxs) {
            match crate::structs::parse(&text) {
                Ok(tpl) => self.template.merge(tpl),
                Err(e) => self.output_lines.push(format!("bxs parse failed: {e}")),
            }
        }
    }

    /// File info + analysis summary; feeds the Analysis tab and --batch mode.
    pub fn info_lines(&self) -> Vec<String> {
        let mut out = vec![
            format!("file: {}", self.buf.path.display()),
            format!(
                "size: {} (0x{:X})",
                self.file_info.size, self.file_info.size
            ),
            format!("type: {}", self.file_info.detected_type),
            format!("entropy: {:.4} bits/byte", self.file_info.entropy),
            format!("md5: {}", self.file_info.md5),
            String::new(),
            format!(
                "magic hits: {}{}",
                self.magic_hits.len(),
                if self.magic_truncated {
                    " (truncated)"
                } else {
                    ""
                }
            ),
        ];
        for h in self.magic_hits.iter().take(200) {
            out.push(format!("  0x{:08X}  {} [{}]", h.offset, h.name, h.category));
        }
        if self.magic_hits.len() > 200 {
            out.push(format!("  … {} more", self.magic_hits.len() - 200));
        }
        if !self.header_details.is_empty() {
            out.push(String::new());
            out.extend(self.header_details.iter().cloned());
        }
        out.push(String::new());
        out.push(format!(
            "arch patterns [heuristic]: {} hit(s){}",
            self.arch_hits.len(),
            if self.arch_truncated {
                " (truncated)"
            } else {
                ""
            }
        ));
        let mut counts: std::collections::BTreeMap<(&str, &str), usize> =
            std::collections::BTreeMap::new();
        for h in &self.arch_hits {
            *counts.entry((h.arch, h.desc)).or_default() += 1;
        }
        for ((arch, desc), n) in counts {
            out.push(format!("  {arch:<12} {desc:<36} ×{n}"));
        }
        out
    }
}

pub struct App {
    pub config: Config,
    /// Open files; never empty. `active` indexes the focused one.
    pub docs: Vec<Document>,
    pub active: usize,
    /// Hex rows visible last frame; the UI updates this during draw.
    pub view_rows: usize,
    pub mode: Mode,
    /// Accumulated hex digits of a `g<hex>g` seek, if a `g` is pending.
    pub pending_g: Option<String>,
    /// Awaiting a bookmark key: `Some(true)` to set, `Some(false)` to jump.
    pub pending_mark: Option<bool>,
    /// Awaiting a fold command after `z`.
    pub pending_z: bool,
    pub cmdline: String,
    pub message: String,
    pub side_tab: SideTab,
    pub side_scroll: u16,
    /// Named transform recipes loaded from `~/.bxpipes`.
    pub pipelines: std::collections::HashMap<String, Vec<String>>,
    pub quit: bool,
}

impl Deref for App {
    type Target = Document;
    fn deref(&self) -> &Document {
        &self.docs[self.active]
    }
}

impl DerefMut for App {
    fn deref_mut(&mut self) -> &mut Document {
        &mut self.docs[self.active]
    }
}

impl App {
    pub fn new(path: &Path, config: Config) -> Result<Self, String> {
        let doc = Document::open(path)?;
        let mut app = Self {
            config,
            docs: vec![doc],
            active: 0,
            view_rows: 24,
            mode: Mode::Normal,
            pending_g: None,
            pending_mark: None,
            pending_z: false,
            cmdline: String::new(),
            message: String::new(),
            side_tab: SideTab::Analysis,
            side_scroll: 0,
            pipelines: std::collections::HashMap::new(),
            quit: false,
        };
        app.message = format!(
            "{} | {} bytes | {} | H={:.2}",
            path.display(),
            app.file_info.size,
            app.file_info.detected_type,
            app.file_info.entropy
        );
        Ok(app)
    }

    // --- multiple files -------------------------------------------------------

    /// Open another file in a new tab and focus it.
    pub fn open_file(&mut self, path: &Path) -> Result<(), String> {
        let doc = Document::open(path)?;
        self.docs.push(doc);
        self.active = self.docs.len() - 1;
        self.enter_file();
        self.message = format!(
            "opened {} [{}/{}]",
            path.display(),
            self.active + 1,
            self.docs.len()
        );
        Ok(())
    }

    /// Move focus by `delta` files (wraps).
    pub fn switch_file(&mut self, delta: isize) {
        let n = self.docs.len() as isize;
        if n <= 1 {
            self.message = "only one file open".into();
            return;
        }
        self.active = (self.active as isize + delta).rem_euclid(n) as usize;
        self.enter_file();
        self.message = format!(
            "[{}/{}] {}",
            self.active + 1,
            self.docs.len(),
            self.buf.path.display()
        );
    }

    /// Focus a file by zero-based index, if in range.
    pub fn goto_file(&mut self, idx: usize) {
        if idx < self.docs.len() {
            self.active = idx;
            self.enter_file();
            self.message = format!(
                "[{}/{}] {}",
                self.active + 1,
                self.docs.len(),
                self.buf.path.display()
            );
        } else {
            self.message = format!("no buffer {} (1..{})", idx + 1, self.docs.len());
        }
    }

    /// Close the active file; quit the app if it was the last one.
    pub fn request_close(&mut self, force: bool) {
        if !force && self.buf.has_unsaved_changes() {
            self.message = "unsaved changes (:w to save, :q! to discard)".into();
            return;
        }
        if self.docs.len() == 1 {
            self.quit = true;
            return;
        }
        self.docs.remove(self.active);
        if self.active >= self.docs.len() {
            self.active = self.docs.len() - 1;
        }
        self.enter_file();
        self.message = format!(
            "[{}/{}] {}",
            self.active + 1,
            self.docs.len(),
            self.buf.path.display()
        );
    }

    /// Reset transient UI state when the focused file changes.
    fn enter_file(&mut self) {
        self.mode = Mode::Normal;
        self.side_scroll = 0;
        self.pending_g = None;
        self.pending_mark = None;
        self.pending_z = false;
    }

    pub fn save_annotations(&mut self) {
        if let Err(e) = annotations::save_sidecar(
            &self.buf.path,
            &self.file_info.md5,
            &self.annotations,
            &self.bookmarks,
        ) {
            self.message = format!("annotation save failed: {e}");
        }
    }

    // --- geometry -------------------------------------------------------------

    pub fn columns(&self) -> u64 {
        self.config.columns as u64
    }

    fn clamp(&self, off: u64) -> u64 {
        off.min(self.buf.len().saturating_sub(1))
    }

    pub fn move_cursor(&mut self, to: u64) {
        if self.buf.is_empty() {
            return;
        }
        self.cursor = self.clamp(to);
        self.nibble_low = false;
        self.ensure_visible();
    }

    fn ensure_visible(&mut self) {
        let cols = self.columns();
        let rows = self.view_rows.max(1) as u64;
        let cursor_row = self.cursor / cols;
        let top_row = self.view_top / cols;
        if cursor_row < top_row {
            self.view_top = cursor_row * cols;
        } else if cursor_row >= top_row + rows {
            self.view_top = (cursor_row + 1 - rows) * cols;
        }
    }

    pub fn selection(&self) -> Option<(u64, u64)> {
        if self.mode == Mode::Visual {
            let a = self.visual_anchor?;
            Some((a.min(self.cursor), a.max(self.cursor) + 1))
        } else {
            None
        }
    }

    /// Active selection, else the one remembered from the last visual mode.
    fn selection_or_last(&self) -> Option<(u64, u64)> {
        self.selection().or(self.last_selection)
    }

    fn leave_visual(&mut self) {
        if let Some(sel) = self.selection() {
            self.last_selection = Some(sel);
        }
        self.visual_anchor = None;
    }

    // --- events ---------------------------------------------------------------

    pub fn handle_event(&mut self, ev: Event) {
        if let Event::Key(key) = ev
            && key.kind == KeyEventKind::Press
        {
            self.handle_key(key);
        }
    }

    pub fn handle_key(&mut self, key: KeyEvent) {
        match self.mode {
            Mode::Command | Mode::Search => self.handle_line_input(key),
            Mode::StrFilter => self.handle_str_filter(key),
            Mode::Edit { ascii } => self.handle_edit(key, ascii),
            Mode::Normal | Mode::Visual => self.handle_normal(key),
        }
    }

    fn handle_normal(&mut self, key: KeyEvent) {
        // A pending fold command (after `z`) consumes the next key.
        if self.pending_z {
            self.pending_z = false;
            self.side_tab = SideTab::Marks;
            self.side_scroll = 0;
            match key.code {
                KeyCode::Char('a') => self.fold_toggle(),
                KeyCode::Char('R') => {
                    self.collapsed.clear();
                    self.message = "expanded all folds".into();
                }
                KeyCode::Char('M') => {
                    self.collapse_all();
                    self.message = "collapsed all folds".into();
                }
                _ => self.message.clear(),
            }
            return;
        }
        // A pending bookmark key (after `m` or `` ` ``) consumes the next char.
        if let Some(set) = self.pending_mark.take() {
            match key.code {
                KeyCode::Char(c) if c.is_alphanumeric() => {
                    if set {
                        self.set_bookmark(c);
                    } else {
                        self.goto_bookmark(c);
                    }
                }
                _ => self.message.clear(),
            }
            return;
        }
        // g<hex>g pending sequence takes priority over normal bindings.
        if let Some(digits) = self.pending_g.take() {
            match key.code {
                KeyCode::Char('g') => {
                    if digits.is_empty() {
                        self.jump_to(0); // gg
                    } else if let Ok(off) = u64::from_str_radix(&digits, 16) {
                        self.jump_to(off);
                        self.message = format!("seek 0x{:X}", self.cursor);
                    }
                }
                KeyCode::Char('t') if digits.is_empty() => self.switch_file(1),
                KeyCode::Char('T') if digits.is_empty() => self.switch_file(-1),
                KeyCode::Char(c) if c.is_ascii_hexdigit() => {
                    self.pending_g = Some(format!("{digits}{c}"));
                }
                _ => self.message.clear(), // cancel
            }
            return;
        }

        let ctrl = key.modifiers.contains(KeyModifiers::CONTROL);
        let cols = self.columns();
        match key.code {
            KeyCode::Char('g') if !ctrl => {
                self.pending_g = Some(String::new());
                self.message = "g…g seek · gt/gT switch file".into();
            }
            KeyCode::Char('h') | KeyCode::Left => self.move_cursor(self.cursor.saturating_sub(1)),
            KeyCode::Char('l') | KeyCode::Right => self.move_cursor(self.cursor + 1),
            KeyCode::Char('j') | KeyCode::Down => self.move_cursor(self.cursor + cols),
            KeyCode::Char('k') | KeyCode::Up => self.move_cursor(self.cursor.saturating_sub(cols)),
            KeyCode::Char('w') => self.move_cursor(self.cursor + cols),
            KeyCode::Char('b') if !ctrl => self.move_cursor(self.cursor.saturating_sub(cols)),
            KeyCode::Char('0') => self.move_cursor(self.cursor - self.cursor % cols),
            KeyCode::Char('$') => self.move_cursor(self.cursor - self.cursor % cols + cols - 1),
            KeyCode::Char('d') if ctrl => {
                self.move_cursor(self.cursor + (self.view_rows as u64 / 2) * cols)
            }
            KeyCode::Char('u') if ctrl => self.move_cursor(
                self.cursor
                    .saturating_sub((self.view_rows as u64 / 2) * cols),
            ),
            KeyCode::Char('f') if ctrl => {
                self.move_cursor(self.cursor + self.view_rows as u64 * cols)
            }
            KeyCode::Char('b') if ctrl => {
                self.move_cursor(self.cursor.saturating_sub(self.view_rows as u64 * cols))
            }
            KeyCode::PageDown => self.move_cursor(self.cursor + self.view_rows as u64 * cols),
            KeyCode::PageUp => {
                self.move_cursor(self.cursor.saturating_sub(self.view_rows as u64 * cols))
            }
            KeyCode::Char('G') | KeyCode::End => self.jump_to(u64::MAX),
            KeyCode::Home => self.jump_to(0),
            KeyCode::Char('o') if ctrl => self.jump_history(true),
            KeyCode::Char('p') if ctrl => self.jump_history(false),
            KeyCode::Char('f') if !ctrl => {
                let le = self.endian_le;
                self.follow_pointer(4, le);
            }
            KeyCode::Char('F') => {
                let le = self.endian_le;
                self.follow_pointer(8, le);
            }
            KeyCode::Char('X') => {
                let (w, le) = (self.ptr_width, self.endian_le);
                self.find_xrefs(w, le);
            }
            KeyCode::Char('m') if self.mode == Mode::Normal => {
                self.pending_mark = Some(true);
                self.message = "set bookmark: press a-z / 0-9".into();
            }
            KeyCode::Char('`') | KeyCode::Char('\'') => {
                self.pending_mark = Some(false);
                self.message = "go to bookmark: press a-z / 0-9".into();
            }
            KeyCode::Char(':') => {
                self.leave_visual();
                self.mode = Mode::Command;
                self.cmdline.clear();
            }
            KeyCode::Char('/') => {
                self.leave_visual();
                self.mode = Mode::Search;
                self.cmdline.clear();
            }
            KeyCode::Char('v') => {
                if self.mode == Mode::Visual {
                    self.leave_visual();
                    self.mode = Mode::Normal;
                } else if !self.buf.is_empty() {
                    self.visual_anchor = Some(self.cursor);
                    self.mode = Mode::Visual;
                }
            }
            KeyCode::Esc => {
                if self.mode == Mode::Visual {
                    self.leave_visual();
                    self.mode = Mode::Normal;
                }
                self.message.clear();
            }
            KeyCode::Char('i') | KeyCode::Insert if self.mode == Mode::Normal => {
                if self.buf.is_empty() {
                    self.message = "empty file".into();
                } else {
                    self.mode = Mode::Edit { ascii: false };
                    self.nibble_low = false;
                    self.message = "-- EDIT (hex) -- Tab toggles ASCII, Esc ends".into();
                }
            }
            KeyCode::Char('u') => match self.buf.undo() {
                Some(off) => {
                    self.move_cursor(off);
                    self.message = format!("undo @ 0x{off:X}");
                }
                None => self.message = "nothing to undo".into(),
            },
            KeyCode::Char('r') if ctrl => match self.buf.redo() {
                Some(off) => {
                    self.move_cursor(off);
                    self.message = format!("redo @ 0x{off:X}");
                }
                None => self.message = "nothing to redo".into(),
            },
            KeyCode::Char('n') => self.nav_next(true),
            KeyCode::Char('N') => self.nav_next(false),
            KeyCode::Char('}') => self.magic_nav(true),
            KeyCode::Char('{') => self.magic_nav(false),
            KeyCode::Char('x') => match self.selection_or_last() {
                Some((s, e)) => {
                    if self.mode == Mode::Visual {
                        self.leave_visual();
                        self.mode = Mode::Normal;
                    }
                    self.run_xor(s, e);
                }
                None => self.message = "no selection (use v first)".into(),
            },
            KeyCode::Char('c') => match self.selection_or_last() {
                Some((s, e)) => {
                    if self.mode == Mode::Visual {
                        self.leave_visual();
                        self.mode = Mode::Normal;
                    }
                    self.run_cyclic(s, e);
                }
                None => self.message = "no selection (use v first)".into(),
            },
            KeyCode::Char('#') => {
                let range = self.selection_or_last();
                if self.mode == Mode::Visual {
                    self.leave_visual();
                    self.mode = Mode::Normal;
                }
                self.run_checksum(range);
            }
            KeyCode::Char('T') => {
                let range = self.selection_or_last();
                if self.mode == Mode::Visual {
                    self.leave_visual();
                    self.mode = Mode::Normal;
                }
                self.start_transform(range, None);
            }
            KeyCode::Char('m') if self.mode == Mode::Visual => {
                let (s, e) = self.selection().unwrap();
                self.leave_visual();
                self.cmdline = format!("mark 0x{s:X} 0x{e:X} ");
                self.mode = Mode::Command;
            }
            KeyCode::Char('e') => {
                self.side_tab = if self.side_tab == SideTab::Entropy {
                    SideTab::Marks
                } else {
                    SideTab::Entropy
                };
                self.side_scroll = 0;
            }
            KeyCode::Char('\\') => {
                self.side_tab = SideTab::Strings;
                self.side_scroll = 0;
                self.cmdline = self.strings_filter.clone();
                self.mode = Mode::StrFilter;
                self.message = "filter strings — Enter jumps to first match, Esc clears".into();
            }
            KeyCode::Tab => {
                self.side_tab = self.side_tab.next();
                self.side_scroll = 0;
            }
            KeyCode::BackTab => {
                self.side_tab = self.side_tab.prev();
                self.side_scroll = 0;
            }
            KeyCode::Char('z') => {
                self.pending_z = true;
                self.message = "z: a toggle fold · R expand all · M collapse all".into();
            }
            KeyCode::Char('J') => {
                if self.side_tab == SideTab::Triage {
                    self.triage_move(1);
                } else {
                    self.side_scroll = self.side_scroll.saturating_add(1);
                }
            }
            KeyCode::Char('K') => {
                if self.side_tab == SideTab::Triage {
                    self.triage_move(-1);
                } else {
                    self.side_scroll = self.side_scroll.saturating_sub(1);
                }
            }
            KeyCode::Enter if self.side_tab == SideTab::Triage => self.triage_jump(),
            KeyCode::Char('<') => {
                self.config.anno_width = self.config.anno_width.saturating_sub(2).max(15);
            }
            KeyCode::Char('>') => {
                self.config.anno_width = (self.config.anno_width + 2).min(120);
            }
            KeyCode::Char('q') => self.request_close(false),
            _ => {}
        }
    }

    fn handle_edit(&mut self, key: KeyEvent, ascii: bool) {
        let cols = self.columns();
        let at = self.cursor;
        match key.code {
            KeyCode::Esc => {
                self.buf.commit_group();
                self.nibble_low = false;
                self.mode = Mode::Normal;
                self.message.clear();
            }
            KeyCode::Tab => {
                self.nibble_low = false;
                self.mode = Mode::Edit { ascii: !ascii };
                self.message = if ascii {
                    "-- EDIT (hex) --".into()
                } else {
                    "-- EDIT (ascii) --".into()
                };
            }
            KeyCode::Left => self.move_cursor(at.saturating_sub(1)),
            KeyCode::Right => self.move_cursor(at + 1),
            KeyCode::Down => self.move_cursor(at + cols),
            KeyCode::Up => self.move_cursor(at.saturating_sub(cols)),
            KeyCode::Backspace => self.move_cursor(at.saturating_sub(1)),
            KeyCode::Char(c) => {
                if ascii {
                    if (' '..='~').contains(&c) {
                        self.buf.set(at, c as u8);
                        self.move_cursor(at + 1);
                    }
                } else if let Some(d) = c.to_digit(16) {
                    let cur = self.buf.get(at).unwrap_or(0);
                    if self.nibble_low {
                        self.buf.set(at, cur & 0xF0 | d as u8);
                        self.move_cursor(at + 1); // resets nibble_low
                    } else {
                        self.buf.set(at, (d as u8) << 4 | cur & 0x0F);
                        self.nibble_low = true;
                    }
                }
            }
            _ => {}
        }
    }

    fn handle_line_input(&mut self, key: KeyEvent) {
        match key.code {
            KeyCode::Esc => {
                self.cmdline.clear();
                self.mode = Mode::Normal;
            }
            KeyCode::Backspace => {
                if self.cmdline.pop().is_none() {
                    self.mode = Mode::Normal;
                }
            }
            KeyCode::Enter => {
                let line = std::mem::take(&mut self.cmdline);
                let was_search = self.mode == Mode::Search;
                self.mode = Mode::Normal;
                if was_search {
                    self.execute_search(&line);
                } else {
                    crate::commands::execute(self, &line);
                }
            }
            KeyCode::Char(c) => self.cmdline.push(c),
            _ => {}
        }
    }

    // --- actions ----------------------------------------------------------------

    pub fn execute_search(&mut self, query: &str) {
        match crate::search::run_search(&self.buf, query) {
            Ok(state) => {
                let n = state.hits.len();
                self.search = state;
                if n == 0 {
                    self.message = format!("no matches for {query}");
                } else {
                    // Jump to the first hit at or after the cursor.
                    let from = self.cursor;
                    let idx = self
                        .search
                        .hits
                        .iter()
                        .position(|&(s, _)| s >= from)
                        .unwrap_or(0);
                    self.search.current = idx;
                    let (s, _) = self.search.hits[idx];
                    self.jump_to(s);
                    self.message = format!("{n} match(es) | n/N to cycle");
                }
            }
            Err(e) => self.message = format!("search: {e}"),
        }
    }

    /// n/N: diff hunks while a diff is loaded, else search hits.
    fn nav_next(&mut self, forward: bool) {
        if self.diff_buf.is_some() {
            let from = self.cursor;
            let h = if forward {
                diff::next_hunk(&self.diff_hunks, from)
            } else {
                diff::prev_hunk(&self.diff_hunks, from)
            };
            match h {
                Some(h) => {
                    let (start, kind) = (h.start, h.kind);
                    self.move_cursor(start);
                    self.message = format!("hunk {kind:?} @ 0x{start:X}");
                }
                None => self.message = "no diff hunks".into(),
            }
        } else {
            let from = self.cursor;
            let hit = if forward {
                self.search.next(from)
            } else {
                self.search.prev(from)
            };
            match hit {
                Some((s, _)) => {
                    self.move_cursor(s);
                    self.message = format!(
                        "match {}/{}",
                        self.search.current + 1,
                        self.search.hits.len()
                    );
                }
                None => self.message = "no search hits (use /)".into(),
            }
        }
    }

    fn magic_nav(&mut self, forward: bool) {
        if self.magic_hits.is_empty() {
            self.message = "no magic hits".into();
            return;
        }
        let cursor = self.cursor;
        let hit = if forward {
            self.magic_hits
                .iter()
                .find(|h| h.offset > cursor)
                .or(self.magic_hits.first())
        } else {
            self.magic_hits
                .iter()
                .rev()
                .find(|h| h.offset < cursor)
                .or(self.magic_hits.last())
        };
        if let Some(h) = hit {
            let (off, name) = (h.offset, h.name);
            self.jump_to(off);
            self.message = format!("{name} @ 0x{off:X}");
        }
    }

    pub fn run_xor(&mut self, start: u64, end: u64) {
        let len = ((end - start) as usize).min(XOR_CAP);
        let data = self.buf.get_range(start, len);
        let hits = xor::brute_force(&data, 0.85);
        self.output_lines = vec![format!(
            "XOR brute-force 0x{start:X}..0x{end:X} ({} bytes{}):",
            data.len(),
            if (end - start) as usize > XOR_CAP {
                ", capped"
            } else {
                ""
            }
        )];
        if hits.is_empty() {
            self.output_lines
                .push("no printable candidates ≥85%".into());
        }
        for h in hits.iter().take(16) {
            self.output_lines.push(format!(
                "key 0x{:02X}  {:5.1}%  {}",
                h.key,
                h.printable_ratio * 100.0,
                h.preview
            ));
        }
        self.side_tab = SideTab::Output;
        self.side_scroll = 0;
        self.message = format!("{} XOR candidate(s)", hits.len());
    }

    pub fn run_cyclic(&mut self, start: u64, end: u64) {
        let len = ((end - start) as usize).min(CYCLIC_CAP);
        let data = self.buf.get_range(start, len);
        let hits = cyclic::detect(&data, 64, 0.90);
        self.output_lines = vec![format!(
            "Cyclic pattern scan 0x{start:X}..0x{end:X} ({} bytes): [heuristic]",
            data.len()
        )];
        if hits.is_empty() {
            self.output_lines
                .push("no repeating structure found".into());
        }
        for h in hits.iter().take(8) {
            self.output_lines.push(format!(
                "period {:3} bytes  self-similarity {:5.1}%",
                h.period,
                h.score * 100.0
            ));
        }
        self.side_tab = SideTab::Output;
        self.side_scroll = 0;
        self.message = format!("{} cyclic candidate(s)", hits.len());
    }

    /// Compute checksums over a byte range (or the whole file if `range` is
    /// None) and show them in the Output tab.
    pub fn run_checksum(&mut self, range: Option<(u64, u64)>) {
        let label = match range {
            Some((s, e)) => format!("selection 0x{s:X}..0x{e:X}"),
            None => "whole file".to_string(),
        };
        let (n, results) = {
            let bytes: Cow<[u8]> = match range {
                Some((s, e)) => Cow::Owned(self.buf.get_range(s, (e - s) as usize)),
                None if self.buf.has_unsaved_changes() => {
                    Cow::Owned(self.buf.get_range(0, self.buf.len() as usize))
                }
                None => Cow::Borrowed(self.buf.raw()),
            };
            (bytes.len(), checksum::all(&bytes))
        };
        let mut lines = vec![format!("Checksums — {label} ({n} bytes):")];
        for (name, val) in results {
            lines.push(format!("  {name:<8} {val}"));
        }
        self.output_lines = lines;
        self.side_tab = SideTab::Output;
        self.side_scroll = 0;
        self.message = format!("checksums computed ({n} bytes)");
    }

    // --- Marks tree folding ---------------------------------------------------

    /// Toggle the fold containing the cursor (vim `za`).
    fn fold_toggle(&mut self) {
        let forest = crate::marks::build(&self.annotations);
        match crate::marks::fold_target(&forest, &self.collapsed, self.cursor) {
            Some(path) => {
                if self.collapsed.remove(&path) {
                    self.message = format!("expand {path}");
                } else {
                    self.collapsed.insert(path.clone());
                    self.message = format!("collapse {path}");
                }
            }
            None => self.message = "no fold at cursor".into(),
        }
    }

    /// Collapse every group, including top-level structs (vim `zM`).
    fn collapse_all(&mut self) {
        let forest = crate::marks::build(&self.annotations);
        self.collapsed = crate::marks::group_paths(&forest, 0).into_iter().collect();
    }

    /// Collapse arrays and nested structs but leave top-level structs open.
    /// Called after `:applystruct` so a fresh parse reads as a tidy tree.
    pub fn autocollapse_marks(&mut self) {
        let forest = crate::marks::build(&self.annotations);
        self.collapsed = crate::marks::group_paths(&forest, 1).into_iter().collect();
    }

    pub fn start_diff(&mut self, path: &Path) -> Result<(), String> {
        let other = FileBuffer::open(path).map_err(|e| format!("{}: {e}", path.display()))?;
        self.diff_hunks = diff::compute(self.buf.raw(), other.raw(), 4);
        let n = self.diff_hunks.len();
        self.diff_buf = Some(other);
        self.message = format!("diff: {n} hunk(s) | n/N to jump, :diffoff to close");
        Ok(())
    }

    // --- navigation: jump list, bookmarks, follow, xrefs ----------------------

    /// Move the cursor while recording the prior position in the jump list.
    pub fn jump_to(&mut self, to: u64) {
        if self.buf.is_empty() {
            return;
        }
        let from = self.cursor;
        let to = self.clamp(to);
        if to != from {
            self.jump_back.push(from);
            if self.jump_back.len() > 256 {
                self.jump_back.remove(0);
            }
            self.jump_fwd.clear();
        }
        self.move_cursor(to);
    }

    /// Ctrl-o / Ctrl-p: walk the jump list backward / forward.
    fn jump_history(&mut self, back: bool) {
        let popped = if back {
            self.jump_back.pop()
        } else {
            self.jump_fwd.pop()
        };
        let Some(to) = popped else {
            self.message = if back {
                "jump list: at oldest".into()
            } else {
                "jump list: at newest".into()
            };
            return;
        };
        let cur = self.cursor;
        if back {
            self.jump_fwd.push(cur);
        } else {
            self.jump_back.push(cur);
        }
        self.move_cursor(to);
        self.message = format!("{} 0x{to:X}", if back { "back to" } else { "forward to" });
    }

    fn set_bookmark(&mut self, key: char) {
        let at = self.cursor;
        self.bookmarks.insert(key, at);
        self.save_annotations(); // persist to .bxa
        self.message = format!("bookmark '{key}' = 0x{at:X}");
    }

    fn goto_bookmark(&mut self, key: char) {
        match self.bookmarks.get(&key).copied() {
            Some(off) => {
                self.jump_to(off);
                self.message = format!("bookmark '{key}' → 0x{off:X}");
            }
            None => self.message = format!("no bookmark '{key}'"),
        }
    }

    /// Read `width` bytes at the cursor as a pointer and jump to it (minus base).
    pub fn follow_pointer(&mut self, width: u8, le: bool) {
        let bytes = self.buf.get_range(self.cursor, width as usize);
        if bytes.len() < width as usize {
            self.message = "not enough bytes to follow".into();
            return;
        }
        let value = decode_uint(&bytes, le);
        let target = value.wrapping_sub(self.ptr_base);
        if target < self.buf.len() {
            self.jump_to(target);
            self.message = format!("follow {}-bit 0x{value:X} → 0x{target:X}", width as u32 * 8);
        } else {
            self.message = format!(
                "0x{value:X} − base 0x{:X} = 0x{target:X} past EOF",
                self.ptr_base
            );
        }
    }

    /// Find every `width`-byte pointer in the file that targets the cursor.
    pub fn find_xrefs(&mut self, width: u8, le: bool) {
        let here = self.cursor;
        let addr = here.wrapping_add(self.ptr_base);
        let needle = encode_ptr(addr, width, le);
        let hits = crate::search::find_bytes(&self.buf, &needle);
        let n = hits.len();
        self.search = SearchState {
            query: format!("xref→0x{here:X}"),
            hits,
            current: 0,
        };
        if n == 0 {
            self.message = format!("no {}-bit pointers to 0x{here:X}", width as u32 * 8);
            return;
        }
        let idx = self
            .search
            .hits
            .iter()
            .position(|&(s, _)| s >= here)
            .unwrap_or(0);
        self.search.current = idx;
        let (s, _) = self.search.hits[idx];
        self.jump_to(s);
        self.message = format!("{n} xref(s) to 0x{here:X} | n/N to cycle");
    }

    /// Extract strings and show them in the Strings tab, jumping to the first.
    pub fn run_strings(&mut self, min: usize, utf16: bool) {
        self.strings_min = min.max(1);
        self.strings_utf16 = utf16;
        let computed = crate::analysis::strings::extract(self.buf.raw(), self.strings_min, utf16);
        let n = computed.0.len();
        let first = computed.0.first().map(|(o, _)| *o);
        self.strings_cache = Some(computed);
        self.side_tab = SideTab::Strings;
        self.side_scroll = 0;
        if let Some(o) = first {
            self.jump_to(o);
        }
        self.message = format!(
            "{n} string(s) ≥{}{}",
            self.strings_min,
            if utf16 { " (+utf16)" } else { "" }
        );
    }

    /// Build the strings list if it hasn't been computed yet.
    pub fn ensure_strings(&mut self) {
        if self.strings_cache.is_none() {
            let computed =
                crate::analysis::strings::extract(self.buf.raw(), self.strings_min, self.strings_utf16);
            self.strings_cache = Some(computed);
        }
    }

    // --- transform pipeline ---------------------------------------------------

    /// Begin a transform with the given input range (or the last selection /
    /// whole file), optionally loading a named pipeline. Switches to the tab.
    pub fn start_transform(&mut self, range: Option<(u64, u64)>, pipeline: Option<&str>) {
        let input = range
            .or(self.selection())
            .or(self.last_selection)
            .unwrap_or((0, self.buf.len()));
        self.tx_input = Some(input);
        if let Some(name) = pipeline {
            match self.pipelines.get(name).cloned() {
                Some(recipe) => self.tx_recipe = recipe,
                None => {
                    self.message = format!("no pipeline '{name}' (see ~/.bxpipes / :pipelines)");
                    return;
                }
            }
        }
        self.recompute_transform();
        self.side_tab = SideTab::Transform;
        self.side_scroll = 0;
        let (s, e) = input;
        self.message = format!("transform input 0x{s:X}..0x{e:X} ({} B)", e - s);
    }

    /// Re-run the recipe over the input bytes and cache the result. Only called
    /// on explicit edits (never per-frame), since `pipe` ops spawn processes.
    pub fn recompute_transform(&mut self) {
        let Some((s, e)) = self.tx_input else {
            self.tx_output = None;
            return;
        };
        let input = self.buf.get_range(s, (e.saturating_sub(s)) as usize);
        self.tx_output = Some(crate::transform::run(&self.tx_recipe, &input));
    }

    pub fn transform_push(&mut self, op: &str) {
        if self.tx_input.is_none() {
            self.start_transform(None, None);
        }
        self.tx_recipe.push(op.trim().to_string());
        self.recompute_transform();
        self.side_tab = SideTab::Transform;
        self.message = format!("+ {op}");
    }

    pub fn transform_pop(&mut self) {
        if self.tx_recipe.pop().is_some() {
            self.recompute_transform();
            self.message = "removed last op".into();
        } else {
            self.message = "recipe is empty".into();
        }
    }

    pub fn transform_clear(&mut self) {
        self.tx_recipe.clear();
        self.recompute_transform();
        self.message = "cleared recipe".into();
    }

    /// Current transform output bytes, if the recipe ran cleanly.
    pub fn transform_output(&self) -> Option<&[u8]> {
        match &self.tx_output {
            Some(Ok(v)) => Some(v),
            _ => None,
        }
    }

    // --- structural triage ----------------------------------------------------

    pub fn ensure_triage(&mut self) {
        if self.triage.is_none() {
            self.triage = crate::analysis::triage::analyze(self.buf.raw());
        }
    }

    /// Move the highlighted triage row (J/K on the Triage tab).
    pub fn triage_move(&mut self, delta: isize) {
        self.ensure_triage();
        if let Some(rep) = &self.triage {
            let n = rep.entries.len() as isize;
            if n > 0 {
                self.triage_sel = (self.triage_sel as isize + delta).clamp(0, n - 1) as usize;
            }
        }
    }

    /// Jump the hex cursor to the selected triage entry's file offset (Enter).
    pub fn triage_jump(&mut self) {
        self.ensure_triage();
        let target = self
            .triage
            .as_ref()
            .and_then(|rep| rep.entries.get(self.triage_sel))
            .and_then(|e| e.offset);
        match target {
            Some(off) => {
                self.jump_to(off);
                self.message = format!("→ 0x{off:X}");
            }
            None => self.message = "this entry has no file offset".into(),
        }
    }

    /// Offset of the first string matching the current filter, if any.
    pub fn first_string_match(&self) -> Option<u64> {
        let (list, _) = self.strings_cache.as_ref()?;
        let q = self.strings_filter.to_lowercase();
        list.iter()
            .find(|(_, s)| q.is_empty() || s.to_lowercase().contains(&q))
            .map(|(o, _)| *o)
    }

    /// Jump the cursor to the first string matching the filter (for `:sfind`).
    pub fn jump_to_string_match(&mut self) {
        self.ensure_strings();
        self.side_tab = SideTab::Strings;
        self.side_scroll = 0;
        match self.first_string_match() {
            Some(o) => {
                self.jump_to(o);
                self.message = format!("filter '{}' → 0x{o:X}", self.strings_filter);
            }
            None if self.strings_filter.is_empty() => self.message = "filter cleared".into(),
            None => self.message = format!("filter '{}': no match", self.strings_filter),
        }
    }

    fn handle_str_filter(&mut self, key: KeyEvent) {
        match key.code {
            KeyCode::Esc => {
                self.strings_filter.clear();
                self.cmdline.clear();
                self.side_scroll = 0;
                self.mode = Mode::Normal;
                self.message = "filter cleared".into();
            }
            KeyCode::Enter => {
                self.mode = Mode::Normal;
                self.cmdline.clear();
                self.ensure_strings();
                match self.first_string_match() {
                    Some(o) => {
                        self.jump_to(o);
                        self.message = format!("filter '{}' → 0x{o:X}", self.strings_filter);
                    }
                    None => self.message = format!("filter '{}': no match", self.strings_filter),
                }
            }
            KeyCode::Backspace => {
                self.cmdline.pop();
                self.strings_filter = self.cmdline.clone();
                self.side_scroll = 0;
            }
            KeyCode::Char(c) => {
                self.cmdline.push(c);
                self.strings_filter = self.cmdline.clone();
                self.side_scroll = 0;
            }
            _ => {}
        }
    }
}

/// Encode `value` as a little/big-endian pointer of `width` (4 or 8) bytes.
fn encode_ptr(value: u64, width: u8, le: bool) -> Vec<u8> {
    if le {
        value.to_le_bytes()[..width as usize].to_vec()
    } else {
        value.to_be_bytes()[8 - width as usize..].to_vec()
    }
}

/// Decode up to 8 bytes as an unsigned integer with the given endianness.
fn decode_uint(bytes: &[u8], le: bool) -> u64 {
    let w = bytes.len().min(8);
    let mut buf = [0u8; 8];
    if le {
        buf[..w].copy_from_slice(&bytes[..w]);
        u64::from_le_bytes(buf)
    } else {
        buf[8 - w..].copy_from_slice(&bytes[..w]);
        u64::from_be_bytes(buf)
    }
}
