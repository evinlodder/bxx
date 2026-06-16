# Changelog

All notable changes to `bxx` are documented here. The format is based on
[Keep a Changelog](https://keepachangelog.com/), and this project adheres to
[Semantic Versioning](https://semver.org/).

## [1.0.0] - 2026-06-14

First stable release. `bxx` is a fast terminal hex editor and reverse-engineering
workbench — a companion to Ghidra/binwalk, not a replacement.

### Core hex editor
- Memory-mapped, vim-style hex/ASCII viewer & overwrite editor with grouped
  undo/redo; multi-hundred-MB files open instantly.
- Visual selection, `:seek`/`g<hex>g`, paging, and a per-file jump list
  (`Ctrl-o`/`Ctrl-p`).
- Bookmarks (`m<key>` / `` `<key> ``), persisted to the `.bxa` sidecar.
- Yank to the system clipboard via OSC52 (`y`, `:yank hex|c|raw|base64`),
  `:paste`, and `:fill <hex>`.

### Search
- Hex patterns with `??` wildcards, ASCII + UTF-16LE strings, case-insensitive
  (`i"text"`), and optional regex (`re:…`, behind the `regex` cargo feature).
- Boyer-Moore-Horspool engine (wildcard-aware) — 256 MB scans in a fraction of
  a second. Scoped search (start `/` from a selection) and `/`+`:` history.

### Annotations, templates, analysis
- Named regions (`:mark`), live-decoded, saved to `.bxa`, exportable to JSON.
- `.bxs` template language: nested structs, dynamic arrays, enums, bitfields,
  conditionals; collapsible Marks tree; built-in templates for ELF/PE/PNG/ZIP/…
- Checksums (CRC32/Adler/MD5/SHA-1/SHA-256), data inspector, entropy graph,
  XOR brute force, cyclic detection, magic-byte scan, heuristic arch patterns,
  and a strings pane.

### Triage & hand-off
- Structural triage pane (ELF sections/segments/symbols/imports/libraries),
  jump-to-offset.
- File-overview minimap on the right of the hex view.
- Ghidra / radare2 export of marks + bookmarks as labels/comments at the right
  addresses (**prototype**).

### Diff & transforms
- Alignment-aware diff (survives inserts/deletes) with a similarity score;
  positional fallback for very large files.
- CyberChef-style transform pipeline with built-in ops, external `pipe <cmd>`,
  and named recipes in `~/.bxpipes`.

### Misc
- Multiple files as tabs, `--batch` headless mode, `~/.bxrc` config.

[1.0.0]: https://github.com/evinlodder/bx/releases/tag/v1.0.0
