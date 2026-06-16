# bxx

[![Crates.io](https://img.shields.io/crates/v/bxx.svg)](https://crates.io/crates/bxx)
[![License: MIT](https://img.shields.io/badge/license-MIT-blue.svg)](LICENSE-MIT)
[![License: APACHE](https://img.shields.io/badge/license-APACHE-blue.svg)](LICENSE-APACHE)

A fast terminal hex editor and reverse-engineering workbench. `bxx` pairs a
vim-style hex/ASCII viewer-editor with the things you actually need to take a
binary apart:

- **annotations & a struct/template language** (`.bxs`) with nested structs,
  dynamic arrays, enums, bitfields, conditionals, and built-in templates
- **structural triage** — ELF sections / segments / symbols / imports, jumpable
- a **CyberChef-style transform pipeline** (`base64`, `xor`, hashes, external
  `pipe`, named recipes)
- **search** (wildcards, strings, case-insensitive, optional regex), checksums,
  a data inspector, entropy + magic-byte + heuristic-arch analysis
- **alignment-aware diffing** with a similarity score, and a **Ghidra / radare2
  hand-off**

Files are memory-mapped, so multi-hundred-MB firmware images open instantly. It
aims to be a fast terminal **companion** to Ghidra and binwalk — triage here,
deep-dive there — not a replacement for either.

> [!NOTE]
> **Disclaimer:** this is primarily a curiosity / hobby project, and a large
> portion of the code is AI-generated. It's reasonably tested but has not been
> battle-hardened — treat it accordingly.

```
┌ fw.bin ────────────────────────────────────────────────┐┌───────────────────────────┐
│00000000  41 4E 44 52 4F 49 44 21  00 00 80 00  ANDROID!││ Marks │ Analysis │ … │    │
│00000010  00 00 20 00 00 00 00 00  00 00 00 00  ·· ·····││ bhdr.kernel_size u32le    │
│…                                                       ││   = 8388608 (0x800000)    │
└────────────────────────────────────────────────────────┘└───────────────────────────┘
 NORMAL  0x0/0x1A9F  Android boot image | H=3.62 | md5 748bb902c38d
```

## Install

```sh
cargo install bxx              # from crates.io (the binary is `bxx`)

# or from source:
cargo install --path .
cargo build --release          # binary at target/release/bxx

# optional regex search (/re:…):
cargo install bxx --features regex
```

Pure-cargo dependencies only (ratatui, crossterm, memmap2, md5, serde) — the
optional `regex` feature is the only extra, and it's off by default. Requires
Rust ≥ 1.87.

Dual-licensed under [MIT](LICENSE-MIT) or [Apache-2.0](LICENSE-APACHE).

## Usage

```sh
bxx file.bin              # open in the TUI
bxx a.bin b.bin c.bin     # open several files as tabs (gt/gT to switch)
bxx --diff a.bin b.bin    # open with a side-by-side diff
bxx file.bin --batch      # headless: print file info, magic hits, parsed
                         # headers and arch summary to stdout, then exit
```

On load, bxx computes the file's size, MD5, Shannon entropy and detected type,
scans the **entire file** for magic signatures (embedded images included), and
runs the heuristic architecture pattern scan. Results land in the **Analysis**
tab of the side pane.

## Keys (vim-style)

| Key | Action |
|---|---|
| `h j k l` / arrows | move by byte / row |
| `w` / `b` | row forward / back |
| `0` / `$` | start / end of row |
| `Ctrl-d` / `Ctrl-u` | half page down / up |
| `Ctrl-f` / `Ctrl-b`, PgDn / PgUp | full page |
| `gg` / `G` | start / end of file |
| `g<hex>g` | seek to hex offset (e.g. `g1845g`) |
| `Ctrl-o` / `Ctrl-p` | jump list — back / forward through visited positions |
| `m<key>` / `` `<key> `` | set bookmark / jump to bookmark (`a-z`, `0-9`) |
| `f` / `F` | follow the 32-/64-bit pointer under the cursor (honours base+endian) |
| `X` | find xrefs — every pointer in the file that targets the cursor (cycle with `n`/`N`) |
| `/` | search — hex wildcards (`de ad ?? ef`), string (`"text"`, ASCII **and** UTF-16LE), case-insensitive (`i"text"`), or regex (`re:…`, needs the `regex` feature). `/` from a selection scopes to it. |
| `n` / `N` | next / prev search hit (or diff hunk while a diff is open) |
| `↑` / `↓` (in `/` or `:`) | recall previous / next search or command from history |
| `\` | live-filter the Strings tab (type to narrow; `Enter` jumps to first match) |
| `{` / `}` | prev / next magic-byte hit |
| `<` / `>` | smaller / larger side-pane |
| `v` | visual selection (movement extends; `Esc`/`v` ends) |
| `m` (in visual) | pre-fill `:mark` for the selection |
| `x` | XOR brute-force the selection (keys 0x00–0xFF, printable hits ranked) |
| `c` | cyclic / repeating-structure detection on the selection |
| `#` | checksums (CRC32/MD5/SHA1/SHA256/…) of the selection, or whole file |
| `T` | open the selection in the transform pipeline (Transform tab) |
| `y` / `p` | yank selection to the clipboard (hex, via OSC52) / paste-overwrite at cursor |
| `gt` / `gT` | switch to next / previous open file |
| `i` | edit mode — type hex nibbles; `Tab` switches to ASCII overtype; `Esc` ends |
| `u` / `Ctrl-r` | undo / redo (grouped per edit session) |
| `e` | toggle entropy graph |
| `za` / `zR` / `zM` | toggle fold / expand all / collapse all (Marks tree, or the selected node on the Template tab) |
| `Tab` / `Shift-Tab` | next / previous side-pane tab (the header is a scrolling carousel) |
| `J` / `K` | scroll side pane — or move the selection on the Triage / Template tabs |
| `Enter` | Triage: jump to the selected entry · Template: fold/unfold the selected struct/source |
| `q` | quit / close active file (refuses if unsaved; `:q!` discards) |

## Commands

```
:seek <target>            jump to 0x<hex>, bare hex, 0d<decimal>, or a mark label
:mark <start> <end> <label> <type>   annotate [start,end) — types: u8 u16le u16be
                                     u32le u32be u64le u64be float str raw
:unmark <label>
:applystruct <name>       lay a struct template down at the cursor
:loadstructs <file|dir>   load a .bxs file, or every .bxs in a directory
:reloadstructs            re-read the <file>.bxs sidecar after editing it
:diff <file> / :diffoff   alignment-aware side-by-side diff (n/N jump hunks)
:xor / :cyclic            analyze the last visual selection
:checksum [start end]     CRC32/Adler/MD5/SHA1/SHA256 of a range (default: selection/file)
:strings [min] [utf16]    list printable strings in the Strings tab (\ / :sfind to filter)
:triage                   sections/symbols/imports of an executable (Triage tab)
:transform [pipe]         transform a selection (also T); :t <op>, :tpop, :tclear,
                          :tsave <f>, :tpatch, :pipelines, :reloadpipes
:export-ghidra / :export-r2   export marks + bookmarks as a Ghidra / r2 script
:follow [u32le|u64be|…]   follow the pointer under the cursor (also f / F)
:xref [u32le|u64be|…]     find pointers that target the cursor (also X)
:base <hex>               load base subtracted by follow/xref (firmware @ nonzero base)
:endian le|be             byte order used by follow/xref (auto-set from ELF)
:bookmarks  :jumps        list bookmarks / jump-list state
:e <file>                 open another file in a new tab
:bn :bp :b <n> :ls        next / prev / nth file; list open files
:close  :bd[!]            close the active file
:export <report.json>     JSON report: file info + annotations with parsed values
:yank [hex|c|raw|base64]  copy the selection to the clipboard (also y)
:paste                    overwrite at the cursor from the yank register (also p)
:fill <hex>               fill the selection with a repeating byte pattern
:w [file]                 write patches in place, or a patched copy to [file]
:revert                   discard unsaved edits in the active file
:q  :q!  :wq  :qa[!]      quit-or-close / discard / write+quit / quit all
:info :template :inspect :entropy :help    switch side-pane tabs
```

## Annotations (`.bxa`)

Marks (and bookmarks) are saved automatically to a JSON sidecar `<binary>.bxa`
and reloaded next session (with an MD5 mismatch warning if the file changed).
The Marks tab shows each region's **live** decoded value — it re-decodes
through your unsaved edits. Annotated bytes are color-coded in the hex view,
and labels work as `:seek` targets.

## Struct templates (`.bxs`)

A small C-like template language, auto-loaded from `<binary>.bxs` (or
`:loadstructs <file>`). Simple cases stay simple — a flat list of typed
fields — but it has the pieces you need to parse real formats:

- **scalars** — `u8 u16le u16be u32le u32be u64le u64be`, `f32`/`f64`,
  `str[n]` (string), `raw[n]` (blob)
- **nested structs** — use another struct's name as a field type
- **dynamic arrays** — `Item items[count];` sized by an *earlier field*, with
  expressions (`data[len * 2 + 4]`)
- **enums** — `enum Kind : u8 { FILE = 1, DIR = 2 }` annotate a field with its
  variant name
- **bitfields** — `bitfield Perm : u8 { read:1, write:1, exec:1, pad:5 }`
  decode a value into named bit groups (LSB first)
- **conditionals** — `if (flag == 1) { … } else { … }` for optional fields
  (full expression operators: `+ - * / %  == != < <= > >=  && ||  & | ^ ~ << >>`)

```c
enum Kind : u8 { FILE = 1, DIR = 2 }
bitfield Perm : u8 { read:1, write:1, exec:1, pad:5 }

struct Entry {
    Kind  kind;
    Perm  perm;
    u8    name_len;
    str   name[name_len];   // length-prefixed string
}

struct Header {
    str    magic[4];
    u32le  count;
    Entry  entries[count];  // array sized by a prior field
}
```

`:applystruct Header` at the cursor walks the actual bytes and annotates every
field — nested labels like `Header.entries[0].name`, enum fields show their
variant name, bitfields show each group's value. (The original flat syntax
still works unchanged.)

**Built-in templates** ship with `bxx`, so `:applystruct png` works on any PNG
with no sidecar: `elf64_header` / `elf32_header` / `elf64_phdr`, `png`, `gif`,
`bmp`, `zip_local`, `gzip` (and the enums/bitfields they use). Your own
`<file>.bxs` definitions override the built-ins by name.

The **Marks** tab renders the result as a **collapsible tree** with
indentation; nested structs and arrays are auto-collapsed so you see the shape
first, then drill in with `za` (toggle the fold at the cursor), `zR` (expand
all) and `zM` (collapse all). The **Template** tab (`:template`) shows the
loaded definitions **grouped by source** (`── built-in ──`, `── yourfile.bxs ──`,
…) as a **foldable tree** — structs are collapsed to one line by default;
`J`/`K` move the selection and `Enter` (or `za`/`zR`/`zM`) folds the selected
struct or whole source group, so you can see what's available and where it
came from without scrolling past every field.

Handy extras: `:applystruct <name> <offset>` applies at a hex offset or mark
label without seeking first (e.g. `:applystruct Phdr e_phoff`); re-applying a
struct clears its old fields first (no orphans), and `:unmark <name>` removes a
whole applied struct. Edit the `.bxs` and `:reloadstructs` to pick up changes
without restarting. Parse errors report the source line (`ls.bxs:line 3: …`).

## Analysis

- **Magic scan** — executables (ELF, PE/MZ, Mach-O incl. fat, COFF, ar, DEX
  035–039, ODEX, VDEX, OAT, ART), firmware (Android boot/vendor_boot, uImage,
  FIT/DTB, SquashFS ×4, JFFS2, UBI/UBIFS, YAFFS2, cramfs, romfs, ext2/3/4,
  F2FS), archives (gzip, zlib ×4, LZMA, LZ4, zstd, bzip2, XZ, 7z, ZIP, RAR,
  tar), crypto (DER x509 / PKCS#8 / PKCS#12, PEM banners, OpenSSH keys,
  Android OTA payload), media (PNG, JPEG, BMP, SQLite3, protobuf/msgpack
  heuristics). Short magics carry validators (e.g. MZ → e_lfanew → `PE\0\0`,
  tar checksum field, ext superblock sanity) to keep firmware noise down;
  noisy entries are capped per type and flagged as truncated.
- **Header parsing** — ELF (class/endian, machine, entry, phoff, section
  count), PE (machine, entrypoint RVA, section table), Android boot image
  v0–v4 (full field set per version), DEX (version, checksum, class count) —
  parsed wherever the magic lands, so embedded images decode too.
- **Arch patterns** *(heuristic, no disassembly — labeled as such)* —
  prologue/epilogue signatures for x86/x86_64, ARM32 (ARM+Thumb), ARM64,
  MIPS (LE/BE), PowerPC, RISC-V, plus NOP sleds, `int3` runs and zero-fill
  padding. Matches are tinted in the hex view (padding dimmed).
- **Entropy** — whole-file value in the status bar; per-region bar graph in
  the Entropy tab (red ≈ compressed/encrypted), cursor position highlighted.
- **XOR brute force** — select a region, press `x`; all 256 keys tried,
  candidates ranked by printability/text-likeness with decoded previews.
- **Cyclic detection** — select a region, press `c`; reports repeating record
  periods (2–64 bytes) by self-similarity.
- **Checksums** — press `#` (or `:checksum`) to compute Sum8/16/32, XOR8,
  Adler-32, CRC32, MD5, SHA-1 and SHA-256 over the selection (or the whole
  file if nothing is selected). CRC/Adler/SHA are hand-rolled — no extra deps.
- **Data inspector** — the **Inspect** tab decodes the bytes at the cursor as
  every integer width (signed/unsigned, LE/BE), `float32`/`float64`, a 32-bit
  `time_t`, plus hex/octal/binary/ASCII — live, no `:mark` needed.

Pattern/string search uses Boyer-Moore-Horspool with a bad-character skip table
(wildcard-aware), so even multi-hundred-MB files scan in a fraction of a second.

## Triage (structural overview)

`:triage` opens the **Triage** tab — a fast structural map of an executable so
you can size it up in the terminal *before* loading it into Ghidra. For ELF it
lists, with the high-signal stuff first:

- **needed libraries** (`DT_NEEDED`) and **imports** (undefined dynamic symbols)
- **segments** (program headers, with R/W/X flags) and **sections**
- **symbols** (functions/objects with address, size, type)

`J`/`K` move the highlight, `Enter` jumps the hex cursor to that entry's file
offset (recorded in the jump list, so `Ctrl-o` brings you back). It's pure
structure — bxx is a companion to Ghidra/binwalk, not a disassembler. *(ELF
today; PE/Mach-O planned.)*

## Hand off to Ghidra / radare2 *(prototype)*

> [!WARNING]
> **Prototype / experimental.** This feature works in the common case but
> hasn't been deeply tested across binaries and tool versions. The
> offset→address translation, label sanitizing, and generated scripts may not
> always be correct — **review the output before running it**, and don't rely
> on it for anything load-bearing yet.

Annotate in bxx, then push your work downstream:

```
:export-ghidra labels.py     # Ghidra Jython script (Script Manager / analyzeHeadless)
:export-r2 labels.r2         # radare2 script (r2 -i labels.r2 <bin>, or `. labels.r2`)
```

Both recreate your marks and bookmarks as **labels + comments** at the right
addresses. bxx works in file offsets; the export translates them to virtual
addresses through the ELF LOAD segments (offsets that aren't in a loadable
segment are skipped), so a mark at file offset `0x25D10` is meant to land on
address `0x26D10` in Ghidra.

## File-overview minimap

A thin 010-style strip on the right of the hex view maps the whole file to the
column height, tinted by entropy (green → yellow → red for compressed/encrypted
regions), with annotated regions highlighted, a `┃` bracket marking the visible
window and `▶` at the cursor — so you can see a big firmware image's structure
and your place in it at a glance. Toggle with `minimap = on|off` in `~/.bxrc`.

## Transform pipeline (CyberChef-style)

Pipe a selection through an ordered **recipe** of operations and see the result
live in the **Transform** tab. Select bytes and press `T` (or `:transform`),
then build the recipe:

```
:t unbase64           # add a step
:t xor 5a             # … then another (data flows through each)
:t pipe zcat          # pipe through any external program
:tpop  :tclear        # remove last step / clear
:tsave out.bin        # write the output to a file
:tpatch               # overwrite the output back into the buffer (then :w)
```

Built-in ops (pure-Rust, no deps): `hex`/`unhex`, `base64`/`unbase64`,
`url`/`unurl`, `xor <key>`, `add`/`sub <n>`, `not`, `rol`/`ror <n>`, `reverse`,
`swap16`/`swap32`/`swap64`, `rot13`, `upper`/`lower`, `take`/`drop <n>`,
`md5`/`sha1`/`sha256`/`crc32`.

**Your own transforms, two ways:**

- **`pipe <cmd>`** streams the bytes through any external program's
  stdin/stdout (`pipe openssl enc -d …`, `pipe ./my_decoder.py`), so a step can
  be written in any language. *(Runs a shell command — only ones you type/configure.)*
- **Named recipes** in `~/.bxpipes` compose built-ins into reusable pipelines:

  ```ini
  # ~/.bxpipes  —  name = op | op | …
  deflate_text = pipe zcat | strings
  deobfuscate  = unbase64 | xor 5a | rot13
  ```

  Load one with `:transform <name>`; `:pipelines` lists them in the Output
  panel; `:reloadpipes` re-reads the file so edits take effect without
  restarting bxx.

## Diffing

`bxx --diff a b` (or `:diff <file>`) opens two files side by side. The diff is
**alignment-aware** — it tracks inserted/deleted bytes (difflib-style matching
blocks) rather than comparing positionally, so a few inserted bytes don't
cascade into "everything after is different." A **similarity score** shows in
the status bar (`DIFF 91% 1h`), each pane is colored by its own
changed/added/removed regions, and `n`/`N` jump between hunks. Very large files
fall back to a fast positional compare (shown with a `~`).

## Multiple files

Open several files at once (`bxx a b c`, or `:e <file>` while running); each is
a tab in the strip across the top with its own cursor, annotations, search and
analysis. `gt`/`gT` (or `:bn`/`:bp`/`:b <n>`) switch between them, `:ls` lists
them, `:close` closes one. `:q` closes the active file and only quits once the
last one is gone (`:qa` quits everything).

## Navigation & xrefs

The moment-to-moment RE loop — jump somewhere, look, come back:

- **Jump list** — every seek, search, follow, bookmark-jump and magic hit is
  recorded; `Ctrl-o` walks back through where you've been and `Ctrl-p` forward
  (browser-style history, per file). `:jumps` shows the stack.
- **Bookmarks** — `m<key>` drops a named position (`a-z`/`0-9`), `` `<key> ``
  jumps to it, `:bookmarks` lists them.
- **Follow pointer** — `f`/`F` read the 32-/64-bit value under the cursor and
  jump there. For images loaded at a non-zero address, set `:base <hex>` and
  the file offset is computed as `value − base`; `:endian le|be` picks byte
  order (auto-detected from an ELF header). `:follow u64be` overrides per-call.
- **Cross-references** — `X` (or `:xref`) scans the whole file for pointers
  whose value equals the cursor offset (`+ base`), loading them as search hits
  so `n`/`N` cycle them and they highlight in the hex view. Pointer width and
  endianness default to the detected ELF class.
- **Strings** — the **Strings** tab lists printable ASCII (and, with
  `:strings <min> utf16`, UTF-16LE) runs with offsets; the entry nearest the
  cursor is highlighted, and the list is windowed so even huge files stay
  snappy. Press `\` (or `:sfind <text>`) to live-filter the list by substring;
  `Enter` jumps the cursor to the first match.

Bookmarks persist to the `.bxa` sidecar, so they survive across sessions.

## Editing model

Overwrite-only by design: insertion would shift offsets and silently
invalidate annotations and diffs, which is the wrong default for binary
patching. Edits live in an overlay (the mapped file is untouched) until `:w`
patches the file in place or `:w copy.bin` writes a patched copy. Modified
bytes are highlighted; undo/redo is unlimited. Diff mode compares on-disk
contents.

## Security

`bxx` is meant for inspecting **untrusted** binaries, so it's built to handle
hostile input safely:

- **Offline.** It makes no network connections — it only reads the files you
  open and its config in your home directory.
- **Memory-safe.** Pure safe Rust except a single read-only `mmap`; the whole
  parsing/analysis surface is fuzz-tested to never panic, overflow, hang, or
  over-allocate on malformed, truncated, or adversarial input (template
  field counts, recursion, string/array lengths, and all format parsers are
  bounded). A malicious file can't corrupt memory or run code.
- **Sidecars are inert data.** `<file>.bxa` (annotations) and `<file>.bxs`
  (templates) are auto-loaded but contain no executable logic — `.bxa` is plain
  JSON, and the `.bxs` template language has no scripting. They do nothing until
  you act on them (`:applystruct`), and even then it's bounded data layout.

Two features run **commands you provide** — treat them like a shell:

- **`pipe <cmd>`** transforms and named recipes in `~/.bxpipes` run the shell
  command you type/configure (like vim's `!filter`). Only use commands and
  recipes you trust.
- The **Ghidra/r2 export** *(prototype)* sanitizes labels and comments before
  writing, but it generates scripts that run in another tool — review them
  before running.

The optional `regex` feature uses the linear-time `regex` crate (no
catastrophic-backtracking / ReDoS). One inherent caveat: because files are
memory-mapped, another process truncating a file while it's open can raise
`SIGBUS` — a robustness limitation of `mmap`, not a memory-safety hole.

## Config (`~/.bxrc`)

`key = value` lines, `#` comments:

```ini
columns = 16            # bytes per hex row (1-64)
anno_pane = right       # right | left | off
anno_width = 44
minimap = on            # file-overview strip on the right (on | off)
color.annotation = cyan        # named colors or #rrggbb
color.cursor = yellow
color.selection = blue
color.search = green
color.diff_changed = yellow
color.diff_added = green
color.diff_removed = red
color.heuristic = magenta
color.modified = lightred
```
