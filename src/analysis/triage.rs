//! Structural triage: parse an executable's high-level structure (segments,
//! sections, symbols, imports, needed libraries) so you can understand a binary
//! at a glance in the terminal and jump to any part of it — then hand off to
//! Ghidra. Pure structure, no disassembly.
//!
//! ELF (32/64, LE/BE) is implemented; the model is format-agnostic so PE and
//! Mach-O can slot in later.

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Kind {
    Segment,
    Section,
    Symbol,
    Import,
    Library,
}

impl Kind {
    pub fn label(self) -> &'static str {
        match self {
            Kind::Segment => "Segments",
            Kind::Section => "Sections",
            Kind::Symbol => "Symbols",
            Kind::Import => "Imports",
            Kind::Library => "Libraries",
        }
    }
}

#[derive(Debug, Clone)]
pub struct Entry {
    pub kind: Kind,
    pub name: String,
    /// File offset to jump to, if the item maps into the file.
    pub offset: Option<u64>,
    /// Virtual address, if meaningful.
    pub addr: Option<u64>,
    pub size: u64,
    /// Type / flags shown after the name.
    pub detail: String,
}

#[derive(Debug, Clone)]
pub struct Report {
    pub format: String,
    /// Flat, grouped by `kind` in display order.
    pub entries: Vec<Entry>,
    /// LOAD mappings `(file_offset, vaddr, file_size)` for offset↔address.
    pub maps: Vec<(u64, u64, u64)>,
}

impl Report {
    /// Translate a file offset to a virtual address, if it falls in a mapped
    /// (loadable) region. Used for the Ghidra/r2 hand-off.
    pub fn off_to_vaddr(&self, off: u64) -> Option<u64> {
        self.maps
            .iter()
            .find(|&&(fo, _, fs)| off >= fo && off < fo + fs)
            .map(|&(fo, va, _)| va + (off - fo))
    }
}

const MAX_SYMS: usize = 4000;
const MAX_IMPORTS: usize = 3000;

/// Analyze the whole-file bytes. Returns None if the format isn't recognized.
pub fn analyze(data: &[u8]) -> Option<Report> {
    if data.len() >= 5 && &data[..4] == b"\x7fELF" {
        parse_elf(data)
    } else {
        None
    }
}

// --- little reader -----------------------------------------------------------

struct R<'a> {
    d: &'a [u8],
    le: bool,
}

impl R<'_> {
    fn u8(&self, o: usize) -> Option<u8> {
        self.d.get(o).copied()
    }
    fn u16(&self, o: usize) -> Option<u16> {
        let b = self.d.get(o..o + 2)?;
        Some(if self.le {
            u16::from_le_bytes([b[0], b[1]])
        } else {
            u16::from_be_bytes([b[0], b[1]])
        })
    }
    fn u32(&self, o: usize) -> Option<u32> {
        let b = self.d.get(o..o + 4)?;
        let a: [u8; 4] = b.try_into().ok()?;
        Some(if self.le {
            u32::from_le_bytes(a)
        } else {
            u32::from_be_bytes(a)
        })
    }
    fn u64(&self, o: usize) -> Option<u64> {
        let b = self.d.get(o..o + 8)?;
        let a: [u8; 8] = b.try_into().ok()?;
        Some(if self.le {
            u64::from_le_bytes(a)
        } else {
            u64::from_be_bytes(a)
        })
    }
    /// NUL-terminated string at `o` inside a table starting at `base`.
    fn cstr(&self, base: usize, off: u32) -> String {
        let start = base + off as usize;
        let mut s = String::new();
        let mut i = start;
        while let Some(&c) = self.d.get(i) {
            if c == 0 {
                break;
            }
            s.push(if (0x20..0x7f).contains(&c) { c as char } else { '?' });
            i += 1;
            if s.len() > 256 {
                break;
            }
        }
        s
    }
}

fn machine_name(m: u16) -> &'static str {
    match m {
        3 => "x86",
        8 => "MIPS",
        20 => "PowerPC",
        40 => "ARM",
        62 => "x86-64",
        183 => "AArch64",
        243 => "RISC-V",
        _ => "unknown",
    }
}

fn sh_type_name(t: u32) -> &'static str {
    match t {
        0 => "NULL",
        1 => "PROGBITS",
        2 => "SYMTAB",
        3 => "STRTAB",
        4 => "RELA",
        6 => "DYNAMIC",
        7 => "NOTE",
        8 => "NOBITS",
        9 => "REL",
        11 => "DYNSYM",
        14 => "INIT_ARRAY",
        15 => "FINI_ARRAY",
        _ => "—",
    }
}

fn p_type_name(t: u32) -> &'static str {
    match t {
        0 => "NULL",
        1 => "LOAD",
        2 => "DYNAMIC",
        3 => "INTERP",
        4 => "NOTE",
        6 => "PHDR",
        7 => "TLS",
        0x6474_e550 => "GNU_EH_FRAME",
        0x6474_e551 => "GNU_STACK",
        0x6474_e552 => "GNU_RELRO",
        0x6474_e553 => "GNU_PROPERTY",
        _ => "—",
    }
}

fn sym_type_name(info: u8) -> &'static str {
    match info & 0xf {
        1 => "OBJECT",
        2 => "FUNC",
        3 => "SECTION",
        4 => "FILE",
        6 => "TLS",
        _ => "NOTYPE",
    }
}

fn parse_elf(data: &[u8]) -> Option<Report> {
    let class64 = data[4] == 2;
    let le = data[5] != 2;
    let r = R { d: data, le };

    let e_machine = r.u16(0x12)?;
    let e_type = r.u16(0x10)?;
    let format = format!(
        "ELF{} {} ({})",
        if class64 { "64" } else { "32" },
        machine_name(e_machine),
        match e_type {
            1 => "REL",
            2 => "EXEC",
            3 => "DYN",
            4 => "CORE",
            _ => "?",
        }
    );

    // header fields differ by class
    let (phoff, shoff, phentsize, phnum, shentsize, shnum, shstrndx) = if class64 {
        (
            r.u64(0x20)?,
            r.u64(0x28)?,
            r.u16(0x36)? as usize,
            r.u16(0x38)? as usize,
            r.u16(0x3a)? as usize,
            r.u16(0x3c)? as usize,
            r.u16(0x3e)? as usize,
        )
    } else {
        (
            r.u32(0x1c)? as u64,
            r.u32(0x20)? as u64,
            r.u16(0x2a)? as usize,
            r.u16(0x2c)? as usize,
            r.u16(0x2e)? as usize,
            r.u16(0x30)? as usize,
            r.u16(0x32)? as usize,
        )
    };

    let mut entries = Vec::new();

    // --- segments (program headers) → also the vaddr→offset map -------------
    let mut loads: Vec<(u64, u64, u64)> = Vec::new(); // (vaddr, filesz, offset)
    for i in 0..phnum.min(1000) {
        let base = phoff as usize + i * phentsize;
        let (p_type, p_flags, p_offset, p_vaddr, p_filesz, p_memsz) = if class64 {
            (
                r.u32(base)?,
                r.u32(base + 4)?,
                r.u64(base + 8)?,
                r.u64(base + 16)?,
                r.u64(base + 32)?,
                r.u64(base + 40)?,
            )
        } else {
            (
                r.u32(base)?,
                r.u32(base + 24)?,
                r.u32(base + 4)? as u64,
                r.u32(base + 8)? as u64,
                r.u32(base + 16)? as u64,
                r.u32(base + 20)? as u64,
            )
        };
        if p_type == 1 && p_filesz > 0 {
            loads.push((p_vaddr, p_filesz, p_offset));
        }
        let flags = format!(
            "{}{}{}",
            if p_flags & 4 != 0 { "r" } else { "-" },
            if p_flags & 2 != 0 { "w" } else { "-" },
            if p_flags & 1 != 0 { "x" } else { "-" },
        );
        entries.push(Entry {
            kind: Kind::Segment,
            name: p_type_name(p_type).to_string(),
            offset: Some(p_offset),
            addr: Some(p_vaddr),
            size: p_memsz,
            detail: flags,
        });
    }
    let vaddr_to_off = |v: u64| -> Option<u64> {
        loads
            .iter()
            .find(|&&(va, sz, _)| v >= va && v < va + sz)
            .map(|&(va, _, off)| off + (v - va))
    };

    // --- sections -----------------------------------------------------------
    let read_shdr = |i: usize| -> Option<(u32, u32, u64, u64, u64, u32, u64)> {
        let b = shoff as usize + i * shentsize;
        if class64 {
            Some((
                r.u32(b)?,       // sh_name
                r.u32(b + 4)?,   // sh_type
                r.u64(b + 16)?,  // sh_addr
                r.u64(b + 24)?,  // sh_offset
                r.u64(b + 32)?,  // sh_size
                r.u32(b + 40)?,  // sh_link
                r.u64(b + 56)?,  // sh_entsize
            ))
        } else {
            Some((
                r.u32(b)?,
                r.u32(b + 4)?,
                r.u32(b + 12)? as u64,
                r.u32(b + 16)? as u64,
                r.u32(b + 20)? as u64,
                r.u32(b + 24)?,
                r.u32(b + 36)? as u64,
            ))
        }
    };

    let shstr_base = if shnum > 0 && shstrndx < shnum {
        read_shdr(shstrndx).map(|s| s.3 as usize).unwrap_or(0)
    } else {
        0
    };

    // symbol tables to walk afterwards: (sym_offset, sym_size, entsize, strtab_base)
    let mut symtabs: Vec<(u64, u64, u64, usize)> = Vec::new();
    let mut dynamic: Option<(u64, u64, u64, usize)> = None; // (off, size, entsize, dynstr_base)

    for i in 0..shnum.min(2000) {
        let (sh_name, sh_type, sh_addr, sh_offset, sh_size, sh_link, sh_entsize) = read_shdr(i)?;
        let name = r.cstr(shstr_base, sh_name);
        if i == 0 && name.is_empty() {
            continue; // the null section
        }
        entries.push(Entry {
            kind: Kind::Section,
            name: if name.is_empty() {
                format!("[{i}]")
            } else {
                name.clone()
            },
            offset: if sh_type == 8 { None } else { Some(sh_offset) },
            addr: if sh_addr != 0 { Some(sh_addr) } else { None },
            size: sh_size,
            detail: sh_type_name(sh_type).to_string(),
        });
        // remember symbol & dynamic tables, resolving their string tables
        if (sh_type == 2 || sh_type == 11) && sh_entsize > 0 {
            let strtab_base = read_shdr(sh_link as usize).map(|s| s.3 as usize).unwrap_or(0);
            symtabs.push((sh_offset, sh_size, sh_entsize, strtab_base));
        }
        if sh_type == 6 && sh_entsize > 0 {
            let dynstr_base = read_shdr(sh_link as usize).map(|s| s.3 as usize).unwrap_or(0);
            dynamic = Some((sh_offset, sh_size, sh_entsize, dynstr_base));
        }
    }

    // --- symbols & imports --------------------------------------------------
    // prefer .symtab (type 2) but a dynsym-only (stripped) binary still works.
    symtabs.sort_by_key(|t| t.1); // walk the smaller (usually dynsym) too; pick the largest as primary
    let primary = symtabs.iter().max_by_key(|t| t.1).copied();
    let (mut nsym, mut nimp) = (0usize, 0usize);
    if let Some((off, size, ent, strtab)) = primary {
        let count = (size / ent) as usize;
        for i in 0..count {
            let b = off as usize + i * ent as usize;
            let (st_name, st_value, st_size, st_info, st_shndx) = if class64 {
                (
                    r.u32(b)?,
                    r.u64(b + 8)?,
                    r.u64(b + 16)?,
                    r.u8(b + 4)?,
                    r.u16(b + 6)?,
                )
            } else {
                (
                    r.u32(b)?,
                    r.u32(b + 4)? as u64,
                    r.u32(b + 8)? as u64,
                    r.u8(b + 12)?,
                    r.u16(b + 14)?,
                )
            };
            let name = r.cstr(strtab, st_name);
            if name.is_empty() {
                continue;
            }
            let ty = st_info & 0xf;
            if st_shndx == 0 {
                // undefined → imported symbol
                if nimp < MAX_IMPORTS {
                    entries.push(Entry {
                        kind: Kind::Import,
                        name,
                        offset: None,
                        addr: None,
                        size: 0,
                        detail: sym_type_name(st_info).to_string(),
                    });
                    nimp += 1;
                }
            } else if (ty == 1 || ty == 2) && st_value != 0 {
                // defined object/function
                if nsym < MAX_SYMS {
                    entries.push(Entry {
                        kind: Kind::Symbol,
                        name,
                        offset: vaddr_to_off(st_value),
                        addr: Some(st_value),
                        size: st_size,
                        detail: sym_type_name(st_info).to_string(),
                    });
                    nsym += 1;
                }
            }
        }
    }

    // --- needed libraries (DT_NEEDED in .dynamic) ---------------------------
    if let Some((off, size, ent, dynstr)) = dynamic {
        let count = (size / ent) as usize;
        for i in 0..count.min(1000) {
            let b = off as usize + i * ent as usize;
            let (tag, val) = if class64 {
                (r.u64(b)? as i64, r.u64(b + 8)?)
            } else {
                (r.u32(b)? as i64, r.u32(b + 4)? as u64)
            };
            if tag == 0 {
                break; // DT_NULL
            }
            if tag == 1 {
                // DT_NEEDED
                let name = r.cstr(dynstr, val as u32);
                if !name.is_empty() {
                    entries.push(Entry {
                        kind: Kind::Library,
                        name,
                        offset: None,
                        addr: None,
                        size: 0,
                        detail: "NEEDED".to_string(),
                    });
                }
            }
        }
    }

    // Display order: high-signal triage info first (deps, imports), the big
    // symbol list last.
    let order = |k: Kind| match k {
        Kind::Segment => 0,
        Kind::Library => 1,
        Kind::Import => 2,
        Kind::Section => 3,
        Kind::Symbol => 4,
    };
    entries.sort_by_key(|e| order(e.kind));

    // loads is (vaddr, filesz, offset) → maps is (offset, vaddr, filesz)
    let maps = loads.iter().map(|&(va, fs, off)| (off, va, fs)).collect();
    Some(Report {
        format,
        entries,
        maps,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_self_or_bin_ls() {
        // Prefer a known-present system binary; skip cleanly if unavailable.
        let path = ["/bin/ls", "/usr/bin/ls"]
            .iter()
            .find(|p| std::path::Path::new(p).exists());
        let Some(path) = path else {
            return;
        };
        let data = std::fs::read(path).unwrap();
        let rep = analyze(&data).expect("ELF recognized");
        assert!(rep.format.starts_with("ELF"));
        assert!(rep.entries.iter().any(|e| e.kind == Kind::Segment));
        assert!(rep.entries.iter().any(|e| e.kind == Kind::Section));
        // dynamically-linked binary → at least one needed library
        assert!(rep.entries.iter().any(|e| e.kind == Kind::Library));
    }
}
