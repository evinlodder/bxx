//! `.bxs` binary-template language (v2).
//!
//! A small C-like language for describing binary layouts. Simple cases stay
//! simple (a flat list of typed fields), but it also supports the pieces you
//! actually need to parse real formats:
//!
//! - **nested structs** — use another struct's name as a field type
//! - **dynamic arrays** — `Item items[count];` sized by an earlier field, with
//!   arithmetic/comparison expressions (`data[len * 2]`)
//! - **enums** — `enum Kind : u8 { A = 1, B = 2 }` annotate a field with names
//! - **bitfields** — `bitfield Flags : u16le { lo : 4, hi : 12 }`
//! - **conditionals** — `if (flag == 1) { ... } else { ... }`
//!
//! ```text
//! enum Kind : u8 { FILE = 1, DIR = 2 }
//!
//! struct Entry {
//!     Kind  kind;
//!     u8    name_len;
//!     str   name[name_len];   // length-prefixed string
//! }
//!
//! struct Header {
//!     str    magic[4];
//!     u32le  count;
//!     Entry  entries[count];  // array sized by a prior field
//! }
//! ```
//!
//! Applying a struct at the cursor walks the actual bytes and emits one
//! annotation per field (with nested labels like `Header.entries[0].name`).

use std::collections::HashMap;

use crate::annotations::{Region, RegionType};
use crate::buffer::FileBuffer;

/// Stop runaway templates (e.g. a garbage length field) from flooding the UI.
const MAX_REGIONS: usize = 8192;
const MAX_DEPTH: usize = 64;

// ---------------------------------------------------------------------------
// AST
// ---------------------------------------------------------------------------

/// A built-in scalar. Endianness for ints is baked into the type name.
#[derive(Debug, Clone, Copy, PartialEq)]
enum Scalar {
    Int(RegionType),
    Float32,
    Float64,
    /// String / blob — always sized by an explicit `[len]`.
    Str,
    Raw,
}

impl Scalar {
    fn from_name(name: &str) -> Option<Self> {
        use RegionType::*;
        Some(match name {
            "u8" => Scalar::Int(U8),
            "u16le" => Scalar::Int(U16Le),
            "u16be" => Scalar::Int(U16Be),
            "u32le" => Scalar::Int(U32Le),
            "u32be" => Scalar::Int(U32Be),
            "u64le" => Scalar::Int(U64Le),
            "u64be" => Scalar::Int(U64Be),
            "float" | "f32" => Scalar::Float32,
            "double" | "f64" => Scalar::Float64,
            "str" | "char" => Scalar::Str,
            "raw" | "bytes" => Scalar::Raw,
            _ => return None,
        })
    }

    fn region_type(self) -> RegionType {
        match self {
            Scalar::Int(rt) => rt,
            Scalar::Float32 | Scalar::Float64 => RegionType::Float,
            Scalar::Str => RegionType::Str,
            Scalar::Raw => RegionType::Raw,
        }
    }
}

#[derive(Debug, Clone)]
enum TypeRef {
    Scalar(Scalar),
    /// A struct / enum / bitfield, resolved by name when applied.
    Named(String),
}

#[derive(Debug, Clone)]
enum Member {
    Field {
        name: String,
        ty: TypeRef,
        /// `Some(expr)` for `name[expr]`. For str/raw it's the byte length; for
        /// everything else it's the element count.
        array: Option<Expr>,
    },
    If {
        cond: Expr,
        then: Vec<Member>,
        els: Vec<Member>,
    },
}

#[derive(Debug, Clone)]
struct StructDef {
    members: Vec<Member>,
    /// Where this definition was loaded from (for the Template pane).
    source: String,
}

#[derive(Debug, Clone)]
struct EnumDef {
    base: RegionType,
    variants: Vec<(String, i64)>,
    source: String,
}

#[derive(Debug, Clone)]
struct BitfieldDef {
    base: RegionType,
    groups: Vec<(String, u32)>, // (name, bit width), LSB first
    source: String,
}

/// One definition rendered for the Template side pane (foldable).
pub struct TemplateEntry {
    pub source: String,
    pub name: String,
    /// e.g. `struct png {` / `enum Kind : u8 {` / `bitfield Perm : u8 {`.
    pub header: String,
    /// Body lines (fields/variants/groups) plus the closing `}`.
    pub body: Vec<String>,
}

/// A parsed set of templates from one or more `.bxs` files.
#[derive(Debug, Clone, Default)]
pub struct Template {
    structs: HashMap<String, StructDef>,
    enums: HashMap<String, EnumDef>,
    bitfields: HashMap<String, BitfieldDef>,
}

// ---------------------------------------------------------------------------
// Expressions
// ---------------------------------------------------------------------------

#[derive(Debug, Clone)]
enum Expr {
    Int(i64),
    Ident(String),
    Unary(UnOp, Box<Expr>),
    Bin(BinOp, Box<Expr>, Box<Expr>),
}

#[derive(Debug, Clone, Copy)]
enum UnOp {
    Neg,
    Not,
    BitNot,
}

#[derive(Debug, Clone, Copy)]
enum BinOp {
    Add,
    Sub,
    Mul,
    Div,
    Mod,
    Eq,
    Ne,
    Lt,
    Le,
    Gt,
    Ge,
    And,
    Or,
    BAnd,
    BOr,
    BXor,
    Shl,
    Shr,
}

fn eval(e: &Expr, scope: &HashMap<String, i64>) -> Result<i64, String> {
    Ok(match e {
        Expr::Int(n) => *n,
        Expr::Ident(s) => *scope
            .get(s)
            .ok_or_else(|| format!("unknown field '{s}' in expression"))?,
        Expr::Unary(op, x) => {
            let v = eval(x, scope)?;
            match op {
                UnOp::Neg => v.wrapping_neg(),
                UnOp::Not => (v == 0) as i64,
                UnOp::BitNot => !v,
            }
        }
        Expr::Bin(op, a, b) => {
            let x = eval(a, scope)?;
            let y = eval(b, scope)?;
            match op {
                BinOp::Add => x.wrapping_add(y),
                BinOp::Sub => x.wrapping_sub(y),
                BinOp::Mul => x.wrapping_mul(y),
                BinOp::Div => {
                    if y == 0 {
                        return Err("division by zero".into());
                    }
                    x / y
                }
                BinOp::Mod => {
                    if y == 0 {
                        return Err("modulo by zero".into());
                    }
                    x % y
                }
                BinOp::Eq => (x == y) as i64,
                BinOp::Ne => (x != y) as i64,
                BinOp::Lt => (x < y) as i64,
                BinOp::Le => (x <= y) as i64,
                BinOp::Gt => (x > y) as i64,
                BinOp::Ge => (x >= y) as i64,
                BinOp::And => ((x != 0) && (y != 0)) as i64,
                BinOp::Or => ((x != 0) || (y != 0)) as i64,
                BinOp::BAnd => x & y,
                BinOp::BOr => x | y,
                BinOp::BXor => x ^ y,
                BinOp::Shl => x.wrapping_shl(y as u32),
                BinOp::Shr => x.wrapping_shr(y as u32),
            }
        }
    })
}

// ---------------------------------------------------------------------------
// Lexer
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, PartialEq)]
enum Tok {
    Ident(String),
    Num(i64),
    LBrace,
    RBrace,
    LBrack,
    RBrack,
    LParen,
    RParen,
    Semi,
    Colon,
    Comma,
    Assign,
    Plus,
    Minus,
    Star,
    Slash,
    Percent,
    EqEq,
    Ne,
    Lt,
    Le,
    Gt,
    Ge,
    AndAnd,
    OrOr,
    Bang,
    Amp,
    Pipe,
    Caret,
    Tilde,
    Shl,
    Shr,
}

/// Strip `//` and `/* */` comments, preserving bytes verbatim (so multi-byte
/// UTF-8 in the source survives) and keeping newlines for accurate line counts.
fn strip_comments(src: &str) -> Vec<u8> {
    let b = src.as_bytes();
    let mut out = Vec::with_capacity(b.len());
    let mut i = 0;
    while i < b.len() {
        if b[i] == b'/' && i + 1 < b.len() && b[i + 1] == b'/' {
            while i < b.len() && b[i] != b'\n' {
                i += 1;
            }
        } else if b[i] == b'/' && i + 1 < b.len() && b[i + 1] == b'*' {
            i += 2;
            while i + 1 < b.len() && !(b[i] == b'*' && b[i + 1] == b'/') {
                if b[i] == b'\n' {
                    out.push(b'\n');
                }
                i += 1;
            }
            i += 2;
            out.push(b' ');
        } else {
            out.push(b[i]);
            i += 1;
        }
    }
    out
}

/// Tokenize, tracking the 1-based source line of each token (for error
/// messages). Returns parallel `(tokens, lines)` vectors. Operates on bytes
/// throughout — the language is ASCII, so any non-ASCII byte is rejected
/// cleanly rather than panicking on a UTF-8 boundary.
fn lex(src: &str) -> Result<(Vec<Tok>, Vec<u32>), String> {
    let b = strip_comments(src);
    let mut out = Vec::new();
    let mut lines = Vec::new();
    let mut i = 0;
    let mut line = 1u32;
    while i < b.len() {
        let c = b[i];
        if c == b'\n' {
            line += 1;
            i += 1;
            continue;
        }
        if c.is_ascii_whitespace() {
            i += 1;
            continue;
        }
        let at = line;
        // maximal-munch two-character operators
        if i + 1 < b.len() {
            let t = match (c, b[i + 1]) {
                (b'=', b'=') => Some(Tok::EqEq),
                (b'!', b'=') => Some(Tok::Ne),
                (b'<', b'=') => Some(Tok::Le),
                (b'>', b'=') => Some(Tok::Ge),
                (b'&', b'&') => Some(Tok::AndAnd),
                (b'|', b'|') => Some(Tok::OrOr),
                (b'<', b'<') => Some(Tok::Shl),
                (b'>', b'>') => Some(Tok::Shr),
                _ => None,
            };
            if let Some(t) = t {
                out.push(t);
                lines.push(at);
                i += 2;
                continue;
            }
        }
        let single = match c {
            b'{' => Some(Tok::LBrace),
            b'}' => Some(Tok::RBrace),
            b'[' => Some(Tok::LBrack),
            b']' => Some(Tok::RBrack),
            b'(' => Some(Tok::LParen),
            b')' => Some(Tok::RParen),
            b';' => Some(Tok::Semi),
            b':' => Some(Tok::Colon),
            b',' => Some(Tok::Comma),
            b'=' => Some(Tok::Assign),
            b'+' => Some(Tok::Plus),
            b'-' => Some(Tok::Minus),
            b'*' => Some(Tok::Star),
            b'/' => Some(Tok::Slash),
            b'%' => Some(Tok::Percent),
            b'<' => Some(Tok::Lt),
            b'>' => Some(Tok::Gt),
            b'!' => Some(Tok::Bang),
            b'&' => Some(Tok::Amp),
            b'|' => Some(Tok::Pipe),
            b'^' => Some(Tok::Caret),
            b'~' => Some(Tok::Tilde),
            _ => None,
        };
        if let Some(t) = single {
            out.push(t);
            lines.push(at);
            i += 1;
            continue;
        }
        if c.is_ascii_digit() {
            let start = i;
            if c == b'0' && i + 1 < b.len() && (b[i + 1] | 0x20) == b'x' {
                i += 2;
                let hs = i;
                while i < b.len() && b[i].is_ascii_hexdigit() {
                    i += 1;
                }
                // bytes here are all ASCII hex digits → valid UTF-8.
                let digits = std::str::from_utf8(&b[hs..i]).unwrap_or("");
                let v = i64::from_str_radix(digits, 16)
                    .map_err(|_| format!("line {at}: bad hex number '0x{digits}'"))?;
                out.push(Tok::Num(v));
            } else {
                while i < b.len() && b[i].is_ascii_digit() {
                    i += 1;
                }
                let digits = std::str::from_utf8(&b[start..i]).unwrap_or("");
                let v: i64 = digits
                    .parse()
                    .map_err(|_| format!("line {at}: bad number '{digits}'"))?;
                out.push(Tok::Num(v));
            }
            lines.push(at);
            continue;
        }
        if c.is_ascii_alphabetic() || c == b'_' {
            let start = i;
            while i < b.len() && (b[i].is_ascii_alphanumeric() || b[i] == b'_') {
                i += 1;
            }
            // identifier bytes are ASCII [A-Za-z0-9_] → valid UTF-8.
            let name = std::str::from_utf8(&b[start..i]).unwrap_or("").to_string();
            out.push(Tok::Ident(name));
            lines.push(at);
            continue;
        }
        return Err(format!("line {at}: unexpected byte 0x{c:02x}"));
    }
    Ok((out, lines))
}

// ---------------------------------------------------------------------------
// Parser
// ---------------------------------------------------------------------------

struct Parser {
    toks: Vec<Tok>,
    lines: Vec<u32>,
    pos: usize,
}

impl Parser {
    fn peek(&self) -> Option<&Tok> {
        self.toks.get(self.pos)
    }

    fn next(&mut self) -> Option<Tok> {
        let t = self.toks.get(self.pos).cloned();
        if t.is_some() {
            self.pos += 1;
        }
        t
    }

    /// 1-based source line at the current position (or the last token's).
    fn line(&self) -> u32 {
        self.lines
            .get(self.pos)
            .or_else(|| self.lines.last())
            .copied()
            .unwrap_or(0)
    }

    /// Prefix an error message with the current source line.
    fn e(&self, msg: String) -> String {
        format!("line {}: {msg}", self.line())
    }

    fn eat(&mut self, t: &Tok) -> Result<(), String> {
        let ln = self.line();
        match self.next() {
            Some(ref got) if got == t => Ok(()),
            other => Err(format!("line {ln}: expected {t:?}, found {other:?}")),
        }
    }

    fn ident(&mut self) -> Result<String, String> {
        let ln = self.line();
        match self.next() {
            Some(Tok::Ident(s)) => Ok(s),
            other => Err(format!("line {ln}: expected identifier, found {other:?}")),
        }
    }

    fn keyword(&self) -> Option<&str> {
        match self.peek() {
            Some(Tok::Ident(s)) => Some(s.as_str()),
            _ => None,
        }
    }

    fn parse_template(&mut self) -> Result<Template, String> {
        let mut tpl = Template::default();
        while self.peek().is_some() {
            match self.keyword() {
                Some("struct") => {
                    self.next();
                    let (name, def) = self.parse_struct()?;
                    tpl.structs.insert(name, def);
                }
                Some("enum") => {
                    self.next();
                    let (name, def) = self.parse_enum()?;
                    tpl.enums.insert(name, def);
                }
                Some("bitfield") => {
                    self.next();
                    let (name, def) = self.parse_bitfield()?;
                    tpl.bitfields.insert(name, def);
                }
                _ => {
                    return Err(self.e(format!(
                        "expected struct/enum/bitfield, found {:?}",
                        self.peek()
                    )));
                }
            }
        }
        if tpl.is_empty() {
            return Err("no definitions found".into());
        }
        Ok(tpl)
    }

    fn parse_struct(&mut self) -> Result<(String, StructDef), String> {
        let name = self.ident()?;
        self.eat(&Tok::LBrace)?;
        let members = self.parse_members()?;
        Ok((
            name,
            StructDef {
                members,
                source: String::new(),
            },
        ))
    }

    /// Parse members up to and including the closing `}`.
    fn parse_members(&mut self) -> Result<Vec<Member>, String> {
        let mut members = Vec::new();
        loop {
            match self.peek() {
                Some(Tok::RBrace) => {
                    self.next();
                    break;
                }
                None => return Err(self.e("unterminated '{'".into())),
                Some(Tok::Ident(k)) if k == "if" => members.push(self.parse_if()?),
                _ => members.push(self.parse_field()?),
            }
        }
        Ok(members)
    }

    fn parse_if(&mut self) -> Result<Member, String> {
        self.next(); // 'if'
        self.eat(&Tok::LParen)?;
        let cond = self.parse_expr(0)?;
        self.eat(&Tok::RParen)?;
        self.eat(&Tok::LBrace)?;
        let then = self.parse_members()?;
        let els = if self.keyword() == Some("else") {
            self.next();
            self.eat(&Tok::LBrace)?;
            self.parse_members()?
        } else {
            Vec::new()
        };
        Ok(Member::If { cond, then, els })
    }

    fn parse_field(&mut self) -> Result<Member, String> {
        let type_name = self.ident()?;
        let ty = match Scalar::from_name(&type_name) {
            Some(s) => TypeRef::Scalar(s),
            None => TypeRef::Named(type_name.clone()),
        };
        let name = self.ident()?;
        let array = if self.peek() == Some(&Tok::LBrack) {
            self.next();
            let e = self.parse_expr(0)?;
            self.eat(&Tok::RBrack)?;
            Some(e)
        } else {
            None
        };
        self.eat(&Tok::Semi)?;
        if matches!(ty, TypeRef::Scalar(Scalar::Str | Scalar::Raw)) && array.is_none() {
            return Err(self.e(format!(
                "'{type_name} {name}' needs a length, e.g. {name}[16]"
            )));
        }
        Ok(Member::Field { name, ty, array })
    }

    fn parse_enum(&mut self) -> Result<(String, EnumDef), String> {
        let name = self.ident()?;
        self.eat(&Tok::Colon)?;
        let base = self.int_type()?;
        self.eat(&Tok::LBrace)?;
        let mut variants = Vec::new();
        let mut next_val = 0i64;
        loop {
            if self.peek() == Some(&Tok::RBrace) {
                self.next();
                break;
            }
            let vname = self.ident()?;
            let val = if self.peek() == Some(&Tok::Assign) {
                self.next();
                let v = self.parse_expr(0)?;
                eval(&v, &HashMap::new())?
            } else {
                next_val
            };
            variants.push((vname, val));
            next_val = val + 1;
            match self.peek() {
                Some(Tok::Comma) => {
                    self.next();
                }
                Some(Tok::RBrace) => {}
                other => {
                    return Err(self.e(format!("expected ',' or '}}' in enum {name}, got {other:?}")));
                }
            }
        }
        if variants.is_empty() {
            return Err(self.e(format!("enum {name} has no variants")));
        }
        Ok((
            name,
            EnumDef {
                base,
                variants,
                source: String::new(),
            },
        ))
    }

    fn parse_bitfield(&mut self) -> Result<(String, BitfieldDef), String> {
        let name = self.ident()?;
        self.eat(&Tok::Colon)?;
        let base = self.int_type()?;
        self.eat(&Tok::LBrace)?;
        let mut groups = Vec::new();
        loop {
            if self.peek() == Some(&Tok::RBrace) {
                self.next();
                break;
            }
            let gname = self.ident()?;
            self.eat(&Tok::Colon)?;
            let ln = self.line();
            let bits = match self.next() {
                Some(Tok::Num(n)) if n > 0 && n <= 64 => n as u32,
                other => {
                    return Err(format!("line {ln}: bitfield {name}.{gname}: bad bit width {other:?}"));
                }
            };
            groups.push((gname, bits));
            match self.peek() {
                Some(Tok::Comma) => {
                    self.next();
                }
                Some(Tok::RBrace) => {}
                other => {
                    return Err(
                        self.e(format!("expected ',' or '}}' in bitfield {name}, got {other:?}"))
                    );
                }
            }
        }
        if groups.is_empty() {
            return Err(self.e(format!("bitfield {name} has no groups")));
        }
        Ok((
            name,
            BitfieldDef {
                base,
                groups,
                source: String::new(),
            },
        ))
    }

    /// Parse a type name that must be an integer scalar (enum/bitfield base).
    fn int_type(&mut self) -> Result<RegionType, String> {
        let n = self.ident()?;
        match Scalar::from_name(&n) {
            Some(Scalar::Int(rt)) => Ok(rt),
            _ => Err(self.e(format!("'{n}' is not an integer type (need u8/u16le/…)"))),
        }
    }

    // Pratt expression parser ------------------------------------------------

    fn parse_expr(&mut self, min_bp: u8) -> Result<Expr, String> {
        let mut lhs = self.parse_unary()?;
        while let Some((op, lbp, rbp)) = self.peek().and_then(binop_bp) {
            if lbp < min_bp {
                break;
            }
            self.next();
            let rhs = self.parse_expr(rbp)?;
            lhs = Expr::Bin(op, Box::new(lhs), Box::new(rhs));
        }
        Ok(lhs)
    }

    fn parse_unary(&mut self) -> Result<Expr, String> {
        let op = match self.peek() {
            Some(Tok::Minus) => Some(UnOp::Neg),
            Some(Tok::Bang) => Some(UnOp::Not),
            Some(Tok::Tilde) => Some(UnOp::BitNot),
            _ => None,
        };
        if let Some(op) = op {
            self.next();
            let inner = self.parse_unary()?;
            return Ok(Expr::Unary(op, Box::new(inner)));
        }
        self.parse_primary()
    }

    fn parse_primary(&mut self) -> Result<Expr, String> {
        let ln = self.line();
        match self.next() {
            Some(Tok::Num(n)) => Ok(Expr::Int(n)),
            Some(Tok::Ident(s)) => Ok(Expr::Ident(s)),
            Some(Tok::LParen) => {
                let e = self.parse_expr(0)?;
                self.eat(&Tok::RParen)?;
                Ok(e)
            }
            other => Err(format!("line {ln}: unexpected {other:?} in expression")),
        }
    }
}

/// (operator, left binding power, right binding power) — all left-associative.
fn binop_bp(t: &Tok) -> Option<(BinOp, u8, u8)> {
    Some(match t {
        Tok::OrOr => (BinOp::Or, 1, 2),
        Tok::AndAnd => (BinOp::And, 3, 4),
        Tok::Pipe => (BinOp::BOr, 5, 6),
        Tok::Caret => (BinOp::BXor, 7, 8),
        Tok::Amp => (BinOp::BAnd, 9, 10),
        Tok::EqEq => (BinOp::Eq, 11, 12),
        Tok::Ne => (BinOp::Ne, 11, 12),
        Tok::Lt => (BinOp::Lt, 13, 14),
        Tok::Le => (BinOp::Le, 13, 14),
        Tok::Gt => (BinOp::Gt, 13, 14),
        Tok::Ge => (BinOp::Ge, 13, 14),
        Tok::Shl => (BinOp::Shl, 15, 16),
        Tok::Shr => (BinOp::Shr, 15, 16),
        Tok::Plus => (BinOp::Add, 17, 18),
        Tok::Minus => (BinOp::Sub, 17, 18),
        Tok::Star => (BinOp::Mul, 19, 20),
        Tok::Slash => (BinOp::Div, 19, 20),
        Tok::Percent => (BinOp::Mod, 19, 20),
        _ => return None,
    })
}

/// Parse a `.bxs` document into a [`Template`].
pub fn parse(text: &str) -> Result<Template, String> {
    let (toks, lines) = lex(text)?;
    Parser {
        toks,
        lines,
        pos: 0,
    }
    .parse_template()
}

// ---------------------------------------------------------------------------
// Apply
// ---------------------------------------------------------------------------

struct Ctx<'a> {
    buf: &'a FileBuffer,
    off: u64,
    regions: Vec<Region>,
    depth: usize,
    warn: Option<String>,
    stop: bool,
}

impl Ctx<'_> {
    /// Emit a region of `size` bytes at the running offset, advancing it.
    fn emit(&mut self, size: u64, label: String, rtype: RegionType, note: Option<String>) {
        if self.stop {
            return;
        }
        // checked_add guards against attacker-controlled sizes wrapping u64.
        let end = match self.off.checked_add(size) {
            Some(e) if e <= self.buf.len() => e,
            _ => {
                self.warn = Some(format!("'{label}' overruns end of file at 0x{:X}", self.off));
                self.stop = true;
                return;
            }
        };
        if self.regions.len() >= MAX_REGIONS {
            self.warn = Some(format!("stopped at {MAX_REGIONS} fields (cap)"));
            self.stop = true;
            return;
        }
        self.regions.push(Region {
            start: self.off,
            end,
            label,
            rtype,
            note,
        });
        self.off = end;
    }
}

impl Template {
    pub fn is_empty(&self) -> bool {
        self.structs.is_empty() && self.enums.is_empty() && self.bitfields.is_empty()
    }

    pub fn has_struct(&self, name: &str) -> bool {
        self.structs.contains_key(name)
    }

    pub fn struct_names(&self) -> Vec<&str> {
        self.structs.keys().map(String::as_str).collect()
    }

    /// Fold another parsed template into this one (later defs win).
    pub fn merge(&mut self, other: Template) {
        self.structs.extend(other.structs);
        self.enums.extend(other.enums);
        self.bitfields.extend(other.bitfields);
    }

    /// Tag every definition with the source it came from (file path or label).
    pub fn set_source(&mut self, src: &str) {
        for d in self.structs.values_mut() {
            d.source = src.to_string();
        }
        for d in self.enums.values_mut() {
            d.source = src.to_string();
        }
        for d in self.bitfields.values_mut() {
            d.source = src.to_string();
        }
    }

    /// All definitions as foldable entries for the Template side tab, sorted
    /// by source then name (so same-source entries group together).
    pub fn entries(&self) -> Vec<TemplateEntry> {
        let mut out = Vec::new();
        for (name, d) in &self.structs {
            let mut body = Vec::new();
            for m in &d.members {
                describe_member(m, 1, &mut body);
            }
            body.push("}".into());
            out.push(TemplateEntry {
                source: group_key(&d.source),
                name: name.clone(),
                header: format!("struct {name} {{"),
                body,
            });
        }
        for (name, e) in &self.enums {
            let mut body: Vec<String> = e
                .variants
                .iter()
                .map(|(vn, v)| format!("    {vn} = {v},"))
                .collect();
            body.push("}".into());
            out.push(TemplateEntry {
                source: group_key(&e.source),
                name: name.clone(),
                header: format!("enum {name} : {} {{", e.base),
                body,
            });
        }
        for (name, b) in &self.bitfields {
            let mut body: Vec<String> = b
                .groups
                .iter()
                .map(|(gn, bits)| format!("    {gn} : {bits},"))
                .collect();
            body.push("}".into());
            out.push(TemplateEntry {
                source: group_key(&b.source),
                name: name.clone(),
                header: format!("bitfield {name} : {} {{", b.base),
                body,
            });
        }
        out.sort_by(|a, b| a.source.cmp(&b.source).then(a.name.cmp(&b.name)));
        out
    }

    /// Lay `name` down at `base`, walking `buf`. Returns the emitted regions
    /// plus an optional warning (EOF overrun, cap hit, eval error).
    pub fn apply(&self, name: &str, base: u64, buf: &FileBuffer) -> (Vec<Region>, Option<String>) {
        let mut ctx = Ctx {
            buf,
            off: base,
            regions: Vec::new(),
            depth: 0,
            warn: None,
            stop: false,
        };
        self.apply_struct(name, name, &mut ctx);
        (ctx.regions, ctx.warn)
    }

    fn apply_struct(&self, sname: &str, prefix: &str, ctx: &mut Ctx) {
        if ctx.stop {
            return;
        }
        if ctx.depth >= MAX_DEPTH {
            ctx.warn = Some("nesting too deep".into());
            ctx.stop = true;
            return;
        }
        let Some(def) = self.structs.get(sname) else {
            ctx.warn = Some(format!("unknown struct '{sname}'"));
            ctx.stop = true;
            return;
        };
        ctx.depth += 1;
        let mut scope: HashMap<String, i64> = HashMap::new();
        for m in &def.members {
            self.apply_member(m, prefix, ctx, &mut scope);
            if ctx.stop {
                break;
            }
        }
        ctx.depth -= 1;
    }

    fn apply_member(
        &self,
        m: &Member,
        prefix: &str,
        ctx: &mut Ctx,
        scope: &mut HashMap<String, i64>,
    ) {
        match m {
            Member::Field { name, ty, array } => {
                // str/raw: the [len] is a byte count → one region.
                if let TypeRef::Scalar(s @ (Scalar::Str | Scalar::Raw)) = ty {
                    let len = match self.eval_len(array.as_ref(), scope, ctx) {
                        Some(n) => n,
                        None => return,
                    };
                    ctx.emit(len, format!("{prefix}.{name}"), s.region_type(), None);
                    return;
                }
                match array {
                    Some(expr) => {
                        let n = match self.eval_len(Some(expr), scope, ctx) {
                            Some(n) => n,
                            None => return,
                        };
                        for i in 0..n {
                            if ctx.stop {
                                break;
                            }
                            self.apply_value(ty, format!("{prefix}.{name}[{i}]"), ctx);
                        }
                    }
                    None => {
                        if let Some(v) = self.apply_value(ty, format!("{prefix}.{name}"), ctx) {
                            scope.insert(name.clone(), v);
                        }
                    }
                }
            }
            Member::If { cond, then, els } => match eval(cond, scope) {
                Ok(c) => {
                    let branch = if c != 0 { then } else { els };
                    for m in branch {
                        self.apply_member(m, prefix, ctx, scope);
                        if ctx.stop {
                            break;
                        }
                    }
                }
                Err(e) => {
                    ctx.warn = Some(e);
                    ctx.stop = true;
                }
            },
        }
    }

    /// Evaluate an array/length expression to a non-negative count.
    fn eval_len(
        &self,
        expr: Option<&Expr>,
        scope: &HashMap<String, i64>,
        ctx: &mut Ctx,
    ) -> Option<u64> {
        let expr = expr?;
        match eval(expr, scope) {
            Ok(v) if v >= 0 => Some(v as u64),
            Ok(v) => {
                ctx.warn = Some(format!("negative length {v}"));
                ctx.stop = true;
                None
            }
            Err(e) => {
                ctx.warn = Some(e);
                ctx.stop = true;
                None
            }
        }
    }

    /// Emit one element and return its integer value (for scoping), if any.
    fn apply_value(&self, ty: &TypeRef, label: String, ctx: &mut Ctx) -> Option<i64> {
        match ty {
            TypeRef::Scalar(Scalar::Int(rt)) => {
                let v = read_uint(ctx.buf, ctx.off, *rt);
                ctx.emit(rt.fixed_size().unwrap(), label, *rt, None);
                v.map(|x| x as i64)
            }
            TypeRef::Scalar(Scalar::Float32) => {
                ctx.emit(4, label, RegionType::Float, None);
                None
            }
            TypeRef::Scalar(Scalar::Float64) => {
                ctx.emit(8, label, RegionType::Float, None);
                None
            }
            // str/raw never reach here (handled in apply_member); guard anyway.
            TypeRef::Scalar(s @ (Scalar::Str | Scalar::Raw)) => {
                ctx.emit(0, label, s.region_type(), None);
                None
            }
            TypeRef::Named(n) => {
                if let Some(ed) = self.enums.get(n) {
                    self.apply_enum(ed, label, ctx)
                } else if let Some(bd) = self.bitfields.get(n) {
                    self.apply_bitfield(bd, label, ctx)
                } else if self.structs.contains_key(n) {
                    self.apply_struct(n, &label, ctx);
                    None
                } else {
                    ctx.warn = Some(format!("unknown type '{n}'"));
                    ctx.stop = true;
                    None
                }
            }
        }
    }

    fn apply_enum(&self, def: &EnumDef, label: String, ctx: &mut Ctx) -> Option<i64> {
        let size = def.base.fixed_size().unwrap();
        let v = read_uint(ctx.buf, ctx.off, def.base);
        let note = v.map(|val| {
            let val = val as i64;
            match def.variants.iter().find(|(_, x)| *x == val) {
                Some((vname, _)) => vname.clone(),
                None => format!("? ({val})"),
            }
        });
        ctx.emit(size, label, def.base, note);
        v.map(|x| x as i64)
    }

    fn apply_bitfield(&self, def: &BitfieldDef, label: String, ctx: &mut Ctx) -> Option<i64> {
        let size = def.base.fixed_size().unwrap();
        let raw = read_uint(ctx.buf, ctx.off, def.base);
        let note = raw.map(|v| {
            let mut pos = 0u32;
            let mut parts = Vec::new();
            for (gname, bits) in &def.groups {
                let mask = if *bits >= 64 { u64::MAX } else { (1u64 << bits) - 1 };
                let val = (v >> pos) & mask;
                parts.push(format!("{gname}={val}"));
                pos += bits;
            }
            parts.join(" ")
        });
        ctx.emit(size, label, def.base, note);
        raw.map(|x| x as i64)
    }
}

fn group_key(src: &str) -> String {
    if src.is_empty() {
        "(unspecified)".to_string()
    } else {
        src.to_string()
    }
}

fn scalar_name(s: Scalar) -> String {
    match s {
        Scalar::Int(rt) => rt.to_string(),
        Scalar::Float32 => "f32".into(),
        Scalar::Float64 => "f64".into(),
        Scalar::Str => "str".into(),
        Scalar::Raw => "raw".into(),
    }
}

fn type_name(ty: &TypeRef) -> String {
    match ty {
        TypeRef::Scalar(s) => scalar_name(*s),
        TypeRef::Named(n) => n.clone(),
    }
}

fn fmt_expr(e: &Expr) -> String {
    match e {
        Expr::Int(n) => n.to_string(),
        Expr::Ident(s) => s.clone(),
        Expr::Unary(op, x) => {
            let s = match op {
                UnOp::Neg => "-",
                UnOp::Not => "!",
                UnOp::BitNot => "~",
            };
            format!("{s}{}", fmt_expr(x))
        }
        Expr::Bin(op, a, b) => {
            let s = match op {
                BinOp::Add => "+",
                BinOp::Sub => "-",
                BinOp::Mul => "*",
                BinOp::Div => "/",
                BinOp::Mod => "%",
                BinOp::Eq => "==",
                BinOp::Ne => "!=",
                BinOp::Lt => "<",
                BinOp::Le => "<=",
                BinOp::Gt => ">",
                BinOp::Ge => ">=",
                BinOp::And => "&&",
                BinOp::Or => "||",
                BinOp::BAnd => "&",
                BinOp::BOr => "|",
                BinOp::BXor => "^",
                BinOp::Shl => "<<",
                BinOp::Shr => ">>",
            };
            format!("{} {s} {}", fmt_expr(a), fmt_expr(b))
        }
    }
}

fn describe_member(m: &Member, depth: usize, out: &mut Vec<String>) {
    let ind = "    ".repeat(depth);
    match m {
        Member::Field { name, ty, array } => {
            let arr = match array {
                Some(e) => format!("[{}]", fmt_expr(e)),
                None => String::new(),
            };
            out.push(format!("{ind}{} {name}{arr};", type_name(ty)));
        }
        Member::If { cond, then, els } => {
            out.push(format!("{ind}if ({}) {{", fmt_expr(cond)));
            for m in then {
                describe_member(m, depth + 1, out);
            }
            if els.is_empty() {
                out.push(format!("{ind}}}"));
            } else {
                out.push(format!("{ind}}} else {{"));
                for m in els {
                    describe_member(m, depth + 1, out);
                }
                out.push(format!("{ind}}}"));
            }
        }
    }
}

/// Read an unsigned integer of the rtype's width at `off` (overlay-aware).
fn read_uint(buf: &FileBuffer, off: u64, rt: RegionType) -> Option<u64> {
    use RegionType::*;
    let size = rt.fixed_size()? as usize;
    let b = buf.get_range(off, size);
    if b.len() < size {
        return None;
    }
    Some(match rt {
        U8 => b[0] as u64,
        U16Le => u16::from_le_bytes([b[0], b[1]]) as u64,
        U16Be => u16::from_be_bytes([b[0], b[1]]) as u64,
        U32Le => u32::from_le_bytes([b[0], b[1], b[2], b[3]]) as u64,
        U32Be => u32::from_be_bytes([b[0], b[1], b[2], b[3]]) as u64,
        U64Le => u64::from_le_bytes(b[..8].try_into().ok()?),
        U64Be => u64::from_be_bytes(b[..8].try_into().ok()?),
        _ => return None,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;

    fn fixture(bytes: &[u8], tag: &str) -> FileBuffer {
        let p = std::env::temp_dir().join(format!("bx-tpltest-{tag}-{}", std::process::id()));
        let mut f = std::fs::File::create(&p).unwrap();
        f.write_all(bytes).unwrap();
        FileBuffer::open(&p).unwrap()
    }

    fn expr(s: &str) -> i64 {
        let (toks, lines) = lex(s).unwrap();
        let e = Parser {
            toks,
            lines,
            pos: 0,
        }
        .parse_expr(0)
        .unwrap();
        eval(&e, &HashMap::new()).unwrap()
    }

    #[test]
    fn expression_precedence() {
        assert_eq!(expr("1 + 2 * 3"), 7);
        assert_eq!(expr("(1 + 2) * 3"), 9);
        assert_eq!(expr("0x10 + 0x0f"), 31);
        assert_eq!(expr("2 < 3"), 1);
        assert_eq!(expr("5 == 5 && 1 != 2"), 1);
        assert_eq!(expr("1 << 4 | 1"), 17);
        assert_eq!(expr("-3 + 10"), 7);
        assert_eq!(expr("7 % 3"), 1);
    }

    #[test]
    fn flat_struct_backward_compatible() {
        let tpl = parse("struct H { str magic[4]; u32le size; }").unwrap();
        // BX!! then size = 0x10
        let buf = fixture(&[0x42, 0x58, 0x21, 0x21, 0x10, 0, 0, 0], "flat");
        let (regions, warn) = tpl.apply("H", 0, &buf);
        assert!(warn.is_none(), "{warn:?}");
        assert_eq!(regions.len(), 2);
        assert_eq!(regions[0].label, "H.magic");
        assert_eq!((regions[0].start, regions[0].end), (0, 4));
        assert_eq!(regions[1].label, "H.size");
        assert_eq!((regions[1].start, regions[1].end), (4, 8));
    }

    #[test]
    fn dynamic_array_and_nested_struct() {
        let src = "
            struct Item { u16le id; u8 nlen; str name[nlen]; }
            struct Hdr { str magic[4]; u32le count; Item items[count]; }
        ";
        let tpl = parse(src).unwrap();
        let mut data = b"BXS!".to_vec();
        data.extend_from_slice(&2u32.to_le_bytes()); // count = 2
        data.extend_from_slice(&[0x01, 0x00, 0x02, b'h', b'i']); // id=1, nlen=2, "hi"
        data.extend_from_slice(&[0x02, 0x00, 0x03, b'a', b'b', b'c']); // id=2, nlen=3, "abc"
        let buf = fixture(&data, "dyn");
        let (r, warn) = tpl.apply("Hdr", 0, &buf);
        assert!(warn.is_none(), "{warn:?}");
        let labels: Vec<&str> = r.iter().map(|x| x.label.as_str()).collect();
        assert_eq!(
            labels,
            vec![
                "Hdr.magic",
                "Hdr.count",
                "Hdr.items[0].id",
                "Hdr.items[0].nlen",
                "Hdr.items[0].name",
                "Hdr.items[1].id",
                "Hdr.items[1].nlen",
                "Hdr.items[1].name",
            ]
        );
        // last field "abc" spans the final 3 bytes
        let last = r.last().unwrap();
        assert_eq!((last.start, last.end), (data.len() as u64 - 3, data.len() as u64));
    }

    #[test]
    fn enums_and_bitfields() {
        let src = "
            enum Kind : u8 { FILE = 1, DIR = 2 }
            bitfield Flags : u8 { lo : 4, hi : 4 }
            struct S { Kind k; Flags f; }
        ";
        let tpl = parse(src).unwrap();
        let buf = fixture(&[0x02, 0x12], "enum"); // k=DIR, f: lo=2 hi=1
        let (r, warn) = tpl.apply("S", 0, &buf);
        assert!(warn.is_none(), "{warn:?}");
        assert_eq!(r[0].note.as_deref(), Some("DIR"));
        assert_eq!(r[1].note.as_deref(), Some("lo=2 hi=1"));
    }

    #[test]
    fn conditional_fields() {
        let src = "struct S { u8 flag; if (flag == 1) { u16le a; } else { u8 b; } }";
        let tpl = parse(src).unwrap();

        let buf1 = fixture(&[0x01, 0x34, 0x12], "if1");
        let (r1, _) = tpl.apply("S", 0, &buf1);
        assert_eq!(r1.len(), 2);
        assert_eq!(r1[1].label, "S.a");
        assert_eq!((r1[1].start, r1[1].end), (1, 3));

        let buf0 = fixture(&[0x00, 0x05], "if0");
        let (r0, _) = tpl.apply("S", 0, &buf0);
        assert_eq!(r0[1].label, "S.b");
        assert_eq!((r0[1].start, r0[1].end), (1, 2));
    }

    #[test]
    fn overrun_warns_but_returns_partial() {
        let tpl = parse("struct S { u32le a; u32le b; }").unwrap();
        let buf = fixture(&[1, 0, 0, 0, 2, 0], "short"); // only 6 bytes
        let (r, warn) = tpl.apply("S", 0, &buf);
        assert_eq!(r.len(), 1); // a fit, b overran
        assert!(warn.unwrap().contains("end of file"));
    }

    #[test]
    fn parse_errors() {
        assert!(parse("struct").is_err());
        assert!(parse("struct S { str s; }").is_err()); // str needs a length
        assert!(parse("enum E : str { A = 0 }").is_err()); // non-int base
        assert!(parse("garbage").is_err());
        // unknown type names parse fine (resolved at apply), so this is Ok:
        assert!(parse("struct S { Foo x; }").is_ok());
    }

    #[test]
    fn errors_carry_line_numbers() {
        // bad char on line 3 (block comment on line 1 keeps the count honest)
        let src = "/* hdr */\nstruct S {\n  u8 @;\n}";
        let err = parse(src).unwrap_err();
        assert!(err.contains("line 3"), "{err}");

        // missing ';' reported at the next token's line
        let err = parse("struct S {\n  u8 a\n}").unwrap_err();
        assert!(err.starts_with("line "), "{err}");
    }
}
