//! File buffer: read-only mmap with a sparse overwrite overlay and undo/redo.
//!
//! The underlying file is never modified until an explicit write. Edits are
//! overwrite-only (no insert/delete) so offsets stay stable for annotations.

use std::collections::BTreeMap;
use std::fs::File;
use std::io::Write as _;
use std::path::{Path, PathBuf};

use memmap2::Mmap;

/// One byte overwritten at an offset.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct EditOp {
    pub offset: u64,
    pub old: u8,
    pub new: u8,
}

/// A group of edits applied/undone atomically (e.g. one visual-mode fill).
type EditGroup = Vec<EditOp>;

pub struct FileBuffer {
    pub path: PathBuf,
    mmap: Option<Mmap>, // None only for zero-length files (cannot mmap empty)
    overlay: BTreeMap<u64, u8>,
    undo_stack: Vec<EditGroup>,
    redo_stack: Vec<EditGroup>,
    /// Edits not grouped yet (open group while in an edit mode).
    pending_group: EditGroup,
}

impl FileBuffer {
    pub fn open(path: &Path) -> std::io::Result<Self> {
        let file = File::open(path)?;
        let len = file.metadata()?.len();
        let mmap = if len == 0 {
            None
        } else {
            // SAFETY: the file is opened read-only and bxx never resizes it
            // while mapped. (Concurrent external truncation by another process
            // could still raise SIGBUS — an inherent mmap limitation, noted in
            // the README's Security section; it is not exploitable for UB.)
            Some(unsafe { Mmap::map(&file)? })
        };
        Ok(Self {
            path: path.to_path_buf(),
            mmap,
            overlay: BTreeMap::new(),
            undo_stack: Vec::new(),
            redo_stack: Vec::new(),
            pending_group: Vec::new(),
        })
    }

    pub fn len(&self) -> u64 {
        self.mmap.as_ref().map_or(0, |m| m.len() as u64)
    }

    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    /// The pristine on-disk bytes (no overlay). Empty slice for empty files.
    pub fn raw(&self) -> &[u8] {
        self.mmap.as_ref().map_or(&[], |m| &m[..])
    }

    /// Byte at `offset` with overlay applied.
    pub fn get(&self, offset: u64) -> Option<u8> {
        if offset >= self.len() {
            return None;
        }
        Some(match self.overlay.get(&offset) {
            Some(&b) => b,
            None => self.raw()[offset as usize],
        })
    }

    /// Copy of `[start, start+len)` with overlay applied, clamped to file end.
    pub fn get_range(&self, start: u64, len: usize) -> Vec<u8> {
        let file_len = self.len();
        if start >= file_len {
            return Vec::new();
        }
        let end = (start + len as u64).min(file_len);
        let mut out = self.raw()[start as usize..end as usize].to_vec();
        for (&off, &b) in self.overlay.range(start..end) {
            out[(off - start) as usize] = b;
        }
        out
    }

    pub fn is_modified_at(&self, offset: u64) -> bool {
        self.overlay.contains_key(&offset)
    }

    pub fn has_unsaved_changes(&self) -> bool {
        !self.overlay.is_empty() || !self.pending_group.is_empty()
    }

    /// Overwrite one byte. Edits accumulate into the pending group until
    /// `commit_group` is called.
    pub fn set(&mut self, offset: u64, new: u8) {
        let Some(old) = self.get(offset) else { return };
        if old == new {
            return;
        }
        self.pending_group.push(EditOp { offset, old, new });
        self.apply_byte(offset, new);
        self.redo_stack.clear();
    }

    fn apply_byte(&mut self, offset: u64, b: u8) {
        if self.raw().get(offset as usize) == Some(&b) {
            self.overlay.remove(&offset);
        } else {
            self.overlay.insert(offset, b);
        }
    }

    /// Close the pending edit group so it undoes as one unit.
    pub fn commit_group(&mut self) {
        if !self.pending_group.is_empty() {
            let group = std::mem::take(&mut self.pending_group);
            self.undo_stack.push(group);
        }
    }

    /// Undo the most recent group. Returns the offset of the first reverted
    /// byte so the caller can move the cursor there.
    pub fn undo(&mut self) -> Option<u64> {
        self.commit_group();
        let group = self.undo_stack.pop()?;
        for op in group.iter().rev() {
            self.apply_byte(op.offset, op.old);
        }
        let first = group.first().map(|op| op.offset);
        self.redo_stack.push(group);
        first
    }

    pub fn redo(&mut self) -> Option<u64> {
        self.commit_group();
        let group = self.redo_stack.pop()?;
        for op in group.iter() {
            self.apply_byte(op.offset, op.new);
        }
        let first = group.first().map(|op| op.offset);
        self.undo_stack.push(group);
        first
    }

    /// Discard all edits (`:q!` support).
    pub fn discard_edits(&mut self) {
        self.overlay.clear();
        self.pending_group.clear();
        self.undo_stack.clear();
        self.redo_stack.clear();
    }

    /// Write the patched contents. With `target = None`, patches the original
    /// file in place; otherwise writes a full copy to `target`.
    pub fn save(&mut self, target: Option<&Path>) -> std::io::Result<PathBuf> {
        self.commit_group();
        match target {
            Some(out) => {
                let mut f = File::create(out)?;
                // Stream in chunks so huge files don't need a full copy in RAM.
                const CHUNK: usize = 4 << 20;
                let mut off = 0u64;
                while off < self.len() {
                    let buf = self.get_range(off, CHUNK);
                    f.write_all(&buf)?;
                    off += buf.len() as u64;
                }
                Ok(out.to_path_buf())
            }
            None => {
                use std::fs::OpenOptions;
                use std::io::{Seek, SeekFrom};
                let mut f = OpenOptions::new().write(true).open(&self.path)?;
                for (&off, &b) in &self.overlay {
                    f.seek(SeekFrom::Start(off))?;
                    f.write_all(&[b])?;
                }
                f.flush()?;
                drop(f);
                // Remap so raw() reflects what's on disk, then the overlay is empty.
                let file = File::open(&self.path)?;
                if !self.is_empty() {
                    // SAFETY: same invariant as in `open` — read-only mapping,
                    // not resized by bxx while mapped.
                    self.mmap = Some(unsafe { Mmap::map(&file)? });
                }
                self.overlay.clear();
                Ok(self.path.clone())
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;

    fn fixture(bytes: &[u8], tag: &str) -> FileBuffer {
        let mut tmp = std::env::temp_dir();
        tmp.push(format!("bx-buftest-{tag}-{}", std::process::id()));
        let mut f = File::create(&tmp).unwrap();
        f.write_all(bytes).unwrap();
        FileBuffer::open(&tmp).unwrap()
    }

    #[test]
    fn overlay_and_range() {
        let mut b = fixture(&[0, 1, 2, 3, 4, 5, 6, 7], "range");
        b.set(2, 0xAA);
        b.set(5, 0xBB);
        assert_eq!(b.get(2), Some(0xAA));
        assert_eq!(b.get_range(0, 8), vec![0, 1, 0xAA, 3, 4, 0xBB, 6, 7]);
        assert_eq!(b.get_range(6, 100), vec![6, 7]); // clamped
        assert!(b.is_modified_at(2));
        assert!(!b.is_modified_at(3));
    }

    #[test]
    fn undo_redo_groups() {
        let mut b = fixture(&[0u8; 4], "undo");
        b.set(0, 1);
        b.set(1, 2);
        b.commit_group();
        b.set(2, 3);
        b.commit_group();
        assert_eq!(b.get_range(0, 4), vec![1, 2, 3, 0]);
        assert_eq!(b.undo(), Some(2));
        assert_eq!(b.get_range(0, 4), vec![1, 2, 0, 0]);
        assert_eq!(b.undo(), Some(0));
        assert_eq!(b.get_range(0, 4), vec![0, 0, 0, 0]);
        assert!(!b.has_unsaved_changes());
        assert_eq!(b.redo(), Some(0));
        assert_eq!(b.get_range(0, 4), vec![1, 2, 0, 0]);
        b.set(3, 9); // new edit clears redo
        assert_eq!(b.redo(), None);
    }

    #[test]
    fn setting_back_to_original_clears_overlay() {
        let mut b = fixture(&[7u8; 2], "revert");
        b.set(0, 1);
        b.set(0, 7);
        b.commit_group();
        assert!(!b.overlay.contains_key(&0));
    }
}
