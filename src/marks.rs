//! Turn flat annotation labels (`Elf64.phdrs[0].p_type`) into a collapsible
//! tree for the Marks side pane. Internal nodes (structs, arrays, array
//! elements) are synthesised from the label paths; leaves map to regions.

use std::collections::HashSet;

use crate::annotations::Region;

pub struct MarkNode {
    /// Last path segment, e.g. `phdrs`, `[0]`, `p_type`.
    pub name: String,
    /// Full path, used as the collapse-state key.
    pub path: String,
    /// Index into the annotation list, for leaves.
    pub region: Option<usize>,
    pub children: Vec<MarkNode>,
    pub start: u64,
    pub end: u64,
}

impl MarkNode {
    fn new(name: String, path: String) -> Self {
        MarkNode {
            name,
            path,
            region: None,
            children: Vec::new(),
            start: u64::MAX,
            end: 0,
        }
    }

    pub fn is_group(&self) -> bool {
        !self.children.is_empty()
    }

    fn is_array(&self) -> bool {
        !self.children.is_empty() && self.children.iter().all(|c| c.name.starts_with('['))
    }

    /// `[N]` for arrays, `{N}` for structs, empty for leaves.
    pub fn summary(&self) -> String {
        if self.is_array() {
            format!("[{}]", self.children.len())
        } else if self.is_group() {
            format!("{{{}}}", self.children.len())
        } else {
            String::new()
        }
    }
}

/// Split a label into path segments, breaking out array subscripts:
/// `phdrs[0].p_type` → `["phdrs", "[0]", "p_type"]`.
fn segments(label: &str) -> Vec<String> {
    let mut out = Vec::new();
    for part in label.split('.') {
        match part.find('[') {
            None => out.push(part.to_string()),
            Some(b) => {
                if b > 0 {
                    out.push(part[..b].to_string());
                }
                let mut rest = &part[b..];
                while let Some(end) = rest.find(']') {
                    out.push(rest[..=end].to_string());
                    rest = &rest[end + 1..];
                }
                if !rest.is_empty() {
                    out.push(rest.to_string());
                }
            }
        }
    }
    out
}

/// Build the forest. Returns owned nodes (no borrow of `annotations`).
pub fn build(annotations: &[Region]) -> Vec<MarkNode> {
    let mut roots: Vec<MarkNode> = Vec::new();
    for (i, r) in annotations.iter().enumerate() {
        let segs = segments(&r.label);
        if !segs.is_empty() {
            insert(&mut roots, &segs, 0, "", i, r.start, r.end);
        }
    }
    sort_nodes(&mut roots);
    roots
}

fn insert(
    level: &mut Vec<MarkNode>,
    segs: &[String],
    idx: usize,
    parent_path: &str,
    region: usize,
    start: u64,
    end: u64,
) {
    let name = &segs[idx];
    let path = if parent_path.is_empty() {
        name.clone()
    } else if name.starts_with('[') {
        format!("{parent_path}{name}")
    } else {
        format!("{parent_path}.{name}")
    };
    let pos = match level.iter().position(|n| n.name == *name) {
        Some(p) => p,
        None => {
            level.push(MarkNode::new(name.clone(), path));
            level.len() - 1
        }
    };
    let node = &mut level[pos];
    node.start = node.start.min(start);
    node.end = node.end.max(end);
    if idx + 1 == segs.len() {
        node.region = Some(region);
    } else {
        let np = node.path.clone();
        insert(&mut node.children, segs, idx + 1, &np, region, start, end);
    }
}

fn sort_nodes(nodes: &mut [MarkNode]) {
    nodes.sort_by_key(|n| n.start);
    for n in nodes.iter_mut() {
        sort_nodes(&mut n.children);
    }
}

/// Which fold to toggle for a cursor at `offset`: the shallowest collapsed
/// group on the path (to expand it), else the deepest group (to collapse it).
pub fn fold_target(forest: &[MarkNode], collapsed: &HashSet<String>, offset: u64) -> Option<String> {
    let mut chain: Vec<&MarkNode> = Vec::new();
    collect_chain(forest, offset, &mut chain);
    for n in &chain {
        if collapsed.contains(&n.path) {
            return Some(n.path.clone());
        }
    }
    chain.last().map(|n| n.path.clone())
}

fn collect_chain<'a>(level: &'a [MarkNode], offset: u64, chain: &mut Vec<&'a MarkNode>) {
    for n in level {
        if n.is_group() && offset >= n.start && offset < n.end {
            chain.push(n);
            collect_chain(&n.children, offset, chain);
            break;
        }
    }
}

/// All group paths at or below `min_depth` (0 includes roots).
pub fn group_paths(forest: &[MarkNode], min_depth: usize) -> Vec<String> {
    fn rec(level: &[MarkNode], depth: usize, min_depth: usize, out: &mut Vec<String>) {
        for n in level {
            if n.is_group() && depth >= min_depth {
                out.push(n.path.clone());
            }
            rec(&n.children, depth + 1, min_depth, out);
        }
    }
    let mut out = Vec::new();
    rec(forest, 0, min_depth, &mut out);
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::annotations::RegionType;

    fn region(label: &str, start: u64, end: u64) -> Region {
        Region {
            start,
            end,
            label: label.into(),
            rtype: RegionType::U8,
            note: None,
        }
    }

    #[test]
    fn builds_nested_tree() {
        let regs = vec![
            region("Hdr.magic", 0, 4),
            region("Hdr.items[0].id", 4, 6),
            region("Hdr.items[0].name", 6, 9),
            region("Hdr.items[1].id", 9, 11),
        ];
        let forest = build(&regs);
        assert_eq!(forest.len(), 1);
        let hdr = &forest[0];
        assert_eq!(hdr.name, "Hdr");
        assert!(hdr.is_group());
        // children: magic (leaf), items (array group)
        let items = hdr.children.iter().find(|c| c.name == "items").unwrap();
        assert!(items.is_array());
        assert_eq!(items.children.len(), 2);
        assert_eq!(items.children[0].name, "[0]");
        assert_eq!(items.children[0].children.len(), 2);
    }

    #[test]
    fn fold_target_picks_deepest_then_expands() {
        let regs = vec![
            region("Hdr.items[0].id", 4, 6),
            region("Hdr.items[0].name", 6, 9),
        ];
        let forest = build(&regs);
        let mut collapsed = HashSet::new();
        // nothing collapsed → toggling at offset 7 collapses the deepest group ([0])
        let t = fold_target(&forest, &collapsed, 7).unwrap();
        assert_eq!(t, "Hdr.items[0]");
        // once a shallower group is collapsed, it takes priority (to expand)
        collapsed.insert("Hdr.items".to_string());
        let t = fold_target(&forest, &collapsed, 7).unwrap();
        assert_eq!(t, "Hdr.items");
    }
}
