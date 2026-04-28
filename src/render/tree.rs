use serde::Serialize;

#[derive(Debug, Serialize)]
pub struct TreeNode {
    pub label: String,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub children: Vec<TreeNode>,
}

pub fn render_tree(root: &TreeNode) -> String {
    let mut out = format!("  {}\n", root.label);
    for (i, child) in root.children.iter().enumerate() {
        let last = i == root.children.len() - 1;
        out.push_str(&render_branch(child, "  ", last));
    }
    out
}

fn render_branch(node: &TreeNode, prefix: &str, is_last: bool) -> String {
    let mut out = String::new();
    let connector = if is_last { "└─ " } else { "├─ " };
    out.push_str(&format!("{}{}{}\n", prefix, connector, node.label));
    for (i, child) in node.children.iter().enumerate() {
        let last = i == node.children.len() - 1;
        let child_prefix = if is_last {
            format!("{}  ", prefix)
        } else {
            format!("{}│   ", prefix)
        };
        out.push_str(&render_branch(child, &child_prefix, last));
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    fn leaf(label: &str) -> TreeNode {
        TreeNode {
            label: label.to_string(),
            children: vec![],
        }
    }

    fn branch(label: &str, children: Vec<TreeNode>) -> TreeNode {
        TreeNode {
            label: label.to_string(),
            children,
        }
    }

    #[test]
    fn test_render_single_node() {
        let root = leaf("nginx (1234)");
        let out = render_tree(&root);
        assert_eq!(out, "  nginx (1234)\n");
    }

    #[test]
    fn test_render_linear_chain() {
        let root = branch(
            "launchd (1)",
            vec![branch("sshd (50)", vec![leaf("nginx (999) ←")])],
        );
        let out = render_tree(&root);
        assert_eq!(out, "  launchd (1)\n  └─ sshd (50)\n    └─ nginx (999) ←\n");
    }

    #[test]
    fn test_render_branched_tree() {
        let root = branch(
            "nginx (1)",
            vec![
                branch("worker (2)", vec![leaf("thread (5)")]),
                leaf("worker (3)"),
                leaf("worker (4)"),
            ],
        );
        let out = render_tree(&root);
        let expected = concat!(
            "  nginx (1)\n",
            "  ├─ worker (2)\n",
            "  │   └─ thread (5)\n",
            "  ├─ worker (3)\n",
            "  └─ worker (4)\n",
        );
        assert_eq!(out, expected);
    }
}
