//! Attack tree construction, path evaluation, and visual traversal (REQ-F04, Autonomous Research Specification).
//!
//! Directly implements the formal attack tree taxonomy from `attack-tree-construction`:
//! hierarchical AND/OR goal decomposition, atomic leaf attack steps, difficulty & cost aggregation,
//! detection risk scoring, and Mermaid diagram export.

use serde::{Deserialize, Serialize};

/// Type of node in an attack tree hierarchy.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum NodeType {
    /// Any child branch achieves the node's objective (disjunction).
    Or,
    /// All child branches are required to achieve the objective (conjunction).
    And,
    /// Atomic, indivisible attack step.
    Leaf,
}

/// Skill and expertise required to execute an attack step.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AttackDifficulty {
    /// Trivial exploit execution (automated script or default credential).
    Trivial = 1,
    /// Low difficulty (standard tooling without customization).
    Low = 2,
    /// Medium difficulty (tailored payload or minor vulnerability chaining).
    Medium = 3,
    /// High difficulty (deep system knowledge or multi-stage bypass).
    High = 4,
    /// Expert level (novel zero-day or complex protocol circumvention).
    Expert = 5,
}

impl AttackDifficulty {
    /// Explicit numeric score from 1 to 5.
    pub const fn score(&self) -> u32 {
        *self as u32
    }
}

/// Monetary or resource cost tier required for execution.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CostTier {
    /// Negligible or zero cost.
    Free = 0,
    /// Low financial investment (< $100).
    Low = 1,
    /// Moderate financial investment ($100 - $1,000).
    Medium = 2,
    /// Substantial investment ($1,000 - $10,000).
    High = 3,
    /// Commercial or state-level budget (> $10,000).
    VeryHigh = 4,
}

impl CostTier {
    /// Explicit numeric rank.
    pub const fn score(&self) -> u32 {
        *self as u32
    }
}

/// Likelihood of attack detection by defensive telemetry and monitoring.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum DetectionRisk {
    /// Completely silent; no standard logging triggers.
    None = 0,
    /// Low detection probability.
    Low = 1,
    /// Medium probability (standard heuristic or audit alert).
    Medium = 2,
    /// High probability (deterministic alert in SIEM/IDS).
    High = 3,
    /// Certain detection (failsafe trigger or immediate alarm).
    Certain = 4,
}

/// Quantitative and operational attributes assigned to an attack node.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct AttackAttributes {
    /// Assessed difficulty tier.
    pub difficulty: AttackDifficulty,
    /// Financial/infrastructure cost tier.
    pub cost: CostTier,
    /// Likelihood of defensive detection.
    pub detection_risk: DetectionRisk,
    /// Estimated time in hours to execute the attack step.
    pub time_hours: f64,
    /// Whether insider access or privileged credentials are required.
    pub requires_insider: bool,
    /// Whether physical hardware or data center access is required.
    pub requires_physical: bool,
}

impl Default for AttackAttributes {
    fn default() -> Self {
        Self {
            difficulty: AttackDifficulty::Medium,
            cost: CostTier::Medium,
            detection_risk: DetectionRisk::Medium,
            time_hours: 8.0,
            requires_insider: false,
            requires_physical: false,
        }
    }
}

/// A node in an attack tree representing a root goal, sub-goal, or atomic attack step.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct AttackNode {
    /// Unique node identifier (e.g. `root`, `sub_1`, `leaf_exploit_cwe78`).
    pub id: String,
    /// Concise human-readable name.
    pub name: String,
    /// Detailed description of the attack scenario.
    pub description: String,
    /// Logical aggregation type (Or, And, Leaf).
    pub node_type: NodeType,
    /// Quantitative attributes.
    pub attributes: AttackAttributes,
    /// Subordinate child attack branches.
    pub children: Vec<AttackNode>,
    /// Documented defensive mitigations or compensating controls.
    pub mitigations: Vec<String>,
    /// Associated CVE or CWE identifiers.
    pub cve_refs: Vec<String>,
}

impl AttackNode {
    /// Creates a new atomic leaf attack node.
    pub fn new_leaf(
        id: impl Into<String>,
        name: impl Into<String>,
        description: impl Into<String>,
        attributes: AttackAttributes,
    ) -> Self {
        Self {
            id: id.into(),
            name: name.into(),
            description: description.into(),
            node_type: NodeType::Leaf,
            attributes,
            children: Vec::new(),
            mitigations: Vec::new(),
            cve_refs: Vec::new(),
        }
    }

    /// Creates an OR combination node (any child satisfies the goal).
    pub fn new_or(
        id: impl Into<String>,
        name: impl Into<String>,
        description: impl Into<String>,
    ) -> Self {
        Self {
            id: id.into(),
            name: name.into(),
            description: description.into(),
            node_type: NodeType::Or,
            attributes: AttackAttributes::default(),
            children: Vec::new(),
            mitigations: Vec::new(),
            cve_refs: Vec::new(),
        }
    }

    /// Creates an AND combination node (all children required to satisfy the goal).
    pub fn new_and(
        id: impl Into<String>,
        name: impl Into<String>,
        description: impl Into<String>,
    ) -> Self {
        Self {
            id: id.into(),
            name: name.into(),
            description: description.into(),
            node_type: NodeType::And,
            attributes: AttackAttributes::default(),
            children: Vec::new(),
            mitigations: Vec::new(),
            cve_refs: Vec::new(),
        }
    }

    /// Appends a child attack node.
    pub fn add_child(&mut self, child: AttackNode) {
        self.children.push(child);
    }

    /// Appends a mitigation to this node.
    pub fn with_mitigation(mut self, mitigation: impl Into<String>) -> Self {
        self.mitigations.push(mitigation.into());
        self
    }

    /// Appends a CVE/CWE reference.
    pub fn with_cve(mut self, cve: impl Into<String>) -> Self {
        self.cve_refs.push(cve.into());
        self
    }

    /// Computes the aggregate path difficulty for this branch.
    ///
    /// For an OR node, an adversary chooses the easiest path (`min(children)`).
    /// For an AND node, the adversary must overcome the hardest required step (`max(children)`).
    pub fn calculate_path_difficulty(&self) -> u32 {
        if self.node_type == NodeType::Leaf || self.children.is_empty() {
            return self.attributes.difficulty.score();
        }

        let child_difficulties: Vec<u32> = self
            .children
            .iter()
            .map(|c| c.calculate_path_difficulty())
            .collect();

        match self.node_type {
            NodeType::Or => child_difficulties.into_iter().min().unwrap_or(0),
            NodeType::And => child_difficulties.into_iter().max().unwrap_or(0),
            NodeType::Leaf => self.attributes.difficulty.score(),
        }
    }

    /// Computes the aggregate resource cost for this branch.
    ///
    /// For an OR node, adversary picks the cheapest path (`min(children)`).
    /// For an AND node, costs accumulate across all required steps (`sum(children)`).
    pub fn calculate_path_cost(&self) -> u32 {
        if self.node_type == NodeType::Leaf || self.children.is_empty() {
            return self.attributes.cost.score();
        }

        let child_costs: Vec<u32> = self
            .children
            .iter()
            .map(|c| c.calculate_path_cost())
            .collect();

        match self.node_type {
            NodeType::Or => child_costs.into_iter().min().unwrap_or(0),
            NodeType::And => child_costs.into_iter().sum(),
            NodeType::Leaf => self.attributes.cost.score(),
        }
    }

    /// Exports the attack tree to a formatted Mermaid flowchart string.
    pub fn to_mermaid_flowchart(&self) -> String {
        let mut lines = Vec::new();
        lines.push("flowchart TD".to_string());
        self.render_mermaid_lines(&mut lines);
        lines.join("\n")
    }

    fn render_mermaid_lines(&self, lines: &mut Vec<String>) {
        let node_repr = match self.node_type {
            NodeType::Or => format!("    {}([\"{} (OR)\"])", self.id, self.name),
            NodeType::And => format!("    {}[[\"{} (AND)\"]]", self.id, self.name),
            NodeType::Leaf => format!("    {}[\"{}\"]", self.id, self.name),
        };
        lines.push(node_repr);

        for child in &self.children {
            lines.push(format!("    {} --> {}", self.id, child.id));
            child.render_mermaid_lines(lines);
        }
    }
}
