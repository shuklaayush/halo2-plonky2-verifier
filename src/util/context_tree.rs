use log::{Level};

// TODO: Change name
// Ref: https://github.com/0xPolygonZero/plonky2/blob/7eff4e2751dea6ef67bd09b184599ff97f509ebf/plonky2/src/util/context_tree.rs

/// The hierarchy of contexts, and the cell count contributed by each one. Useful for debugging.
pub struct ContextTree {
    /// The name of this scope.
    name: String,
    /// The level at which to log this scope and its children.
    level: log::Level,
    /// The cell count when this scope was created.
    enter_cell_count: usize,
    /// The cell count when this scope was destroyed, or None if it has not yet been destroyed.
    exit_cell_count: Option<usize>,
    /// Any child contexts.
    children: Vec<ContextTree>,
}

impl ContextTree {
    pub fn new() -> Self {
        Self {
            name: "root".to_string(),
            level: Level::Debug,
            enter_cell_count: 0,
            exit_cell_count: None,
            children: vec![],
        }
    }

    /// Whether this context is still in scope.
    const fn is_open(&self) -> bool {
        self.exit_cell_count.is_none()
    }

    /// A description of the stack of currently-open scopes.
    pub fn open_stack(&self) -> String {
        let mut stack = Vec::new();
        self.open_stack_helper(&mut stack);
        stack.join(" > ")
    }

    fn open_stack_helper(&self, stack: &mut Vec<String>) {
        if self.is_open() {
            stack.push(self.name.clone());
            if let Some(last_child) = self.children.last() {
                last_child.open_stack_helper(stack);
            }
        }
    }

    pub fn push(&mut self, ctx: &str, mut level: log::Level, current_cell_count: usize) {
        assert!(self.is_open());

        // We don't want a scope's log level to be stronger than that of its parent.
        level = level.max(self.level);

        if let Some(last_child) = self.children.last_mut() {
            if last_child.is_open() {
                last_child.push(ctx, level, current_cell_count);
                return;
            }
        }

        self.children.push(ContextTree {
            name: ctx.to_string(),
            level,
            enter_cell_count: current_cell_count,
            exit_cell_count: None,
            children: vec![],
        })
    }

    /// Close the deepest open context from this tree.
    pub fn pop(&mut self, current_cell_count: usize) {
        assert!(self.is_open());

        if let Some(last_child) = self.children.last_mut() {
            if last_child.is_open() {
                last_child.pop(current_cell_count);
                return;
            }
        }

        self.exit_cell_count = Some(current_cell_count);
    }

    fn cell_count_delta(&self, current_cell_count: usize) -> usize {
        self.exit_cell_count.unwrap_or(current_cell_count) - self.enter_cell_count
    }

    /// Filter out children with a low cell count.
    pub fn filter(&self, current_cell_count: usize, min_delta: usize) -> Self {
        Self {
            name: self.name.clone(),
            level: self.level,
            enter_cell_count: self.enter_cell_count,
            exit_cell_count: self.exit_cell_count,
            children: self
                .children
                .iter()
                .filter(|c| c.cell_count_delta(current_cell_count) >= min_delta)
                .map(|c| c.filter(current_cell_count, min_delta))
                .collect(),
        }
    }

    pub fn print(&self, current_cell_count: usize) {
        println!();
        self.print_helper(current_cell_count, 0);
    }

    fn print_helper(&self, current_cell_count: usize, depth: usize) {
        let prefix = "| ".repeat(depth);
        // TODO: Proper log levelling
        println!(
            // self.level,
            "{}{} cells for {}",
            prefix,
            self.cell_count_delta(current_cell_count),
            self.name
        );
        for child in &self.children {
            child.print_helper(current_cell_count, depth + 1);
        }
    }
}

/// Creates a named scope; useful for debugging.
#[macro_export]
macro_rules! count {
    ($ctx:expr, $level:expr, $label:expr, $exp:expr) => {{
        $ctx.push_context($level, $label);
        let res = $exp;
        $ctx.pop_context();
        res
    }};
    // If no context is specified, default to Debug.
    ($ctx:expr, $label:expr, $exp:expr) => {{
        $ctx.push_context(log::Level::Debug, $label);
        let res = $exp;
        $ctx.pop_context();
        res
    }};
}
