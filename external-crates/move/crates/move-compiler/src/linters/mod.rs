// Copyright (c) The Move Contributors
// SPDX-License-Identifier: Apache-2.0

use move_symbol_pool::Symbol;

use crate::{
    command_line::compiler::Visitor, diagnostics::codes::WarningFilter,
    linters::redundant_conditional::RedundantConditional, typing::visitor::TypingVisitor,
};
pub mod redundant_conditional;
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LintLevel {
    // No linters
    None,
    // Run only the default linters
    Default,
    // Run all linters
    All,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum LinterDiagnosticCategory {
    Correctness,
    Complexity,
    Suspicious,
    Deprecated,
    Style,
    Sui = 99,
}

pub const ALLOW_ATTR_CATEGORY: &str = "lint";
pub const LINT_WARNING_PREFIX: &str = "Lint ";
pub const REDUNDANT_CONDITIONAL_FILTER_NAME: &str = "redundant_conditional";

pub const LINTER_DEFAULT_DIAG_CODE: u8 = 1;
pub const REDUNDANT_CONDITIONAL_DIAG_CODE: u8 = 2;
pub enum LinterDiagCategory {
    Readability,
}

pub fn known_filters() -> (Option<Symbol>, Vec<WarningFilter>) {
    (
        Some(ALLOW_ATTR_CATEGORY.into()),
        vec![WarningFilter::code(
            Some(LINT_WARNING_PREFIX),
            LinterDiagCategory::Readability as u8,
            REDUNDANT_CONDITIONAL_DIAG_CODE,
            Some(REDUNDANT_CONDITIONAL_FILTER_NAME),
        )],
    )
}

pub fn linter_visitors(level: LintLevel) -> Vec<Visitor> {
    match level {
        LintLevel::None => vec![],
        LintLevel::Default | LintLevel::All => {
            vec![redundant_conditional::RedundantConditional::visitor(
                RedundantConditional,
            )]
        }
    }
}
