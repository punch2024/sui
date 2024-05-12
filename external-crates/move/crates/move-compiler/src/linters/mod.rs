// Copyright (c) The Move Contributors
// SPDX-License-Identifier: Apache-2.0

use move_symbol_pool::Symbol;

use crate::{
    command_line::compiler::Visitor, diagnostics::codes::WarningFilter,
    linters::abort_constant::AssertAbortNamedConstants, typing::visitor::TypingVisitor,
};
pub mod abort_constant;
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
pub const ABORT_CONSTANT_FILTER_NAME: &str = "shift_overflow";

pub const LINTER_DEFAULT_DIAG_CODE: u8 = 1;
pub const LINTER_ABORT_CONSTANT_DIAG_CODE: u8 = 5;
pub enum LinterDiagCategory {
    Style,
}

pub fn known_filters() -> (Option<Symbol>, Vec<WarningFilter>) {
    (
        Some(ALLOW_ATTR_CATEGORY.into()),
        vec![WarningFilter::code(
            Some(LINT_WARNING_PREFIX),
            LinterDiagCategory::Style as u8,
            LINTER_ABORT_CONSTANT_DIAG_CODE,
            Some(ABORT_CONSTANT_FILTER_NAME),
        )],
    )
}

pub fn linter_visitors(level: LintLevel) -> Vec<Visitor> {
    match level {
        LintLevel::None => vec![],
        LintLevel::Default | LintLevel::All => {
            vec![abort_constant::AssertAbortNamedConstants::visitor(
                AssertAbortNamedConstants,
            )]
        }
    }
}
