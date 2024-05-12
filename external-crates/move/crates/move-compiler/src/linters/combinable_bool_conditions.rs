//! The `CombinableBool` detects and warns about boolean conditions in Move code that can be simplified.
//! It identifies comparisons that are logically equivalent and suggests more concise alternatives.
//! This rule focuses on simplifying expressions involving `==`, `<`, `>`, and `!=` operators to improve code readability.
use move_ir_types::location::Loc;

use crate::{
    diag,
    diagnostics::{
        codes::{custom, DiagnosticInfo, Severity},
        WarningFilters,
    },
    parser::ast::BinOp_,
    shared::{program_info::TypingProgramInfo, CompilationEnv},
    typing::{
        ast::{self as T, UnannotatedExp_},
        visitor::{TypingVisitorConstructor, TypingVisitorContext},
    },
};

use super::{LinterDiagCategory, LINTER_COMB_BOOL, LINT_WARNING_PREFIX};

const COMBINABLE_BOOL_COND_DIAG: DiagnosticInfo = custom(
    LINT_WARNING_PREFIX,
    Severity::Warning,
    LinterDiagCategory::Readability as u8,
    LINTER_COMB_BOOL,
    "",
);

pub struct CombinableBool;

pub struct Context<'a> {
    env: &'a mut CompilationEnv,
}

impl TypingVisitorConstructor for CombinableBool {
    type Context<'a> = Context<'a>;

    fn context<'a>(
        env: &'a mut CompilationEnv,
        _program_info: &'a TypingProgramInfo,
        _program: &T::Program_,
    ) -> Self::Context<'a> {
        Context { env }
    }
}

impl TypingVisitorContext for Context<'_> {
    fn visit_exp_custom(&mut self, exp: &mut T::Exp) -> bool {
        if let UnannotatedExp_::BinopExp(e1, op, _, e2) = &exp.exp.value {
            if let (
                UnannotatedExp_::BinopExp(lhs1, op1, _, rhs1),
                UnannotatedExp_::BinopExp(lhs2, op2, _, rhs2),
            ) = (&e1.exp.value, &e2.exp.value)
            {
                // Check both exp side are the same
                if lhs1 == lhs2 && rhs1 == rhs2 {
                    match (&op1.value, &op2.value) {
                        // Existing simplification cases
                        (BinOp_::Eq, BinOp_::Lt) | (BinOp_::Lt, BinOp_::Eq) => {
                            if op.value == BinOp_::And {
                                add_replaceable_comparison_diag(
                                    self.env,
                                    exp.exp.loc,
                                    "This is always contradictory and can be simplified to false",
                                );
                            } else {
                                add_replaceable_comparison_diag(
                                    self.env,
                                    exp.exp.loc,
                                    "Consider simplifying to `<=`.",
                                );
                            }
                        }
                        (BinOp_::Eq, BinOp_::Gt) | (BinOp_::Gt, BinOp_::Eq) => {
                            if op.value == BinOp_::And {
                                add_replaceable_comparison_diag(
                                    self.env,
                                    exp.exp.loc,
                                    "This is always contradictory and can be simplified to false",
                                );
                            } else {
                                add_replaceable_comparison_diag(
                                    self.env,
                                    exp.exp.loc,
                                    "Consider simplifying to `>=`.",
                                );
                            }
                        }
                        (BinOp_::Ge, BinOp_::Eq) | (BinOp_::Eq, BinOp_::Ge) => {
                            if op.value == BinOp_::And {
                                add_replaceable_comparison_diag(
                                    self.env,
                                    exp.exp.loc,
                                    "Consider simplifying to `==`.",
                                );
                            } else {
                                add_replaceable_comparison_diag(
                                    self.env,
                                    exp.exp.loc,
                                    "Consider simplifying to `>=`.",
                                );
                            }
                        }
                        (BinOp_::Le, BinOp_::Eq) | (BinOp_::Eq, BinOp_::Le) => {
                            if op.value == BinOp_::And {
                                add_replaceable_comparison_diag(
                                    self.env,
                                    exp.exp.loc,
                                    "Consider simplifying to `==`.",
                                );
                            } else {
                                add_replaceable_comparison_diag(
                                    self.env,
                                    exp.exp.loc,
                                    "Consider simplifying to `<=`.",
                                );
                            }
                        }
                        (BinOp_::Neq, BinOp_::Lt) | (BinOp_::Lt, BinOp_::Neq) => {
                            if op.value == BinOp_::And {
                                add_replaceable_comparison_diag(
                                    self.env,
                                    exp.exp.loc,
                                    "Consider simplifying to `<`.",
                                );
                            }
                        }
                        (BinOp_::Neq, BinOp_::Gt) | (BinOp_::Gt, BinOp_::Neq) => {
                            if op.value == BinOp_::And {
                                add_replaceable_comparison_diag(
                                    self.env,
                                    exp.exp.loc,
                                    "Consider simplifying to `>`.",
                                );
                            }
                        }
                        _ => {}
                    }
                }
            }
        }
        false
    }
    fn add_warning_filter_scope(&mut self, filter: WarningFilters) {
        self.env.add_warning_filter_scope(filter)
    }

    fn pop_warning_filter_scope(&mut self) {
        self.env.pop_warning_filter_scope()
    }
}

fn add_replaceable_comparison_diag(env: &mut CompilationEnv, loc: Loc, message: &str) {
    let d = diag!(COMBINABLE_BOOL_COND_DIAG, (loc, message));
    env.add_diag(d);
}
