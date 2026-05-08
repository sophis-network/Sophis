use rustc_hir::{BinOpKind, Expr, ExprKind};
use rustc_lint::{LateContext, LateLintPass, LintContext};
use rustc_middle::ty::TyKind;
use rustc_session::{declare_lint, declare_lint_pass};

declare_lint! {
    /// Integer overflow in a contract causes a panic in debug builds and silently
    /// wraps in release builds — both outcomes are consensus bugs.  Every arithmetic
    /// operation must use a `checked_*` / `saturating_*` method so the overflow case
    /// is handled explicitly.
    pub SOPHIS_NO_UNCHECKED_ARITH,
    Deny,
    "unchecked integer arithmetic is forbidden in Sophis contracts; use checked_add / checked_sub / checked_mul"
}

declare_lint_pass!(NoUncheckedArith => [SOPHIS_NO_UNCHECKED_ARITH]);

impl<'tcx> LateLintPass<'tcx> for NoUncheckedArith {
    fn check_expr(&mut self, cx: &LateContext<'tcx>, expr: &'tcx Expr<'tcx>) {
        let ExprKind::Binary(op, lhs, _rhs) = expr.kind else { return };

        let Some(method) = checked_method(op.node) else { return };

        // Only flag integer arithmetic — float arithmetic is caught by SOPHIS_NO_FLOAT.
        let lhs_ty = cx.typeck_results().expr_ty(lhs).peel_refs();
        if !matches!(lhs_ty.kind(), TyKind::Int(_) | TyKind::Uint(_)) {
            return;
        }

        cx.span_lint(SOPHIS_NO_UNCHECKED_ARITH, expr.span, |diag| {
            diag.primary_message("unchecked integer arithmetic in Sophis contract")
                .span_label(
                    op.span,
                    format!("use `.{method}()` and handle the `None` overflow case"),
                )
                .note(
                    "integer overflow panics in debug mode and wraps in release mode; \
                     either outcome is a consensus bug — always use checked arithmetic",
                )
                .help(format!(
                    "rewrite as `lhs.{method}(rhs).expect(\"overflow in contract\")`  \
                     or handle `None` with a fallback"
                ));
        });
    }
}

/// Maps an integer arithmetic operator to the corresponding `checked_*` method name.
/// Returns `None` for operators that cannot overflow (comparisons, bitwise ops, etc.).
fn checked_method(op: BinOpKind) -> Option<&'static str> {
    match op {
        BinOpKind::Add => Some("checked_add"),
        BinOpKind::Sub => Some("checked_sub"),
        BinOpKind::Mul => Some("checked_mul"),
        BinOpKind::Div => Some("checked_div"),
        BinOpKind::Rem => Some("checked_rem"),
        _ => None,
    }
}

pub fn register(_sess: &rustc_session::Session, lint_store: &mut rustc_lint::LintStore) {
    lint_store.register_lints(&[SOPHIS_NO_UNCHECKED_ARITH]);
    lint_store.register_late_pass(|_tcx| Box::new(NoUncheckedArith));
}
