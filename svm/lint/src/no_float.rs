use rustc_ast::{Expr, ExprKind, LitKind, Ty, TyKind};
use rustc_lint::{EarlyContext, EarlyLintPass, LintContext};
use rustc_session::{declare_lint, declare_lint_pass};

declare_lint! {
    /// Float types and literals are non-deterministic across CPU architectures and
    /// therefore forbidden in any Sophis contract.  Use `u64`/`u128` with an explicit
    /// basis-point scale (e.g. 10_000 = 100%).
    pub SOPHIS_NO_FLOAT,
    Deny,
    "float types and float literals are forbidden in Sophis smart contracts"
}

declare_lint_pass!(NoFloat => [SOPHIS_NO_FLOAT]);

impl EarlyLintPass for NoFloat {
    fn check_expr(&mut self, cx: &EarlyContext<'_>, expr: &Expr) {
        if let ExprKind::Lit(lit) = &expr.kind {
            if matches!(lit.kind, LitKind::Float(..)) {
                cx.span_lint(SOPHIS_NO_FLOAT, expr.span, |diag| {
                    diag.primary_message("float literal is forbidden in Sophis contracts")
                        .span_label(
                            expr.span,
                            "use integer arithmetic with fixed-point scaling instead",
                        )
                        .note(
                            "IEEE 754 floats are non-deterministic across platforms; \
                             contracts must produce identical results on every node",
                        )
                        .help("replace with `u64`/`u128` and a basis-point scale, e.g. `1_0000` = 100%");
                });
            }
        }
    }

    fn check_ty(&mut self, cx: &EarlyContext<'_>, ty: &Ty) {
        if let TyKind::Path(_, path) = &ty.kind {
            if let Some(seg) = path.segments.last() {
                let name = seg.ident.name.as_str();
                if name == "f32" || name == "f64" {
                    cx.span_lint(SOPHIS_NO_FLOAT, ty.span, |diag| {
                        diag.primary_message(format!(
                            "`{name}` type is forbidden in Sophis contracts"
                        ))
                        .span_label(ty.span, "replace with `u64` or `u128`")
                        .note(
                            "IEEE 754 floats are non-deterministic across CPU architectures; \
                             all contract arithmetic must be deterministic for consensus",
                        );
                    });
                }
            }
        }
    }
}

pub fn register(_sess: &rustc_session::Session, lint_store: &mut rustc_lint::LintStore) {
    lint_store.register_lints(&[SOPHIS_NO_FLOAT]);
    lint_store.register_early_pass(|| Box::new(NoFloat));
}
