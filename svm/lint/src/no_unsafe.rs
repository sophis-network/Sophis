use rustc_ast::{Block, BlockCheckMode, FnKind, Item, ItemKind, Safety, UnsafeSource};
use rustc_lint::{EarlyContext, EarlyLintPass, LintContext};
use rustc_session::{declare_lint, declare_lint_pass};
use rustc_span::Span;

declare_lint! {
    /// The sVM cannot verify the memory-safety properties of `unsafe` code.
    /// All contract logic must be expressible in safe Rust so the runtime can
    /// guarantee termination and absence of undefined behaviour.
    pub SOPHIS_NO_UNSAFE,
    Deny,
    "unsafe code is forbidden in Sophis smart contracts"
}

declare_lint_pass!(NoUnsafe => [SOPHIS_NO_UNSAFE]);

impl NoUnsafe {
    fn emit(cx: &EarlyContext<'_>, span: Span, what: &str) {
        cx.span_lint(SOPHIS_NO_UNSAFE, span, |diag| {
            diag.primary_message(format!("`{what}` is forbidden in Sophis contracts"))
                .span_label(span, "remove or rewrite without `unsafe`")
                .note(
                    "the sVM verifies contracts at deploy time; \
                     `unsafe` blocks cannot be statically verified and are therefore rejected",
                );
        });
    }
}

impl EarlyLintPass for NoUnsafe {
    fn check_block(&mut self, cx: &EarlyContext<'_>, block: &Block) {
        if matches!(block.rules, BlockCheckMode::Unsafe(UnsafeSource::UserProvided)) {
            Self::emit(cx, block.span, "unsafe block");
        }
    }

    fn check_fn(
        &mut self,
        cx: &EarlyContext<'_>,
        fn_kind: FnKind<'_>,
        span: Span,
        _id: rustc_ast::NodeId,
    ) {
        if let FnKind::Fn(_, _, _, _, Some(sig), _) = fn_kind {
            if matches!(sig.header.safety, Safety::Unsafe(_)) {
                Self::emit(cx, span, "unsafe fn");
            }
        }
    }

    fn check_item(&mut self, cx: &EarlyContext<'_>, item: &Item) {
        if let ItemKind::Impl(impl_item) = &item.kind {
            if matches!(impl_item.safety, Safety::Unsafe(_)) {
                Self::emit(cx, item.span, "unsafe impl");
            }
        }
    }
}

pub fn register(_sess: &rustc_session::Session, lint_store: &mut rustc_lint::LintStore) {
    lint_store.register_lints(&[SOPHIS_NO_UNSAFE]);
    lint_store.register_early_pass(|| Box::new(NoUnsafe));
}
