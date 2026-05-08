use proc_macro::TokenStream;
use proc_macro2::TokenStream as TokenStream2;
use quote::quote;
use syn::{BinOp, Expr, ItemFn, Lit, Type, parse_macro_input, visit::Visit};

/// Marks the contract entry point and generates the `validate() -> i32` WASM export.
///
/// The annotated function must accept [`sophis_sdk::Env`] by value and return `bool`.
/// Returning `true` approves the transaction; `false` rejects it.
///
/// # Compile-time safety checks
///
/// The macro rejects:
/// - `unsafe` blocks and `unsafe fn` declarations
/// - Float types (`f32`, `f64`) and float literals
/// - Unchecked arithmetic (`+`, `-`, `*`, `/`, `%`); use `checked_add` etc. instead
///
/// # Example
///
/// ```ignore
/// use sophis_sdk::prelude::*;
///
/// #[sophis_contract]
/// pub fn my_contract(env: Env) -> bool {
///     let height = env.block_height();
///     height.checked_sub(1000).map_or(false, |_| true)
/// }
/// ```
///
/// The macro renames the user function to `__sophis_inner_<name>` and generates:
///
/// ```ignore
/// #[no_mangle]
/// pub extern "C" fn validate() -> i32 { ... }
/// ```
#[proc_macro_attribute]
pub fn sophis_contract(_attr: TokenStream, item: TokenStream) -> TokenStream {
    let input = parse_macro_input!(item as ItemFn);

    // --- compile-time safety enforcement ---
    let mut checker = ContractChecker::new();

    // Check the outer function signature for `unsafe fn`.
    if let Some(unsafety) = &input.sig.unsafety {
        checker
            .errors
            .push(syn::Error::new_spanned(unsafety, "`unsafe fn` is forbidden in #[sophis_contract]; make this function safe"));
    }

    // Walk the entire function body.
    checker.visit_block(&input.block);

    if !checker.errors.is_empty() {
        let compile_errors: TokenStream2 = checker.errors.iter().map(syn::Error::to_compile_error).collect();
        return compile_errors.into();
    }

    // --- code generation ---
    let attrs = &input.attrs;
    let vis = &input.vis;
    let block = &input.block;
    let orig_sig = &input.sig;
    let fn_name = &orig_sig.ident;

    let inner_ident = syn::Ident::new(&format!("__sophis_inner_{fn_name}"), fn_name.span());
    let inner_sig = syn::Signature { ident: inner_ident.clone(), ..orig_sig.clone() };

    quote! {
        #(#attrs)*
        #[doc(hidden)]
        #vis #inner_sig #block

        // Rust 2024: #[no_mangle] is an unsafe attribute and must be written as
        // #[unsafe(no_mangle)] to acknowledge the link-name aliasing risk.
        #[unsafe(no_mangle)]
        pub extern "C" fn validate() -> i32 {
            let env = ::sophis_sdk::Env::new();
            if #inner_ident(env) { 1 } else { 0 }
        }
    }
    .into()
}

// ---------------------------------------------------------------------------
// AST visitor — catches forbidden patterns at compile time
// ---------------------------------------------------------------------------

struct ContractChecker {
    errors: Vec<syn::Error>,
}

impl ContractChecker {
    fn new() -> Self {
        Self { errors: Vec::new() }
    }
}

impl<'ast> Visit<'ast> for ContractChecker {
    // Reject unsafe blocks.
    fn visit_expr_unsafe(&mut self, node: &'ast syn::ExprUnsafe) {
        self.errors.push(syn::Error::new_spanned(
            node,
            "`unsafe` blocks are forbidden in #[sophis_contract]; all contract code must be verifiably safe",
        ));
        syn::visit::visit_expr_unsafe(self, node);
    }

    // Reject unsafe fn declared inside the contract.
    fn visit_item_fn(&mut self, node: &'ast ItemFn) {
        if let Some(unsafety) = &node.sig.unsafety {
            self.errors.push(syn::Error::new_spanned(unsafety, "`unsafe fn` is forbidden inside #[sophis_contract]"));
        }
        syn::visit::visit_item_fn(self, node);
    }

    // Reject float literals and unchecked arithmetic operators.
    fn visit_expr(&mut self, node: &'ast Expr) {
        match node {
            Expr::Lit(l) => {
                if let Lit::Float(f) = &l.lit {
                    self.errors.push(syn::Error::new_spanned(
                        f,
                        "float literals are forbidden in #[sophis_contract]; \
                         use integer arithmetic with fixed-point scaling \
                         (e.g., 1 unit = 1/10_000 for basis-point precision)",
                    ));
                }
            }
            Expr::Binary(b) => {
                if let Some(method) = arith_method(&b.op) {
                    self.errors.push(syn::Error::new_spanned(
                        b.op,
                        format!(
                            "unchecked arithmetic is forbidden in #[sophis_contract]; \
                             use `.{method}()` and handle the `None` overflow case explicitly"
                        ),
                    ));
                }
            }
            _ => {}
        }
        syn::visit::visit_expr(self, node);
    }

    // Reject float types (f32, f64) in any type position.
    fn visit_type(&mut self, node: &'ast Type) {
        if let Type::Path(tp) = node
            && let Some(seg) = tp.path.segments.last()
        {
            let name = seg.ident.to_string();
            if name == "f32" || name == "f64" {
                self.errors.push(syn::Error::new_spanned(
                    &seg.ident,
                    format!(
                        "`{name}` is forbidden in #[sophis_contract]; \
                         use `u64`/`u128` with basis-point scaling — \
                         IEEE 754 floats are non-deterministic across platforms"
                    ),
                ));
            }
        }
        syn::visit::visit_type(self, node);
    }
}

/// Returns the `checked_*` method name for arithmetic operators that can overflow,
/// or `None` for operators that are safe from overflow (comparisons, bitwise, etc.).
fn arith_method(op: &BinOp) -> Option<&'static str> {
    match op {
        BinOp::Add(_) | BinOp::AddAssign(_) => Some("checked_add"),
        BinOp::Sub(_) | BinOp::SubAssign(_) => Some("checked_sub"),
        BinOp::Mul(_) | BinOp::MulAssign(_) => Some("checked_mul"),
        BinOp::Div(_) | BinOp::DivAssign(_) => Some("checked_div"),
        BinOp::Rem(_) | BinOp::RemAssign(_) => Some("checked_rem"),
        _ => None,
    }
}
