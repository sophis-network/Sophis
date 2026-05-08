/// Compile-error tests for the safety checks in `#[sophis_contract]`.
///
/// Each `compile_fail/` file must fail to compile with the expected error message.
/// Each `pass/` file must compile cleanly.
///
/// Run: `cargo test -p sophis-sdk-macros`
#[test]
fn contract_lint_compile_errors() {
    let t = trybuild::TestCases::new();
    // Must fail — forbidden patterns.
    t.compile_fail("tests/compile_fail/unsafe_block.rs");
    t.compile_fail("tests/compile_fail/unsafe_fn_decl.rs");
    t.compile_fail("tests/compile_fail/float_literal.rs");
    t.compile_fail("tests/compile_fail/float_type.rs");
    t.compile_fail("tests/compile_fail/unchecked_add.rs");
    t.compile_fail("tests/compile_fail/unchecked_sub.rs");
    t.compile_fail("tests/compile_fail/unchecked_mul.rs");
    // Must pass — clean contract.
    t.pass("tests/compile_fail/clean_contract.rs");
}
