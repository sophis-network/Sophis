/// dylint UI tests — each file under `ui/fail/` must produce the expected diagnostics,
/// and each file under `ui/pass/` must compile without any lint errors.
#[test]
fn ui() {
    dylint_testing::ui_test(
        env!("CARGO_PKG_NAME"),
        &std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("ui"),
    );
}
