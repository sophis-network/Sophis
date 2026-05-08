// Rejects unsafe fn declarations.
unsafe fn low_level_op(ptr: *const u8) -> u8 { //~ ERROR `unsafe fn` is forbidden in Sophis contracts
    *ptr
}

fn main() {}
