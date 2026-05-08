// Rejects unsafe blocks in contract code.
fn validate_contract() -> bool {
    let _result = unsafe { //~ ERROR `unsafe block` is forbidden in Sophis contracts
        std::mem::transmute::<u32, f32>(0x3f800000_u32)
    };
    true
}

fn main() {}
