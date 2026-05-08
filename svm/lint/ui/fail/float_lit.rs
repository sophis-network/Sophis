// Rejects float literals in contract code.
fn price_in_percent() -> u64 {
    let rate = 0.05_f64; //~ ERROR float literal is forbidden in Sophis contracts
    (rate * 1_000_000.0) as u64 //~ ERROR float literal is forbidden in Sophis contracts
                                //~| ERROR float literal is forbidden in Sophis contracts
}

fn main() {}
