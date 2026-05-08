// Rejects unchecked integer arithmetic operators.
fn transfer(balance: u64, amount: u64, fee: u64) -> u64 {
    let total = amount + fee; //~ ERROR unchecked integer arithmetic in Sophis contract
    balance - total           //~ ERROR unchecked integer arithmetic in Sophis contract
}

fn compound_assign(mut x: u64) {
    x += 1; //~ ERROR unchecked integer arithmetic in Sophis contract
    x *= 2; //~ ERROR unchecked integer arithmetic in Sophis contract
    let _ = x;
}

fn main() {}
