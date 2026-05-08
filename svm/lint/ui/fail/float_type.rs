// Rejects f32 and f64 in type positions.
struct FeeRate {
    rate: f64, //~ ERROR `f64` type is forbidden in Sophis contracts
}

fn compute(x: f32) -> f64 { //~ ERROR `f32` type is forbidden
                             //~| ERROR `f64` type is forbidden
    x as f64 //~ ERROR `f64` type is forbidden
}

fn main() {}
