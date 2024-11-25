use risc0_zkvm::guest::env;
use rz_ecvrf::{verify, R0ECVRF};

fn main() {
    // TODO: Implement your guest code here

    // read the input
    let input: Vec<u8> = env::read();
    let proof = R0ECVRF::deserialize(&input);

    // TODO: do something with the input
    let result: bool = verify(&proof);

    // write public output to the journal
    env::commit(&result);
}
