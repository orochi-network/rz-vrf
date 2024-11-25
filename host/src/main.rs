// These constants represent the RISC-V ELF and the image ID generated by risc0-build.
// The ELF is used for proving and the ID is used for verification.
use libecvrf::{curve::Scalar, extend::Randomize, KeyPair, ECVRF};
use methods::{RZ_VRF_ELF, RZ_VRF_ID};
use risc0_zkvm::{default_prover, ExecutorEnv};
use rz_ecvrf::{verify, R0ECVRF};

fn main() {
    let key_pair = KeyPair::new();
    let ecvrf = ECVRF::new(key_pair.secret_key);
    let alpha = Scalar::random();

    // Generate ECVRF Proof
    let proof = ecvrf.prove(&alpha).unwrap();

    let rz_ecvrf_proof = R0ECVRF {
        public_key: key_pair.public_key,
        gamma: proof.gamma,
        c: proof.c,
        s: proof.s,
        y: proof.y,
        alpha,
    };

    println!("ECVRF proof: {:#?}", rz_ecvrf_proof);

    // Verify the proof with tiny_ec
    println!("Verify proof out side guest: {:?}", verify(&rz_ecvrf_proof));

    // Initialize tracing. In order to view logs, run `RISC0_DEV_MODE=1 RUST_LOG=info cargo run --release`
    tracing_subscriber::fmt()
        .with_env_filter(tracing_subscriber::filter::EnvFilter::from_default_env())
        .init();

    // An executor environment describes the configurations for the zkVM
    // including program inputs.
    // An default ExecutorEnv can be created like so:
    // `let env = ExecutorEnv::builder().build().unwrap();`
    // However, this `env` does not have any inputs.
    //
    // To add guest input to the executor environment, use
    // ExecutorEnvBuilder::write().
    // To access this method, you'll need to use ExecutorEnv::builder(), which
    // creates an ExecutorEnvBuilder. When you're done adding input, call
    // ExecutorEnvBuilder::build().

    // Serialize ECVRF manually
    let input = rz_ecvrf_proof.serialize();

    let env = ExecutorEnv::builder()
        .write(&input)
        .unwrap()
        .build()
        .unwrap();

    // Obtain the default prover.
    let prover = default_prover();

    // Proof information by proving the specified ELF binary.
    // This struct contains the receipt along with statistics about execution of the guest
    let prove_info = prover.prove(env, RZ_VRF_ELF).unwrap();

    // extract the receipt.
    let receipt = prove_info.receipt;

    // Result from the guest:
    let output: bool = receipt.journal.decode().unwrap();

    println!("Proof successful! guest's output: {:?}", output);

    // The receipt was verified at the end of proving, but the below code is an
    // example of how someone else could verify this receipt.
    receipt.verify(RZ_VRF_ID).unwrap();
}