// run with RUSTFLAGS="-C target-cpu=native" cargo run --release
// edited from https://www.binius.xyz/building/example

use crate::lattice::lattice_circuit;
use crate::sha256::sha256_circuit;
use crate::blake2b::blake2b_circuit;

mod lattice;
mod sha256;
mod blake2b;
use rand::Rng;


// -------------------- main --------------------

fn main() -> Result<(), Box<dyn std::error::Error>> {
    // demo image vector
    let n = 1 << 20;
    let mut rng = rand::rng();
    let mut image = vec![0u8; n];
    rng.fill(&mut image[..]);
    println!("Starting proofs for image size: {}", n);
    //lattice_circuit(&image)?;
    //sha256_circuit(&image)?;
    blake2b_circuit(&image)?;
    Ok(())
}