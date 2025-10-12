// run with RUSTFLAGS="-C target-cpu=native" cargo run --release
// edited from https://www.binius.xyz/building/example
use binius_circuits::sha256::Sha256;
use binius_core::{verify::verify_constraints, word::Word};
use binius_frontend::CircuitBuilder;
use sha2::{Digest, Sha256 as StdSha256};

use binius_prover::{
    hash::parallel_compression::ParallelCompressionAdaptor, OptimalPackedB128, Prover,
};
use binius_transcript::{ProverTranscript, VerifierTranscript};
use binius_verifier::{
    config::StdChallenger,
    hash::{StdCompression, StdDigest},
    Verifier,
};

fn main() -> Result<(), Box<dyn std::error::Error>> {
    // New Circuit
    let builder = CircuitBuilder::new();

    // Wire and circuit stuff I'm not sure I completely understand
    let content: Vec<_> = (0..4).map(|_| builder.add_witness()).collect();
    let nonce: Vec<_> = (0..4).map(|_| builder.add_witness()).collect();
    let commitment: [_; 4] = core::array::from_fn(|_| builder.add_inout());

    let message: Vec<_> = content.clone().into_iter().chain(nonce.clone()).collect();
    let len_bytes = builder.add_witness();
    let sha256 = Sha256::new(&builder, len_bytes, commitment, message);
    let circuit = builder.build();

    let mut witness = circuit.new_witness_filler();
    witness[len_bytes] = Word(64); // feed the circuit a wire containing the preimage length, in bytes.

    // make m
    let m: &[u8] = b"this is my message to commit";

    let mut message_bytes = [0u8; 64];
    message_bytes[..m.len()].copy_from_slice(m);

    witness[len_bytes] = Word(64);
    sha256.populate_message(&mut witness, &message_bytes);

    let digest = StdSha256::digest(&message_bytes);
    let mut digest_bytes = [0u8; 32];
    digest_bytes.copy_from_slice(&digest);
    sha256.populate_digest(&mut witness, digest_bytes);

    circuit.populate_wire_witness(&mut witness)?;

    // check sha256(m) = h
    let cs = circuit.constraint_system();
    let witness_vec = witness.into_value_vec();
    verify_constraints(cs, &witness_vec)?;

    println!("✓ the wire values you populated satisfy the circuit's constraints");

    // prove / verify sha256(m) = h
    let compression = ParallelCompressionAdaptor::new(StdCompression::default());
    let verifier = Verifier::<StdDigest, _>::setup(cs.clone(), 1, StdCompression::default())?;
    let prover = Prover::<OptimalPackedB128, _, StdDigest>::setup(verifier.clone(), compression)?;

    let challenger = StdChallenger::default();
    let mut prover_transcript = ProverTranscript::new(challenger.clone());
    let public_words = witness_vec.public().to_vec();
    prover.prove(witness_vec, &mut prover_transcript)?;
    let proof = prover_transcript.finalize();

    let mut verifier_transcript = VerifierTranscript::new(challenger, proof);
    verifier.verify(&public_words, &mut verifier_transcript)?;
    verifier_transcript.finalize()?;

    println!("✓ proof successfully verified");

    Ok(())
}
