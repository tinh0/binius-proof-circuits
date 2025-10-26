use binius_circuits::sha256::Sha256;
use binius_core::{verify::verify_constraints, word::Word};
use binius_frontend::CircuitBuilder;
use sha2::{Digest, Sha256 as StdSha256};

use binius_prover::{
    OptimalPackedB128, Prover, hash::parallel_compression::ParallelCompressionAdaptor,
};
use binius_transcript::{ProverTranscript, VerifierTranscript};
use binius_verifier::{
    Verifier,
    config::StdChallenger,
    hash::{StdCompression, StdDigest},
};

use std::time::Instant;

pub fn sha256_circuit(image_bytes: &[u8]) -> Result<(), Box<dyn std::error::Error>> {
    // // make m
    // let mut rng = rand::rng();
    // let mut message_bytes = vec![0u8; size];
    // rng.fill(&mut message_bytes[..]);

    println!("Proof for sha256 circuit: ");
    // Start timer for setup
    //let setup_timer = Instant::now();
    // New Circuit
    let builder = CircuitBuilder::new();

    let size = image_bytes.len();
    // Make wires for message
    let n_wires = (size + 7) / 8;

    let message: Vec<_> = (0..n_wires).map(|_| builder.add_witness()).collect();

    let commitment: [_; 4] = core::array::from_fn(|_| builder.add_inout());

    // Build sha256 gadget
    let len_bytes = builder.add_witness();
    let sha256 = Sha256::new(&builder, len_bytes, commitment, message);

    let circuit = builder.build();

    let mut witness = circuit.new_witness_filler();
    witness[len_bytes] = Word(size as u64); // feed the circuit a wire containing the preimage length, in bytes.

    // println!("Message bytes: {:?}", message_bytes);

    sha256.populate_message(&mut witness, &image_bytes);

    let digest = StdSha256::digest(&image_bytes);
    let mut digest_bytes = [0u8; 32];
    digest_bytes.copy_from_slice(&digest);
    sha256.populate_digest(&mut witness, digest_bytes);

    circuit.populate_wire_witness(&mut witness)?;

    // check sha256(m) = h
    let cs = circuit.constraint_system();
    let witness_vec = witness.into_value_vec();
    verify_constraints(cs, &witness_vec)?;

    println!("✓ constraint verified");

    // prove / verify sha256(m) = h
    let compression = ParallelCompressionAdaptor::new(StdCompression::default());
    let verifier = Verifier::<StdDigest, _>::setup(cs.clone(), 1, StdCompression::default())?;
    let prover = Prover::<OptimalPackedB128, _, StdDigest>::setup(verifier.clone(), compression)?;

    let challenger = StdChallenger::default();
    let mut prover_transcript = ProverTranscript::new(challenger.clone());
    let public_words = witness_vec.public().to_vec();

    //println!("Setup time {}ms", setup_timer.elapsed().as_millis());

    let prove_timer = Instant::now();

    prover.prove(witness_vec, &mut prover_transcript)?;
    let proof = prover_transcript.finalize();

    println!("Proof time {}ms", prove_timer.elapsed().as_millis());

    let mut verifier_transcript = VerifierTranscript::new(challenger, proof);

    let verify_timer = Instant::now();

    verifier.verify(&public_words, &mut verifier_transcript)?;
    verifier_transcript.finalize()?;

    println!("Verify time {}ms", verify_timer.elapsed().as_millis());

    println!("✓ proof successfully verified");

    Ok(())
}
