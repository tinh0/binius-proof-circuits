use binius_circuits::blake2b::{Blake2bCircuit, blake2b};
use binius_core::{verify::verify_constraints};
use binius_frontend::CircuitBuilder;

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

pub fn blake2b_circuit(image_bytes: &[u8]) -> Result<(), Box<dyn std::error::Error>> {
    println!("Proof for Blake2b circuit:");
    // Start timer for setup
    //let setup_timer = Instant::now();

    // New Circuit
    let builder = CircuitBuilder::new();

    // Create Circuit
    let max_msg_len_bytes = image_bytes.len();
    let blake2b_circuit = Blake2bCircuit::new_with_length(&builder, max_msg_len_bytes);
    let circuit = builder.build();

    // Create witness
    let mut witness = circuit.new_witness_filler();

    // 5) Compute expected digest using the reference Blake2b (64-byte output)
    let expected_digest_vec = blake2b(&image_bytes, 64);
    let mut expected_digest = [0u8; 64];
    expected_digest.copy_from_slice(&expected_digest_vec);

    // 6) Populate the circuit witness
    blake2b_circuit.populate_message(&mut witness, &image_bytes);
    blake2b_circuit.populate_digest(&mut witness, &expected_digest);

    // 7) Finish population (derive internal wires)
    circuit.populate_wire_witness(&mut witness)?;

    // 8) Check constraints locally
    let cs = circuit.constraint_system();
    let witness_vec = witness.into_value_vec();
    verify_constraints(cs, &witness_vec)?;
    println!("✓ constraints verified");

    // prover / verifier
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
