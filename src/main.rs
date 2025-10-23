// run with: RUSTFLAGS="-C target-cpu=native" cargo run --release

use binius_core::{verify::verify_constraints, word::Word};
use binius_field::{BinaryField128bGhash as F, Field};
use binius_frontend::{CircuitBuilder, Wire};

use binius_prover::{
    hash::parallel_compression::ParallelCompressionAdaptor, OptimalPackedB128, Prover,
};
use binius_transcript::{ProverTranscript, VerifierTranscript};
use binius_verifier::{config::StdChallenger, hash::{StdCompression, StdDigest}, Verifier};

use rand::Rng;

// -------------------- 128-bit “wire element” --------------------

#[derive(Clone, Copy)]
struct U128 { lo: Wire, hi: Wire }

#[inline]
fn split128(v: u128) -> (u64, u64) { (v as u64, (v >> 64) as u64) }

#[inline]
fn u128_xor(b: &CircuitBuilder, a: U128, c: U128) -> U128 {
    U128 { lo: b.bxor(a.lo, c.lo), hi: b.bxor(a.hi, c.hi) }
}

// -------------------- Tiny GF(2^128) multiply-by-byte gadget --------------------
//
// We only need A * byte (since I[j] is a byte). Implement as 8 conditional XORs
// with a “multiply by x” primitive (shift-left + conditional XOR 0x87).

// shift-left by 1 in GF(2^128) with GHASH reduction (x^128 + x^7 + x^2 + x + 1)
fn mul_x(b: &CircuitBuilder, a: U128) -> U128 {
    // 128-bit shift left by 1
    let lo_sh = b.shl(a.lo, 1);
    let carry = b.shr(a.lo, 63);                 // bit 63 of lo to bit 0 of hi
    let hi_sh = b.bxor(b.shl(a.hi, 1), carry);

    // old MSB of 'a' is bit 63 of a.hi (before shift). Use MSB-bool select for a 0/!0 mask.
    // rotl(x, 0) is allowed and returns x; MSB of a.hi is already in its bit63.
    let cond = b.rotl(a.hi, 0);
    let all1 = b.add_constant(Word::ALL_ONE);
    let zero = b.add_constant_64(0);
    let mask = b.select(cond, all1, zero);

    // If old MSB=1, XOR low limb with 0x87 (GHASH reduction poly bits).
    let red = b.add_constant_64(0x87);
    let red_masked = b.band(red, mask);

    U128 { lo: b.bxor(lo_sh, red_masked), hi: hi_sh }
}

// conditional XOR: if cond (MSB-bool) then acc ^= x
fn cxor(b: &CircuitBuilder, acc: U128, x: U128, cond_msb: Wire) -> U128 {
    let all1 = b.add_constant(Word::ALL_ONE);
    let zero = b.add_constant_64(0);
    let m = b.select(cond_msb, all1, zero);      // 0/!0 mask
    let xlo = b.band(x.lo, m);
    let xhi = b.band(x.hi, m);
    U128 { lo: b.bxor(acc.lo, xlo), hi: b.bxor(acc.hi, xhi) }
}

// A * (public byte in x.lo). Assumes x.hi == 0; only low byte of x.lo is used.
fn gfmul_by_public_byte(b: &CircuitBuilder, a: U128, x: U128) -> U128 {
    let byte0 = b.extract_byte(x.lo, 0);         // 0..255 in low 8 bits
    let mut acc = U128 { lo: b.add_constant_64(0), hi: b.add_constant_64(0) };
    let mut p = a;

    // For k in 0..8: if ((byte0 >> k) & 1) acc ^= p; then p *= x
    for k in 0..8u32 {
        // Make MSB-bool from bit k: rotate so that bit k becomes MSB.
        let cond = b.rotl(byte0, 63 - k);
        acc = cxor(b, acc, p, cond);
        p = mul_x(b, p);
    }
    acc
}

// -------------------- The matrix-hash circuit: H = A · I over GF(2^128) --------------------

pub fn lattice_circuit(image_bytes: &[u8]) -> Result<(), Box<dyn std::error::Error>> {
    let m = 128usize;
    let n = image_bytes.len();

    // ----- Host: sample A (private), lift I (public), compute H (public) -----
    let mut rng = rand::rng();

    // Secret random A in GF(2^128)
    let A: Vec<Vec<F>> = (0..m)
        .map(|_| (0..n).map(|_| rng.random::<F>()).collect())
        .collect();

    // Public I: bytes -> field elems (lo=byte, hi=0)
    let I: Vec<F> = image_bytes.iter().map(|&b| F::from(b as u128)).collect();

    // Public H = A · I (field mat-vec multiply)
    let mut H: Vec<F> = vec![F::ZERO; m];
    for i in 0..m {
        let mut acc = F::ZERO;
        for j in 0..n { acc += &(A[i][j] * I[j]); }
        H[i] = acc;
    }

    // ----- Prints (A is secret; only print if explicitly requested) -----
    // print_vector_bytes("I (bytes)", image_bytes);
    // print_vector_field("H (field)", &H);
    // if std::env::var("PRINT_SECRET_A").as_deref() == Ok("1") {
    //     print_matrix_field("A (field, PRIVATE!)", &A);
    // }
    println!("✓ building circuit");
    // ----- Circuit build: A = witness, I/H = inout -----
    let builder = CircuitBuilder::new();

    // A[i][j] (private) -> 2 wires each
    let a_idx: Vec<Vec<U128>> = (0..m).map(|_| {
        (0..n).map(|_| U128 { lo: builder.add_witness(), hi: builder.add_witness() }).collect()
    }).collect();

    // I[j] (public) -> 2 wires each
    let x_idx: Vec<U128> = (0..n).map(|_| U128 { lo: builder.add_inout(), hi: builder.add_inout() }).collect();

    // H[i] (public) -> 2 wires each
    let h_idx: Vec<U128> = (0..m).map(|_| U128 { lo: builder.add_inout(), hi: builder.add_inout() }).collect();

    // Enforce H[i] = XOR_j ( A[i][j] * I[j] )  where * is GF(2^128) and I[j] is a byte
    for i in 0..m {
        let mut acc = U128 { lo: builder.add_constant_64(0), hi: builder.add_constant_64(0) };
        for j in 0..n {
            let prod = gfmul_by_public_byte(&builder, a_idx[i][j], x_idx[j]);
            acc = u128_xor(&builder, acc, prod);
        }
        builder.assert_eq(format!("H[{i}].lo"), acc.lo, h_idx[i].lo);
        builder.assert_eq(format!("H[{i}].hi"), acc.hi, h_idx[i].hi);
    }

    let circuit = builder.build();
    println!("✓ circuit built");
    // ----- Fill wires -----
    let mut filler = circuit.new_witness_filler();

    // A (private)
    for i in 0..m {
        for j in 0..n {
            let v: u128 = A[i][j].into();
            let (lo, hi) = split128(v);
            filler[a_idx[i][j].lo] = Word(lo);
            filler[a_idx[i][j].hi] = Word(hi);
        }
    }
    // I (public): lo = byte, hi = 0
    for j in 0..n {
        filler[x_idx[j].lo] = Word(image_bytes[j] as u64);
        filler[x_idx[j].hi] = Word(0);
    }
    // H (public)
    for i in 0..m {
        let v: u128 = H[i].into();
        let (lo, hi) = split128(v);
        filler[h_idx[i].lo] = Word(lo);
        filler[h_idx[i].hi] = Word(hi);
    }

    circuit.populate_wire_witness(&mut filler)?;

    // Optional local constraint check
    let cs = circuit.constraint_system();
    let witness_vec = filler.into_value_vec();
    verify_constraints(cs, &witness_vec)?;
    println!("✓ constraint verified");
    // ----- Prove / Verify -----
    let compression = ParallelCompressionAdaptor::new(StdCompression::default());
    let verifier = Verifier::<StdDigest, _>::setup(cs.clone(), 1, StdCompression::default())?;
    let prover   = Prover::<OptimalPackedB128, _, StdDigest>::setup(verifier.clone(), compression)?;

    let challenger = StdChallenger::default();
    let mut prover_tx = ProverTranscript::new(challenger.clone());
    let public_words = witness_vec.public().to_vec();

    let prove_timer = std::time::Instant::now();
    prover.prove(witness_vec, &mut prover_tx)?;
    let proof = prover_tx.finalize();
    eprintln!("Proof time {}ms", prove_timer.elapsed().as_millis());

    let mut verifier_tx = VerifierTranscript::new(challenger, proof);
    let verify_timer = std::time::Instant::now();
    verifier.verify(&public_words, &mut verifier_tx)?;
    verifier_tx.finalize()?;
    eprintln!("Verify time {}ms", verify_timer.elapsed().as_millis());

    println!("✓ proof successfully verified");
    Ok(())
}


// -------------------- main --------------------

fn main() -> Result<(), Box<dyn std::error::Error>> {
    // demo image vector
    let n = 512;
    let mut rng = rand::rng();
    let mut image = vec![0u8; n];
    rng.fill(&mut image[..]);

    lattice_circuit(&image)?;
    Ok(())
}