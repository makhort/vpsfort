//! The fuzz target (`fuzz/`, nightly) on stable: its seeds, the week of real ejabberd logs,
//! and a few thousand mutations of them, so `cargo test` catches a panic in the log parsers
//! without libFuzzer. The real search runs with `cargo +nightly fuzz run records`.

use std::path::PathBuf;

fn inputs() -> Vec<Vec<u8>> {
    let root = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    let mut v: Vec<Vec<u8>> =
        std::fs::read_dir(root.join("fuzz/seeds/records")).unwrap().map(|e| std::fs::read(e.unwrap().path()).unwrap()).collect();
    v.sort();
    if let Ok(week) = std::fs::read_to_string(root.join("../sample_data/logs/weekly.log")) {
        let lines: Vec<&str> = week.lines().collect();
        v.extend(lines.chunks(40).take(50).map(|c| c.join("\n").into_bytes()));
    }
    v
}

/// xorshift: the same mutations on every run.
struct Rng(u64);

impl Rng {
    fn next(&mut self) -> u64 {
        self.0 ^= self.0 << 13;
        self.0 ^= self.0 >> 7;
        self.0 ^= self.0 << 17;
        self.0
    }

    fn below(&mut self, n: usize) -> usize {
        (self.next() % n.max(1) as u64) as usize
    }
}

const TOKENS: &[&[u8]] = &[
    b"\n",
    b" ",
    b":",
    b"[",
    b"]",
    b"(",
    b")",
    b"<",
    b">",
    b"\"",
    b"{",
    b"}",
    b"\\u0000",
    b"\xff\xfe",
    b"::ffff:",
    b"%",
    b"..",
    b"999999999999999999999",
    b"-1",
    b" port ",
    b" from ",
    b"SRC=",
    b"DPT=",
    b"(tls|<0.1.0>) ",
    b"(#PID<0.1.0>) ",
    b"\xe2\x80\xae",
];

fn mutate(rng: &mut Rng, input: &[u8], others: &[Vec<u8>]) -> Vec<u8> {
    let mut out = input.to_vec();
    for _ in 0..1 + rng.below(8) {
        let at = rng.below(out.len() + 1);
        match rng.below(6) {
            0 if !out.is_empty() => {
                let i = at.min(out.len() - 1);
                out[i] = rng.next() as u8;
            }
            1 if at < out.len() => {
                let end = (at + rng.below(16)).min(out.len());
                out.drain(at..end);
            }
            2 => {
                let t = TOKENS[rng.below(TOKENS.len())];
                out.splice(at..at, t.iter().copied());
            }
            3 => {
                // a piece of another input
                let o = &others[rng.below(others.len())];
                let from = rng.below(o.len());
                let end = (from + rng.below(200)).min(o.len());
                out.splice(at..at, o[from..end].iter().copied());
            }
            4 if at < out.len() => {
                // repeat a piece: long names, many fields
                let end = (at + rng.below(32)).min(out.len());
                let piece = out[at..end].repeat(1 + rng.below(64));
                out.splice(at..at, piece);
            }
            _ => out.truncate(at),
        }
    }
    out
}

/// The decision-log target: its seeds (synthetic logs, documentation addresses) and mutations.
#[test]
fn actions_log_target_survives_seeds_and_mutations() {
    let root = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    let mut inputs: Vec<Vec<u8>> =
        std::fs::read_dir(root.join("fuzz/seeds/actions_log")).unwrap().map(|e| std::fs::read(e.unwrap().path()).unwrap()).collect();
    inputs.sort();
    assert!(inputs.len() >= 2, "the seed files are missing");
    for i in &inputs {
        vpsfort::fuzzing::actions_log(i);
    }
    let mut rng = Rng(0x2545_f491_4f6c_dd1d);
    // each input builds a whole dashboard snapshot: a few hundred keep `cargo test` quick
    for _ in 0..300 {
        let base = &inputs[rng.below(inputs.len())];
        let m = mutate(&mut rng, base, &inputs);
        vpsfort::fuzzing::actions_log(&m);
    }
}

/// The index target: forged indexes against a log must never place a reader inside a line.
#[test]
fn log_index_target_survives_seeds_and_mutations() {
    let root = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    let mut inputs: Vec<Vec<u8>> =
        std::fs::read_dir(root.join("fuzz/seeds/log_index")).unwrap().map(|e| std::fs::read(e.unwrap().path()).unwrap()).collect();
    inputs.sort();
    assert!(inputs.len() >= 2, "the seed files are missing");
    for i in &inputs {
        vpsfort::fuzzing::log_index(i);
    }
    let mut rng = Rng(0x7f4a_7c15_2545_f491);
    for _ in 0..3000 {
        let base = &inputs[rng.below(inputs.len())];
        let m = mutate(&mut rng, base, &inputs);
        vpsfort::fuzzing::log_index(&m);
    }
}

#[test]
fn records_target_survives_seeds_and_mutations() {
    let cfg = vpsfort::fuzzing::config();
    let inputs = inputs();
    assert!(inputs.len() >= 5, "the seed files are missing");
    for i in &inputs {
        vpsfort::fuzzing::records(&cfg, i);
    }
    let mut rng = Rng(0x9e37_79b9_7f4a_7c15);
    for _ in 0..3000 {
        let base = &inputs[rng.below(inputs.len())];
        let m = mutate(&mut rng, base, &inputs);
        vpsfort::fuzzing::records(&cfg, &m);
    }
}
