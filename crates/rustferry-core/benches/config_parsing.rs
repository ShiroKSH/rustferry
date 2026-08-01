//! Repeatable wall-clock measurement for strict configuration parsing.

use std::hint::black_box;
use std::time::Instant;

fn main() {
    let source = rustferry_core::FerryConfig::starter("Benchmark", "com.example.benchmark")
        .to_pretty_toml()
        .expect("serialize benchmark configuration");
    let iterations = 10_000_u32;
    let started = Instant::now();
    for _ in 0..iterations {
        let config = rustferry_core::FerryConfig::parse(black_box(&source))
            .expect("parse benchmark configuration");
        black_box(config);
    }
    println!(
        "config parsing: {iterations} iterations in {:?}",
        started.elapsed()
    );
}
