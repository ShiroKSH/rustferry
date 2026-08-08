//! Repeatable wall-clock measurement for complete atomic template generation.

use std::hint::black_box;
use std::time::Instant;

use camino::Utf8Path;
use rustferry_codegen::{
    PlatformSelection, ProjectGenerator, ProjectRequest, RuntimeDependency, TemplateKind,
};

fn main() {
    let temporary = tempfile::tempdir().expect("temporary benchmark directory");
    let parent = Utf8Path::from_path(temporary.path()).expect("UTF-8 benchmark path");
    let iterations = 100_u32;
    let started = Instant::now();
    for index in 0..iterations {
        let request = ProjectRequest {
            name: format!("benchmark-{index}"),
            display_name: None,
            identifier: Some(format!("com.example.benchmark{index}")),
            template: TemplateKind::Starter,
            platforms: PlatformSelection::Both,
            runtime_dependency: RuntimeDependency::Registry("0.1.0".to_owned()),
        };
        let generated = ProjectGenerator::new(parent, request)
            .generate()
            .expect("generate benchmark project");
        black_box(generated);
    }
    println!(
        "template generation: {iterations} projects in {:?}",
        started.elapsed()
    );
}
