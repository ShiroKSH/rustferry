use clap::CommandFactory;
use serde::Serialize;

use crate::cli::{Cli, CompletionArgs};
use crate::output::Reporter;

#[derive(Debug, Serialize)]
struct CompletionPlan {
    shell: String,
    binary: &'static str,
}

pub fn run(arguments: &CompletionArgs, dry_run: bool, reporter: &Reporter) {
    let plan = CompletionPlan {
        shell: arguments.shell.to_string(),
        binary: "cargo-ferry",
    };
    if reporter.is_json() || dry_run {
        reporter.success(
            "completions",
            &plan,
            || format!("Generate {} completions for cargo-ferry", plan.shell),
            &[],
        );
        return;
    }
    let mut command = Cli::command();
    clap_complete::generate(
        arguments.shell,
        &mut command,
        "cargo-ferry",
        &mut std::io::stdout(),
    );
}
