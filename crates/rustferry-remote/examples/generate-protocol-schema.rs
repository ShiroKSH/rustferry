//! Generate the checked-in Ferry Remote Build Protocol v1 JSON Schema.

use std::{env, fs, process::ExitCode};

use rustferry_remote::protocol_v1_schema_json;

fn main() -> ExitCode {
    let mut arguments = env::args_os().skip(1);
    let Some(output) = arguments.next() else {
        eprintln!("usage: generate-protocol-schema <output-path>");
        return ExitCode::from(2);
    };
    if arguments.next().is_some() {
        eprintln!("usage: generate-protocol-schema <output-path>");
        return ExitCode::from(2);
    }
    let schema = match protocol_v1_schema_json() {
        Ok(schema) => schema,
        Err(error) => {
            eprintln!("could not generate protocol schema: {error}");
            return ExitCode::FAILURE;
        }
    };
    if let Err(error) = fs::write(&output, schema) {
        eprintln!("could not write protocol schema: {error}");
        return ExitCode::FAILURE;
    }
    ExitCode::SUCCESS
}
