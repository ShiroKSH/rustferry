use camino::Utf8PathBuf;

use crate::cli::{
    DevicePlatformChoice, DevicesArgs, IdeArgs, IdeCommand, IdeDevicePlatform, IdeDevicesArgs,
};
use crate::error::CliError;
use crate::output::Reporter;

pub fn run(
    arguments: DevicesArgs,
    dry_run: bool,
    json_stream: bool,
    reporter: &Reporter,
) -> Result<(), CliError> {
    if json_stream {
        return super::ide::run(
            IdeArgs {
                command: IdeCommand::Devices(IdeDevicesArgs {
                    platform: ide_platform(arguments.platform),
                    watch: arguments.watch,
                    interval_ms: arguments.interval_ms,
                    operation_id: None,
                    parent_operation_id: None,
                }),
            },
            dry_run,
            reporter,
        );
    }
    if arguments.watch {
        return Err(CliError::Unsupported {
            message: "device watch mode requires newline-delimited JSON".to_owned(),
            help: "Run `cargo ferry devices --watch --json-stream`.".to_owned(),
        });
    }
    let current_directory = working_directory(arguments.project_dir)?;
    let snapshot = cargo_ferry::deployment::DeviceService::new(
        cargo_ferry::deployment::SystemExecutor,
        current_directory,
    )
    .discover(device_filter(arguments.platform));
    let warnings = snapshot
        .warnings
        .iter()
        .map(|warning| format!("{}: {}", warning.source, warning.message))
        .collect::<Vec<_>>();
    reporter.success(
        "devices",
        &snapshot,
        || {
            if snapshot.devices.is_empty() {
                return "No compatible devices found.\n\nConnect an Android device, boot an emulator/Simulator, or pair an iPhone, then rerun `cargo ferry devices`.".to_owned();
            }
            let rows = snapshot
                .devices
                .iter()
                .map(|device| {
                    format!(
                        "{}\t{}\t{:?}\t{:?}\tinstall={} launch={} logs={}",
                        device.id,
                        device.name,
                        device.kind,
                        device.state,
                        device.capabilities.install,
                        device.capabilities.launch,
                        device.capabilities.logs,
                    )
                })
                .collect::<Vec<_>>()
                .join("\n");
            format!("ID\tNAME\tKIND\tSTATE\tCAPABILITIES\n{rows}")
        },
        &warnings,
    );
    Ok(())
}

fn working_directory(path: Option<Utf8PathBuf>) -> Result<Utf8PathBuf, CliError> {
    let path = path.map_or_else(
        || {
            std::env::current_dir()
                .map_err(|source| CliError::Io {
                    action: "read current directory",
                    path: Utf8PathBuf::from("."),
                    source,
                })
                .and_then(|path| Utf8PathBuf::from_path_buf(path).map_err(CliError::NonUtf8Path))
        },
        Ok,
    )?;
    let canonical = path.canonicalize_utf8().map_err(|source| CliError::Io {
        action: "resolve device discovery directory",
        path: path.clone(),
        source,
    })?;
    if !canonical.is_dir() {
        return Err(CliError::Unsupported {
            message: format!("device discovery path is not a directory: {canonical}"),
            help: "Pass an existing directory with --project-dir.".to_owned(),
        });
    }
    Ok(canonical)
}

const fn device_filter(platform: DevicePlatformChoice) -> cargo_ferry::deployment::DeviceFilter {
    match platform {
        DevicePlatformChoice::All => cargo_ferry::deployment::DeviceFilter::All,
        DevicePlatformChoice::Android => cargo_ferry::deployment::DeviceFilter::Android,
        DevicePlatformChoice::Ios => cargo_ferry::deployment::DeviceFilter::Ios,
    }
}

const fn ide_platform(platform: DevicePlatformChoice) -> IdeDevicePlatform {
    match platform {
        DevicePlatformChoice::All => IdeDevicePlatform::All,
        DevicePlatformChoice::Android => IdeDevicePlatform::Android,
        DevicePlatformChoice::Ios => IdeDevicePlatform::Ios,
    }
}
