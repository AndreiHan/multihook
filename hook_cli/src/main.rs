#[macro_use]
extern crate log;

use std::io::Write;

use anyhow::Result;
use clap::Parser;

#[derive(Parser, Debug)]
#[command(version, long_about = None)]
struct Args {
    #[arg(short, long)]
    pid: u32,

    #[arg(short, long, default_value_t = false)]
    verbose: bool,

    #[arg(short, long, default_value_t = 4)]
    events_per_pid: u32,

    #[arg(short, long, default_value_t = 30)]
    timeout: u32,

    #[arg(short, long, default_value_t = false)]
    crash: bool,

    #[arg(short, long)]
    output_file: Option<String>,
}

fn main() -> Result<()> {
    let args = Args::try_parse()?;

    if args.verbose {
        env_logger::init_from_env(
            env_logger::Env::default().filter_or(env_logger::DEFAULT_FILTER_ENV, "debug"),
        );
    } else {
        env_logger::init_from_env(
            env_logger::Env::default().filter_or(env_logger::DEFAULT_FILTER_ENV, "info"),
        );
    }

    let dll_path = dll_injector::get_dll_path(args.crash, args.pid)?;
    let thread_results = pipe_com::start_monitor(Some(args.events_per_pid));

    info!("Injecting DLL: {:?}, into: {:?}", dll_path, args.pid);
    match dll_injector::inject(&dll_path, args.pid) {
        Ok(status) => {
            info!("DLL injected successfully, exit status");
            debug!("DLL thread inject status: {status}");
        }
        Err(e) => error!("Error injecting DLL: {e:?}"),
    };

    let results = thread_results.retrieve_results(Some(args.timeout));

    if let Some(output_file) = args.output_file {
        match write_to_file(&output_file, &results) {
            Ok(()) => info!("Results written to: {:?}", output_file),
            Err(e) => error!("Error writing to file: {output_file}, err: {e:?}"),
        }
    } else {
        for result in results {
            println!("{result},");
        }
    }
    Ok(())
}

fn write_to_file(output_file: &str, data: &[msg_protocol::DllMessage]) -> Result<()> {
    let mut writer = std::io::BufWriter::new(std::fs::File::create(output_file)?);
    serde_json::to_writer_pretty(&mut writer, &data)?;
    writer.flush()?;
    Ok(())
}
