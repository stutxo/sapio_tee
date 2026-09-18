mod app;
mod keys;
mod nsm;

use anyhow::{bail, Result};

#[tokio::main(worker_threads = 2)]
async fn main() -> Result<()> {
    let mut args = std::env::args().skip(1);
    let command = args.next();
    if args.next().is_some() {
        bail!("unexpected arguments; use --help");
    }
    match command.as_deref() {
        Some("--help") => {
            println!("sapio-tee: Nitro-only Sapio ProgramOracle\nRun without arguments inside the measured enclave.\nAPI: 127.0.0.1:8000; SignProgramV1 TCP: 127.0.0.1:8367\n--program-profile: print the measured protocol/evaluator profile without NSM");
            #[cfg(feature = "local-dev")]
            println!("--local-dev: ephemeral regtest program oracle WITHOUT enclave security");
            return Ok(());
        }
        Some("--program-profile") => {
            println!(
                "{}",
                serde_json::to_string_pretty(&sapio_tee::deployment::program_profile())?
            );
            return Ok(());
        }
        #[cfg(feature = "local-dev")]
        Some("--local-dev") => return app::run(None).await,
        Some(_) => bail!("unexpected arguments; use --help"),
        None => {}
    }
    let nsm = nsm::Nsm::open()?;
    app::run(Some(nsm)).await
}
