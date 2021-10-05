use anyhow::Result;
use clap::Clap;

use cmd::{pki as pki_cmd, run as run_cmd};

mod cmd;
mod network;
mod pki;
mod proto;

#[derive(Clap)]
struct Opts {
    #[clap(subcommand)]
    cmd: Cmd,
}

#[derive(Clap)]
enum Cmd {
    Run(run_cmd::Opts),
    PKI(pki_cmd::Opts),
}

#[tokio::main]
async fn main() -> Result<()> {
    let opts = Opts::parse();

    pretty_env_logger::init();

    let db = sled::open(".nuts")?;

    match opts.cmd {
        Cmd::Run(opts) => run_cmd::cmd(db, opts).await,
        Cmd::PKI(opts) => pki_cmd::cmd(db, opts).await,
    }?;

    Ok(())
}
