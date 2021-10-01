use clap::Clap;

mod cmd;
mod proto;
mod network;

#[derive(Clap)]
struct Opts {
    #[clap(subcommand)]
    cmd: Cmd,
}

#[derive(Clap)]
struct RunOpts {
    bootstrap_node: String,
}

#[derive(Clap)]
enum Cmd {
    Run(RunOpts),
}

#[tokio::main]
async fn main() {
    let opts = Opts::parse();

    pretty_env_logger::init();

    match opts.cmd {
        Cmd::Run(opts) => cmd::run(opts.bootstrap_node)
            .await
            .expect("an error occurred"),
    };
}
