use std::{env, fs};

fn main() -> Result<(), Box<dyn std::error::Error>> {
    tonic_build::compile_protos("proto/network.proto")?;

    // Fix for `connect` gRPC method conflict
    let output_file = format!("{}/transport.rs", env::var("OUT_DIR")?);
    let source = fs::read_to_string(&output_file)?;

    fs::write(
        output_file,
        source
            .replace("fn connect(", "fn connect_method(")
            .replace("connect(request)", "connect_method(request)"),
    )?;

    Ok(())
}
