fn main() -> Result<(), Box<dyn std::error::Error>> {
    tonic_build::configure()
        .build_server(true)
        .build_client(true) // client needed for tests
        .compile_protos(&["../../proto/license.proto"], &["../../proto"])?;
    println!("cargo:rerun-if-changed=../../proto/license.proto");
    Ok(())
}
