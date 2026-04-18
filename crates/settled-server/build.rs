fn main() -> Result<(), Box<dyn std::error::Error>> {
    let manifest = std::env::var("CARGO_MANIFEST_DIR").unwrap();
    let proto = format!("{manifest}/../../proto/settled.v1.proto");
    println!("cargo:rerun-if-changed=../../proto/settled.v1.proto");
    tonic_build::compile_protos(&proto)?;
    Ok(())
}
