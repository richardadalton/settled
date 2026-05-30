fn main() -> Result<(), Box<dyn std::error::Error>> {
    let manifest = std::env::var("CARGO_MANIFEST_DIR").unwrap();
    let proto = format!("{manifest}/../../proto/settled.v1.proto");
    println!("cargo:rerun-if-changed=../../proto/settled.v1.proto");
    tonic_build::configure()
        .file_descriptor_set_path(
            std::path::PathBuf::from(std::env::var("OUT_DIR").unwrap())
                .join("settled.v1.descriptor.bin"),
        )
        .compile_protos(
            &[proto.as_str()],
            &[format!("{manifest}/../../proto").as_str()],
        )?;
    Ok(())
}
