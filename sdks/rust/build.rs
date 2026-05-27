fn main() {
    let manifest = std::env::var("CARGO_MANIFEST_DIR").unwrap();
    let proto = format!("{manifest}/proto/settled.v1.proto");
    let include = format!("{manifest}/proto");
    tonic_build::configure()
        .build_server(false)
        .compile(&[proto.as_str()], &[include.as_str()])
        .expect("failed to compile proto");
    println!("cargo:rerun-if-changed=proto/settled.v1.proto");
}
