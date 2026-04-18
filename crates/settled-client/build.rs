fn main() {
    tonic_build::configure()
        .build_server(false)
        .compile(&["proto/settled.v1.proto"], &["proto"])
        .expect("failed to compile proto");
    println!("cargo:rerun-if-changed=proto/settled.v1.proto");
}
