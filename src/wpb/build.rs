use std::error::Error;

fn main() -> Result<(), Box<dyn Error>> {
    println!("cargo:rerun-if-changed=../perfetto_trace.proto");

    let fds = protox::Compiler::new([".."])?
        .include_source_info(false)
        .include_imports(true)
        .open_file("perfetto_trace.proto")?
        .file_descriptor_set();

    let mut config = prost_build::Config::new();
    config.boxed(".perfetto.protos.TracePacket.data.track_event");
    config.compile_fds(fds)?;
    Ok(())
}
