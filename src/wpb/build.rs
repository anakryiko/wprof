use std::error::Error;

use prost_types::{field_descriptor_proto, DescriptorProto, FileDescriptorSet};

fn force_bytes_field(msg: &mut DescriptorProto, msg_name: &str, field_name: &str) -> bool {
    let mut found = false;

    if msg.name.as_deref() == Some(msg_name) {
        for field in &mut msg.field {
            if field.name.as_deref() == Some(field_name) {
                field.r#type = Some(field_descriptor_proto::Type::Bytes as i32);
                found = true;
            }
        }
    }

    for nested in &mut msg.nested_type {
        found |= force_bytes_field(nested, msg_name, field_name);
    }

    found
}

fn force_bytes_fields(fds: &mut FileDescriptorSet, fields: &[(&str, &str)]) {
    for (msg_name, field_name) in fields {
        let mut found = false;

        for file in &mut fds.file {
            for msg in &mut file.message_type {
                found |= force_bytes_field(msg, msg_name, field_name);
            }
        }

        assert!(found, "missing protobuf field {msg_name}.{field_name}");
    }
}

fn main() -> Result<(), Box<dyn Error>> {
    println!("cargo:rerun-if-changed=../perfetto_trace.proto");

    let mut fds = protox::Compiler::new([".."])?
        .include_source_info(false)
        .include_imports(true)
        .open_file("perfetto_trace.proto")?
        .file_descriptor_set();

    force_bytes_fields(
        &mut fds,
        &[
            ("EventCategory", "name"),
            ("EventName", "name"),
            ("DebugAnnotationName", "name"),
            ("ProcessDescriptor", "process_name"),
            ("ThreadDescriptor", "thread_name"),
            ("TrackDescriptor", "name"),
            ("TrackDescriptor", "static_name"),
            ("TrackDescriptor", "atrace_name"),
            ("SchedSwitchFtraceEvent", "prev_comm"),
            ("SchedSwitchFtraceEvent", "next_comm"),
            ("SchedWakingFtraceEvent", "comm"),
            ("SchedWakeupNewFtraceEvent", "comm"),
        ],
    );

    let mut config = prost_build::Config::new();
    config.boxed(".perfetto.protos.TracePacket.data.track_event");
    config.compile_fds(fds)?;
    Ok(())
}
