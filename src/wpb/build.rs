use std::collections::{HashMap, HashSet, VecDeque};
use std::error::Error;

use prost_types::{DescriptorProto, FileDescriptorSet};

/// Per top-level message, the subset of fields wprof actually emits. Messages
/// not listed here keep all their fields. Pruning the big "data"/"event" oneofs
/// (TracePacket, FtraceEvent) is what collapses the reachable type set from
/// ~1000 down to the handful we encode. Field names are protobuf field names
/// (asserted to exist, so a proto upgrade that renames one fails the build).
const KEEP_FIELDS: &[(&str, &[&str])] = &[
    (
        "TracePacket",
        &[
            "timestamp",
            "sequence_flags",
            "trusted_packet_sequence_id",
            "track_event",
            "track_descriptor",
            "clock_snapshot",
            "system_info",
            "trace_attributes",
            "trace_uuid",
            "ftrace_events",
            "interned_data",
        ],
    ),
    (
        "TrackEvent",
        &[
            "type",
            "track_uuid",
            "name",
            "name_iid",
            "category_iids",
            "categories",
            "flow_ids",
            "callstack_iid",
            "debug_annotations",
        ],
    ),
    (
        "InternedData",
        &[
            "event_categories",
            "event_names",
            "debug_annotation_names",
            "debug_annotation_string_values",
            "function_names",
            "mappings",
            "frames",
            "callstacks",
        ],
    ),
    (
        "DebugAnnotation",
        &[
            "name",
            "name_iid",
            "bool_value",
            "uint_value",
            "int_value",
            "double_value",
            "pointer_value",
            "string_value",
            "string_value_iid",
        ],
    ),
    (
        "FtraceEvent",
        &["timestamp", "pid", "sched_switch", "sched_waking", "sched_wakeup_new"],
    ),
    ("FtraceEventBundle", &["cpu", "event", "compact_sched"]),
];

/// Top-level message(s) wprof actually constructs. Everything else is kept only
/// if transitively reachable from here.
const ROOTS: &[&str] = &[".perfetto.protos.TracePacket"];

fn prune_message_fields(fds: &mut FileDescriptorSet, msg_name: &str, keep: &[&str]) {
    for file in &mut fds.file {
        for msg in &mut file.message_type {
            if msg.name.as_deref() != Some(msg_name) {
                continue;
            }
            for k in keep {
                assert!(
                    msg.field.iter().any(|f| f.name.as_deref() == Some(*k)),
                    "missing protobuf field {msg_name}.{k}"
                );
            }
            msg.field
                .retain(|f| keep.contains(&f.name.as_deref().unwrap_or_default()));
            return;
        }
    }
    panic!("missing protobuf message {msg_name}");
}

/// Where a fully-qualified type name lives: inside a top-level message (kept by
/// keeping that message) or a file-level enum (kept on its own).
enum TopRef {
    Msg(String),
    FileEnum(String),
}

/// Register `msg` and all of its nested messages/enums, mapping each FQN to the
/// top-level message that must be kept for prost to generate it.
fn register_msg(map: &mut HashMap<String, TopRef>, prefix: &str, top: &str, msg: &DescriptorProto) {
    let fqn = format!("{prefix}.{}", msg.name());
    map.insert(fqn.clone(), TopRef::Msg(top.to_string()));
    for en in &msg.enum_type {
        map.insert(format!("{fqn}.{}", en.name()), TopRef::Msg(top.to_string()));
    }
    for nested in &msg.nested_type {
        register_msg(map, &fqn, top, nested);
    }
}

/// Collect every message/enum type referenced by `msg`'s fields, including those
/// of its nested messages (which prost also generates).
fn collect_refs(msg: &DescriptorProto, out: &mut Vec<String>) {
    for f in &msg.field {
        if let Some(tn) = &f.type_name {
            out.push(tn.clone());
        }
    }
    for nested in &msg.nested_type {
        collect_refs(nested, out);
    }
}

/// Delete every top-level message and file-level enum not transitively reachable
/// from ROOTS, so prost only generates the types we actually use.
fn prune_unreachable(fds: &mut FileDescriptorSet, roots: &[&str]) {
    let mut fqn_to_top: HashMap<String, TopRef> = HashMap::new();
    let mut top_msgs: HashMap<String, DescriptorProto> = HashMap::new();

    for file in &fds.file {
        let prefix = format!(".{}", file.package());
        for msg in &file.message_type {
            let top = format!("{prefix}.{}", msg.name());
            register_msg(&mut fqn_to_top, &prefix, &top, msg);
            top_msgs.insert(top, msg.clone());
        }
        for en in &file.enum_type {
            let fqn = format!("{prefix}.{}", en.name());
            fqn_to_top.insert(fqn.clone(), TopRef::FileEnum(fqn));
        }
    }

    let mut keep_msgs: HashSet<String> = HashSet::new();
    let mut keep_enums: HashSet<String> = HashSet::new();
    let mut queue: VecDeque<String> = roots.iter().map(|s| s.to_string()).collect();

    while let Some(fqn) = queue.pop_front() {
        if !keep_msgs.insert(fqn.clone()) {
            continue;
        }
        let Some(msg) = top_msgs.get(&fqn) else {
            continue;
        };
        let mut refs = Vec::new();
        collect_refs(msg, &mut refs);
        for r in refs {
            match fqn_to_top.get(&r) {
                Some(TopRef::Msg(top)) => {
                    if !keep_msgs.contains(top) {
                        queue.push_back(top.clone());
                    }
                }
                Some(TopRef::FileEnum(e)) => {
                    keep_enums.insert(e.clone());
                }
                None => {}
            }
        }
    }

    for file in &mut fds.file {
        let prefix = format!(".{}", file.package());
        file.message_type
            .retain(|m| keep_msgs.contains(&format!("{prefix}.{}", m.name())));
        file.enum_type
            .retain(|e| keep_enums.contains(&format!("{prefix}.{}", e.name())));
    }
}

fn main() -> Result<(), Box<dyn Error>> {
    println!("cargo:rerun-if-changed=../perfetto_trace.proto");

    let mut fds = protox::Compiler::new([".."])?
        .include_source_info(false)
        .include_imports(true)
        .open_file("perfetto_trace.proto")?
        .file_descriptor_set();

    for (msg, fields) in KEEP_FIELDS {
        prune_message_fields(&mut fds, msg, fields);
    }
    prune_unreachable(&mut fds, ROOTS);

    let mut config = prost_build::Config::new();
    config.boxed(".perfetto.protos.TracePacket.data.track_event");
    config.compile_fds(fds)?;
    Ok(())
}
