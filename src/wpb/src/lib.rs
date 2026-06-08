// SPDX-License-Identifier: (LGPL-2.1 OR BSD-2-Clause)
//! C-compatible protobuf encoder for wprof trace packets.

use std::ffi::{c_char, c_int, c_void};
use std::ptr;
use std::slice;

use prost::Message;
use rustc_hash::FxHashMap;

include!(concat!(env!("OUT_DIR"), "/perfetto.protos.rs"));

const EINVAL: c_int = 22;
const EIO: c_int = 5;
const TRACE_PACKET_KEY: u8 = 0x0a;

const WPB_ANN_BOOL: u8 = 0;
const WPB_ANN_UINT: u8 = 1;
const WPB_ANN_INT: u8 = 2;
const WPB_ANN_DOUBLE: u8 = 3;
const WPB_ANN_PTR: u8 = 4;
const WPB_ANN_STR: u8 = 5;
const WPB_ANN_STR_IID: u8 = 6;
const WPB_SEQ_ID_THREADS: u32 = 0x7;
const WPB_TRACK_EVENT_INSTANT: i32 = 3;
const WPB_TRACK_DESCRIPTOR_GENERIC: u8 = 0;
const WPB_TRACK_DESCRIPTOR_PROCESS: u8 = 1;
const WPB_TRACK_DESCRIPTOR_THREAD: u8 = 2;
const WPB_FTRACE_SCHED_SWITCH: u8 = 0;
const WPB_FTRACE_SCHED_WAKING: u8 = 1;
const WPB_FTRACE_SCHED_WAKEUP_NEW: u8 = 2;
const WPB_SEQ_INCREMENTAL_STATE_CLEARED: u32 = 1;
const CLOCK_BOOTTIME: u32 = 6;
const CLOCK_REALTIME: u32 = 1;

type WriteFn = unsafe extern "C" fn(ctx: *mut c_void, buf: *const u8, len: usize) -> c_int;

#[repr(C)]
#[derive(Clone, Copy)]
pub struct WpbStr {
    iid: u64,
    s: *const c_char,
    len: usize,
}

#[repr(C)]
pub union WpbAnnotVal {
    b: u8,
    u: u64,
    i: i64,
    d: f64,
    ptr: u64,
    s: WpbStr,
}

#[repr(C)]
pub struct WpbAnnot {
    name: WpbStr,
    kind: u8,
    val: WpbAnnotVal,
}

#[repr(C)]
pub struct WpbIntern {
    iid: u64,
    s: *const c_char,
    len: usize,
}

#[repr(C)]
pub struct WpbTrackEvent {
    ts: u64,
    trusted_packet_sequence_id: u32,
    sequence_flags: u32,
    track_uuid: u64,
    event_type: i32,
    name: WpbStr,
    category: WpbStr,
    annots: *const WpbAnnot,
    annot_cnt: usize,
    flow_ids: *const u64,
    flow_cnt: usize,
    interns: *const WpbIntern,
    intern_cnt: usize,
    callstack_iid: i64,
}

#[repr(C)]
pub struct WpbAttr {
    key: WpbStr,
    val: WpbStr,
}

#[repr(C)]
pub struct WpbInternSet {
    entries: *const WpbIntern,
    cnt: usize,
}

#[repr(C)]
pub struct WpbMapping {
    iid: u64,
    start: u64,
    end: u64,
    start_offset: u64,
}

#[repr(C)]
pub struct WpbFrame {
    iid: u64,
    function_name_id: u64,
    mapping_id: u64,
    rel_pc: u64,
}

#[repr(C)]
pub struct WpbCallstack {
    iid: u64,
    frame_ids: *const c_int,
    frame_cnt: usize,
}

#[repr(C)]
pub struct WpbInternedData {
    ts: u64,
    trusted_packet_sequence_id: u32,
    event_categories: WpbInternSet,
    event_names: WpbInternSet,
    debug_annotation_names: WpbInternSet,
    debug_annotation_string_values: WpbInternSet,
    function_names: WpbInternSet,
    mappings: *const WpbMapping,
    mapping_cnt: usize,
    frames: *const WpbFrame,
    frame_cnt: usize,
    callstacks: *const WpbCallstack,
    callstack_cnt: usize,
}

#[repr(C)]
pub struct WpbTrackDescriptor {
    trusted_packet_sequence_id: u32,
    kind: u8,
    uuid: u64,
    parent_uuid: u64,
    name: WpbStr,
    process_pid: i32,
    process_name: WpbStr,
    thread_tid: i64,
    thread_pid: i32,
    thread_name: WpbStr,
    child_ordering: i32,
    sibling_order_rank: i32,
    sibling_merge_behavior: i32,
    disallow_merging_with_system_tracks: u8,
    emit_disallow_merging_with_system_tracks: u8,
    interned_strings: WpbInternSet,
}

#[repr(C)]
pub struct WpbFtraceEvent {
    timestamp: u64,
    pid: u32,
    kind: u8,
    prev_comm: WpbStr,
    prev_pid: i32,
    prev_prio: i32,
    prev_state: i64,
    next_comm: WpbStr,
    next_pid: i32,
    next_prio: i32,
    comm: WpbStr,
    event_pid: i32,
    prio: i32,
    target_cpu: i32,
}

/// Reusable scratch buffers for emit_ftrace_bundle, kept on the writer so they
/// are allocated once and reused for every flushed bundle rather than per call.
#[derive(Default)]
struct FtraceScratch {
    pb_events: Vec<FtraceEvent>,
    intern_table: Vec<String>,
    intern_map: FxHashMap<String, u32>,
    sw_timestamp: Vec<u64>,
    sw_prev_state: Vec<i64>,
    sw_next_pid: Vec<i32>,
    sw_next_prio: Vec<i32>,
    sw_next_comm_index: Vec<u32>,
}

pub struct WpbWriter {
    write: WriteFn,
    ctx: *mut c_void,
    packet: TracePacket,
    track_event: Option<Box<TrackEvent>>,
    interned_data: Option<InternedData>,
    buf: Vec<u8>,
    ftrace: FtraceScratch,
}

impl WpbWriter {
    fn new(write: WriteFn, ctx: *mut c_void) -> Self {
        Self {
            write,
            ctx,
            packet: TracePacket::default(),
            track_event: Some(Box::new(TrackEvent::default())),
            interned_data: Some(InternedData::default()),
            buf: Vec::with_capacity(4096),
            ftrace: FtraceScratch::default(),
        }
    }

    fn emit_track_event(&mut self, ev: &WpbTrackEvent) -> Result<(), c_int> {
        let annots = checked_slice(ev.annots, ev.annot_cnt);
        let flow_ids = checked_slice(ev.flow_ids, ev.flow_cnt);
        let interns = checked_slice(ev.interns, ev.intern_cnt);

        {
            let te = self.track_event.as_mut().unwrap();
            reset_track_event(te);
            fill_track_event(te, ev, annots, flow_ids);
        }

        let has_interned_data = !interns.is_empty();
        if has_interned_data {
            let data = self.interned_data.as_mut().unwrap();
            reset_track_event_interned_data(data);
            fill_interned_data(data, interns);
        }

        self.packet.timestamp = Some(ev.ts);
        self.packet.sequence_flags = (ev.sequence_flags != 0).then_some(ev.sequence_flags);
        self.packet.optional_trusted_packet_sequence_id = if ev.trusted_packet_sequence_id != 0 {
            Some(
                trace_packet::OptionalTrustedPacketSequenceId::TrustedPacketSequenceId(
                    ev.trusted_packet_sequence_id,
                ),
            )
        } else {
            None
        };
        self.packet.data = Some(trace_packet::Data::TrackEvent(
            self.track_event.take().unwrap(),
        ));
        self.packet.interned_data = if has_interned_data {
            self.interned_data.take()
        } else {
            None
        };

        let res = encode_and_write_packet(&self.packet, &mut self.buf, self.write, self.ctx);
        self.restore_packet_state();
        res
    }

    fn emit_packet(&mut self, packet: &TracePacket) -> Result<(), c_int> {
        encode_and_write_packet(packet, &mut self.buf, self.write, self.ctx)
    }

    fn emit_clock_snapshot(&mut self, realtime_ts: u64) -> Result<(), c_int> {
        let mut packet = base_packet(WPB_SEQ_ID_THREADS);
        packet.data = Some(trace_packet::Data::ClockSnapshot(ClockSnapshot {
            clocks: vec![
                clock_snapshot::Clock {
                    clock_id: Some(CLOCK_BOOTTIME),
                    timestamp: Some(0),
                    ..clock_snapshot::Clock::default()
                },
                clock_snapshot::Clock {
                    clock_id: Some(CLOCK_REALTIME),
                    timestamp: Some(realtime_ts),
                    ..clock_snapshot::Clock::default()
                },
            ],
            ..ClockSnapshot::default()
        }));
        self.emit_packet(&packet)
    }

    fn emit_system_info(
        &mut self,
        hostname: Option<&WpbStr>,
        kernel: Option<&WpbStr>,
        arch: Option<&WpbStr>,
        num_cpus: u32,
    ) -> Result<(), c_int> {
        let mut packet = base_packet(WPB_SEQ_ID_THREADS);
        packet.data = Some(trace_packet::Data::SystemInfo(SystemInfo {
            utsname: Some(Utsname {
                sysname: read_optional_string(hostname),
                release: read_optional_string(kernel),
                machine: read_optional_string(arch),
                ..Utsname::default()
            }),
            num_cpus: (num_cpus != 0).then_some(num_cpus),
            ..SystemInfo::default()
        }));
        self.emit_packet(&packet)
    }

    fn emit_trace_attributes(&mut self, attrs: &[WpbAttr]) -> Result<(), c_int> {
        let mut pb_attrs = Vec::with_capacity(attrs.len());
        for attr in attrs {
            pb_attrs.push(trace_attributes::Attribute {
                key: read_string(&attr.key),
                value: read_string(&attr.val).map(trace_attributes::attribute::Value::StringValue),
            });
        }

        let mut packet = base_packet(WPB_SEQ_ID_THREADS);
        packet.data = Some(trace_packet::Data::TraceAttributes(TraceAttributes {
            attribute: pb_attrs,
        }));
        self.emit_packet(&packet)
    }

    fn emit_interned_data(&mut self, src: &WpbInternedData) -> Result<(), c_int> {
        let mut interned_data = InternedData::default();
        fill_packet_interned_data(&mut interned_data, src);

        let mut packet = base_packet(src.trusted_packet_sequence_id);
        packet.timestamp = Some(src.ts);
        packet.interned_data = Some(interned_data);
        self.emit_packet(&packet)
    }

    fn emit_trace_start(&mut self, src: &WpbInternedData) -> Result<(), c_int> {
        let mut interned_data = InternedData::default();
        fill_packet_interned_data(&mut interned_data, src);

        let mut packet = base_packet(WPB_SEQ_ID_THREADS);
        packet.timestamp = Some(0);
        packet.sequence_flags = Some(WPB_SEQ_INCREMENTAL_STATE_CLEARED);
        packet.interned_data = Some(interned_data);
        packet.data = Some(trace_packet::Data::TrackEvent(Box::new(TrackEvent {
            r#type: Some(WPB_TRACK_EVENT_INSTANT),
            name_field: Some(track_event::NameField::Name("START".to_owned())),
            ..TrackEvent::default()
        })));
        self.emit_packet(&packet)
    }

    fn emit_track_descriptor(&mut self, desc: &WpbTrackDescriptor) -> Result<(), c_int> {
        let mut td = TrackDescriptor {
            uuid: Some(desc.uuid),
            parent_uuid: (desc.parent_uuid != 0).then_some(desc.parent_uuid),
            child_ordering: (desc.child_ordering != 0).then_some(desc.child_ordering),
            ..TrackDescriptor::default()
        };

        match desc.kind {
            WPB_TRACK_DESCRIPTOR_GENERIC => {
                td.static_or_dynamic_name =
                    read_string(&desc.name).map(track_descriptor::StaticOrDynamicName::Name);
                td.disallow_merging_with_system_tracks =
                    (desc.emit_disallow_merging_with_system_tracks != 0)
                        .then_some(desc.disallow_merging_with_system_tracks != 0);
                td.sibling_order_rank =
                    (desc.sibling_order_rank != 0).then_some(desc.sibling_order_rank);
                td.sibling_merge_behavior =
                    (desc.sibling_merge_behavior != 0).then_some(desc.sibling_merge_behavior);
            }
            WPB_TRACK_DESCRIPTOR_PROCESS => {
                td.process = Some(ProcessDescriptor {
                    pid: Some(desc.process_pid),
                    process_name: read_string(&desc.process_name),
                    ..ProcessDescriptor::default()
                });
                td.sibling_order_rank = Some(desc.sibling_order_rank);
            }
            WPB_TRACK_DESCRIPTOR_THREAD => {
                td.thread = Some(ThreadDescriptor {
                    tid: Some(desc.thread_tid),
                    pid: Some(desc.thread_pid),
                    thread_name: read_string(&desc.thread_name),
                    ..ThreadDescriptor::default()
                });
                td.sibling_order_rank = Some(desc.sibling_order_rank);
            }
            _ => wpb_bug("unsupported track descriptor kind"),
        }

        let mut packet = base_packet(desc.trusted_packet_sequence_id);
        let interns = checked_intern_set(&desc.interned_strings);
        if !interns.is_empty() {
            let mut interned_data = InternedData::default();
            fill_interned_data(&mut interned_data, interns);
            packet.interned_data = Some(interned_data);
        }
        packet.data = Some(trace_packet::Data::TrackDescriptor(td));
        self.emit_packet(&packet)
    }

    fn emit_ftrace_bundle(&mut self, cpu: u32, events: &[WpbFtraceEvent]) -> Result<(), c_int> {
        use std::mem::take;

        // Per-bundle interned comm table; *_comm_index reference it by 0-based index.
        fn intern(table: &mut Vec<String>, map: &mut FxHashMap<String, u32>, comm: Option<String>) -> u32 {
            let comm = comm.unwrap_or_default();
            if let Some(&i) = map.get(&comm) {
                return i;
            }
            let i = table.len() as u32;
            table.push(comm.clone());
            map.insert(comm, i);
            i
        }

        // Reuse buffers across bundles: take the scratch off the writer, clear
        // (keeps capacity), refill, then reclaim them after encoding.
        let mut scr = take(&mut self.ftrace);
        scr.pb_events.clear();
        scr.intern_table.clear();
        scr.intern_map.clear();
        scr.sw_timestamp.clear();
        scr.sw_prev_state.clear();
        scr.sw_next_pid.clear();
        scr.sw_next_prio.clear();
        scr.sw_next_comm_index.clear();

        // sched_switch is encoded compactly (structure-of-arrays + interned
        // next_comm + delta timestamps). sched_waking / sched_wakeup_new stay as
        // verbose FtraceEvents in the same bundle.
        let mut prev_ts: u64 = 0;
        for event in events {
            match event.kind {
                WPB_FTRACE_SCHED_SWITCH => {
                    // Switches are produced in timestamp order (emitted at e->ts
                    // into the e->cpu bundle), so deltas are non-negative.
                    let ts = event.timestamp;
                    debug_assert!(ts >= prev_ts, "sched_switch timestamps not ordered within bundle");
                    let delta = if scr.sw_timestamp.is_empty() { ts } else { ts - prev_ts };
                    prev_ts = ts;
                    scr.sw_timestamp.push(delta);
                    scr.sw_prev_state.push(event.prev_state);
                    scr.sw_next_pid.push(event.next_pid);
                    scr.sw_next_prio.push(event.next_prio);
                    let idx = intern(&mut scr.intern_table, &mut scr.intern_map,
                                     read_string(&event.next_comm));
                    scr.sw_next_comm_index.push(idx);
                }
                WPB_FTRACE_SCHED_WAKING => {
                    scr.pb_events.push(FtraceEvent {
                        timestamp: Some(event.timestamp),
                        pid: Some(event.pid),
                        event: Some(ftrace_event::Event::SchedWaking(SchedWakingFtraceEvent {
                            comm: read_string(&event.comm),
                            pid: Some(event.event_pid),
                            prio: Some(event.prio),
                            target_cpu: Some(event.target_cpu),
                            ..SchedWakingFtraceEvent::default()
                        })),
                        ..FtraceEvent::default()
                    });
                }
                WPB_FTRACE_SCHED_WAKEUP_NEW => {
                    scr.pb_events.push(FtraceEvent {
                        timestamp: Some(event.timestamp),
                        pid: Some(event.pid),
                        event: Some(ftrace_event::Event::SchedWakeupNew(SchedWakeupNewFtraceEvent {
                            comm: read_string(&event.comm),
                            pid: Some(event.event_pid),
                            prio: Some(event.prio),
                            target_cpu: Some(event.target_cpu),
                            ..SchedWakeupNewFtraceEvent::default()
                        })),
                        ..FtraceEvent::default()
                    });
                }
                _ => wpb_bug("unsupported ftrace event kind"),
            }
        }

        // Move buffers into the packet for encoding (reclaimed afterwards).
        let compact_sched = if scr.sw_timestamp.is_empty() {
            None
        } else {
            Some(ftrace_event_bundle::CompactSched {
                intern_table: take(&mut scr.intern_table),
                switch_timestamp: take(&mut scr.sw_timestamp),
                switch_prev_state: take(&mut scr.sw_prev_state),
                switch_next_pid: take(&mut scr.sw_next_pid),
                switch_next_prio: take(&mut scr.sw_next_prio),
                switch_next_comm_index: take(&mut scr.sw_next_comm_index),
                ..ftrace_event_bundle::CompactSched::default()
            })
        };

        let mut packet = base_packet(WPB_SEQ_ID_THREADS);
        packet.data = Some(trace_packet::Data::FtraceEvents(FtraceEventBundle {
            cpu: Some(cpu),
            event: take(&mut scr.pb_events),
            compact_sched,
            ..FtraceEventBundle::default()
        }));
        let res = self.emit_packet(&packet);

        // Reclaim buffers (capacity intact) back into the scratch for next time.
        if let Some(trace_packet::Data::FtraceEvents(b)) = &mut packet.data {
            scr.pb_events = take(&mut b.event);
            if let Some(cs) = &mut b.compact_sched {
                scr.intern_table = take(&mut cs.intern_table);
                scr.sw_timestamp = take(&mut cs.switch_timestamp);
                scr.sw_prev_state = take(&mut cs.switch_prev_state);
                scr.sw_next_pid = take(&mut cs.switch_next_pid);
                scr.sw_next_prio = take(&mut cs.switch_next_prio);
                scr.sw_next_comm_index = take(&mut cs.switch_next_comm_index);
            }
        }
        self.ftrace = scr;
        res
    }

    fn restore_packet_state(&mut self) {
        match self.packet.data.take() {
            Some(trace_packet::Data::TrackEvent(te)) => self.track_event = Some(te),
            _ => wpb_bug("missing TrackEvent after encode"),
        }
        if let Some(data) = self.packet.interned_data.take() {
            self.interned_data = Some(data);
        }
    }
}

fn encode_and_write_packet(
    packet: &TracePacket,
    buf: &mut Vec<u8>,
    write: WriteFn,
    ctx: *mut c_void,
) -> Result<(), c_int> {
    let packet_len = packet.encoded_len();

    buf.clear();
    buf.reserve(1 + encoded_varint_len(packet_len as u64) + packet_len);
    buf.push(TRACE_PACKET_KEY);
    encode_varint(packet_len as u64, buf);
    if packet.encode(buf).is_err() {
        wpb_bug("TracePacket encoding into Vec failed");
    }

    let ret = unsafe { write(ctx, buf.as_ptr(), buf.len()) };
    if ret == 0 {
        Ok(())
    } else if ret < 0 {
        Err(ret)
    } else {
        Err(-EIO)
    }
}

fn checked_slice<'a, T>(ptr: *const T, len: usize) -> &'a [T] {
    if len == 0 {
        &[]
    } else if ptr.is_null() {
        wpb_bug("non-empty slice has null pointer")
    } else {
        unsafe { slice::from_raw_parts(ptr, len) }
    }
}

fn wpb_bug(msg: &str) -> ! {
    eprintln!("wprof protobuf encoder BUG: {msg}");
    std::process::abort();
}

fn wpb_emit_failed(packet: &str, err: c_int) -> ! {
    eprintln!("Failed to encode {packet} through Rust protobuf encoder: {err}");
    std::process::exit(1);
}

fn encoded_varint_len(mut val: u64) -> usize {
    let mut len = 1;
    while val >= 0x80 {
        val >>= 7;
        len += 1;
    }
    len
}

fn encode_varint(mut val: u64, buf: &mut Vec<u8>) {
    while val >= 0x80 {
        buf.push((val as u8) | 0x80);
        val >>= 7;
    }
    buf.push(val as u8);
}

fn reset_track_event(te: &mut TrackEvent) {
    te.category_iids.clear();
    te.categories.clear();
    te.r#type = None;
    te.track_uuid = None;
    te.flow_ids.clear();
    te.debug_annotations.clear();
    te.name_field = None;
    te.callstack_field = None;
}

fn fill_track_event(te: &mut TrackEvent, ev: &WpbTrackEvent, annots: &[WpbAnnot], flow_ids: &[u64]) {
    te.r#type = (ev.event_type != 0).then_some(ev.event_type);
    te.track_uuid = (ev.track_uuid != 0).then_some(ev.track_uuid);

    if ev.name.iid != 0 {
        te.name_field = Some(track_event::NameField::NameIid(ev.name.iid));
    } else if let Some(name) = read_string(&ev.name) {
        te.name_field = Some(track_event::NameField::Name(name));
    }

    if ev.category.iid != 0 {
        te.category_iids.push(ev.category.iid);
    } else if let Some(category) = read_string(&ev.category) {
        te.categories.push(category);
    }

    te.flow_ids.extend_from_slice(flow_ids);

    if ev.callstack_iid > 0 {
        te.callstack_field = Some(track_event::CallstackField::CallstackIid(
            ev.callstack_iid as u64,
        ));
    }

    te.debug_annotations.reserve(annots.len());
    for ann in annots {
        te.debug_annotations.push(convert_annotation(ann));
    }
}

fn reset_track_event_interned_data(data: &mut InternedData) {
    data.event_names.clear();
    data.debug_annotation_names.clear();
    data.debug_annotation_string_values.clear();
}

fn read_bytes(s: &WpbStr) -> Option<&[u8]> {
    if s.s.is_null() {
        if s.len == 0 {
            return None;
        }
        wpb_bug("non-empty string has null pointer");
    }
    Some(unsafe { slice::from_raw_parts(s.s as *const u8, s.len) })
}

fn read_string(s: &WpbStr) -> Option<String> {
    read_bytes(s).map(|bytes| String::from_utf8_lossy(bytes).into_owned())
}

fn read_optional_string(s: Option<&WpbStr>) -> Option<String> {
    s.and_then(read_string)
}

fn base_packet(seq_id: u32) -> TracePacket {
    let mut packet = TracePacket::default();
    set_trusted_sequence_id(&mut packet, seq_id);
    packet
}

fn set_trusted_sequence_id(packet: &mut TracePacket, seq_id: u32) {
    if seq_id != 0 {
        packet.optional_trusted_packet_sequence_id = Some(
            trace_packet::OptionalTrustedPacketSequenceId::TrustedPacketSequenceId(seq_id),
        );
    }
}

fn intern_bytes(intern: &WpbIntern) -> &[u8] {
    if intern.s.is_null() {
        if intern.len == 0 {
            return &[];
        }
        wpb_bug("non-empty interned string has null pointer");
    }
    unsafe { slice::from_raw_parts(intern.s as *const u8, intern.len) }
}

fn fill_interned_strings(dst: &mut Vec<InternedString>, src: &[WpbIntern]) {
    dst.reserve(src.len());
    for intern in src {
        let bytes = intern_bytes(intern);
        dst.push(InternedString {
            iid: Some(intern.iid),
            str: Some(bytes.to_vec()),
        });
    }
}

fn fill_event_categories(dst: &mut Vec<EventCategory>, src: &[WpbIntern]) {
    dst.reserve(src.len());
    for intern in src {
        let bytes = intern_bytes(intern);
        dst.push(EventCategory {
            iid: Some(intern.iid),
            name: Some(String::from_utf8_lossy(bytes).into_owned()),
        });
    }
}

fn fill_event_names(dst: &mut Vec<EventName>, src: &[WpbIntern]) {
    dst.reserve(src.len());
    for intern in src {
        let bytes = intern_bytes(intern);
        dst.push(EventName {
            iid: Some(intern.iid),
            name: Some(String::from_utf8_lossy(bytes).into_owned()),
        });
    }
}

fn fill_debug_annotation_names(dst: &mut Vec<DebugAnnotationName>, src: &[WpbIntern]) {
    dst.reserve(src.len());
    for intern in src {
        let bytes = intern_bytes(intern);
        dst.push(DebugAnnotationName {
            iid: Some(intern.iid),
            name: Some(String::from_utf8_lossy(bytes).into_owned()),
        });
    }
}

fn convert_annotation(ann: &WpbAnnot) -> DebugAnnotation {
    let name_field = if ann.name.iid != 0 {
        Some(debug_annotation::NameField::NameIid(ann.name.iid))
    } else {
        read_string(&ann.name).map(debug_annotation::NameField::Name)
    };

    let value = unsafe {
        match ann.kind {
            WPB_ANN_BOOL => Some(debug_annotation::Value::BoolValue(ann.val.b != 0)),
            WPB_ANN_UINT => Some(debug_annotation::Value::UintValue(ann.val.u)),
            WPB_ANN_INT => Some(debug_annotation::Value::IntValue(ann.val.i)),
            WPB_ANN_DOUBLE => Some(debug_annotation::Value::DoubleValue(ann.val.d)),
            WPB_ANN_PTR => Some(debug_annotation::Value::PointerValue(ann.val.ptr)),
            WPB_ANN_STR => read_string(&ann.val.s).map(debug_annotation::Value::StringValue),
            WPB_ANN_STR_IID => Some(debug_annotation::Value::StringValueIid(ann.val.s.iid)),
            _ => wpb_bug("unsupported annotation kind"),
        }
    };

    DebugAnnotation {
        name_field,
        value,
        ..DebugAnnotation::default()
    }
}

fn fill_interned_data(data: &mut InternedData, interns: &[WpbIntern]) {
    fill_event_names(&mut data.event_names, interns);
    fill_debug_annotation_names(&mut data.debug_annotation_names, interns);
    fill_interned_strings(&mut data.debug_annotation_string_values, interns);
}

fn checked_intern_set(set: &WpbInternSet) -> &[WpbIntern] {
    checked_slice(set.entries, set.cnt)
}

fn fill_packet_interned_data(data: &mut InternedData, src: &WpbInternedData) {
    fill_event_categories(&mut data.event_categories, checked_intern_set(&src.event_categories));
    fill_event_names(&mut data.event_names, checked_intern_set(&src.event_names));
    fill_debug_annotation_names(
        &mut data.debug_annotation_names,
        checked_intern_set(&src.debug_annotation_names),
    );
    fill_interned_strings(
        &mut data.debug_annotation_string_values,
        checked_intern_set(&src.debug_annotation_string_values),
    );
    fill_interned_strings(&mut data.function_names, checked_intern_set(&src.function_names));

    let mappings = checked_slice(src.mappings, src.mapping_cnt);
    data.mappings.reserve(mappings.len());
    for mapping in mappings {
        data.mappings.push(Mapping {
            iid: Some(mapping.iid),
            start: Some(mapping.start),
            end: Some(mapping.end),
            start_offset: Some(mapping.start_offset),
            ..Mapping::default()
        });
    }

    let frames = checked_slice(src.frames, src.frame_cnt);
    data.frames.reserve(frames.len());
    for frame in frames {
        data.frames.push(Frame {
            iid: Some(frame.iid),
            function_name_id: Some(frame.function_name_id),
            mapping_id: Some(frame.mapping_id),
            rel_pc: Some(frame.rel_pc),
            ..Frame::default()
        });
    }

    let callstacks = checked_slice(src.callstacks, src.callstack_cnt);
    data.callstacks.reserve(callstacks.len());
    for callstack in callstacks {
        let frame_ids = checked_slice(callstack.frame_ids, callstack.frame_cnt);
        data.callstacks.push(Callstack {
            iid: Some(callstack.iid),
            frame_ids: frame_ids.iter().map(|id| *id as u64).collect(),
        });
    }
}

#[no_mangle]
pub unsafe extern "C" fn wpb_writer_new(
    write: Option<WriteFn>,
    ctx: *mut c_void,
) -> *mut WpbWriter {
    let Some(write) = write else {
        return ptr::null_mut();
    };
    Box::into_raw(Box::new(WpbWriter::new(write, ctx)))
}

#[no_mangle]
pub unsafe extern "C" fn wpb_writer_free(writer: *mut WpbWriter) {
    if !writer.is_null() {
        drop(Box::from_raw(writer));
    }
}

#[no_mangle]
pub unsafe extern "C" fn wpb_emit_track_event(
    writer: *mut WpbWriter,
    ev: *const WpbTrackEvent,
) {
    if writer.is_null() || ev.is_null() {
        wpb_emit_failed("TrackEvent", -EINVAL);
    }

    if let Err(err) = (*writer).emit_track_event(&*ev) {
        wpb_emit_failed("TrackEvent", err);
    }
}

#[no_mangle]
pub unsafe extern "C" fn wpb_emit_clock_snapshot(
    writer: *mut WpbWriter,
    realtime_ts: u64,
) {
    if writer.is_null() {
        wpb_emit_failed("ClockSnapshot", -EINVAL);
    }

    if let Err(err) = (*writer).emit_clock_snapshot(realtime_ts) {
        wpb_emit_failed("ClockSnapshot", err);
    }
}

#[no_mangle]
pub unsafe extern "C" fn wpb_emit_system_info(
    writer: *mut WpbWriter,
    hostname: *const WpbStr,
    kernel: *const WpbStr,
    arch: *const WpbStr,
    num_cpus: u32,
) {
    if writer.is_null() {
        wpb_emit_failed("SystemInfo", -EINVAL);
    }

    if let Err(err) = (*writer).emit_system_info(hostname.as_ref(), kernel.as_ref(), arch.as_ref(), num_cpus) {
        wpb_emit_failed("SystemInfo", err);
    }
}

#[no_mangle]
pub unsafe extern "C" fn wpb_emit_trace_attributes(
    writer: *mut WpbWriter,
    attrs: *const WpbAttr,
    attr_cnt: usize,
) {
    if writer.is_null() {
        wpb_emit_failed("TraceAttributes", -EINVAL);
    }

    let attrs = checked_slice(attrs, attr_cnt);

    if let Err(err) = (*writer).emit_trace_attributes(attrs) {
        wpb_emit_failed("TraceAttributes", err);
    }
}

#[no_mangle]
pub unsafe extern "C" fn wpb_emit_interned_data(
    writer: *mut WpbWriter,
    data: *const WpbInternedData,
) {
    if writer.is_null() || data.is_null() {
        wpb_emit_failed("InternedData", -EINVAL);
    }

    if let Err(err) = (*writer).emit_interned_data(&*data) {
        wpb_emit_failed("InternedData", err);
    }
}

#[no_mangle]
pub unsafe extern "C" fn wpb_emit_trace_start(
    writer: *mut WpbWriter,
    data: *const WpbInternedData,
) {
    if writer.is_null() || data.is_null() {
        wpb_emit_failed("trace start", -EINVAL);
    }

    if let Err(err) = (*writer).emit_trace_start(&*data) {
        wpb_emit_failed("trace start", err);
    }
}

#[no_mangle]
pub unsafe extern "C" fn wpb_emit_track_descriptor(
    writer: *mut WpbWriter,
    desc: *const WpbTrackDescriptor,
) {
    if writer.is_null() || desc.is_null() {
        wpb_emit_failed("TrackDescriptor", -EINVAL);
    }

    if let Err(err) = (*writer).emit_track_descriptor(&*desc) {
        wpb_emit_failed("TrackDescriptor", err);
    }
}

#[no_mangle]
pub unsafe extern "C" fn wpb_emit_ftrace_bundle(
    writer: *mut WpbWriter,
    cpu: u32,
    events: *const WpbFtraceEvent,
    event_cnt: usize,
) {
    if writer.is_null() {
        wpb_emit_failed("FtraceEventBundle", -EINVAL);
    }

    let events = checked_slice(events, event_cnt);

    if let Err(err) = (*writer).emit_ftrace_bundle(cpu, events) {
        wpb_emit_failed("FtraceEventBundle", err);
    }
}
