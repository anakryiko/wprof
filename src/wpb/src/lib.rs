// SPDX-License-Identifier: (LGPL-2.1 OR BSD-2-Clause)
//! C-compatible protobuf encoder for wprof trace packets.

use std::ffi::{c_char, c_int, c_void};
use std::ptr;
use std::slice;

use prost::Message;

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

pub struct WpbWriter {
    write: WriteFn,
    ctx: *mut c_void,
    packet: TracePacket,
    track_event: Option<Box<TrackEvent>>,
    interned_data: Option<InternedData>,
    buf: Vec<u8>,
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
        }
    }

    fn emit_track_event(&mut self, ev: &WpbTrackEvent) -> Result<usize, c_int> {
        let annots = checked_slice(ev.annots, ev.annot_cnt)?;
        let flow_ids = checked_slice(ev.flow_ids, ev.flow_cnt)?;
        let interns = checked_slice(ev.interns, ev.intern_cnt)?;

        {
            let te = self
                .track_event
                .get_or_insert_with(|| Box::new(TrackEvent::default()));
            reset_track_event(te);
            fill_track_event(te, ev, annots, flow_ids)?;
        }

        let has_interned_data = !interns.is_empty();
        {
            let data = self.interned_data.get_or_insert_with(InternedData::default);
            reset_interned_data(data);
            if has_interned_data {
                fill_interned_data(data, interns)?;
            }
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

        let res = self.encode_and_write_packet();
        self.restore_packet_state();
        res
    }

    fn encode_and_write_packet(&mut self) -> Result<usize, c_int> {
        let packet_len = self.packet.encoded_len();

        self.buf.clear();
        self.buf
            .reserve(1 + encoded_varint_len(packet_len as u64) + packet_len);
        self.buf.push(TRACE_PACKET_KEY);
        encode_varint(packet_len as u64, &mut self.buf);
        self.packet.encode(&mut self.buf).map_err(|_| -EIO)?;

        let ret = unsafe { (self.write)(self.ctx, self.buf.as_ptr(), self.buf.len()) };
        if ret == 0 {
            Ok(self.buf.len())
        } else if ret < 0 {
            Err(ret)
        } else {
            Err(-EIO)
        }
    }

    fn restore_packet_state(&mut self) {
        if let Some(trace_packet::Data::TrackEvent(te)) = self.packet.data.take() {
            self.track_event = Some(te);
        }
        if let Some(data) = self.packet.interned_data.take() {
            self.interned_data = Some(data);
        }
    }
}

fn checked_slice<'a, T>(ptr: *const T, len: usize) -> Result<&'a [T], c_int> {
    if len == 0 {
        Ok(&[])
    } else if ptr.is_null() {
        Err(-EINVAL)
    } else {
        Ok(unsafe { slice::from_raw_parts(ptr, len) })
    }
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

fn fill_track_event(
    te: &mut TrackEvent,
    ev: &WpbTrackEvent,
    annots: &[WpbAnnot],
    flow_ids: &[u64],
) -> Result<(), c_int> {
    te.r#type = (ev.event_type != 0).then_some(ev.event_type);
    te.track_uuid = (ev.track_uuid != 0).then_some(ev.track_uuid);

    if ev.name.iid != 0 {
        te.name_field = Some(track_event::NameField::NameIid(ev.name.iid));
    } else if let Some(name) = read_string(&ev.name)? {
        te.name_field = Some(track_event::NameField::Name(name));
    }

    if ev.category.iid != 0 {
        te.category_iids.push(ev.category.iid);
    } else if let Some(category) = read_string(&ev.category)? {
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
        te.debug_annotations.push(convert_annotation(ann)?);
    }

    Ok(())
}

fn reset_interned_data(data: &mut InternedData) {
    data.event_names.clear();
    data.debug_annotation_names.clear();
    data.debug_annotation_string_values.clear();
}

fn read_bytes(s: &WpbStr) -> Result<Option<&[u8]>, c_int> {
    if s.s.is_null() {
        if s.len == 0 {
            return Ok(None);
        }
        return Err(-EINVAL);
    }
    Ok(Some(unsafe { slice::from_raw_parts(s.s as *const u8, s.len) }))
}

fn read_string(s: &WpbStr) -> Result<Option<String>, c_int> {
    let Some(bytes) = read_bytes(s)? else {
        return Ok(None);
    };
    Ok(Some(String::from_utf8_lossy(bytes).into_owned()))
}

fn convert_annotation(ann: &WpbAnnot) -> Result<DebugAnnotation, c_int> {
    let name_field = if ann.name.iid != 0 {
        Some(debug_annotation::NameField::NameIid(ann.name.iid))
    } else {
        read_string(&ann.name)?.map(debug_annotation::NameField::Name)
    };

    let value = unsafe {
        match ann.kind {
            WPB_ANN_BOOL => Some(debug_annotation::Value::BoolValue(ann.val.b != 0)),
            WPB_ANN_UINT => Some(debug_annotation::Value::UintValue(ann.val.u)),
            WPB_ANN_INT => Some(debug_annotation::Value::IntValue(ann.val.i)),
            WPB_ANN_DOUBLE => Some(debug_annotation::Value::DoubleValue(ann.val.d)),
            WPB_ANN_PTR => Some(debug_annotation::Value::PointerValue(ann.val.ptr)),
            WPB_ANN_STR => read_string(&ann.val.s)?.map(debug_annotation::Value::StringValue),
            WPB_ANN_STR_IID => Some(debug_annotation::Value::StringValueIid(ann.val.s.iid)),
            _ => return Err(-EINVAL),
        }
    };

    Ok(DebugAnnotation {
        name_field,
        value,
        ..DebugAnnotation::default()
    })
}

fn fill_interned_data(data: &mut InternedData, interns: &[WpbIntern]) -> Result<(), c_int> {
    data.event_names.reserve(interns.len());
    data.debug_annotation_names.reserve(interns.len());
    data.debug_annotation_string_values.reserve(interns.len());

    for intern in interns {
        if intern.s.is_null() && intern.len > 0 {
            return Err(-EINVAL);
        }
        let bytes = if intern.s.is_null() {
            &[][..]
        } else {
            unsafe { slice::from_raw_parts(intern.s as *const u8, intern.len) }
        };
        data.event_names.push(EventName {
            iid: Some(intern.iid),
            name: Some(bytes.to_vec()),
        });
        data.debug_annotation_names.push(DebugAnnotationName {
            iid: Some(intern.iid),
            name: Some(bytes.to_vec()),
        });
        data.debug_annotation_string_values.push(InternedString {
            iid: Some(intern.iid),
            str: Some(bytes.to_vec()),
        });
    }

    Ok(())
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
) -> isize {
    if writer.is_null() || ev.is_null() {
        return (-EINVAL) as isize;
    }

    match (*writer).emit_track_event(&*ev) {
        Ok(n) => n as isize,
        Err(err) => err as isize,
    }
}
