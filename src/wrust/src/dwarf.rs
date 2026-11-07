use std::borrow::Cow;
use std::cell::RefCell;
use std::collections::{HashMap, HashSet};
use std::ffi::{CStr, CString};
use std::fs::File;
use std::io;
use std::mem::MaybeUninit;
use std::num::NonZeroUsize;
use std::ops::Deref;
use std::path::Path;
use std::ptr;
use std::sync::Arc;

use gimli::{AttributeValue, EndianReader, Reader, RunTimeEndian, SectionId};
use libc::c_char;
use lru::LruCache;
use memmap2::Mmap;
use object::{Object, ObjectSection};
use path_clean::PathClean;

#[derive(Debug, Clone)]
enum SectionBytes {
    Mapped(Arc<Mmap>),
    Owned(Arc<[u8]>),
}

impl Deref for SectionBytes {
    type Target = [u8];

    fn deref(&self) -> &[u8] {
        match self {
            Self::Mapped(mapping) => mapping,
            Self::Owned(bytes) => bytes,
        }
    }
}

// Moving or cloning the owner keeps the same backing bytes at the same address.
unsafe impl gimli::StableDeref for SectionBytes {}
unsafe impl gimli::CloneStableDeref for SectionBytes {}

type SectionReader = EndianReader<RunTimeEndian, SectionBytes>;
type Dwarf = gimli::Dwarf<SectionReader>;
type Unit = gimli::Unit<SectionReader>;
type DebuggingInformationEntry = gimli::DebuggingInformationEntry<SectionReader>;

#[repr(C)]
pub struct DwarfFuncAddr {
    pub addr: u64,
    pub file_name: *const c_char,
    pub is_inline: bool,
}

// Compilation units are costly to re-parse and expensive to keep all
// of them in-memory, hence resort to an LRU cache.
// Used when processing cross compilation unit references.
struct UnitsCache {
    dwarf: Dwarf,
    // Sorted unit header offsets in .debug_info, used to find the unit
    // containing a DW_FORM_ref_addr target.
    unit_offsets: Vec<gimli::DebugInfoOffset>,
    // Recently parsed units, keyed by header offset. Avoid reparsing
    // referenced units without retaining every unit in memory.
    units: RefCell<LruCache<gimli::DebugInfoOffset, Arc<Unit>>>,
    // Unit languages, keyed by header offset. Avoid rescanning unit DIEs
    // for DW_AT_language each time a name needs demangling.
    languages: RefCell<LruCache<usize, Option<gimli::DwLang>>>,
}

pub struct DwarfInfo {
    elf_path: CString,
    // Linked ELF addresses, before applying the running kernel's KASLR slide.
    func_addrs: HashMap<String, Vec<DwarfFuncAddr>>,
    // Owns the string buffers referenced by `DwarfFuncAddr::file_name` in `func_addrs`.
    // Buffer addresses do not change when the set grows.
    file_names: HashSet<CString>,
}

impl UnitsCache {
    fn new(dwarf: Dwarf) -> gimli::Result<Self> {
        let mut unit_offsets = Vec::new();
        let mut headers = dwarf.units();
        while let Some(header) = headers.next()? {
            unit_offsets.push(header.debug_info_offset().unwrap());
        }
        Ok(Self {
            dwarf,
            unit_offsets,
            units: RefCell::new(LruCache::new(NonZeroUsize::new(8).unwrap())),
            languages: RefCell::new(LruCache::new(NonZeroUsize::new(8).unwrap())),
        })
    }

    // `offset` is an offset of a DIE or of a compilation unit.
    // Returned values survive cache eviction.
    fn find_containing_unit(&self, offset: gimli::DebugInfoOffset) -> Option<Arc<Unit>> {
        let header_offset = match self.unit_offsets.binary_search(&offset) {
            Ok(i) => self.unit_offsets[i],
            Err(0) => return None,
            Err(i) => self.unit_offsets[i - 1],
        };
        let cached = self.units.borrow_mut().get(&header_offset).cloned();
        let unit = if let Some(unit) = cached {
            unit
        } else {
            let header = self.dwarf.unit_header(header_offset).ok()?;
            let unit = Arc::new(self.dwarf.unit(header).ok()?);
            self.units.borrow_mut().put(header_offset, Arc::clone(&unit));
            unit
        };
        if offset.0 - header_offset.0 >= unit.header.length_including_self() {
            return None;
        }
        Some(unit)
    }

    // Search top-level unit attributes for DW_AT_language entry.
    fn unit_language(&self, unit: &Unit) -> Option<gimli::DwLang> {
        let offset = unit.header.offset().0;
        if let Some(language) = self.languages.borrow_mut().get(&offset).copied() {
            return language;
        }
        let mut language = None;
        let mut entries = unit.entries();
        if entries.next_entry().is_ok() {
            while let Some(die) = entries.current() {
                if let Some(AttributeValue::Language(value)) = die.attr_value(gimli::DW_AT_language) {
                    language = Some(value);
                    break;
                }
                if entries.next_sibling().is_err() {
                    break;
                }
            }
        }
        self.languages.borrow_mut().put(offset, language);
        language
    }
}

// An attribute can encode an offset of some DIE as relative to
// attribute's unit header (DW_FORM_ref{1,2,4,8,_udata}),
// or relative to a .debug_info section (DW_FORM_ref_addr).
// Convert such references to a pair (unit, unit-local-offset).
fn resolve_formref(
    ctx: &UnitsCache,
    unit: &Arc<Unit>,
    value: AttributeValue<SectionReader>,
) -> Option<(Arc<Unit>, gimli::UnitOffset)> {
    match value {
        AttributeValue::UnitRef(offset) => Some((Arc::clone(unit), offset)),
        AttributeValue::DebugInfoRef(offset) => {
            let unit = ctx.find_containing_unit(offset)?;
            let offset = offset.to_unit_offset(&unit.header)?;
            Some((unit, offset))
        }
        _ => None,
    }
}

// Search this DIE and its DW_AT_abstract_origin/DW_AT_specification links,
// returning the first value produced by `matcher`.
// Necessary e.g. to recover information about DW_TAG_inlined_subroutine origins:
//
// 0x03926e3d: DW_TAG_subprogram   <-----------------------------------------------.
//               DW_AT_name	("vfs_write")                                      |
//               DW_AT_decl_file	("/rw/compile/fs/read_write.c")            |
//                                                                                 |
// 0x039276e9: DW_TAG_subprogram                                                   |
//               DW_AT_name	("__x64_sys_write")                                |
//                                                                                 |
// 0x0392780a:           DW_TAG_inlined_subroutine                                 |
//                         DW_AT_abstract_origin	(0x03926e3d "vfs_write") --'
//                         DW_AT_ranges	(0x0023fdd0
//                                       [0xffffffff81ec6b59, 0xffffffff81ec6c67)
//                                       [0xffffffff81ec6ca7, 0xffffffff81ec6e82)
//                                       [0xffffffff81ec6e9c, 0xffffffff81ec7047))
//
// Note how inlined subroutine name and decl_file are available
// through an DW_AT_abstract_origin link.
// Some libraries (e.g libdw) hide these details from the users,
// but gimli is hardcore.
fn find_inherited_value<T>(
    ctx: &UnitsCache,
    unit: &Arc<Unit>,
    entry: &DebuggingInformationEntry,
    recursion_limit: usize,
    matcher: &mut impl FnMut(&Unit, &DebuggingInformationEntry) -> Option<T>,
) -> Option<T> {
    if recursion_limit == 0 {
        return None;
    }
    if let Some(value) = matcher(unit, entry) {
        return Some(value);
    }
    for attr in [gimli::DW_AT_abstract_origin, gimli::DW_AT_specification] {
        let Some((unit, offset)) = entry.attr_value(attr).and_then(|value| resolve_formref(ctx, unit, value)) else {
            continue;
        };
        let origin = unit.entry(offset).ok()?;
        if let Some(value) = find_inherited_value(ctx, &unit, &origin, recursion_limit - 1, matcher) {
            return Some(value);
        }
    }
    None
}

fn entry_name(ctx: &UnitsCache, unit: &Arc<Unit>, entry: &DebuggingInformationEntry) -> Option<String> {
    find_inherited_value(ctx, unit, entry, 16, &mut |unit, entry| {
        for attr in [gimli::DW_AT_linkage_name, gimli::DW_AT_MIPS_linkage_name, gimli::DW_AT_name] {
            if let Some(value) = entry.attr_value(attr) {
                let name = ctx.dwarf.attr_string(unit, value).ok()?;
                return Some(addr2line::demangle_auto(name.to_string_lossy().ok()?, ctx.unit_language(unit)).into_owned());
            }
        }
        None
    })
}

fn entry_decl_file(ctx: &UnitsCache, unit: &Arc<Unit>, entry: &DebuggingInformationEntry) -> Option<String> {
    find_inherited_value(ctx, unit, entry, 16, &mut |unit, entry| {
        let AttributeValue::FileIndex(index) = entry.attr_value(gimli::DW_AT_decl_file)? else {
            return None;
        };
        let header = unit.line_program.as_ref()?.header();
        let file = header.file(index)?;
        let name = ctx.dwarf.attr_string(unit, file.path_name()).ok()?;
        let name = name.to_string_lossy().ok()?;
        let mut path = Path::new(name.as_ref()).to_path_buf();
        // Append file directory if DW_LNCT_directory_index is specified.
        if !path.is_absolute() {
            if let Some(directory) = file.directory(header) {
                let directory = ctx.dwarf.attr_string(unit, directory).ok()?;
                let directory = directory.to_string_lossy().ok()?;
                path = Path::new(directory.as_ref()).join(path);
            }
        }
        Some(path.clean().to_string_lossy().into_owned())
    })
}

impl DwarfInfo {
    fn new(elf_path: &Path) -> Self {
        Self {
            elf_path: CString::new(elf_path.as_os_str().as_encoded_bytes()).unwrap(),
            func_addrs: HashMap::new(),
            file_names: HashSet::new(),
        }
    }

    fn collect_func_addrs(&mut self, ctx: &UnitsCache, func_names: &HashSet<&str>) -> gimli::Result<()> {
        for &offset in &ctx.unit_offsets {
            let unit = ctx.find_containing_unit(offset)
                .ok_or(gimli::Error::NoEntryAtGivenOffset(offset.0 as u64))?;
            let mut entries = unit.entries();
            while let Some(entry) = entries.next_dfs()? {
                let is_inline = match entry.tag() {
                    gimli::DW_TAG_inlined_subroutine => true,
                    gimli::DW_TAG_subprogram => false,
                    _ => continue,
                };
                // Empirically, DW_AT_entry_pc is produced by gcc but not by clang.
                let mut addr = match entry.attr_value(gimli::DW_AT_entry_pc) {
                    Some(value) => ctx.dwarf.attr_address(&unit, value)?,
                    None => None,
                };
                if addr.is_none() {
                    // die_ranges() looks for both DW_AT_low_pc/DW_AT_high_pc and DW_AT_ranges.
                    addr = ctx.dwarf.die_ranges(&unit, entry)?.next()?.map(|range| range.begin);
                }
                let Some(addr) = addr else { continue };
                let Some(name) = entry_name(ctx, &unit, entry) else { continue };
                if !func_names.contains(name.as_str()) {
                    continue;
                }
                let file_name = match entry_decl_file(ctx, &unit, entry) {
                    Some(file) => {
                        let file = CString::new(file).unwrap();
                        match self.file_names.get(file.as_c_str()) {
                            Some(file) => file.as_ptr(),
                            None => {
                                let ptr = file.as_ptr();
                                self.file_names.insert(file);
                                ptr
                            }
                        }
                    }
                    None => ptr::null(),
                };
                self.func_addrs.entry(name).or_default().push(DwarfFuncAddr { addr, file_name, is_inline });
            }
        }
        Ok(())
    }
}

fn read_section(
    id: SectionId,
    elf: &object::File<'_>,
    mapped: &SectionReader,
    path: &Path,
) -> Result<SectionReader, ()> {
    let Some(section) = elf.section_by_name(id.name()) else {
        // Dwarf::load doc says that it expects an empty reader for missing sections.
        return Ok(mapped.range(0..0));
    };

    let bytes = section.uncompressed_data().map_err(|err| {
        vprintf!(
            "dwarf: failed to load section '{}' from {}: {err}",
            id.name(),
            path.display(),
        );
    })?;
    let reader = match bytes {
        Cow::Borrowed(bytes) => {
            let (offset, _) = section.file_range().unwrap_or_default();
            let start = offset as usize;
            mapped.range(start..start + bytes.len())
        }
        Cow::Owned(bytes) => {
            SectionReader::new(SectionBytes::Owned(Arc::from(bytes)), mapped.endian())
        }
    };
    Ok(reader)
}

fn load_dwarf(path: &Path, func_names: &HashSet<&str>) -> Option<DwarfInfo> {
    let file = File::open(path)
        .inspect_err(|err| vprintf!("dwarf: failed to open {}: {err}", path.display()))
        .ok()?;
    let data = unsafe { Mmap::map(&file) }
        .inspect_err(|err| vprintf!("dwarf: failed to map {}: {err}", path.display()))
        .ok()?;
    let data = Arc::new(data);
    let elf = object::File::parse(&data[..])
        .inspect_err(|err| vprintf!("dwarf: failed to parse {}: {err}", path.display()))
        .ok()?;
    let endian = if elf.is_little_endian() {
        RunTimeEndian::Little
    } else {
        RunTimeEndian::Big
    };
    let mapped = SectionReader::new(SectionBytes::Mapped(Arc::clone(&data)), endian);
    let dwarf = Dwarf::load(|id| read_section(id, &elf, &mapped, path)).ok()?;
    let ctx = UnitsCache::new(dwarf)
        .inspect_err(|err| vprintf!("dwarf: failed to load units from {}: {err}", path.display()))
        .ok()?;
    let mut data = DwarfInfo::new(path);
    data.collect_func_addrs(&ctx, func_names)
        .inspect_err(|err| vprintf!("dwarf: failed to index functions from {}: {err}", path.display()))
        .ok()?;
    vprintf!("dwarf: indexed {} function names from {}", data.func_addrs.len(), path.display());
    Some(data)
}

fn load_vmlinux(func_names: &HashSet<&str>) -> Option<DwarfInfo> {
    let mut uts = MaybeUninit::<libc::utsname>::uninit();
    if unsafe { libc::uname(uts.as_mut_ptr()) } != 0 {
        vprintf!("dwarf: uname failed: {}", io::Error::last_os_error());
        return None;
    }
    let uts = unsafe { uts.assume_init() };
    let release = unsafe { CStr::from_ptr(uts.release.as_ptr()) }.to_string_lossy();
    let paths = [
        format!("/boot/vmlinux-{release}"),
        format!("/usr/lib/modules/{release}/vmlinux-{release}"),
    ];

    for path in paths {
        vprintf!("dwarf: trying {path}");
        if let Some(dwarf) = load_dwarf(Path::new(&path), func_names) {
            vprintf!("dwarf: loaded {path}");
            return Some(dwarf);
        }
    }
    None
}

#[no_mangle]
pub unsafe extern "C" fn dwarf_info_init_vmlinux(
    func_names: *const *const c_char,
    func_name_cnt: usize,
) -> *mut DwarfInfo {
    let func_names = if func_name_cnt == 0 {
        &[]
    } else {
        std::slice::from_raw_parts(func_names, func_name_cnt)
    };
    let mut names = HashSet::with_capacity(func_names.len());
    for &name in func_names {
        let Ok(name) = CStr::from_ptr(name).to_str() else {
            vprintf!("dwarf: function name is not valid UTF-8");
            return ptr::null_mut();
        };
        names.insert(name);
    }
    load_vmlinux(&names).map_or(ptr::null_mut(), |info| Box::into_raw(Box::new(info)))
}

#[no_mangle]
pub unsafe extern "C" fn dwarf_info_elf_path(info: *const DwarfInfo) -> *const c_char {
    info.as_ref().map_or(ptr::null(), |info| info.elf_path.as_ptr())
}

#[no_mangle]
pub unsafe extern "C" fn dwarf_info_find_func(
    info: *const DwarfInfo,
    name: *const c_char,
    cnt: *mut usize,
) -> *const DwarfFuncAddr {
    *cnt = 0;
    let Some(data) = info.as_ref() else { return ptr::null() };
    let Ok(name) = CStr::from_ptr(name).to_str() else { return ptr::null() };
    let Some(addrs) = data.func_addrs.get(name) else { return ptr::null() };
    *cnt = addrs.len();
    addrs.as_ptr()
}

#[no_mangle]
pub unsafe extern "C" fn dwarf_info_free(info: *mut DwarfInfo) {
    if !info.is_null() {
        drop(Box::from_raw(info));
    }
}
