use std::borrow::Cow;
use std::cell::RefCell;
use std::collections::{HashMap, HashSet};
use std::ffi::{CStr, CString};
use std::fs::File;
use std::io;
use std::mem::MaybeUninit;
use std::num::NonZeroUsize;
use std::path::Path;
use std::ptr;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;
use std::thread;

use gimli::{
    AttributeValue, DebuggingInformationEntry, Dwarf, EndianSlice, Reader, ReaderOffset, RunTimeEndian, SectionId, Unit,
};
use libc::c_char;
use lru::LruCache;
use memmap2::Mmap;
use object::{Object, ObjectSection};
use path_clean::PathClean;

// Iterates over DW_TAG_subprogram and DW_TAG_inlined_subroutine instances in the `unit`.
// Skips decoding DIE attributes for other tags, which turns out to be about twice as fast
// compared to plain gimli::EntriesCursor::next_dfs().
// Idea borrowed from blazesym and gimli::EntriesRaw documentation.
struct SubroutineIterator<'a, R: Reader> {
    unit: &'a Unit<R>,
    raw: gimli::EntriesRaw<'a, R>,
    current: DebuggingInformationEntry<R>,
}

impl<'a, R: Reader> SubroutineIterator<'a, R> {
    fn new(unit: &'a Unit<R>) -> gimli::Result<Self> {
        Ok(Self {
            unit,
            raw: unit.entries_raw(None)?,
            current: DebuggingInformationEntry::default(),
        })
    }

    fn next(&mut self) -> gimli::Result<Option<&DebuggingInformationEntry<R>>> {
        while !self.raw.is_empty() {
            let offset = self.raw.next_offset();
            //              after read_abbreviation()
            //              v
            // [abbrev code][attributes][children / next DIE]
            // ^                        ^
            // offset                   after skip_attributes()
            let Some(abbrev) = self.raw.read_abbreviation()? else {
                continue;
            };
            let wanted = matches!(abbrev.tag(), gimli::DW_TAG_subprogram | gimli::DW_TAG_inlined_subroutine);
            self.raw.skip_attributes(abbrev.attributes())?;
            if !wanted {
                continue;
            }
            // Rereads this DIE from `offset`.
            let mut selected = self.unit.entries_raw(Some(offset))?;
            selected.read_entry(&mut self.current)?;
            return Ok(Some(&self.current));
        }
        Ok(None)
    }
}

#[repr(C)]
pub struct DwarfFuncInfo {
    pub addr: u64,
    pub file_name: *const c_char,
    pub is_inline: bool,
}

// Compilation units are costly to re-parse and expensive to keep all
// of them in-memory, hence resort to an LRU cache.
// Used when processing cross compilation unit references.
struct UnitsCache<'a, R: Reader> {
    dwarf: &'a Dwarf<R>,
    // Sorted unit header offsets in .debug_info, used to find the unit
    // containing a DW_FORM_ref_addr target.
    unit_offsets: &'a [gimli::DebugInfoOffset<R::Offset>],
    // Recently parsed units, keyed by header offset. Avoid reparsing
    // referenced units without retaining every unit in memory.
    units: RefCell<LruCache<gimli::DebugInfoOffset<R::Offset>, Arc<Unit<R>>>>,
    // Unit languages, keyed by header offset. Avoid rescanning unit DIEs
    // for DW_AT_language each time a name needs demangling.
    languages: RefCell<LruCache<R::Offset, Option<gimli::DwLang>>>,
}

pub struct DwarfInfo {
    elf_path: CString,
    // Linked ELF addresses, before applying the running kernel's KASLR slide.
    func_infos: HashMap<String, Vec<DwarfFuncInfo>>,
    // Owns the string buffers referenced by `DwarfFuncInfo::file_name` in `func_infos`.
    // Buffer addresses do not change when the set grows.
    file_names: HashSet<CString>,
}

// DwarfFuncInfo::file_name is a raw pointer, so Send must be implemented explicitly.
unsafe impl Send for DwarfInfo {}

impl<'a, R: Reader> UnitsCache<'a, R> {
    fn new(dwarf: &'a Dwarf<R>, unit_offsets: &'a [gimli::DebugInfoOffset<R::Offset>]) -> Self {
        Self {
            dwarf,
            unit_offsets,
            units: RefCell::new(LruCache::new(NonZeroUsize::new(8).unwrap())),
            languages: RefCell::new(LruCache::new(NonZeroUsize::new(8).unwrap())),
        }
    }

    // `offset` is an offset of a DIE or of a compilation unit.
    // Returned values survive cache eviction.
    fn find_containing_unit(&self, offset: gimli::DebugInfoOffset<R::Offset>) -> Option<Arc<Unit<R>>> {
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
    fn unit_language(&self, unit: &Unit<R>) -> Option<gimli::DwLang> {
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
fn resolve_formref<R: Reader>(
    ctx: &UnitsCache<R>,
    unit: &Arc<Unit<R>>,
    value: AttributeValue<R>,
) -> Option<(Arc<Unit<R>>, gimli::UnitOffset<R::Offset>)> {
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
fn find_inherited_value<R: Reader, T>(
    ctx: &UnitsCache<R>,
    unit: &Arc<Unit<R>>,
    entry: &DebuggingInformationEntry<R>,
    recursion_limit: usize,
    matcher: &mut impl FnMut(&Unit<R>, &DebuggingInformationEntry<R>) -> Option<T>,
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

fn entry_name<R: Reader>(
    ctx: &UnitsCache<R>,
    unit: &Arc<Unit<R>>,
    entry: &DebuggingInformationEntry<R>,
) -> Option<String> {
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

fn entry_decl_file<R: Reader>(
    ctx: &UnitsCache<R>,
    unit: &Arc<Unit<R>>,
    entry: &DebuggingInformationEntry<R>,
) -> Option<String> {
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
            func_infos: HashMap::new(),
            file_names: HashSet::new(),
        }
    }

    fn intern(&mut self, file: CString) -> *const c_char {
        match self.file_names.get(file.as_c_str()) {
            Some(existing) => existing.as_ptr(),
            None => {
                let ptr = file.as_ptr();
                self.file_names.insert(file);
                ptr
            }
        }
    }

    fn scan_unit<R: Reader>(
        &mut self,
        ctx: &UnitsCache<R>,
        offset: gimli::DebugInfoOffset<R::Offset>,
        func_names: &HashSet<&str>,
    ) -> gimli::Result<()> {
        let unit = ctx.find_containing_unit(offset)
            .ok_or(gimli::Error::NoEntryAtGivenOffset(offset.0.into_u64()))?;
        let mut entries = SubroutineIterator::new(&unit)?;
        while let Some(entry) = entries.next()? {
            let is_inline = entry.tag() == gimli::DW_TAG_inlined_subroutine;
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
                Some(file) => self.intern(CString::new(file).unwrap()),
                None => ptr::null(),
            };
            self.func_infos.entry(name).or_default().push(DwarfFuncInfo { addr, file_name, is_inline });
        }
        Ok(())
    }

    // Merge partial indexes for the same ELF.
    fn merge(&mut self, other: Self) {
        // Need to re-intern `other`s file name strings.
        let mut file_ptrs = HashMap::with_capacity(other.file_names.len());
        for file in other.file_names {
            let old_ptr = file.as_ptr();
            let new_ptr = self.intern(file);
            file_ptrs.insert(old_ptr, new_ptr);
        }

        for (name, mut infos) in other.func_infos {
            for info in &mut infos {
                if !info.file_name.is_null() {
                    info.file_name = file_ptrs[&info.file_name];
                }
            }
            self.func_infos.entry(name).or_default().append(&mut infos);
        }
    }
}

fn read_section<'data>(
    id: SectionId,
    elf: &object::File<'data>,
    path: &Path,
) -> Result<Cow<'data, [u8]>, ()> {
    let Some(section) = elf.section_by_name(id.name()) else {
        // DwarfSections::load expects empty data for missing sections.
        return Ok(Cow::Borrowed(&[]));
    };

    section.uncompressed_data().map_err(|err| {
        vprintf!(
            "dwarf: failed to load section '{}' from {}: {err}",
            id.name(),
            path.display(),
        );
    })
}

fn collect_unit_offsets<R: Reader>(dwarf: &Dwarf<R>) -> gimli::Result<Vec<gimli::DebugInfoOffset<R::Offset>>> {
    let mut unit_offsets = Vec::new();
    let mut headers = dwarf.units();
    while let Some(header) = headers.next()? {
        unit_offsets.push(header.debug_info_offset().unwrap());
    }
    Ok(unit_offsets)
}

fn load_dwarf(path: &Path, func_names: &HashSet<&str>) -> Option<DwarfInfo> {
    const MAX_DWARF_WORKERS: usize = 32;

    let file = File::open(path)
        .inspect_err(|err| dprintf!(2, "dwarf: failed to open {}: {err}", path.display()))
        .ok()?;
    let data = unsafe { Mmap::map(&file) }
        .inspect_err(|err| vprintf!("dwarf: failed to map {}: {err}", path.display()))
        .ok()?;
    let elf = object::File::parse(&data[..])
        .inspect_err(|err| vprintf!("dwarf: failed to parse {}: {err}", path.display()))
        .ok()?;
    let endian = if elf.is_little_endian() {
        RunTimeEndian::Little
    } else {
        RunTimeEndian::Big
    };
    let sections = gimli::DwarfSections::load(|id| read_section(id, &elf, path)).ok()?;
    let dwarf = sections.borrow(|section| EndianSlice::new(section.as_ref(), endian));
    let unit_offsets = collect_unit_offsets(&dwarf)
        .inspect_err(|err| vprintf!("dwarf: failed to load units from {}: {err}", path.display()))
        .ok()?;
    let workers = unit_offsets.len().clamp(1, MAX_DWARF_WORKERS);
    let next = AtomicUsize::new(0);
    let merged_info = thread::scope(|scope| {
        // Collect multiple dwarf_info instances in parallel...
        let handles = (0..workers)
            .map(|_| scope.spawn(|| {
                let ctx = UnitsCache::new(&dwarf, &unit_offsets);
                let mut worker_info = DwarfInfo::new(path);
                loop {
                    let index = next.fetch_add(1, Ordering::Relaxed);
                    if index >= unit_offsets.len() {
                        break;
                    }
                    worker_info.scan_unit(&ctx, unit_offsets[index], func_names)?;
                }
                Ok::<_, gimli::Error>(worker_info)
            }))
            .collect::<Vec<_>>();
        // ...and merge them into a singe dwarf_info instance.
        let mut handles = handles.into_iter();
        let mut merged_info = handles.next().unwrap().join().expect("DWARF worker panicked")?;
        for handle in handles {
            merged_info.merge(handle.join().expect("DWARF worker panicked")?);
        }
        Ok::<_, gimli::Error>(merged_info)
    })
    .inspect_err(|err| vprintf!("dwarf: failed to index functions from {}: {err}", path.display()))
    .ok()?;
    dprintf!(2, "dwarf: indexed {} function names from {}", merged_info.func_infos.len(), path.display());
    Some(merged_info)
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
        dprintf!(2, "dwarf: trying {path}");
        if let Some(dwarf) = load_dwarf(Path::new(&path), func_names) {
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
) -> *const DwarfFuncInfo {
    *cnt = 0;
    let Some(data) = info.as_ref() else { return ptr::null() };
    let Ok(name) = CStr::from_ptr(name).to_str() else { return ptr::null() };
    let Some(infos) = data.func_infos.get(name) else { return ptr::null() };
    *cnt = infos.len();
    infos.as_ptr()
}

#[no_mangle]
pub unsafe extern "C" fn dwarf_info_free(info: *mut DwarfInfo) {
    if !info.is_null() {
        drop(Box::from_raw(info));
    }
}
