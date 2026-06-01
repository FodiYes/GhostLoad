// антидебаг и антианализ в рантайме
use std::ptr;
use std::time::{Instant, Duration};
use winapi::um::debugapi::{IsDebuggerPresent, CheckRemoteDebuggerPresent};
use winapi::um::processthreadsapi::{GetCurrentProcess, GetCurrentThread};
use winapi::um::winnt::{HANDLE, CONTEXT, CONTEXT_DEBUG_REGISTERS};
use winapi::um::errhandlingapi::SetUnhandledExceptionFilter;
use winapi::um::winnt::EXCEPTION_POINTERS;
use winapi::shared::ntdef::LONG;

// IsDebuggerPresent - самый базовый способ
#[inline(always)]
pub fn check_debugger_present() -> bool {
    unsafe { IsDebuggerPresent() != 0 }
}

// ремоут дебаггер (например x64dbg attach)
#[inline(always)]
pub fn check_remote_debugger() -> bool {
    unsafe {
        let mut is_debugged = 0;
        CheckRemoteDebuggerPresent(GetCurrentProcess(), &mut is_debugged);
        is_debugged != 0
    }
}

// хардварные брейкпоинты через debug-регистры
pub fn check_hardware_breakpoints() -> bool {
    use winapi::um::processthreadsapi::GetThreadContext;

    unsafe {
        let mut ctx: CONTEXT = std::mem::zeroed();
        ctx.ContextFlags = CONTEXT_DEBUG_REGISTERS;

        if GetThreadContext(GetCurrentThread(), &mut ctx) != 0 {
            // DR0-DR3 - регистры брейкпоинтов
            if ctx.Dr0 != 0 || ctx.Dr1 != 0 || ctx.Dr2 != 0 || ctx.Dr3 != 0 {
                return true;
            }
            // DR7 - контрольный регистр
            if ctx.Dr7 & 0xFF != 0 {
                return true;
            }
        }
    }
    false
}

// тайминг - под дебаггером выполнение замедляется
#[inline(always)]
pub fn check_timing_delta() -> bool {
    let start = Instant::now();

    let mut x = 0u64;
    for i in 0..1000 {
        x = x.wrapping_add(i);
        x = x.wrapping_mul(3);
    }

    let elapsed = start.elapsed();

    // простой цикл > 5мс - подозрительно
    elapsed > Duration::from_millis(5)
}

// проверяем список процессов по имени
pub fn check_debugger_processes() -> bool {
    use sysinfo::System;

    let mut sys = System::new_all();
    sys.refresh_processes();

    let debuggers = [
        "ollydbg", "x64dbg", "x32dbg", "windbg", "ida", "ida64",
        "idaq", "idaq64", "idaw", "idaw64", "idag", "idag64",
        "scylla", "protection_id", "pestudio", "lordpe",
        "importrec", "reshacker", "dnspy", "de4dot", "ilspy",
        "dotpeek", "processhacker", "procexp", "procexp64",
        "procmon", "procmon64", "wireshark", "fiddler",
        "httpdebugger", "charles", "burp", "ghidra", "radare2",
        "r2", "cutter", "binary ninja", "hopper", "immunity",
    ];

    for (_pid, process) in sys.processes() {
        let name = process.name().to_lowercase();
        for debugger in &debuggers {
            if name.contains(debugger) {
                return true;
            }
        }
    }
    false
}

// родительский процесс не должен быть отладчиком или консолью
pub fn check_parent_process() -> bool {
    use sysinfo::{System, Pid};
    use winapi::um::processthreadsapi::GetCurrentProcessId;
    use winapi::um::tlhelp32::{CreateToolhelp32Snapshot, Process32First, Process32Next, PROCESSENTRY32, TH32CS_SNAPPROCESS};

    unsafe {
        let current_pid = GetCurrentProcessId();
        let snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);

        if snapshot == winapi::um::handleapi::INVALID_HANDLE_VALUE {
            return false;
        }

        let mut entry: PROCESSENTRY32 = std::mem::zeroed();
        entry.dwSize = std::mem::size_of::<PROCESSENTRY32>() as u32;

        if Process32First(snapshot, &mut entry) != 0 {
            loop {
                if entry.th32ProcessID == current_pid {
                    let parent_pid = entry.th32ParentProcessID;

                    let mut sys = System::new_all();
                    sys.refresh_processes();

                    if let Some(parent) = sys.process(Pid::from_u32(parent_pid)) {
                        let parent_name = parent.name().to_lowercase();
                        let suspicious = ["cmd", "powershell", "python", "ida", "x64dbg", "ollydbg"];
                        for sus in &suspicious {
                            if parent_name.contains(sus) {
                                winapi::um::handleapi::CloseHandle(snapshot);
                                return true;
                            }
                        }
                    }
                    break;
                }

                if Process32Next(snapshot, &mut entry) == 0 {
                    break;
                }
            }
        }

        winapi::um::handleapi::CloseHandle(snapshot);
    }
    false
}

// DebugPort через NtQueryInformationProcess (ProcessDebugPort = 7)
pub fn check_debug_port() -> bool {
    use winapi::um::winnt::HANDLE;
    use winapi::um::processthreadsapi::GetCurrentProcess;

    type NtQueryInformationProcessFn = unsafe extern "system" fn(
        HANDLE,
        u32,
        *mut std::ffi::c_void,
        u32,
        *mut u32,
    ) -> i32;

    unsafe {
        let ntdll = winapi::um::libloaderapi::GetModuleHandleA(b"ntdll.dll\0".as_ptr() as *const i8);
        if ntdll.is_null() {
            return false;
        }

        let func = winapi::um::libloaderapi::GetProcAddress(
            ntdll,
            b"NtQueryInformationProcess\0".as_ptr() as *const i8,
        );

        if func.is_null() {
            return false;
        }

        let nt_query: NtQueryInformationProcessFn = std::mem::transmute(func);

        let mut debug_port: usize = 0;
        let status = nt_query(
            GetCurrentProcess(),
            7,
            &mut debug_port as *mut _ as *mut std::ffi::c_void,
            std::mem::size_of::<usize>() as u32,
            ptr::null_mut(),
        );

        status == 0 && debug_port != 0
    }
}

// SeDebugPrivilege (LUID 20) часто включен при отладке
pub fn check_debug_privilege() -> bool {
    use winapi::um::processthreadsapi::{GetCurrentProcess, OpenProcessToken};
    use winapi::um::securitybaseapi::GetTokenInformation;
    use winapi::um::winnt::{TOKEN_QUERY, TokenPrivileges, TOKEN_PRIVILEGES};
    use winapi::um::handleapi::CloseHandle;

    unsafe {
        let mut token: HANDLE = ptr::null_mut();
        if OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &mut token) == 0 {
            return false;
        }

        let mut size = 0u32;
        GetTokenInformation(token, TokenPrivileges, ptr::null_mut(), 0, &mut size);

        if size == 0 {
            CloseHandle(token);
            return false;
        }

        let mut buffer = vec![0u8; size as usize];
        let privileges = buffer.as_mut_ptr() as *mut TOKEN_PRIVILEGES;

        if GetTokenInformation(token, TokenPrivileges, privileges as *mut _, size, &mut size) != 0 {
            let priv_count = (*privileges).PrivilegeCount;
            let privs = std::slice::from_raw_parts(
                (*privileges).Privileges.as_ptr(),
                priv_count as usize,
            );

            // LUID 20 = SeDebugPrivilege
            for privilege in privs {
                if privilege.Luid.LowPart == 20 && privilege.Attributes & 0x00000002 != 0 {
                    CloseHandle(token);
                    return true;
                }
            }
        }

        CloseHandle(token);
    }
    false
}

// суммируем всё, возращаем очки подозрительности
pub fn run_anti_debug_checks() -> u32 {
    let mut score = 0u32;

    if check_debugger_present() { score += 10; }
    if check_remote_debugger() { score += 10; }
    if check_hardware_breakpoints() { score += 8; }
    if check_timing_delta() { score += 5; }
    if check_debugger_processes() { score += 7; }
    if check_parent_process() { score += 6; }
    if check_debug_port() { score += 9; }
    if check_debug_privilege() { score += 4; }

    score
}

// обработчик исключений — если сработало под дебаггером, тихо уходим
pub unsafe fn install_anti_debug_handler() {
    extern "system" fn exception_handler(_: *mut EXCEPTION_POINTERS) -> LONG {
        std::process::exit(0);
    }

    SetUnhandledExceptionFilter(Some(exception_handler));
}
