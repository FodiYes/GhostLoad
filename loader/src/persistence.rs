use anyhow::Result;
use winapi::um::winreg::{RegCreateKeyExA, RegSetValueExA, HKEY_CURRENT_USER};
use winapi::um::winnt::{KEY_WRITE, REG_SZ};
use winapi::shared::winerror::ERROR_SUCCESS;
use std::ptr;

// HKCU\...\Run - автозапуск при входе пользователя
pub fn install_registry_persistence(app_name: &str, exe_path: &str) -> Result<()> {
    let key_path = "Software\\Microsoft\\Windows\\CurrentVersion\\Run\0";

    unsafe {
        let mut hkey = ptr::null_mut();
        if RegCreateKeyExA(
            HKEY_CURRENT_USER,
            key_path.as_ptr() as *const i8,
            0,
            ptr::null_mut(),
            0,
            KEY_WRITE,
            ptr::null_mut(),
            &mut hkey,
            ptr::null_mut(),
        ) == ERROR_SUCCESS as i32 {

            let mut value_data = exe_path.to_string();
            value_data.push('\0'); // null-terminate

            let result = RegSetValueExA(
                hkey,
                format!("{}\0", app_name).as_ptr() as *const i8,
                0,
                REG_SZ,
                value_data.as_ptr(),
                value_data.len() as u32,
            );

            winapi::um::winreg::RegCloseKey(hkey);

            if result == ERROR_SUCCESS as i32 {
                return Ok(());
            } else {
                return Err(anyhow::anyhow!("Failed to set registry value. Error code: {}", result));
            }
        } else {
            return Err(anyhow::anyhow!("Failed to open/create registry key"));
        }
    }
}
