use anyhow::Result;
use std::process::Command;
use std::os::windows::process::CommandExt;
use std::ffi::OsStr;
use std::os::windows::ffi::OsStrExt;
use winapi::um::shellapi::ShellExecuteW;
use std::ptr;

const CREATE_NO_WINDOW: u32 = 0x08000000;
const DETACHED_PROCESS: u32 = 0x00000008;

// запуск без окна, отцепляем от текущего процесса
pub fn execute_silent(path: &str) -> Result<()> {
    Command::new(path)
        .creation_flags(CREATE_NO_WINDOW | DETACHED_PROCESS)
        .spawn()?;

    Ok(())
}

// запуск с повышением привелегий через ShellExecuteW + runas
pub fn execute_elevated(path: &str) -> Result<()> {
    let wide_path: Vec<u16> = OsStr::new(path).encode_wide().chain(std::iter::once(0)).collect();
    let verb: Vec<u16> = OsStr::new("runas").encode_wide().chain(std::iter::once(0)).collect();

    unsafe {
        let result = ShellExecuteW(
            ptr::null_mut(),
            verb.as_ptr(),
            wide_path.as_ptr(),
            ptr::null(),
            ptr::null(),
            winapi::um::winuser::SW_HIDE,
        );

        if (result as isize) <= 32 {
            return Err(anyhow::anyhow!("Failed to execute elevated, error code: {}", result as isize));
        }
    }

    Ok(())
}
