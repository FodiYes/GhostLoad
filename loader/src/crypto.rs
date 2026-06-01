// xor-шифрование строк, ключи из compile time

// xor декрипт с одним ключом
#[inline(always)]
pub fn decrypt_str(encrypted: &[u8], key: u8) -> String {
    encrypted
        .iter()
        .map(|b| (b ^ key) as char)
        .collect()
}

// строка на стеке, чтоб не светить в .rdata
#[inline(always)]
pub fn stack_string(chars: &[u8]) -> String {
    let mut s = String::with_capacity(chars.len());
    for &c in chars {
        s.push(c as char);
    }
    s
}

// xor с ротирующим ключем
#[inline(always)]
pub fn decrypt_multibyte(encrypted: &[u8], key: &[u8]) -> String {
    encrypted
        .iter()
        .enumerate()
        .map(|(i, b)| (b ^ key[i % key.len()]) as char)
        .collect()
}

// rc4-подобный стрим шифр для длинных строк
pub struct StreamCipher {
    s: [u8; 256],
    i: u8,
    j: u8,
}

impl StreamCipher {
    pub fn new(key: &[u8]) -> Self {
        let mut s = [0u8; 256];
        for i in 0..256 {
            s[i] = i as u8;
        }

        // иницилизация S-box ключем
        let mut j = 0u8;
        for i in 0..256 {
            j = j.wrapping_add(s[i]).wrapping_add(key[i % key.len()]);
            s.swap(i, j as usize);
        }

        Self { s, i: 0, j: 0 }
    }

    pub fn decrypt(&mut self, data: &[u8]) -> Vec<u8> {
        let mut result = Vec::with_capacity(data.len());
        for &byte in data {
            self.i = self.i.wrapping_add(1);
            self.j = self.j.wrapping_add(self.s[self.i as usize]);
            self.s.swap(self.i as usize, self.j as usize);
            let k = self.s[(self.s[self.i as usize].wrapping_add(self.s[self.j as usize])) as usize];
            result.push(byte ^ k);
        }
        result
    }
}
