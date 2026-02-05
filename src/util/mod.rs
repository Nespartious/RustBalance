//! Utility functions
//!
//! Pure helpers - time, randomization, encoding.

pub mod rand;
pub mod time;

/// Base64 encode bytes (standard alphabet, no padding)
pub fn base64_encode(data: &[u8]) -> String {
    const ALPHABET: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

    let mut result = String::new();
    let mut chunks = data.chunks_exact(3);

    for chunk in &mut chunks {
        let n = ((chunk[0] as u32) << 16) | ((chunk[1] as u32) << 8) | (chunk[2] as u32);
        result.push(ALPHABET[((n >> 18) & 0x3f) as usize] as char);
        result.push(ALPHABET[((n >> 12) & 0x3f) as usize] as char);
        result.push(ALPHABET[((n >> 6) & 0x3f) as usize] as char);
        result.push(ALPHABET[(n & 0x3f) as usize] as char);
    }

    let remainder = chunks.remainder();
    match remainder.len() {
        1 => {
            let n = (remainder[0] as u32) << 16;
            result.push(ALPHABET[((n >> 18) & 0x3f) as usize] as char);
            result.push(ALPHABET[((n >> 12) & 0x3f) as usize] as char);
        },
        2 => {
            let n = ((remainder[0] as u32) << 16) | ((remainder[1] as u32) << 8);
            result.push(ALPHABET[((n >> 18) & 0x3f) as usize] as char);
            result.push(ALPHABET[((n >> 12) & 0x3f) as usize] as char);
            result.push(ALPHABET[((n >> 6) & 0x3f) as usize] as char);
        },
        _ => {},
    }

    result
}

/// Base64 decode string
pub fn base64_decode(data: &str) -> Option<Vec<u8>> {
    const DECODE: [i8; 128] = [
        -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
        -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, 62, -1, -1,
        -1, 63, 52, 53, 54, 55, 56, 57, 58, 59, 60, 61, -1, -1, -1, -1, -1, -1, -1, 0, 1, 2, 3, 4,
        5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23, 24, 25, -1, -1, -1,
        -1, -1, -1, 26, 27, 28, 29, 30, 31, 32, 33, 34, 35, 36, 37, 38, 39, 40, 41, 42, 43, 44, 45,
        46, 47, 48, 49, 50, 51, -1, -1, -1, -1, -1,
    ];

    let data = data.trim_end_matches('=');
    let mut result = Vec::new();
    let mut buffer: u32 = 0;
    let mut bits = 0;

    for c in data.chars() {
        let val = if (c as usize) < 128 {
            DECODE[c as usize]
        } else {
            -1
        };

        if val < 0 {
            return None;
        }

        buffer = (buffer << 6) | (val as u32);
        bits += 6;

        if bits >= 8 {
            bits -= 8;
            result.push(((buffer >> bits) & 0xff) as u8);
        }
    }

    Some(result)
}
