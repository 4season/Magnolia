use aes::Aes256;
use base64::{Engine as _, engine::general_purpose};
use cbc::Decryptor;
use cipher::{BlockDecryptMut, KeyIvInit, block_padding::Pkcs7};
use sha1::{Digest, Sha1};
use std::str;

const IV: &[u8; 16] = &[
    15, 8, 1, 0, 25, 71, 37, 220, 21, 245, 23, 224, 225, 21, 12, 53,
];
const PBE_PASSWORD: &[u8; 34] = &[
    0, 22, 0, 8, 0, 9, 0, 111, 0, 2, 0, 23, 0, 43, 0, 8, 0, 33, 0, 33, 0, 10, 0, 16, 0, 3, 0, 3, 0,
    7, 0, 6, 0, 0,
];
const PREFIXES: &[&str; 32] = &[
    "",
    "",
    "12",
    "24",
    "18",
    "30",
    "36",
    "12",
    "48",
    "7",
    "35",
    "40",
    "17",
    "23",
    "29",
    "isabel",
    "kale",
    "sulli",
    "van",
    "merry",
    "kyle",
    "james",
    "maddux",
    "tony",
    "hayden",
    "paul",
    "elijah",
    "dorothy",
    "sally",
    "bran",
    "extr.ursra",
    "veil",
];

type Aes256CbcDec = Decryptor<Aes256>;

/// 바이트 배열 `a`에 `b`와 `1`을 더하는 연산을 수행합니다 (큰 정수 덧셈).
fn pkcs12_adjust(a: &mut [u8], b: &[u8]) {
    let mut carry: u16 = 1;
    (0..b.len()).rev().for_each(|i| {
        let sum = (a[i] as u16) + (b[i] as u16) + carry;
        a[i] = sum as u8; // 결과의 하위 8비트를 저장
        carry = sum >> 8; // 올림수(carry)를 계산
    });
}

/// 키 생성 로직(PKCS#12 KDF)을 그대로 구현한 함수입니다.
fn pkcs12_kdf(password: &[u8], salt: &[u8], iteration: usize, dkey_size: usize) -> Vec<u8> {
    // SHA1의 블록 크기와 해시 크기입니다.
    const V_BLOCK_SIZE: usize = 64;
    const U_HASH_SIZE: usize = 20;

    // 1. 솔트(S)와 비밀번호(P)를 V_BLOCK_SIZE의 배수로 확장합니다.
    let s_len = V_BLOCK_SIZE * ((salt.len() + V_BLOCK_SIZE - 1) / V_BLOCK_SIZE);
    let mut s_buf = vec![0u8; s_len];
    (0..s_len).for_each(|i| s_buf[i] = salt[i % salt.len()]);

    let p_len = V_BLOCK_SIZE * ((password.len() + V_BLOCK_SIZE - 1) / V_BLOCK_SIZE);
    let mut p_buf = vec![0u8; p_len];
    (0..p_len).for_each(|i| p_buf[i] = password[i % password.len()]);

    // 확장된 솔트와 비밀번호를 하나로 합쳐 거대한 입력 버퍼(I)를 만듭니다.
    let mut i_buf = [s_buf, p_buf].concat();
    let mut d_key = vec![0u8; dkey_size];

    // 필요한 키 길이를 얻기 위해 루프를 몇 번 돌아야 하는지 계산합니다.
    let loops = (dkey_size + U_HASH_SIZE - 1) / U_HASH_SIZE;

    for i in 0..loops {
        // 2. 해시 계산: `sha1(D + I)`를 계산합니다.
        let mut hasher = Sha1::new();
        // 키를 만들 때는 ID가 '1'인 다목적 바이트(D)를 사용합니다.
        hasher.update(&vec![1u8; V_BLOCK_SIZE]);
        hasher.update(&i_buf);
        let mut a_buf = hasher.finalize();

        // 3. 반복(Iteration)
        for _ in 1..iteration {
            let mut inner_hasher = Sha1::new();
            inner_hasher.update(&a_buf);
            a_buf = inner_hasher.finalize();
        }

        // 4. 최종 키에 결과값 복사
        let start = i * U_HASH_SIZE;
        let copy_len = (dkey_size - start).min(U_HASH_SIZE);
        d_key[start..start + copy_len].copy_from_slice(&a_buf[..copy_len]);

        // 5. 피드백 메커니즘: 다음 계산을 위해 입력 버퍼(I)를 수정합니다.
        let b_buf: Vec<u8> = (0..V_BLOCK_SIZE).map(|j| a_buf[j % U_HASH_SIZE]).collect();
        i_buf
            .chunks_mut(V_BLOCK_SIZE)
            .for_each(|chunk| pkcs12_adjust(chunk, &b_buf));
    }
    d_key
}

/// 암호문을 복호화하는 메인 함수
fn decrypt_data(user_id: u64, i9: usize, ciphertext_b64: &str) -> Result<String, String> {
    // --- 1단계: 직접 구현한 함수로 암호화 키(Key) 생성 ---
    let prefix = PREFIXES
        .get(i9)
        .ok_or_else(|| format!("오류: 유효하지 않은 i9 타입 번호입니다: {}", i9))?;
    let pbe_salt_base = format!("{}{}", prefix, user_id);

    // salt를 16바이트로 만들고, 부족하면 0으로 채웁니다.
    let mut pbe_salt_bytes = pbe_salt_base.into_bytes();
    pbe_salt_bytes.truncate(16); // 1. 16바이트로 자르고
    pbe_salt_bytes.resize(16, 0); // 2. 길이가 모자라면 0으로 채웁니다.

    // 이제 `pkcs12_kdf` 함수를 사용하여 키를 생성합니다.
    let aes_key = pkcs12_kdf(PBE_PASSWORD, &pbe_salt_bytes, 2, 32);

    // --- 2단계: 실제 복호화 실행 ---
    let ciphertext = general_purpose::STANDARD
        .decode(ciphertext_b64)
        .map_err(|e| format!("Base64 디코딩 실패: {}", e))?;
    let cipher = Aes256CbcDec::new((&(*aes_key)).into(), &(*IV).into());
    let decrypted_bytes = cipher
        .decrypt_padded_vec_mut::<Pkcs7>(&ciphertext)
        .map_err(|e| format!("복호화 실패: {}", e))?;
    String::from_utf8(decrypted_bytes).map_err(|e| format!("UTF-8 변환 실패: {}", e))
}

fn main() {
    // 첫 번째 성공했던 테스트 케이스
    println!("--- 테스트 ---");
    let user_id_1: u64 = {id};
    let encrypted_message_1 = "{message}";
    match decrypt_data(user_id_1, 31, encrypted_message_1) {
        Ok(decrypted) => println!("✅ 복호화 성공! 결과: {}", decrypted),
        Err(e) => println!("❌ 복호화 실패! 오류: {}", e),
    }
}
