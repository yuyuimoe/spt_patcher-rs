use sha2::{Digest, Sha256};

pub fn compare_sha256_bytes(input_bytes: &Vec<u8>, target_hash: [u8; 32]) -> bool {
    let mut hasher = Sha256::new();
    hasher.update(input_bytes);
    let input_hash: [u8; 32] = hasher.finalize().into(); // Convert it to raw bytes

    input_hash == target_hash
}
