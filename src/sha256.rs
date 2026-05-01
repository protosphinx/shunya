//! SHA-256, hand-rolled (FIPS 180-4 §6.2).
//!
//! 32-bit working words, 64 rounds per 512-bit block. Output 32 bytes.
//! No `unsafe`, no dependencies, no SIMD - the goal is correctness and
//! readability. Validated against the canonical NIST FIPS 180-4 test
//! vectors at the bottom of this file.
//!
//! v0.7 makes shunya's transcript and Merkle trees actually
//! collision-resistant. The toy FNV mixer that shipped in v0.3 is replaced
//! by this implementation behind the existing [`hash`](crate::hash)
//! interface; the rest of the crate sees no API change.

const H_INIT: [u32; 8] = [
    0x6a09_e667, 0xbb67_ae85, 0x3c6e_f372, 0xa54f_f53a, 0x510e_527f, 0x9b05_688c, 0x1f83_d9ab,
    0x5be0_cd19,
];

const K: [u32; 64] = [
    0x428a_2f98, 0x7137_4491, 0xb5c0_fbcf, 0xe9b5_dba5, 0x3956_c25b, 0x59f1_11f1, 0x923f_82a4,
    0xab1c_5ed5, 0xd807_aa98, 0x1283_5b01, 0x2431_85be, 0x550c_7dc3, 0x72be_5d74, 0x80de_b1fe,
    0x9bdc_06a7, 0xc19b_f174, 0xe49b_69c1, 0xefbe_4786, 0x0fc1_9dc6, 0x240c_a1cc, 0x2de9_2c6f,
    0x4a74_84aa, 0x5cb0_a9dc, 0x76f9_88da, 0x983e_5152, 0xa831_c66d, 0xb003_27c8, 0xbf59_7fc7,
    0xc6e0_0bf3, 0xd5a7_9147, 0x06ca_6351, 0x1429_2967, 0x27b7_0a85, 0x2e1b_2138, 0x4d2c_6dfc,
    0x5338_0d13, 0x650a_7354, 0x766a_0abb, 0x81c2_c92e, 0x9272_2c85, 0xa2bf_e8a1, 0xa81a_664b,
    0xc24b_8b70, 0xc76c_51a3, 0xd192_e819, 0xd699_0624, 0xf40e_3585, 0x106a_a070, 0x19a4_c116,
    0x1e37_6c08, 0x2748_774c, 0x34b0_bcb5, 0x391c_0cb3, 0x4ed8_aa4a, 0x5b9c_ca4f, 0x682e_6ff3,
    0x748f_82ee, 0x78a5_636f, 0x84c8_7814, 0x8cc7_0208, 0x90be_fffa, 0xa450_6ceb, 0xbef9_a3f7,
    0xc671_78f2,
];

/// Compute the SHA-256 digest of `input`. Returns 32 bytes.
pub fn sha256(input: &[u8]) -> [u8; 32] {
    let mut h = H_INIT;

    // Pad: append 0x80, then zeros, then 64-bit big-endian bit length, so
    // the total length is a multiple of 64.
    let bit_len = (input.len() as u64).wrapping_mul(8);
    let mut padded = Vec::with_capacity(input.len() + 72);
    padded.extend_from_slice(input);
    padded.push(0x80);
    while padded.len() % 64 != 56 {
        padded.push(0);
    }
    padded.extend_from_slice(&bit_len.to_be_bytes());

    // Process each 512-bit (64-byte) block.
    for chunk in padded.chunks_exact(64) {
        let mut w = [0u32; 64];
        for i in 0..16 {
            w[i] = u32::from_be_bytes([
                chunk[i * 4],
                chunk[i * 4 + 1],
                chunk[i * 4 + 2],
                chunk[i * 4 + 3],
            ]);
        }
        for i in 16..64 {
            let s0 = w[i - 15].rotate_right(7) ^ w[i - 15].rotate_right(18) ^ (w[i - 15] >> 3);
            let s1 = w[i - 2].rotate_right(17) ^ w[i - 2].rotate_right(19) ^ (w[i - 2] >> 10);
            w[i] = w[i - 16]
                .wrapping_add(s0)
                .wrapping_add(w[i - 7])
                .wrapping_add(s1);
        }

        let mut a = h[0];
        let mut b = h[1];
        let mut c = h[2];
        let mut d = h[3];
        let mut e = h[4];
        let mut f = h[5];
        let mut g = h[6];
        let mut hh = h[7];

        for i in 0..64 {
            let s1 = e.rotate_right(6) ^ e.rotate_right(11) ^ e.rotate_right(25);
            let ch = (e & f) ^ ((!e) & g);
            let t1 = hh
                .wrapping_add(s1)
                .wrapping_add(ch)
                .wrapping_add(K[i])
                .wrapping_add(w[i]);
            let s0 = a.rotate_right(2) ^ a.rotate_right(13) ^ a.rotate_right(22);
            let maj = (a & b) ^ (a & c) ^ (b & c);
            let t2 = s0.wrapping_add(maj);

            hh = g;
            g = f;
            f = e;
            e = d.wrapping_add(t1);
            d = c;
            c = b;
            b = a;
            a = t1.wrapping_add(t2);
        }

        h[0] = h[0].wrapping_add(a);
        h[1] = h[1].wrapping_add(b);
        h[2] = h[2].wrapping_add(c);
        h[3] = h[3].wrapping_add(d);
        h[4] = h[4].wrapping_add(e);
        h[5] = h[5].wrapping_add(f);
        h[6] = h[6].wrapping_add(g);
        h[7] = h[7].wrapping_add(hh);
    }

    let mut out = [0u8; 32];
    for (i, word) in h.iter().enumerate() {
        out[i * 4..i * 4 + 4].copy_from_slice(&word.to_be_bytes());
    }
    out
}

/// SHA-256 truncated to 8 bytes, returned as a `u64` (big-endian).
pub fn sha256_u64(input: &[u8]) -> u64 {
    let h = sha256(input);
    u64::from_be_bytes([h[0], h[1], h[2], h[3], h[4], h[5], h[6], h[7]])
}

#[cfg(test)]
mod tests {
    use super::*;

    fn hex(bytes: &[u8]) -> String {
        bytes.iter().map(|b| format!("{:02x}", b)).collect()
    }

    #[test]
    fn empty_input_matches_known_digest() {
        assert_eq!(
            hex(&sha256(b"")),
            "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
        );
    }

    #[test]
    fn abc_matches_known_digest() {
        // FIPS 180-4 Appendix A test vector.
        assert_eq!(
            hex(&sha256(b"abc")),
            "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
        );
    }

    #[test]
    fn fips_two_block_test_vector() {
        // FIPS 180-4 Appendix B test vector (56 bytes, spans two blocks
        // after padding).
        let msg = b"abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq";
        assert_eq!(
            hex(&sha256(msg)),
            "248d6a61d20638b8e5c026930c3e6039a33ce45964ff2167f6ecedd419db06c1"
        );
    }

    #[test]
    fn long_repeated_message() {
        // Million 'a's is the canonical long-message test (we use 1000 'a's
        // here for speed; the digest is documented in many references).
        let msg = vec![b'a'; 1000];
        let h = sha256(&msg);
        assert_eq!(
            hex(&h),
            "41edece42d63e8d9bf515a9ba6932e1c20cbc9f5a5d134645adb5db1b9737ea3"
        );
    }

    #[test]
    fn determinism_same_input_same_output() {
        let m = b"deterministic";
        assert_eq!(sha256(m), sha256(m));
    }

    #[test]
    fn one_bit_change_avalanche() {
        let a = sha256(b"shunya");
        let b = sha256(b"shunyb");
        let mut diff_bits = 0u32;
        for (x, y) in a.iter().zip(b.iter()) {
            diff_bits += (x ^ y).count_ones();
        }
        // Strict avalanche criterion expects ~50% bits flipped, give or
        // take. 256 / 2 = 128. Tolerance: at least 96, no more than 160.
        assert!(
            (96..=160).contains(&diff_bits),
            "avalanche bits: {} (expected near 128)",
            diff_bits
        );
    }

    #[test]
    fn truncation_to_u64_is_consistent() {
        let m = b"truncate me";
        let full = sha256(m);
        let truncated = sha256_u64(m);
        let expected = u64::from_be_bytes([
            full[0], full[1], full[2], full[3], full[4], full[5], full[6], full[7],
        ]);
        assert_eq!(truncated, expected);
    }
}
