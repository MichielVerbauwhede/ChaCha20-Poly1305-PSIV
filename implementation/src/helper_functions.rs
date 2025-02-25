use std::cmp::min;

fn quarterround(mut x: [u32; 16], a: usize, b: usize, c: usize, d: usize) -> [u32; 16] {
    x[a] = x[a].wrapping_add(x[b]);
    x[d] ^= x[a];
    x[d] = x[d].rotate_left(16);
    x[c] = x[c].wrapping_add(x[d]);
    x[b] ^= x[c];
    x[b] = x[b].rotate_left(12);
    x[a] = x[a].wrapping_add(x[b]);
    x[d] ^= x[a];
    x[d] = x[d].rotate_left(8);
    x[c] = x[c].wrapping_add(x[d]);
    x[b] ^= x[c];
    x[b] = x[b].rotate_left(7);

    x
}

pub fn chacha20_core(input: &[u8; 64]) -> [u8; 64] {
    let mut x: [u32; 16] = [0; 16];

    for i in 0..16 {
        x[i] = u32::from_le_bytes([
            input[4 * i],
            input[4 * i + 1],
            input[4 * i + 2],
            input[4 * i + 3],
        ]);
    }

    for _ in 0..10 {
        x = quarterround(x, 0, 4, 8, 12);
        x = quarterround(x, 1, 5, 9, 13);
        x = quarterround(x, 2, 6, 10, 14);
        x = quarterround(x, 3, 7, 11, 15);
        x = quarterround(x, 0, 5, 10, 15);
        x = quarterround(x, 1, 6, 11, 12);
        x = quarterround(x, 2, 7, 8, 13);
        x = quarterround(x, 3, 4, 9, 14);
    }

    let mut output: [u8; 64] = [0; 64];
    for i in 0..16 {
        output[i * 4..][..4].copy_from_slice(
            &(x[i].wrapping_add(u32::from_le_bytes([
                input[4 * i],
                input[4 * i + 1],
                input[4 * i + 2],
                input[4 * i + 3],
            ])))
            .to_le_bytes(),
        )
    }
    output
}

pub fn concatenate_key_nonce_tag(key: &[u8; 36], nonce: &[u8; 12], tag_ctr: &[u8; 8], tag_rest: &[u8; 8]) -> [u8; 64] {
    let mut res: [u8; 64] = [0; 64];
    let (first, rest) = res.split_at_mut(36);
    let (second, rest2) = rest.split_at_mut(12);
    let (third, fourth) = rest2.split_at_mut(8);
    first.copy_from_slice(key);
    second.copy_from_slice(nonce);
    third.copy_from_slice(tag_ctr);
    fourth.copy_from_slice(tag_rest);
    res
}

pub fn concatenate_key_zero(poly1305_keygen_key: &[u8; 36]) -> [u8; 64] {
    concatenate_key_nonce_tag(poly1305_keygen_key, &[0; 12], &[0; 8], &[0; 8])
}

pub fn lengths_to_block(l1: usize, l2: usize) -> [u8; 16] {
    let mut length_block: [u8; 16] = [0u8; 16];
    // precautions, usize is not the same size on every machine
    let l1_bytes = l1.to_le_bytes();
    let l2_bytes = l2.to_le_bytes();
    length_block[..min(l1_bytes.len(), 8)].copy_from_slice(&l1_bytes[..min(l1_bytes.len(), 8)]);
    length_block[8..min(l2_bytes.len(), 8) + 8]
        .copy_from_slice(&l2_bytes[..min(l2_bytes.len(), 8)]);

    length_block
}

pub fn print_u8_array(ar: &[u8]) {
    for b in ar {
        print!("{:02x}", b);
    }
    println!();
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn validate_chacha20_core() {
        let input: [u8; 64] = [0; 64];
        assert_eq!(input, chacha20_core(&input));

        let u32input: [u32; 16] = [
            0x61707865, 0x3320646e, 0x79622d32, 0x6b206574, 0x03020100, 0x07060504, 0x0b0a0908,
            0x0f0e0d0c, 0x13121110, 0x17161514, 0x1b1a1918, 0x1f1e1d1c, 0x00000001, 0x09000000,
            0x4a000000, 0x00000000,
        ];
        let mut input: [u8; 64] = [0; 64];
        for i in 0..16 {
            input[i * 4..][..4].copy_from_slice(&u32input[i].to_le_bytes())
        }
        let u32ref: [u32; 16] = [
            0xe4e7f110, 0x15593bd1, 0x1fdd0f50, 0xc47120a3, 0xc7f4d1c7, 0x0368c033, 0x9aaa2204,
            0x4e6cd4c3, 0x466482d2, 0x09aa9f07, 0x05d7c214, 0xa2028bd9, 0xd19c12b5, 0xb94e16de,
            0xe883d0cb, 0x4e3c50a2,
        ];
        let mut reference: [u8; 64] = [0; 64];
        for i in 0..16 {
            reference[i * 4..][..4].copy_from_slice(&u32ref[i].to_le_bytes())
        }
        assert_eq!(reference, chacha20_core(&input));
    }
}
