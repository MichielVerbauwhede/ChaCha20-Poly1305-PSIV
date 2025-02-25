mod helper_functions;

use helper_functions::*;
use poly1305::{universal_hash::*, Poly1305};
use rand::{Rng, RngCore, SeedableRng};

fn chacha20_stream_encrypt(
    input: &[u8],
    key: &[u8; 36],
    tag: &[u8; 16],
    nonce: &[u8; 12],
) -> Vec<u8> {
    let mut output: Vec<u8> = Vec::with_capacity(input.len());
    let mut ctr: u64 = u64::from_le_bytes(tag[..8].try_into().unwrap());

    for block in input.chunks(64) {
        let buf = chacha20_core(&concatenate_key_nonce_tag(
            key,
            nonce,
            &ctr.to_le_bytes(),
            tag[8..].try_into().unwrap(),
        ));
        for i in 0..block.len() {
            output.push(block[i] ^ buf[i]);
        }
        ctr = ctr.wrapping_add(1);
    }

    output
}

fn chacha20_poly1305_psiv_init(key: &[u8; 32]) -> ([u8; 36], [u8; 36], Poly1305) {
    let poly1305_keygen_key = [
        key[0], key[1], key[2], 0x03, key[4], key[5], key[6], 0x0c, key[8], key[9], key[10], 0x30,
        key[3], key[7], key[11], 0xc0, key[12], key[13], key[14], key[15], key[16], key[17],
        key[18], key[19], key[20], key[21], key[22], key[23], key[24], key[25], key[26], key[27],
        key[28], key[29], key[30], key[31],
    ];
    let tag_key = [
        key[0], key[1], key[2], 0x05, key[4], key[5], key[6], 0x0a, key[8], key[9], key[10], 0x50,
        key[3], key[7], key[11], 0xa0, key[12], key[13], key[14], key[15], key[16], key[17],
        key[18], key[19], key[20], key[21], key[22], key[23], key[24], key[25], key[26], key[27],
        key[28], key[29], key[30], key[31],
    ];
    let enc_key = [
        key[0], key[1], key[2], 0x06, key[4], key[5], key[6], 0x09, key[8], key[9], key[10], 0x60,
        key[3], key[7], key[11], 0x90, key[12], key[13], key[14], key[15], key[16], key[17],
        key[18], key[19], key[20], key[21], key[22], key[23], key[24], key[25], key[26], key[27],
        key[28], key[29], key[30], key[31],
    ];

    let buf = chacha20_core(&concatenate_key_zero(
        &poly1305_keygen_key
    ));
    let poly1305_key = buf.split_at(32).0;

    (
        tag_key,
        enc_key,
        Poly1305::new_from_slice(poly1305_key).unwrap(),
    )
}

fn chacha20_poly1305_psiv_generate_tag(
    mut poly1305: Poly1305,
    input: &[u8],
    ad_len: usize,
    tag_key: &[u8; 36],
    nonce: &[u8; 12],
) -> [u8; 16] {
    poly1305.update_padded(input);

    poly1305.update(&[lengths_to_block(ad_len, input.len()).into()]);

    let digest = poly1305.finalize();
    let mut tag: [u8; 16] = [0; 16];
    tag.copy_from_slice(
        chacha20_core(&concatenate_key_nonce_tag(
            tag_key,
            nonce,
            &digest[..8].try_into().unwrap(),
            &digest[8..].try_into().unwrap()
        ))
        .split_at(16)
        .0,
    );

    tag
}

fn chacha20_poly1305_psiv_encrypt(
    input: &[u8],
    ad: &[u8],
    key: &[u8; 32],
    nonce: &[u8; 12],
) -> (Vec<u8>, [u8; 16]) {
    // in a scenario where the same key is used multiple times,
    // this init function would only have to be called once
    let (tag_key, enc_key, poly1305_initial) = chacha20_poly1305_psiv_init(key);

    // in a scenario where the AD (or part of the message) is reused multiple times,
    // AD (or part of the message) would only have to be added once and the Poly1305 struct can be cloned
    let mut poly1305_with_ad = poly1305_initial.clone();
    poly1305_with_ad.update_padded(ad);

    // everything else has to be computed for every encryption
    let tag = chacha20_poly1305_psiv_generate_tag(
        poly1305_with_ad.clone(),
        input,
        ad.len(),
        &tag_key,
        nonce,
    );
    let output = chacha20_stream_encrypt(input, &enc_key, &tag, nonce);

    (output, tag)
}

fn chacha20_poly1305_psiv_decrypt(
    input: &[u8],
    ad: &[u8],
    key: &[u8; 32],
    nonce: &[u8; 12],
    tag: &[u8; 16],
) -> Option<Vec<u8>> {
    let (tag_key, enc_key, poly1305_initial) = chacha20_poly1305_psiv_init(key);

    let mut poly1305_with_ad = poly1305_initial.clone();
    poly1305_with_ad.update_padded(ad);

    let output = chacha20_stream_encrypt(input, &enc_key, tag, nonce);

    if &chacha20_poly1305_psiv_generate_tag(
        poly1305_with_ad.clone(),
        output.as_slice(),
        ad.len(),
        &tag_key,
        nonce,
    ) == tag
    {
        Some(output)
    } else {
        None
    }
}

fn main() {
    let mut rng = rand_pcg::Pcg64::seed_from_u64(0);

    // generate test vectors
    let mut input: Vec<u8> = vec![0; 2];
    rng.fill_bytes(&mut input);
    let mut ad: Vec<u8> = vec![0; 13];
    rng.fill_bytes(&mut ad);
    let key: [u8; 32] = rng.gen::<[u8; 32]>();
    let nonce: [u8; 12] = rng.gen::<[u8; 12]>();
    let (ciphertext, tag) = chacha20_poly1305_psiv_encrypt(&input, &ad, &key, &nonce);

    print!("Key = ",);
    print_u8_array(&key);
    print!("Nonce = ",);
    print_u8_array(&nonce);
    print!("AD = ",);
    print_u8_array(&ad);
    print!("Tag = ",);
    print_u8_array(&tag);
    print!("Plaintext = ",);
    print_u8_array(&input);
    print!("Ciphertext = ",);
    print_u8_array(&ciphertext);
    println!();
    for i in 1..10 {
        let mut input: Vec<u8> = vec![0; 16 * i];
        rng.fill_bytes(&mut input);
        let mut ad: Vec<u8> = vec![0; 16 * i];
        rng.fill_bytes(&mut ad);
        let key: [u8; 32] = rng.gen::<[u8; 32]>();
        let nonce: [u8; 12] = rng.gen::<[u8; 12]>();
        let (ciphertext, tag) = chacha20_poly1305_psiv_encrypt(&input, &ad, &key, &nonce);
        print!("Key = ",);
        print_u8_array(&key);
        print!("Nonce = ",);
        print_u8_array(&nonce);
        print!("AD = ",);
        print_u8_array(&ad);
        print!("Tag = ",);
        print_u8_array(&tag);
        print!("Plaintext = ",);
        print_u8_array(&input);
        print!("Ciphertext = ",);
        print_u8_array(&ciphertext);
        println!();
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn stream_encryption_of_encryption_is_plaintext() {
        let mut rng = rand_pcg::Pcg64::seed_from_u64(1);
        for i in 1..=1024 {
            let mut input: Vec<u8> = Vec::with_capacity(i);
            rng.fill_bytes(&mut input);
            let mut key: [u8; 36] = [0; 36];
            rng.fill_bytes(&mut key);
            let tag: [u8; 16] = rng.gen::<[u8; 16]>();
            let nonce: [u8; 12] = rng.gen::<[u8; 12]>();
            assert_eq!(
                chacha20_stream_encrypt(
                    &chacha20_stream_encrypt(&input, &key, &tag, &nonce),
                    &key,
                    &tag,
                    &nonce
                ),
                input
            );
        }
    }

    #[test]
    fn aead_encryption_of_encryption_is_plaintext() {
        let mut rng = rand_pcg::Pcg64::seed_from_u64(2);
        for i in 1..=1024 {
            let mut input: Vec<u8> = vec![0; i];
            rng.fill_bytes(&mut input);
            let mut ad: Vec<u8> = vec![0; i];
            rng.fill_bytes(&mut ad);
            let key: [u8; 32] = rng.gen::<[u8; 32]>();
            let nonce: [u8; 12] = rng.gen::<[u8; 12]>();
            let (ciphertext, tag) = chacha20_poly1305_psiv_encrypt(&input, &ad, &key, &nonce);
            assert_eq!(
                chacha20_poly1305_psiv_decrypt(ciphertext.as_slice(), &ad, &key, &nonce, &tag)
                    .unwrap(),
                input
            );
        }
    }

    #[test]
    fn aead_wrong_tag() {
        let mut rng = rand_pcg::Pcg64::seed_from_u64(3);
        for i in 1..=1024 {
            let mut input: Vec<u8> = vec![0; i];
            rng.fill_bytes(&mut input);
            let mut ad: Vec<u8> = vec![0; i];
            rng.fill_bytes(&mut ad);
            let key: [u8; 32] = rng.gen::<[u8; 32]>();
            let nonce: [u8; 12] = rng.gen::<[u8; 12]>();
            let (ciphertext, mut tag) = chacha20_poly1305_psiv_encrypt(&input, &ad, &key, &nonce);
            tag[0] ^= 1;
            assert_eq!(
                chacha20_poly1305_psiv_decrypt(ciphertext.as_slice(), &ad, &key, &nonce, &tag),
                None
            );
        }
    }
}
