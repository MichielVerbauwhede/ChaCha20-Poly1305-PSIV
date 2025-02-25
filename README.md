# ChaCha20-Poly1305-PSIV
This is supplementary material for the paper ["A Robust Variant of ChaCha20-Poly1305"](https://github.com/MichielVerbauwhede/ChaCha20-Poly1305-PSIV).

## Reference Implementation
A reference implementation in rust is provided in `implementation`. It can be build and run with `cargo run`.

## Performance measurements
A patch for [libsodium](https://doc.libsodium.org/) is provided in `performance`. It hacks ChaCha20-Poly1305-PSIV into libsodium and compares its performance to existing ChaCha-Poly1305.
