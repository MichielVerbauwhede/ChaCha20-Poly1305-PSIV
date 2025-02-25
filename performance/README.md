To patch libsodium perform the following commands:

```
git clone https://github.com/jedisct1/libsodium.git && cd libsodium && git checkout 1.0.18-RELEASE && git am ../chacha20-poly1305-PSIV.patch
```

Then follow the instructions in `README.markdown`.