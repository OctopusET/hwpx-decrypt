# hwpx-decrypt

Decrypt HWPX distribution (read-only) documents.

## Sources

The encryption password is hardcoded in Hancom's open-source library.
The user-visible "distribution password" is just for write-protection, not encryption.

- [`OWPMLSerialize.cpp` L32](https://github.com/hancom-io/hwpx-owpml-model/blob/main/OWPMLApi/OWPMLSerialize.cpp#L32)
- [`encrypt.cpp`](https://github.com/hancom-io/hwpx-owpml-model/blob/main/OWPML/Zip/encrypt.cpp)
- [`Document.cpp` L810](https://github.com/hancom-io/hwpx-owpml-model/blob/main/OWPML/Document.cpp#L810)
- [`HncSha1.cpp` L874](https://github.com/hancom-io/hwpx-owpml-model/blob/main/OWPMLUtil/HncSha1.cpp#L874)

Source: [hancom-io/hwpx-owpml-model](https://github.com/hancom-io/hwpx-owpml-model) (Apache-2.0)

## Usage

```bash
uv run --with cryptography python hwpx_decrypt.py encrypted.hwpx -o decrypted.hwpx
```

```bash
pip install -r requirements.txt
python hwpx_decrypt.py encrypted.hwpx -o decrypted.hwpx
```

## Algorithm

```
SHA-256(fixed_password) -> PBKDF2-HMAC-SHA1(salt, 1024 iter) -> AES-256-CBC -> DEFLATE
```

salt, IV, iterations read from `META-INF/manifest.xml`.

Same structure as ODF 1.2 encryption, but:
- Password: hardcoded (not user input)
- Padding: zero-padding (not PKCS7)
- Checksum: over plaintext (not compressed data)
- salt == IV (identical)

## Test

Tested with [H2Orestart #42](https://github.com/ebandal/H2Orestart/issues/42) sample file (password `1qa2ws3ed`):

```
$ uv run --with cryptography python hwpx_decrypt.py 배포용.hwpx -o decrypted.hwpx
$ libreoffice --headless --convert-to pdf decrypted.hwpx  # works
```

## See also

- [H2Orestart #42](https://github.com/ebandal/H2Orestart/issues/42)
- [hwp-foss mailing list](https://groups.google.com/g/hwp-foss/c/lOr89cyqBXE)
- HWP5 binary distribution uses the same pattern (embedded key in ViewText/, AES-128-ECB)

## License

0BSD
