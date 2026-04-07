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
# Check if files are encrypted
uv run --with cryptography python hwpx_decrypt.py --check *.hwpx

# Decrypt
uv run --with cryptography python hwpx_decrypt.py encrypted.hwpx -o decrypted.hwpx
```

Or:
```bash
pip install -r requirements.txt
python hwpx_decrypt.py --check *.hwpx
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

Test files in `samples/`:

- `encrypted.hwpx` -- [H2Orestart #42](https://github.com/ebandal/H2Orestart/issues/42) sample (distribution password `1qa2ws3ed`)
- `korea-encrypted.zip` -- 8 distribution press releases from korea.kr ([KOGL Type 1](https://en.wikipedia.org/wiki/Korea_Open_Government_License), source: Korean Government Policy Briefing)

korea.kr sources:
- https://www.korea.kr/briefing/pressReleaseView.do?newsId=156747079
- https://www.korea.kr/briefing/pressReleaseView.do?newsId=156747394
- https://www.korea.kr/briefing/pressReleaseView.do?newsId=156747531
- https://www.korea.kr/briefing/pressReleaseView.do?newsId=156742677
- https://www.korea.kr/briefing/pressReleaseView.do?newsId=156745446
- https://www.korea.kr/briefing/pressReleaseView.do?newsId=156745223
- https://www.korea.kr/briefing/pressReleaseView.do?newsId=156742557
- https://www.korea.kr/briefing/pressReleaseView.do?newsId=156742140

```
$ uv run --with cryptography python hwpx_decrypt.py samples/encrypted.hwpx -o decrypted.hwpx
$ libreoffice --headless --convert-to pdf decrypted.hwpx  # works
```

## See also

- [H2Orestart #42](https://github.com/ebandal/H2Orestart/issues/42)
- [hwp-foss mailing list](https://groups.google.com/g/hwp-foss/c/lOr89cyqBXE)
- HWP5 binary distribution uses the same pattern (embedded key in ViewText/, AES-128-ECB)

## License

0BSD
