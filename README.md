# hwpx-decrypt

HWPX 배포용 문서 복호화.

암호화 패스워드가 한컴 오픈소스에 하드코딩되어 있다.
사용자 배포 암호는 쓰기 보호용일 뿐, 암호화 키와 무관.

## 출처
- [`OWPMLSerialize.cpp` L32](https://github.com/hancom-io/hwpx-owpml-model/blob/main/OWPMLApi/OWPMLSerialize.cpp#L32)
- [`encrypt.cpp`](https://github.com/hancom-io/hwpx-owpml-model/blob/main/OWPML/Zip/encrypt.cpp)
- [`Document.cpp` L810](https://github.com/hancom-io/hwpx-owpml-model/blob/main/OWPML/Document.cpp#L810)
- [`HncSha1.cpp` L874](https://github.com/hancom-io/hwpx-owpml-model/blob/main/OWPMLUtil/HncSha1.cpp#L874)

## 사용법

```bash
# 암호화 여부 확인
uv run --with cryptography python hwpx_decrypt.py --check *.hwpx

# 복호화
uv run --with cryptography python hwpx_decrypt.py 배포용.hwpx -o 복호화.hwpx
```

또는:
```bash
pip install -r requirements.txt
python hwpx_decrypt.py --check *.hwpx
python hwpx_decrypt.py 배포용.hwpx -o 복호화.hwpx
```

## 알고리즘

```
SHA-256(고정_패스워드) -> PBKDF2-HMAC-SHA1(salt, 1024회) -> AES-256-CBC -> DEFLATE 해제
```

salt, IV, iterations는 `META-INF/manifest.xml`에서 읽는다.

ODF 1.2 암호화와 같은 구조지만 차이점:
- 패스워드: 하드코딩 (사용자 입력 아님)
- 패딩: PKCS7 대신 zero-padding
- 체크섬: 압축 전 평문 기준
- salt == IV (동일값)

## 테스트

`samples/` 에 테스트 파일 포함:

- `encrypted.hwpx` -- [H2Orestart #42](https://github.com/ebandal/H2Orestart/issues/42) 테스트 파일 (배포용 암호 `1qa2ws3ed`)
- `korea-encrypted.zip` -- korea.kr 배포용 보도자료 8건 ([공공누리 제1유형](https://en.wikipedia.org/wiki/Korea_Open_Government_License), 출처: 대한민국 정책브리핑)

korea.kr 원본:
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
$ libreoffice --headless --convert-to pdf decrypted.hwpx  # 정상 열림
```

## 관련

- [H2Orestart #42](https://github.com/ebandal/H2Orestart/issues/42)
- [hwp-foss 메일링 리스트](https://groups.google.com/g/hwp-foss/c/lOr89cyqBXE)
- HWP5 바이너리 배포용도 같은 패턴 (ViewText/ 키 내장, AES-128-ECB)

## 라이선스

0BSD
