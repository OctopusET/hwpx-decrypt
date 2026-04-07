#!/usr/bin/env python3
"""Decrypt HWPX distribution (read-only) documents.

HWPX distribution documents use ODF-style encryption (manifest.xml) with a
hardcoded password instead of a user-provided one. The user-visible
"distribution password" is only for write-protection verification.

Algorithm:
  1. SHA-256(FIXED_PASSWORD) -> start_key
  2. PBKDF2-HMAC-SHA1(start_key, salt, iterations, dklen) -> derived_key
  3. AES-256-CBC(derived_key, IV) -> decrypt
  4. Raw DEFLATE decompress (trailing zero-padding is ignored by zlib)
  5. Verify SHA-256-1K checksum (first 1024 bytes of plaintext)

Sources (as of 2026-04-07):
  hancom-io/hwpx-owpml-model 4156079 (Apache-2.0)
    OWPMLApi/OWPMLSerialize.cpp#L32   hardcoded password
    OWPML/Zip/encrypt.cpp#L50        decryption: SHA-256 -> PBKDF2 -> AES-CBC
    OWPML/Document.cpp#L810          manifest parsing
    OWPMLUtil/HncSha1.cpp#L874       PBKDF2-HMAC-SHA1
    OWPML/Zip/zip.cpp#L2535          zero-padding on encrypt

Differences from ODF 1.2 encryption:
  - Password: hardcoded, not user-provided
  - Padding: zero-padding, not PKCS7
  - Checksum: SHA-256 of first 1024 bytes of plaintext (not compressed)
  - Salt == IV (ODF: independently random)
"""

import argparse
import base64
import hashlib
import sys
import xml.etree.ElementTree as ET
import zipfile
import zlib

from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes

# OWPMLApi/OWPMLSerialize.cpp line 32
DISTRIBUTE_PASSWORD = b'"Yang WangSunv!!"'

# line 33: old password has a coding bug ("\0x59" = null + literal "x59")
# strlen() sees only the leading '"' (1 byte) before the null terminator.
OLD_DISTRIBUTE_PASSWORD = b'"'

NS = "urn:oasis:names:tc:opendocument:xmlns:manifest:1.0"


def parse_manifest(manifest_bytes):
    """Parse META-INF/manifest.xml, return {path: entry_info} for encrypted entries."""
    root = ET.fromstring(manifest_bytes)
    entries = {}
    for fe in root.findall(f"{{{NS}}}file-entry"):
        path = fe.get("full-path")
        enc = fe.find(f"{{{NS}}}encryption-data")
        if enc is None:
            continue
        algo = enc.find(f"{{{NS}}}algorithm")
        kd = enc.find(f"{{{NS}}}key-derivation")
        if algo is None or kd is None:
            continue
        entries[path] = {
            "original_size": int(fe.get("size", "0")),
            "checksum": base64.b64decode(enc.get("checksum", "")),
            "iv": base64.b64decode(algo.get("initialisation-vector", "")),
            "salt": base64.b64decode(kd.get("salt", "")),
            "key_size": int(kd.get("key-size", "32")),
            "iterations": int(kd.get("iteration-count", "1024")),
        }
    return entries


def derive_key(password, salt, iterations, key_size):
    """SHA-256(password) -> PBKDF2-HMAC-SHA1 -> derived key."""
    start_key = hashlib.sha256(password).digest()
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA1(),
        length=key_size,
        salt=salt,
        iterations=iterations,
    )
    return kdf.derive(start_key)


def decrypt_and_decompress(data, key, iv, original_size):
    """AES-CBC decrypt, then raw DEFLATE decompress.

    Zero-padding from AES block alignment sits after the DEFLATE stream.
    zlib.decompress ignores trailing bytes, so no stripping needed.
    For tiny uncompressed entries (e.g. 16-byte PrvText.txt), DEFLATE
    fails and we fall back to truncating to original_size.
    """
    dec = Cipher(algorithms.AES(key), modes.CBC(iv)).decryptor()
    decrypted = dec.update(data) + dec.finalize()

    # Raw DEFLATE. Use decompressobj to tolerate trailing zero-padding
    # from AES block alignment (decompress() rejects trailing bytes).
    try:
        d = zlib.decompressobj(-15)
        return d.decompress(decrypted)
    except zlib.error:
        pass

    # Fallback: no compression (very small files)
    return decrypted[:original_size]


def verify_checksum(plaintext, expected):
    """SHA-256 of first 1024 bytes of plaintext."""
    return hashlib.sha256(plaintext[:1024]).digest() == expected


def decrypt_hwpx(input_path, output_path=None):
    """Decrypt a HWPX distribution document. Returns True on success."""
    with zipfile.ZipFile(input_path, "r") as zin:
        try:
            manifest = zin.read("META-INF/manifest.xml")
        except KeyError:
            print("Not encrypted: no META-INF/manifest.xml", file=sys.stderr)
            return True

        entries = parse_manifest(manifest)
        if not entries:
            print("Not encrypted: no encrypted entries in manifest",
                  file=sys.stderr)
            return True

        # Try current password, fall back to old buggy password
        passwords = [DISTRIBUTE_PASSWORD, OLD_DISTRIBUTE_PASSWORD]
        test_path = min(entries, key=lambda p: entries[p]["original_size"])
        test_info = entries[test_path]
        test_data = zin.read(test_path)

        working_pwd = None
        for pwd in passwords:
            k = derive_key(pwd, test_info["salt"],
                           test_info["iterations"], test_info["key_size"])
            pt = decrypt_and_decompress(test_data, k, test_info["iv"],
                                        test_info["original_size"])
            if verify_checksum(pt, test_info["checksum"]):
                working_pwd = pwd
                break

        if working_pwd is None:
            print("Decryption failed: neither password worked",
                  file=sys.stderr)
            return False

        results = {}
        all_ok = True
        for path, info in entries.items():
            encrypted = zin.read(path)
            # Per-entry key derivation in case params differ
            entry_key = derive_key(working_pwd, info["salt"],
                                   info["iterations"], info["key_size"])
            plaintext = decrypt_and_decompress(encrypted, entry_key,
                                               info["iv"],
                                               info["original_size"])
            ok = verify_checksum(plaintext, info["checksum"])
            results[path] = plaintext
            status = "OK" if ok else "FAIL"
            print(f"  {path}: {len(encrypted)}B -> {len(plaintext)}B [{status}]",
                  file=sys.stderr)
            if not ok:
                all_ok = False

        if not all_ok:
            print("Checksum verification failed", file=sys.stderr)
            return False

        if output_path:
            # Clean manifest: remove encryption-data elements
            mroot = ET.fromstring(manifest)
            for fe in mroot.findall(f"{{{NS}}}file-entry"):
                enc = fe.find(f"{{{NS}}}encryption-data")
                if enc is not None:
                    fe.remove(enc)
                    fe.attrib.pop("size", None)
            clean_manifest = ET.tostring(mroot, encoding="unicode",
                                         xml_declaration=True)

            with zipfile.ZipFile(output_path, "w",
                                zipfile.ZIP_DEFLATED) as zout:
                for item in zin.infolist():
                    if item.filename in results:
                        zout.writestr(item.filename, results[item.filename])
                    elif item.filename == "META-INF/manifest.xml":
                        zout.writestr(item.filename, clean_manifest)
                    else:
                        zout.writestr(item, zin.read(item.filename))
            print(f"Decrypted: {output_path}", file=sys.stderr)

        return True


def check_hwpx(input_path):
    """Check if a HWPX file is distribution-encrypted."""
    try:
        with zipfile.ZipFile(input_path, "r") as zin:
            try:
                manifest = zin.read("META-INF/manifest.xml")
            except KeyError:
                print(f"{input_path}: not encrypted (no manifest)", file=sys.stderr)
                return False
            entries = parse_manifest(manifest)
            if entries:
                print(f"{input_path}: encrypted ({len(entries)} entries)",
                      file=sys.stderr)
                return True
            else:
                print(f"{input_path}: not encrypted", file=sys.stderr)
                return False
    except zipfile.BadZipFile:
        print(f"{input_path}: not a ZIP file", file=sys.stderr)
        return False


def main():
    p = argparse.ArgumentParser(
        description="Decrypt HWPX distribution (read-only) documents")
    p.add_argument("input", nargs="+", help="HWPX file(s)")
    p.add_argument("-o", "--output", help="Output decrypted HWPX file")
    p.add_argument("-c", "--check", action="store_true",
                   help="Check if files are encrypted (no decryption)")
    args = p.parse_args()

    if args.check:
        any_encrypted = False
        for f in args.input:
            if check_hwpx(f):
                any_encrypted = True
        sys.exit(0 if any_encrypted else 1)

    if len(args.input) != 1:
        print("Decryption requires exactly one input file", file=sys.stderr)
        sys.exit(2)

    ok = decrypt_hwpx(args.input[0], args.output)
    sys.exit(0 if ok else 1)


if __name__ == "__main__":
    main()
