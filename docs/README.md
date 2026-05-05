# cryptobase module docs

This document serves as the master index for all features available in the `cryptobase` module.
Every cryptographic class, module, and utility is documented below.

## 🛠️ High-Level Protocols & Utilities
The best place to start. Easy-to-use wrappers for common security operations.
- **[cryptobase](./CryptoBase.md)**: Wrapper for everyday data protection and signing.
- **[Credentials](./Credentials.md)**: Windows Credential Manager abstractions.
- **[Vault](./Vault.md)**: Secure cross-platform secret storage handling.
- **[OpenPgp](./OpenPgp.md)** & **[Armor](./Armor.md)**: ASCII armoring and OpenPGP packet processing for binary data.
- **[Opaque](./opaque.md)**: Strong asymmetric PAKE (Password Authenticated Key Exchange).
- **[FileMonitor](./FileMonitor.md)**: Monitor and track cryptographic integrity of files.
- **[OTPKIT](./OTPKIT.md)**: TOTP/HOTP codes (Google Authenticator compatible).

## 🔒 Symmetric Encryption (AEAD & Stream Ciphers)
Authenticated Encryption with Associated Data (AEAD) provides both confidentiality and integrity.
- **[AesGCM](./AesGCM.md)**: The industry standard for authenticated encryption.
- **[XChaCha20Poly1305](./XChaCha20Poly1305.md)** / **[ChaCha20](./ChaCha20.md)**: Modern, high-speed stream cipher with a 192-bit nonce.
- **[AesOcb](./AesOcb.md)**: Extremely fast, single-pass authenticated encryption.
- **[AesSIV](./AesSIV.md)**: Deterministic, nonce-reuse resistant encryption.
- **[XSalsa20](./XSalsa20.md)**: Extended nonce stream cipher.
- **[Rabbit](./Rabbit.md)**: Ultra-fast stream cipher.
- **[Hc128](./Hc128.md)** / **[Hc256](./Hc256.md)**: eSTREAM portfolio software-optimized stream ciphers.

## 🧱 Legacy & Block Ciphers
Lower-level primitives or legacy ciphers maintained for compatibility.
- **[AesCng](./AesCng.md)**: AES via Windows Cryptography Next Generation.
- **[AesCfb](./AesCfb.md)** / **[AesCtr](./AesCtr.md)**: AES in Cipher Feedback and Counter modes.
- **[TripleDES](./TripleDES.md)**: Legacy 3DES block cipher.
- **[XOR](./XOR.md)**: Simple XOR obfuscation.

## 🧬 Asymmetric Cryptography
Public-key algorithms for encryption, key agreement, and digital signatures.
- **[EllipticCurve](./EllipticCurve.md)** / **[EdwardsCurve](./EdwardsCurve.md)**: Core ECC math and operations.
- **[Curve25519](./Curve25519.md)**: State-of-the-art ECDH key exchange.
- **[Ecdsa](./Ecdsa.md)**: Elliptic Curve Digital Signature Algorithm.
- **[Secp256k1](./Secp256k1.md)**: The Bitcoin elliptic curve.
- **[RSA](./RSA.md)**: Classic public key algorithms.
- **[KeypairGen](./KeypairGen.md)**: Convenience generators for asymmetric keypairs.
- **[X509](./X509.md)**: Certificate manipulations and generation.
- **[PostQuantum](./PostQuantum.md)**: Future-proof ML-KEM and ML-DSA implementations resistant to quantum computers.

## 🔑 Key Derivation (KDF) & Password Hashing
Secure ways to derive cryptographic keys or store passwords.
- **[PasswordHashing](./PasswordHashing.md)**: Includes Argon2id.
- **[BCrypt](./BCrypt.md)**: Traditional password hashing with bcrypt logic.
- **[S2K](./S2K.md)**: String-to-Key OpenPGP standard.
- **[Hkdf](./Hkdf.md)**: HMAC-based Extract-and-Expand Key Derivation Function.
- **[Pbkdf2](./Pbkdf2.md)**: Password-Based Key Derivation Function 2.

## ⚡ Hashing & MACs
Integrity checks, message digests, and message authentication codes.
- **[Sha](./Sha.md)**: SHA-2, SHA-3, Keccak, and BLAKE3 implementations.
- **[Blake2b](./Blake2b.md)**: Optimized 64-bit platform hashing.
- **[MD5](./MD5.md)** / **[Crc24](./Crc24.md)**: Checksums and legacy hashing.
- **[AesCmac](./AesCmac.md)**: Cipher-based Message Authentication Code.
- **[KMACAuth](./KMACAuth.md)**: Keccak Message Authentication Code.

## 🧰 internals
Data models and shared internals.
- **[Utilities](./Utilities.md)**: Foundational bitwise logic and helper scripts.
- **[Models](./Models.md)**: Structured classes and DTOs.