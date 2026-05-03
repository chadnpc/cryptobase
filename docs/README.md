# cryptobase module docs

This document provides a quick usage overview of the major classes available in the `cryptobase` module.

**🔒 Symmetric Encryption (AEAD)**
Authenticated Encryption with Associated Data (AEAD) provides both confidentiality and integrity.

- **[AesGCM](./AesGCM.md)**: The industry standard for authenticated encryption.
- **[XChaCha20Poly1305](./XChaCha20Poly1305.md)**: Modern, high-speed stream cipher with a 192-bit nonce.
- **[AesOCB](./AesOcb.md)**: Extremely fast, single-pass authenticated encryption.
- **[AesSIV](./AesSIV.md)**: Deterministic, nonce-reuse resistant encryption.
- **[XSalsa20](./XSalsa20.md)**: Extended nonce stream cipher (unauthenticated).


**⚡ Hashing & MACs**

- **[BLAKE3](./Blake3.md)**: The fastest cryptographic hash function.
- **[SHA-3 (Keccak)](./Sha.md)**: The latest NIST standard for hashing and SHAKE XOF.
- **[Blake2b](./Blake2b.md)**: Optimized 64-bit hashing.
- **[Legacy Hashes](./Legacy.md)**: MD5 and other compatibility hashes.



**🔑 Password Hashing & KDF**
Securely store passwords and derive keys.

- **[Argon2id](./Argon2.md)**: Winner of the PHC, the recommended choice.
- **[BCrypt](./BCrypt.md)**: Traditional password hashing (with V3 enhancements).
- **[Key Derivation (KDF)](./KeyDerivation.md)**: HKDF, PBKDF2, and S2K.



**🧬 Elliptic Curve Cryptography (ECC)**

- **[ECC Overview](./ECC.md)**: Secp256k1 (Bitcoin), Curve25519 (X25519), and NIST curves.
- **[Ed25519](./Ed25519.md)**: Edwards-curve Digital Signature Algorithm (Ed25519 and Ed448).



**🕰️ Post-Quantum Cryptography (PQC)**
Future-proof algorithms designed to resist quantum computer attacks.

- **[Post-Quantum Algorithms](./PostQuantum.md)**: ML-KEM (Kyber), ML-DSA (Dilithium), and SLH-DSA.



**🛠️ High-Level Protocols & Utils**

- **[CryptoBase Convenience](./CryptoBase.md)**: Wrapper for everyday data protection and signing.
- **[OPAQUE Protocol](./Opaque.md)**: Strong asymmetric PAKE.
- **[Credentials & Vaults](./Credentials.md)**: Windows Credential Manager and secure secret storage.
- **[OTPKIT](./OTPKIT.md)**: TOTP/HOTP codes (Google Authenticator compatible).
- **[OpenPgp & Armor](./OpenPgp.md)**: ASCII armoring for binary data.