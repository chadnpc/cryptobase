#!/usr/bin/env pwsh

enum EncryptionScope {
  User    # The encrypted data can be decrypted with the same user on any machine.
  Machine # The encrypted data can only be decrypted with the same user on the same machine it was encrypted on.
}

enum keyStoreMode {
  Vault
  KeyFile
  SecureString
}
enum KeyExportPolicy {
  NonExportable
  ExportableEncrypted
  Exportable
}
enum KeyProtection {
  None
  Protect
  ProtectHigh
  ProtectFingerPrint
}
enum KeyUsage {
  None
  CRLSign
  CertSign
  EncipherOnly
  KeyAgreement
  DataEncipherment
  KeyEncipherment
  NonRepudiation
  DigitalSignature
  DecipherOnly
}
enum X509ContentType {
  Unknown
  Cert
  SerializedCert
  Pfx
  PEM
  Pkcs12
  SerializedStore
  Pkcs7
  Authenticode
}

enum ECCurveName {
  ansix9p256r1
  ansix9p384r1
  ansix9p521r1
  brainpoolP256r1
  brainpoolP384r1
  brainpoolP512r1
  nistP256
  nistP384
  nistP521
  secp256k1
}

enum SdCategory {
  Token
  Password
}
enum ExpType {
  Milliseconds
  Years
  Months
  Days
  Hours
  Minutes
  Seconds
}
enum CertStoreName {
  MY
  ROOT
  TRUST
  CA
}
# Only Encryption algorithms that are widely trusted and used in real-world
enum CryptoAlgorithm {
  AesGCM # AES-GCM (Galois/Counter Mode). A strong encryption on its own that doesn't necessarily with its built-in authentication functions. Its a mode of operation for AES that provides both confidentiality and authenticity for the encrypted data. GCM provides faster encryption and decryption compared to CBC mode and is widely used for secure communication, especially in VPN and TLS/SSL apps.
  ChaCha20 # ChaCha20 + SHA256 in this case. I would prefer ChaCha20Poly1305 but the Poly1305 class is still not working/usable. But no wories, ChaCha20 is like the salsa of the cryptography world, it's got the moves to keep your data secure and grooving to its own beat! :) Get it? [ref] to the dance-like steps performed in the algorithm's mixing process? Nevermind ... Its a symmetric key encryption algorithm, based on salsa20 algorithm. ChaCha20 provides the encryption, while Poly1305 (or SHA256 in this case) provides the authentication. This combination provides both confidentiality and authenticity for the encrypted data.
  RsaAesHMAC # RSA + AES + HMAC: This combination uses RSA for key exchange, AES for encryption, and HMAC (hash-based message authentication code) for authentication. This provides a secure mechanism for exchanging keys and encrypting data, as well as a way to verify the authenticity of the data. ie: By combining RSA and AES, one can take advantage of both algorithms' strengths: RSA is used to securely exchange the AES key, while AES is be used for the actual encryption and decryption of the data. This way, RSA provides security for key exchange, and AES provides fast encryption and decryption for the data.
  RsaECDSA # RSA + ECDSA (Elliptic Curve Digital Signature Algorithm) are public-key cryptography algorithms that are often used together. RSA can be used for encrypting data, while ECDSA can be used for digital signatures, providing both confidentiality and authenticity for the data.
  RsaOAEP # RSA-OAEP (Optimal Asymmetric Encryption Padding)
}
# System.Security.Cryptography.RSAEncryptionPadding Names
enum RSAPadding {
  Pkcs1
  OaepSHA1
  OaepSHA256
  OaepSHA384
  OaepSHA512
}

enum Compression {
  Gzip
  Deflate
  ZLib
  # Zstd # Todo: Add Zstandard. (The one from facebook. or maybe zstd-sharp idk. I just can't find a way to make it work in powershell! no dll nothing!)
}

enum CredFlags {
  None = 0x0
  PromptNow = 0x2
  UsernameTarget = 0x4
}

enum CredType {
  Generic = 1
  DomainPassword = 2
  DomainCertificate = 3
  DomainVisiblePassword = 4
  GenericCertificate = 5
  DomainExtended = 6
  Maximum = 7
  MaximumEx = 1007 # (Maximum + 1000)
}

enum CredentialPersistence {
  Session = 1
  LocalComputer = 2
  Enterprise = 3
}


enum HashType {
  None = -1
  SHA256 = 0
  SHA384 = 1
  SHA512 = 2
}


#region KeypairGen_Enums

enum AsymmetricAlgorithm {
  ED25519
  RSA
  ECDSA
  ECDH
  ED448
  DIFFIE_HELLMAN
  DSA
  ELGAMAL
  KYBER
  DILITHIUM
  SPHINCS
  X25519
  X448
  CURVE25519
  SECP256K1
  SECP256R1
  SECP384R1
  SECP521R1
}

enum KeyFormat {
  Raw
  Base64
  Hex
  Pem
  Pkcs8
  Pkcs12
  Xml
}

enum KeySize {
  Low = 1024
  Medium = 2048
  High = 3072
  VeryHigh = 4096
  Maximum = 8192
}



enum ArmorType {
  Message
  PublicKey
  PrivateKey
  Signature
  SignedMessage
}
