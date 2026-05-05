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

enum MLKemSecurityLevel {
  MLKem512
  MLKem768
  MLKem1024
}

enum SlhDsaSecurityLevel {
  SlhDsa128s
  SlhDsa128f
  SlhDsa192s
  SlhDsa192f
  SlhDsa256s
  SlhDsa256f
}

#region OpenPgpEnums
enum PgpHashAlgorithmId : byte {
  Md5 = 1
  Sha1 = 2
  RipeMd160 = 3
  Sha256 = 8
  Sha384 = 9
  Sha512 = 10
  Sha224 = 11
  Sha3_256 = 12
  Sha3_512 = 14
}

enum PgpPublicKeyAlgorithm : byte {
  RsaEncryptOrSign = 1
  RsaEncryptOnly = 2
  RsaSignOnly = 3
  ElgamalEncryptOnly = 16
  Dsa = 17
  Ecdh = 18
  Ecdsa = 19
  Reserved20 = 20
  Reserved21 = 21
  EdDsaLegacy = 22
  X25519 = 25
  X448 = 26
  Ed25519 = 27
  Ed448 = 28
  Private100 = 100
  Private101 = 101
  Private110 = 110
}

enum PgpPacketTag : byte {
  Reserved = 0
  PublicKeyEncryptedSessionKey = 1
  Signature = 2
  SymmetricKeyEncryptedSessionKey = 3
  OnePassSignature = 4
  SecretKey = 5
  PublicKey = 6
  SecretSubkey = 7
  CompressedData = 8
  SymmetricallyEncryptedData = 9
  Marker = 10
  LiteralData = 11
  Trust = 12
  UserId = 13
  PublicSubkey = 14
  UserAttribute = 17
  SymmetricallyEncryptedIntegrityProtectedData = 18
  ModificationDetectionCode = 19
  AeadEncryptedData = 20
  Padding = 21
  Private60 = 60
  Private61 = 61
  Private62 = 62
  Private63 = 63
}

enum PgpS2KUsage : byte {
  None = 0
  Aead = 253
  Sha1Hash = 254
  Checksum = 255
}

enum PgpCompressionAlgorithm : byte {
  Uncompressed = 0
  Zip = 1
  Zlib = 2
  BZip2 = 3
}

enum PgpSignatureType : byte {
  BinaryDocument = 0x00
  CanonicalTextDocument = 0x01
  Standalone = 0x02
  GenericCertification = 0x10
  PersonaCertification = 0x11
  CasualCertification = 0x12
  PositiveCertification = 0x13
  SubkeyBinding = 0x18
  PrimaryKeyBinding = 0x19
  DirectKey = 0x1F
  KeyRevocation = 0x20
  SubkeyRevocation = 0x28
  CertificationRevocation = 0x30
  Timestamp = 0x40
  ThirdPartyConfirmation = 0x50
}

enum PgpSignatureSubpacketType : byte {
  Reserved0 = 0
  Reserved1 = 1
  SignatureCreationTime = 2
  SignatureExpirationTime = 3
  ExportableCertification = 4
  TrustSignature = 5
  RegularExpression = 6
  Revocable = 7
  KeyExpirationTime = 9
  PlaceholderBackwardCompatibility = 10
  PreferredSymmetricAlgorithms = 11
  RevocationKey = 12
  IssuerKeyId = 16
  NotationData = 20
  PreferredHashAlgorithms = 21
  PreferredCompressionAlgorithms = 22
  KeyServerPreferences = 23
  PreferredKeyServer = 24
  PrimaryUserId = 25
  PolicyUri = 26
  KeyFlags = 27
  SignersUserId = 28
  ReasonForRevocation = 29
  Features = 30
  SignatureTarget = 31
  EmbeddedSignature = 32
  IssuerFingerprint = 33
  PreferredAeadAlgorithms = 34
  IntendedRecipientFingerprint = 35
  AttestationKeySignature = 37
}

enum PgpUserAttributeSubpacketType : byte {
  Image = 1
  PrivateExperimental100 = 100
  PrivateExperimental101 = 101
  PrivateExperimental110 = 110
}

enum PgpPacketFormat : byte {
  Old = 0
  New = 1
}

enum PgpLiteralDataFormat : byte {
  Binary = 0x62 # 'b'
  Text = 0x74   # 't'
  Utf8 = 0x75   # 'u'
}

enum PgpImageEncoding : byte {
  Jpeg = 1
  PrivateExperimental100 = 100
  PrivateExperimental101 = 101
  PrivateExperimental110 = 110
}

enum PgpRevocationReason : byte {
  NoReason = 0x00
  KeySuperseded = 0x01
  KeyCompromised = 0x02
  KeyRetired = 0x03
  UserIdNoLongerValid = 0x20
}
#endregion OpenPgpEnums