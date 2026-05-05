# Enums

> **Note:** This documentation was automatically generated.

## Enums

### EncryptionScope
```powershell
enum EncryptionScope {
  User
  Machine
}
```

### keyStoreMode
```powershell
enum keyStoreMode {
  Vault
  KeyFile
  SecureString
}
```

### KeyExportPolicy
```powershell
enum KeyExportPolicy {
  NonExportable
  ExportableEncrypted
  Exportable
}
```

### KeyProtection
```powershell
enum KeyProtection {
  None
  Protect
  ProtectHigh
  ProtectFingerPrint
}
```

### KeyUsage
```powershell
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
```

### X509ContentType
```powershell
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
```

### ECCurveName
```powershell
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
```

### SdCategory
```powershell
enum SdCategory {
  Token
  Password
}
```

### ExpType
```powershell
enum ExpType {
  Milliseconds
  Years
  Months
  Days
  Hours
  Minutes
  Seconds
}
```

### CertStoreName
```powershell
enum CertStoreName {
  MY
  ROOT
  TRUST
  CA
}
```

### CryptoAlgorithm
```powershell
enum CryptoAlgorithm {
  AesGCM
  ChaCha20
  RsaAesHMAC
  RsaECDSA
  RsaOAEP
}
```

### RSAPadding
```powershell
enum RSAPadding {
  Pkcs1
  OaepSHA1
  OaepSHA256
  OaepSHA384
  OaepSHA512
}
```

### Compression
```powershell
enum Compression {
  Gzip
  Deflate
  ZLib
}
```

### CredFlags
```powershell
enum CredFlags {
  None
  PromptNow
  UsernameTarget
}
```

### CredType
```powershell
enum CredType {
  Generic
  DomainPassword
  DomainCertificate
  DomainVisiblePassword
  GenericCertificate
  DomainExtended
  Maximum
  MaximumEx
}
```

### CredentialPersistence
```powershell
enum CredentialPersistence {
  Session
  LocalComputer
  Enterprise
}
```

### HashType
```powershell
enum HashType {
  None
  SHA256
  SHA384
  SHA512
}
```

### S2KType
```powershell
enum S2KType {
  Simple
  Salted
  Reserved
  IteratedAndSalted
  Argon2
}
```

### AsymmetricAlgorithm
```powershell
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
```

### KeyFormat
```powershell
enum KeyFormat {
  Raw
  Base64
  Hex
  Pem
  Pkcs8
  Pkcs12
  Xml
}
```

### KeySize
```powershell
enum KeySize {
  Low
  Medium
  High
  VeryHigh
  Maximum
}
```

### ArmorType
```powershell
enum ArmorType {
  Message
  PublicKey
  PrivateKey
  Signature
  SignedMessage
}
```

### MLKemSecurityLevel
```powershell
enum MLKemSecurityLevel {
  MLKem512
  MLKem768
  MLKem1024
}
```

### SlhDsaSecurityLevel
```powershell
enum SlhDsaSecurityLevel {
  SlhDsa128s
  SlhDsa128f
  SlhDsa192s
  SlhDsa192f
  SlhDsa256s
  SlhDsa256f
}
```

### PgpHashAlgorithmId
```powershell
enum PgpHashAlgorithmId {
  Md5
  Sha1
  RipeMd160
  Sha256
  Sha384
  Sha512
  Sha224
  Sha3_256
  Sha3_512
}
```

### PgpPublicKeyAlgorithm
```powershell
enum PgpPublicKeyAlgorithm {
  RsaEncryptOrSign
  RsaEncryptOnly
  RsaSignOnly
  ElgamalEncryptOnly
  Dsa
  Ecdh
  Ecdsa
  Reserved20
  Reserved21
  EdDsaLegacy
  X25519
  X448
  Ed25519
  Ed448
  Private100
  Private101
  Private110
}
```

### PgpPacketTag
```powershell
enum PgpPacketTag {
  Reserved
  PublicKeyEncryptedSessionKey
  Signature
  SymmetricKeyEncryptedSessionKey
  OnePassSignature
  SecretKey
  PublicKey
  SecretSubkey
  CompressedData
  SymmetricallyEncryptedData
  Marker
  LiteralData
  Trust
  UserId
  PublicSubkey
  UserAttribute
  SymmetricallyEncryptedIntegrityProtectedData
  ModificationDetectionCode
  AeadEncryptedData
  Padding
  Private60
  Private61
  Private62
  Private63
}
```

### PgpS2KUsage
```powershell
enum PgpS2KUsage {
  None
  Aead
  Sha1Hash
  Checksum
}
```

### PgpCompressionAlgorithm
```powershell
enum PgpCompressionAlgorithm {
  Uncompressed
  Zip
  Zlib
  BZip2
}
```

### PgpSignatureType
```powershell
enum PgpSignatureType {
  BinaryDocument
  CanonicalTextDocument
  Standalone
  GenericCertification
  PersonaCertification
  CasualCertification
  PositiveCertification
  SubkeyBinding
  PrimaryKeyBinding
  DirectKey
  KeyRevocation
  SubkeyRevocation
  CertificationRevocation
  Timestamp
  ThirdPartyConfirmation
}
```

### PgpSignatureSubpacketType
```powershell
enum PgpSignatureSubpacketType {
  Reserved0
  Reserved1
  SignatureCreationTime
  SignatureExpirationTime
  ExportableCertification
  TrustSignature
  RegularExpression
  Revocable
  KeyExpirationTime
  PlaceholderBackwardCompatibility
  PreferredSymmetricAlgorithms
  RevocationKey
  IssuerKeyId
  NotationData
  PreferredHashAlgorithms
  PreferredCompressionAlgorithms
  KeyServerPreferences
  PreferredKeyServer
  PrimaryUserId
  PolicyUri
  KeyFlags
  SignersUserId
  ReasonForRevocation
  Features
  SignatureTarget
  EmbeddedSignature
  IssuerFingerprint
  PreferredAeadAlgorithms
  IntendedRecipientFingerprint
  AttestationKeySignature
}
```

### PgpUserAttributeSubpacketType
```powershell
enum PgpUserAttributeSubpacketType {
  Image
  PrivateExperimental100
  PrivateExperimental101
  PrivateExperimental110
}
```

### PgpPacketFormat
```powershell
enum PgpPacketFormat {
  Old
  New
}
```

### PgpLiteralDataFormat
```powershell
enum PgpLiteralDataFormat {
  Binary
  Text
  Utf8
}
```

### PgpImageEncoding
```powershell
enum PgpImageEncoding {
  Jpeg
  PrivateExperimental100
  PrivateExperimental101
  PrivateExperimental110
}
```

### PgpRevocationReason
```powershell
enum PgpRevocationReason {
  NoReason
  KeySuperseded
  KeyCompromised
  KeyRetired
  UserIdNoLongerValid
}
```


