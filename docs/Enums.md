# Enums

> **Note:** This documentation was automatically generated.

## Enums

### EncryptionScope
`powershell
enum EncryptionScope {
  User
  Machine
}
``n
### keyStoreMode
`powershell
enum keyStoreMode {
  Vault
  KeyFile
  SecureString
}
``n
### KeyExportPolicy
`powershell
enum KeyExportPolicy {
  NonExportable
  ExportableEncrypted
  Exportable
}
``n
### KeyProtection
`powershell
enum KeyProtection {
  None
  Protect
  ProtectHigh
  ProtectFingerPrint
}
``n
### KeyUsage
`powershell
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
``n
### X509ContentType
`powershell
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
``n
### ECCurveName
`powershell
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
``n
### SdCategory
`powershell
enum SdCategory {
  Token
  Password
}
``n
### ExpType
`powershell
enum ExpType {
  Milliseconds
  Years
  Months
  Days
  Hours
  Minutes
  Seconds
}
``n
### CertStoreName
`powershell
enum CertStoreName {
  MY
  ROOT
  TRUST
  CA
}
``n
### CryptoAlgorithm
`powershell
enum CryptoAlgorithm {
  AesGCM
  ChaCha20
  RsaAesHMAC
  RsaECDSA
  RsaOAEP
}
``n
### RSAPadding
`powershell
enum RSAPadding {
  Pkcs1
  OaepSHA1
  OaepSHA256
  OaepSHA384
  OaepSHA512
}
``n
### Compression
`powershell
enum Compression {
  Gzip
  Deflate
  ZLib
}
``n
### CredFlags
`powershell
enum CredFlags {
  None
  PromptNow
  UsernameTarget
}
``n
### CredType
`powershell
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
``n
### CredentialPersistence
`powershell
enum CredentialPersistence {
  Session
  LocalComputer
  Enterprise
}
``n
### HashType
`powershell
enum HashType {
  None
  SHA256
  SHA384
  SHA512
}
``n
### S2KType
`powershell
enum S2KType {
  Simple
  Salted
  Reserved
  IteratedAndSalted
  Argon2
}
``n
### AsymmetricAlgorithm
`powershell
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
``n
### KeyFormat
`powershell
enum KeyFormat {
  Raw
  Base64
  Hex
  Pem
  Pkcs8
  Pkcs12
  Xml
}
``n
### KeySize
`powershell
enum KeySize {
  Low
  Medium
  High
  VeryHigh
  Maximum
}
``n
### ArmorType
`powershell
enum ArmorType {
  Message
  PublicKey
  PrivateKey
  Signature
  SignedMessage
}
``n
### MLKemSecurityLevel
`powershell
enum MLKemSecurityLevel {
  MLKem512
  MLKem768
  MLKem1024
}
``n
### SlhDsaSecurityLevel
`powershell
enum SlhDsaSecurityLevel {
  SlhDsa128s
  SlhDsa128f
  SlhDsa192s
  SlhDsa192f
  SlhDsa256s
  SlhDsa256f
}
``n
### PgpHashAlgorithmId
`powershell
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
``n
### PgpPublicKeyAlgorithm
`powershell
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
``n
### PgpPacketTag
`powershell
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
``n
### PgpS2KUsage
`powershell
enum PgpS2KUsage {
  None
  Aead
  Sha1Hash
  Checksum
}
``n
### PgpCompressionAlgorithm
`powershell
enum PgpCompressionAlgorithm {
  Uncompressed
  Zip
  Zlib
  BZip2
}
``n
### PgpSignatureType
`powershell
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
``n
### PgpSignatureSubpacketType
`powershell
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
``n
### PgpUserAttributeSubpacketType
`powershell
enum PgpUserAttributeSubpacketType {
  Image
  PrivateExperimental100
  PrivateExperimental101
  PrivateExperimental110
}
``n
### PgpPacketFormat
`powershell
enum PgpPacketFormat {
  Old
  New
}
``n
### PgpLiteralDataFormat
`powershell
enum PgpLiteralDataFormat {
  Binary
  Text
  Utf8
}
``n
### PgpImageEncoding
`powershell
enum PgpImageEncoding {
  Jpeg
  PrivateExperimental100
  PrivateExperimental101
  PrivateExperimental110
}
``n
### PgpRevocationReason
`powershell
enum PgpRevocationReason {
  NoReason
  KeySuperseded
  KeyCompromised
  KeyRetired
  UserIdNoLongerValid
}
``n

