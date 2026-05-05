#!/usr/bin/env pwsh

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
