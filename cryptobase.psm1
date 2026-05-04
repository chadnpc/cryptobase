#!/usr/bin/env pwsh
using namespace System
using namespace System.IO
using namespace System.Web
using namespace System.Text
using namespace System.Net.Http
using namespace System.Security
using namespace System.Reflection
using namespace System.Globalization
using namespace System.Reflection.Emit
using namespace System.Runtime.Serialization
using namespace System.Security.Cryptography
using namespace System.Runtime.InteropServices
using namespace System.Collections.ObjectModel

# Load all sub-modules :
# (Get-ChildItem ./Private).Name.ForEach({ "using module Private/" + $_ })

using module Private/Enums.psm1
using module Private/Exceptions.psm1
using module Private/Utilities.psm1
using module Private/Models.psm1
using module Private/AesCCM.psm1
using module Private/AesCfb.psm1
using module Private/AesCmac.psm1
using module Private/AesCng.psm1
using module Private/AesCtr.psm1
using module Private/AesGCM.psm1
using module Private/AesOcb.psm1
using module Private/AesSIV.psm1
using module Private/Armor.psm1
using module Private/BCrypt.psm1
using module Private/Blake2b.psm1
using module Private/ChaCha20.psm1
using module Private/Crc24.psm1
using module Private/Credentials.psm1
using module Private/Curve25519.psm1
using module Private/Ecdsa.psm1
using module Private/EdwardsCurve.psm1
using module Private/EllipticCurve.psm1
using module Private/FileMonitor.psm1
using module Private/Hc128.psm1
using module Private/Hc256.psm1
using module Private/Hkdf.psm1
using module Private/KeypairGen.psm1
using module Private/KMACAuth.psm1
using module Private/MD5.psm1
using module Private/opaque.psm1
using module Private/OpenPgp.psm1
using module Private/OTPKIT.psm1
using module Private/PasswordHashing.psm1
using module Private/Pbkdf2.psm1
using module Private/PostQuantum.psm1
using module Private/Rabbit.psm1
using module Private/RSA.psm1
using module Private/S2K.psm1
using module Private/Secp256k1.psm1
using module Private/Sha.psm1
using module Private/TripleDES.psm1
using module Private/Vault.psm1
using module Private/X509.psm1
using module Private/XChaCha20Poly1305.psm1
using module Private/XOR.psm1
using module Private/XSalsa20.psm1

#Requires -PSEdition Core
#Requires -Modules PsModuleBase, cliHelper.xconvert

# Main class
class CryptoBase : CryptobaseUtils {
  static [Type[]] $ReturnTypes = ([CryptoBase]::Methods.ReturnType | Sort-Object -Unique Name)
  static [MethodInfo[]] $Methods = ([Cryptobase].GetMethods().Where({ $_.IsStatic -and !$_.IsHideBySig }))

  CryptoBase() {}

  static [string] GetHelp() {
    return "this is help info"
  }

  static [byte[]] ProtectData([byte[]]$plainbytes, [string]$passw0rd) {
    return [CryptoBase]::ProtectData($plainbytes, $passw0rd, $null)
  }

  static [byte[]] ProtectData([byte[]]$plainbytes, [SecureString]$password) {
    return [CryptoBase]::ProtectData($plainbytes, $password, $null)
  }

  static [byte[]] ProtectData([byte[]]$plainbytes, [string]$passw0rd, [byte[]]$aad) {
    return [CryptoBase]::ProtectData($plainbytes, [xconvert]::ToSecurestring($passw0rd), $aad)
  }

  static [byte[]] ProtectData([byte[]]$plainbytes, [securestring]$password, [byte[]]$aad) {
    $salt = [byte[]]::new(16)
    $nonce = [byte[]]::new(12)
    [RandomNumberGenerator]::Fill($salt)
    [RandomNumberGenerator]::Fill($nonce)
    $passBytes = [Encoding]::UTF8.GetBytes([CryptoBase]::SecureStringToString($password))
    $key = [Argon2id]::Hash($passBytes, $salt, 65536, 3, 4, 32)
    $ciphertext = [byte[]]::new($plainbytes.Length)
    $tag = [byte[]]::new(16)
    $aes = [System.Security.Cryptography.AesGcm]::new($key)
    try {
      $aes.Encrypt($nonce, $plainbytes, $ciphertext, $tag, $aad)
    } finally {
      $aes.Dispose()
      [Array]::Clear($passBytes, 0, $passBytes.Length)
      [Array]::Clear($key, 0, $key.Length)
    }
    # payload: version(1) + salt(16) + nonce(12) + tag(16) + ciphertext
    return [byte[]]@(0x01) + $salt + $nonce + $tag + $ciphertext
  }

  static [byte[]] ProtectDataCascade([byte[]]$plainbytes, [securestring]$password) {
    $salt = [byte[]]::new(32)
    [RandomNumberGenerator]::Fill($salt)

    $passBytes = [Encoding]::UTF8.GetBytes([CryptoBase]::SecureStringToString($password))
    $masterKey = [Argon2id]::Hash($passBytes, $salt, 65536, 4, 4, 64)
    [Array]::Clear($passBytes, 0, $passBytes.Length)

    $aesKey = [byte[]]$masterKey[0..31]
    $xchachaKey = [byte[]]$masterKey[32..63]
    [Array]::Clear($masterKey, 0, $masterKey.Length)

    $aesNonce = [byte[]]::new(12)
    [RandomNumberGenerator]::Fill($aesNonce)
    $innerCiphertext = [byte[]]::new($plainbytes.Length)
    $aesTag = [byte[]]::new(16)

    $aes = [System.Security.Cryptography.AesGcm]::new($aesKey)
    try {
      $aes.Encrypt($aesNonce, $plainbytes, $innerCiphertext, $aesTag)
    } finally {
      $aes.Dispose()
      [Array]::Clear($aesKey, 0, $aesKey.Length)
    }

    $innerPayload = [byte[]]$aesNonce + $aesTag + $innerCiphertext

    $xNonce = [byte[]]::new(24)
    [RandomNumberGenerator]::Fill($xNonce)
    $outerPayload = [XChaCha20Poly1305]::Encrypt($innerPayload, $xchachaKey, $xNonce)
    [Array]::Clear($xchachaKey, 0, $xchachaKey.Length)

    return [byte[]]@(0x02) + $salt + $xNonce + $outerPayload
  }

  static [byte[]] UnprotectDataCascade([byte[]]$protectedBytes, [securestring]$password) {
    if ($protectedBytes.Length -lt 58) { throw [ArgumentException]::new("Invalid cascade payload.") }
    if ($protectedBytes[0] -ne 0x02) { throw [ArgumentException]::new("Unsupported cascade payload version.") }

    $salt = [byte[]]$protectedBytes[1..32]
    $xNonce = [byte[]]$protectedBytes[33..56]
    $outerPayload = [byte[]]$protectedBytes[57..($protectedBytes.Length - 1)]

    $passBytes = [Encoding]::UTF8.GetBytes([CryptoBase]::SecureStringToString($password))
    $masterKey = [Argon2id]::Hash($passBytes, $salt, 65536, 4, 4, 64)
    [Array]::Clear($passBytes, 0, $passBytes.Length)

    $aesKey = [byte[]]$masterKey[0..31]
    $xchachaKey = [byte[]]$masterKey[32..63]
    [Array]::Clear($masterKey, 0, $masterKey.Length)

    $innerPayload = [XChaCha20Poly1305]::Decrypt($outerPayload, $xchachaKey, $xNonce)
    [Array]::Clear($xchachaKey, 0, $xchachaKey.Length)

    $aesNonce = [byte[]]$innerPayload[0..11]
    $aesTag = [byte[]]$innerPayload[12..27]
    $innerCiphertext = [byte[]]$innerPayload[28..($innerPayload.Length - 1)]
    $plainbytes = [byte[]]::new($innerCiphertext.Length)

    $aes = [System.Security.Cryptography.AesGcm]::new($aesKey)
    try {
      $aes.Decrypt($aesNonce, $innerCiphertext, $aesTag, $plainbytes)
      return $plainbytes
    } finally {
      $aes.Dispose()
      [Array]::Clear($aesKey, 0, $aesKey.Length)
    }
  }

  static [byte[]] CreateSealedBox([byte[]]$plainbytes, [byte[]]$senderPrivateKey, [byte[]]$recipientPublicKey) {
    # NOTE: [Curve25519] currently wraps ECDH over NIST P-256 key material in this module.
    $sharedSecret = [Curve25519]::DeriveSharedSecret($senderPrivateKey, $recipientPublicKey)
    $info = [Encoding]::UTF8.GetBytes("CryptoBase_SealedBox_P256_v1")
    $symmetricKey = [HKDF]::DeriveKey($sharedSecret, $null, $info, 32)
    [Array]::Clear($sharedSecret, 0, $sharedSecret.Length)

    $nonce = [byte[]]::new(24)
    [RandomNumberGenerator]::Fill($nonce)
    $ciphertextWithTag = [XChaCha20Poly1305]::Encrypt($plainbytes, $symmetricKey, $nonce)
    [Array]::Clear($symmetricKey, 0, $symmetricKey.Length)

    return [byte[]]$nonce + $ciphertextWithTag
  }

  static [hashtable] ProtectDataQuantumHybrid([byte[]]$plainbytes, [byte[]]$recipientP256Pub, [byte[]]$recipientKemPub) {
    # NOTE: [Curve25519] currently wraps ECDH over NIST P-256 key material in this module.
    $ephemeralCurve = [Curve25519]::GenerateKeyPair()
    $classicShared = [Curve25519]::DeriveSharedSecret($ephemeralCurve.PrivateKey, $recipientP256Pub)

    $mlKem = [MLKem]::new()
    $kemResult = $mlKem.Encapsulate($recipientKemPub)
    $pqcShared = $kemResult.SharedSecret

    $hybridSecret = [BLAKE3]::ComputeHash([byte[]]$classicShared + $pqcShared)
    [Array]::Clear($classicShared, 0, $classicShared.Length)
    [Array]::Clear($pqcShared, 0, $pqcShared.Length)

    $nonce = [byte[]]::new(24)
    [RandomNumberGenerator]::Fill($nonce)
    $ciphertext = [XChaCha20Poly1305]::Encrypt($plainbytes, $hybridSecret, $nonce)
    [Array]::Clear($hybridSecret, 0, $hybridSecret.Length)

    return @{
      Ciphertext        = [byte[]]$nonce + $ciphertext
      EphemeralCurvePub = $ephemeralCurve.PublicKey
      KemCiphertext     = $kemResult.Ciphertext
    }
  }

  static [byte[]] UnprotectData([byte[]]$protectedBytes, [string]$passw0rd) {
    return [CryptoBase]::UnprotectData($protectedBytes, [xconvert]::ToSecurestring($passw0rd), $null)
  }

  static [byte[]] UnprotectData([byte[]]$protectedBytes, [securestring]$password) {
    return [CryptoBase]::UnprotectData($protectedBytes, $password, $null)
  }

  static [byte[]] UnprotectData([byte[]]$protectedBytes, [string]$passw0rd, [byte[]]$aad) {
    if ([string]::IsNullOrWhiteSpace($passw0rd)) {
      throw [ArgumentException]::new("Password cannot be null or empty.")
    }
    return [CryptoBase]::UnprotectData($protectedBytes, [xconvert]::ToSecurestring($passw0rd), $aad)
  }

  static [byte[]] UnprotectData([byte[]]$protectedBytes, [securestring]$password, [byte[]]$aad) {
    if ($protectedBytes.Length -lt 45) { throw [ArgumentException]::new("Invalid protected payload.") }
    if ($protectedBytes[0] -ne 0x01) { throw [ArgumentException]::new("Unsupported payload version.") }
    $salt = [byte[]]::new(16); [Array]::Copy($protectedBytes, 1, $salt, 0, 16)
    $nonce = [byte[]]::new(12); [Array]::Copy($protectedBytes, 17, $nonce, 0, 12)
    $tag = [byte[]]::new(16); [Array]::Copy($protectedBytes, 29, $tag, 0, 16)
    $cipherLen = $protectedBytes.Length - 45
    $ciphertext = [byte[]]::new($cipherLen); [Array]::Copy($protectedBytes, 45, $ciphertext, 0, $cipherLen)
    $passBytes = [Encoding]::UTF8.GetBytes([CryptoBase]::SecureStringToString($password))
    $key = [Argon2id]::Hash($passBytes, $salt, 65536, 3, 4, 32)
    $plainbytes = [byte[]]::new($cipherLen)
    $aes = [System.Security.Cryptography.AesGcm]::new($key)
    try {
      $aes.Decrypt($nonce, $ciphertext, $tag, $plainbytes, $aad)
      return $plainbytes
    } finally {
      $aes.Dispose()
      [Array]::Clear($passBytes, 0, $passBytes.Length)
      [Array]::Clear($key, 0, $key.Length)
    }
  }

  static [Secp256k1SignResult] SignMessage([string]$string) {
    return [CryptoBase]::SignMessage([Encoding]::UTF8.GetBytes($string))
  }
  static [Secp256k1SignResult] SignMessage([byte[]]$data) {
    $kp = [Secp256k1]::GenerateKeyPair()
    $sig = [Secp256k1]::Sign($data, $kp.PrivateKey)
    return [Secp256k1SignResult]::new($sig, $kp.PrivateKey, $kp.PublicKey)
  }
  static [bool] VerifyMessage([string]$string, [byte[]]$signature, [byte[]]$publicKey) {
    return [CryptoBase]::VerifyMessage([Encoding]::UTF8.GetBytes($string), $signature, $publicKey)
  }
  static [bool] VerifyMessage([byte[]]$data, [byte[]]$signature, [byte[]]$publicKey) {
    return [Secp256k1]::Verify($data, $signature, $publicKey)
  }

  static [void] ObfuscateFile([string]$inputPath, [string]$outputPath, [securestring]$password) {
    $data = [File]::ReadAllBytes($inputPath)
    $wrapped = [CryptoBase]::ProtectData($data, $password)
    $fileCrc = [Crc24]::ComputeToBytes($wrapped)
    [File]::WriteAllBytes($outputPath, $fileCrc + $wrapped)
  }

  static [void] DeobfuscateFile([string]$inputPath, [string]$outputPath, [securestring]$password) {
    $blob = [File]::ReadAllBytes($inputPath)
    if ($blob.Length -lt 4) { throw [ArgumentException]::new("Invalid obfuscated file.") }
    $crc = $blob[0..2]
    $payload = [byte[]]::new($blob.Length - 3)
    [Array]::Copy($blob, 3, $payload, 0, $payload.Length)
    if (![Crc24]::Verify($crc, $payload)) { throw [CryptographicException]::new("CRC24 verification failed.") }
    $plain = [CryptoBase]::UnprotectData($payload, $password)
    [File]::WriteAllBytes($outputPath, $plain)
  }
  static [string] ReadSecureString() {
    [SecureString]$ss = Read-Host -AsSecureString
    return [CryptoBase]::SecureStringToString($ss)
  }

  static [string] SecureStringToString([SecureString]$secureString) {
    [SecureString]$ss = $secureString.Copy(); $result = [string]::Empty
    $mdp = [Marshal]::SecureStringToBSTR($ss)
    try {
      $result = [Marshal]::PtrToStringBSTR($mdp)
    } finally {
      [Marshal]::ZeroFreeBSTR($mdp)
      $ss.Dispose()
    }
    return $result
  }
}

# Types that will be available to users when they import the module.
# Hint: To automatically generate typestoexport variable you can use this one liner to generate types to export variable
# (Get-ChildItem *.psm1 -Recurse -File | ForEach-Object { [IO.File]::ReadAllLines((Get-Item $_.FullName)).Where({ $_.StartsWith("class") -or $_.StartsWith("enum ") }).ForEach({ $_.Replace("class ", '[').Replace("enum ", '[') }).ForEach({ ($_ -like "* : *") ? $_.split(" : ")[0] + ']' : $_.Replace(' {', ']') }) }) -join ', '

$typestoExport = @(
  [AesCCM], [AesCfb], [AesCmac], [AesCng], [AesCtr], [AesGCM], [AesOcbCore], [AesOcb], [AesSIV], [ArmorDecodeResult], [Armor], [BCryptCore], [BCrypt], [BCryptExtendedV3], [Blake2b], [ChaCha20Poly1305Managed], [Crc24], [CredManaged], [NativeCredential], [CredentialManager], [Curve25519], [Ecdsa], [Ed25519Impl], [Ed25519], [Ed448], [ECC],
  [EncryptionScope], [keyStoreMode], [KeyExportPolicy], [KeyProtection], [KeyUsage], [X509ContentType], [ECCurveName], [SdCategory], [ExpType], [CertStoreName], [CryptoAlgorithm], [RSAPadding], [Compression], [CredFlags], [CredType], [CredentialPersistence], [HashType], [AsymmetricAlgorithm], [KeyFormat], [KeySize], [ArmorType],
  [InvalidArgumentException], [CredentialNotFoundException], [IntegrityCheckFailedException], [InvalidPasswordException], [SaltParseException], [BcryptAuthenticationException], [HashInformationException], [KeypairException], [KeyGenerationException], [KeyImportException], [FileMonitor], [Hc128], [Hc256], [HKDF], [Keypair],
  [NamedKeypair], [KeypairGenerationResult], [KeypairHelper], [KeypairGen], [KeypairManager], [KMAC256], [MD5], [Expiration], [HashParser], [HashInformation], [HashFormatDescriptor], [CipherObject], [SecretStore], [KSFConfigType], [opaqueServerLoginState], [opaqueClientRegistrationState], [opaqueClientLoginState], [opaqueKSFConfig],
  [opaqueOpaqueServer], [opaqueOpaqueClient], [KSFConfig], [OpaqueServer], [OpaqueClient], [OPAQUE], [OpenPgp], [OTPKIT], [Argon2id], [Argon2i], [Argon2d], [Scrypt], [Pbkdf2], [MLKem], [MLDsa], [SLHDsa], [RabbitState], [Rabbit], [RSA], [S2KType], [S2K], [Secp256k1], [Keccak], [KeccakManaged], [IdentityHash], [DoubleSha256],
  [SHA3256], [SHA3384], [SHA3512], [SHAKE128Managed], [SHAKE256Managed], [KMAC128], [FipsHmacSha256], [BLAKE3], [TripleDES], [Asn1Parser], [PemParser], [SecureBox], [SecureArray], [NoiseProtocol], [VOPRF], [BitwUtil], [Shuffl3r], [SignatureUtils], [CryptobaseUtils], [VaultClient], [X509], [XChaCha20Poly1305], [XOR], [XSalsa20],
  [CryptoBase]
)
$TypeAcceleratorsClass = [PsObject].Assembly.GetType('System.Management.Automation.TypeAccelerators')
# Add type accelerators for every exportable type.
foreach ($Type in $typestoExport) {
  try {
    $TypeAcceleratorsClass::Add($Type.FullName, $Type)
  } catch {
    # Ignore if already exists
    $null
  }
}
# Remove type accelerators when the module is removed.
$MyInvocation.MyCommand.ScriptBlock.Module.OnRemove = {
  foreach ($Type in $typestoExport) {
    $TypeAcceleratorsClass::Remove($Type.FullName)
  }
}.GetNewClosure();

$scripts = @();
$Public = Get-ChildItem "$PSScriptRoot/Public" -Filter "*.ps1" -Recurse -ErrorAction SilentlyContinue
$scripts += Get-ChildItem "$PSScriptRoot/Private" -Filter "*.ps1" -Recurse -ErrorAction SilentlyContinue
$scripts += $Public

foreach ($file in $scripts) {
  try {
    if ([string]::IsNullOrWhiteSpace($file.fullname)) { continue }
    . "$($file.fullname)"
  } catch {
    Write-Warning "Failed to import function $($file.BaseName): $_"
    $host.UI.WriteErrorLine($_)
  }
}

$Param = @{
  Function = $Public.BaseName
  Cmdlet   = '*'
  Alias    = '*'
  Verbose  = $false
}
Export-ModuleMember @Param
