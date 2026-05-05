# Utilities

Broad toolset of helper functions for byte array manipulation, zeroization, and constant-time comparisons.

## Usage Example

```powershell
$secret1 = [byte[]](1,2,3)
$secret2 = [byte[]](1,2,3)

# Constant-time compare prevents timing side-channel attacks
$isMatch = [CryptobaseUtils]::ConstantTimeEquals($secret1, $secret2)

# Securely clear memory
[CryptobaseUtils]::SecureClear($secret1)
```

## Classes

### Asn1Parser

#### Methods

- `[void] Asn1Parser()`
- `[object] Parse($Data)`
- `static [object] Parse($Data, $Unused)`
- `static [object] ParseElement($Reader)`

### PemParser

#### Methods

- `[void] PemParser()`
- `[byte[]] Decode($Content)`
- `static [hashtable] Parse($Content)`
- `static [string] Encode($Data, $Label)`

### SecureBox

#### Properties

- $type $key

#### Methods

- `[void] SecureBox($key)`
- `[byte[]] Encrypt($plainbytes)`
- `[byte[]] Decrypt($ciphertext)`
- `static [byte[]] Encrypt($Password, $Data, $Salt)`
- `static [byte[]] Decrypt($Password, $EncryptedData)`

### SecureArray

#### Properties

- $type $Data
- $type $Length

#### Methods

- `[void] SecureArray($Size)`
- `[void] SecureArray($data)`
- `[byte[]] GetData()`
- `[void] SetData($Data)`
- `[void] Clear()`
- `[void] Dispose()`

### NoiseProtocol

#### Methods

- `[void] NoiseProtocol()`
- `[object] GenerateKeyPair()`
- `static [string] GetSupportedPatterns()`

### VOPRF

#### Methods

- `[void] VOPRF()`
- `[object] GenerateKeyPair()`
- `[byte[]] Evaluate($data, $privateKey)`
- `static [byte[]] GenerateKey()`

### BitwUtil

#### Methods

- `static [Byte[]] Prepend($Bytes, $BytesToPrepend)`
- `static [byte[][]] Shift($Bytes, $size)`
- `static [Int32] RotateLeft($val, $amount)`
- `static [Int64] RotateLeft($val, $amount)`
- `static [void] QuaterRound($a, $b, $c, $d)`
- `static [int32[]] QuaterRound($a, $b, $c, $d)`
- `static [byte[ ]] MixColumns($state)`
- `static [int32[]] ShiftRows($state)`
- `static [int32[]] KeyExpansion($key, $rounds)`
- `static hidden [int32[]] KeyExpansionCore($temp, $round)`
- `static [byte[]] SubBytes($state, $sBox)`
- `static [byte[]] AddRoundKey($state, $roundKey)`
- `static [Int64] Reduce($nput)`
- `static [Int64[]] Reduce($arr)`
- `[byte[]] ToLittleEndian($value)`

### Shuffl3r

#### Methods

- `static [Byte[]] Combine($Bytes, $Nonce, $Passwod)`
- `static [Byte[]] Combine($Bytes, $Nonce, $Passw0d)`
- `static [array] Split($ShuffledBytes, $Passwod, $NonceLength)`
- `static [array] Split($ShuffledBytes, $Passw0d, $NonceLength)`
- `static hidden [int[]] GenerateIndices($Count, $randomString, $HighestIndex)`

### SignatureUtils

#### Properties

- $type $SIGNATURE_KEYNAME
- $type $AppName
- $type $NewLine
- $type $EmptyUriPath
- $type $equals
- $type $And
- $type $UTF_8_Encoding

#### Methods

- `static [string] signParameters($parameters, $key, $HttpMethod, $h0st, $RequestURI, $algorithm)`
- `static [string] calculateStringToSignV2($parameters, $httpMethod, $hostHeader, $requestURI)`
- `static [string] UrlEncode($data, $path)`
- `static [string] sign($data, $key, $signatureMethod)`

### CryptobaseUtils

#### Properties

- $type $caller
- $type $counter
- $type $Scope
- $type $_SkipReadHostPrompts
- $type $_salt
- $type $_bytes
- $type $_Password
- $type $_Algorithm

#### Methods

- `[void] CryptobaseUtils()`
- `static [string] GetRandomName()`
- `static [string] GetRandomName($Length)`
- `static [string] GetRandomName($IncludeNumbers)`
- `static [string] GetRandomName($Length, $IncludeNumbers)`
- `static [string] GetRandomName($minLength, $maxLength)`
- `static [string] GetRandomName($minLength, $maxLength, $IncludeNumbers)`
- `static [byte[]] GetRfc2898DeriveBytes()`
- `static [byte[]] GetRfc2898DeriveBytes($Length)`
- `static [byte[]] GetRfc2898DeriveBytes($password)`
- `static [byte[]] GetRfc2898DeriveBytes($password, $Length)`
- `static [byte[]] GetRfc2898DeriveBytes($password, $salt, $Length)`
- `static [byte[]] GetKey($password)`
- `static [byte[]] GetKey()`
- `static [byte[]] GetKey($Length)`
- `static [byte[]] GetKey($password, $Length)`
- `static [byte[]] GetKey($password, $salt)`
- `static [byte[]] GetKey($password, $salt, $Length)`
- `static [byte[]] GetRandomEntropy()`
- `static [string] GetRandomSTR($InputSample, $Length)`
- `static [string] GetRandomSTR($InputSample, $iterations, $Length)`
- `static [string] GetRandomSTR($InputSample, $iterations, $minLength, $maxLength)`
- `static [string] GeneratePassword()`
- `static [string] GeneratePassword($Length)`
- `static [string] GeneratePassword($Length, $StartWithLetter)`
- `static [string] GeneratePassword($Length, $StartWithLetter, $NoSymbols, $UseAmbiguousCharacters, $UseExtendedAscii)`
- `static [int] GetPasswordStrength($passw0rd)`
- `static [bool] IsBase64String($base64)`
- `static [bool] IsValidAES($aes)`
- `static [bool] IsValidUrl($url)`
- `static [void] CheckProps($Aes)`
- `static [string] GetResolvedPath($Path)`
- `static [string] GetResolvedPath($session, $Path)`
- `static [string] GetUnResolvedPath($Path)`
- `static [string] GetUnResolvedPath($session, $Path)`
- `static [Type] CreateEnum($Name, $IsPublic, $Members)`
- `static [Aes] GetAes()`
- `static [Aes] GetAes($Iterations)`
- `static [Aes] GetAes($password, $salt, $iterations)`
- `static [string] GetUniqueMachineId()`
- `static [securestring] GetPassword()`
- `static [securestring] GetPassword($Prompt)`
- `static [securestring] GetPassword($ThrowOnFailure)`
- `static [securestring] GetPassword($Prompt, $ThrowOnFailure)`
- `static [void] ValidateCompression($Compression)`
- `static [void] AddSignature($File)`
- `static [void] SetAuthenticodeSignature($FilePath, $Certificate)`
- `static [string] ExportCertificate($CertPath, $ExportPath, $Password)`
- `static [void] ImportCertificate($PfxPath, $Password)`
- `static [bool] VerifySignature($FilePath)`
- `static [void] RemoveSignature($FilePath)`
- `static [void] SignDirectory($DirectoryPath, $CertPath, $Filter)`
- `static [string] CreatedataUUID($Info)`
- `static [X509Certificate2] GetCodeSigningCert()`
- `static hidden [void] SaveConfiguration()`
- `static [X509Certificate2[]] GetCertificate($CurrentOnly)`
- `static [X509Certificate2] CreateCertificate($Name, $YearsValid, $FriendlyName)`
- `static [void] SetCurrentUserCertificate($InputStr)`
- `static [bool] IsThumbprint($InputStr)`
- `static [bool] IsSubject($InputStr)`
- `static [bool] IsFriendlyName($InputStr)`
- `static [string] ExportCertificatePublicKey()`
- `static [PSCustomObject[]] GetContact($Name)`
- `static [PSCustomObject] ImportContactData($JsonData, $TrustedOnly)`
- `static [void] RemoveContact($Identity)`
- `static hidden [RSA] GetRsaPublicKey($Certificate)`
- `static hidden [RSA] GetRsaPrivateKey($Certificate)`
- `static [string] ProtectFile($Path, $OwnCertificate, $Contact, $OutPath, $PassThru)`
- `static [string] ProtectContent($Content, $Name, $OwnCertificate, $Contact)`
- `static [string] UnprotectDataset($JsonContent, $OutDirectory, $Cmdlet)`



