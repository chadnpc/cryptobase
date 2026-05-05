# KeypairGen

> **Note:** This documentation was automatically generated.

## Classes

### Keypair

#### Properties

- $type $Algorithm
- $type $PublicKey
- $type $PrivateKey
- $type $KeySize
- $type $CreatedAt
- $type $CurveName
- $type $Parameters

#### Methods

- `[void] Keypair()`
- `[void] Keypair($algorithm)`
- `[string] ToBase64Public()`
- `[string] ToBase64Private()`
- `[string] ToHexPublic()`
- `[string] ToHexPrivate()`
- `[System.Security.SecureString] ToSecureStringPrivate()`
- `[int] GetKeySizeInBits()`
- `[bool] HasPrivateKey()`
- `[bool] HasPublicKey()`
- `[hashtable] ToHashtable()`
- `static [Keypair] FromHashtable($data)`
- `[string] ToString()`

### NamedKeypair

#### Properties

- $type $Name
- $type $Description
- $type $Tags
- $type $Owner
- $type $ExpiresAt

#### Methods

- `[void] NamedKeypair()`
- `[void] NamedKeypair($algorithm, $name)`
- `[bool] IsExpired()`
- `[void] AddTag($tag)`
- `[void] RemoveTag($tag)`

### KeypairGenerationResult

#### Properties

- $type $Success
- $type $Keypair
- $type $ErrorMessage
- $type $Warnings
- $type $Duration
- $type $GeneratedAt

#### Methods

- `[void] KeypairGenerationResult()`
- `static [KeypairGenerationResult] Successful($keypair, $duration)`
- `static [KeypairGenerationResult] Failed($errorMessage, $duration)`
- `[void] AddWarning($warning)`

### KeypairHelper

#### Methods

- `static [byte[]] HexToBytes($hex)`
- `static [string] BytesToHex($bytes)`
- `static [string] BytesToBase64($bytes)`
- `static [byte[]] Base64ToBytes($base64)`
- `static [System.Security.SecureString] ToSecureString($bytes)`
- `static [byte[]] FromSecureString($secureString)`
- `static [int] GetKeySizeForCurve($curveName)`
- `static [bool] IsSupportedAlgorithm($algorithm)`

### KeypairGen

#### Properties

- $type $VerboseOutput

#### Methods

- `static [Keypair] Generate($Algorithm)`
- `static [Keypair] Generate($Algorithm, $KeySize)`
- `static [Keypair] Generate($Algorithm, $KeySize, $Curve)`
- `static [KeypairGenerationResult] GenerateWithResult($Algorithm, $KeySize, $Curve)`
- `static [KeypairGenerationResult] GenerateWithResult($Algorithm)`
- `static [Keypair] GenerateRSA($keySize)`
- `static [Keypair] GenerateDSA($keySize)`
- `static [Keypair] GenerateDiffieHellman($keySize)`
- `static [Keypair] GenerateECDsa($curveName)`
- `static [Keypair] GenerateECDH($curveName)`
- `static [Keypair] GenerateEdCurve($curveName)`
- `static [object[]] GetAlgorithmInfo()`
- `static [void] TestKeypairGenerator()`

### KeypairManager

#### Properties

- $type $Keypairs
- $type $DefaultPath

#### Methods

- `[void] KeypairManager()`
- `[void] KeypairManager($path)`
- `[void] Add($name, $keypair)`
- `[void] Remove($name)`
- `[Keypair] Get($name)`
- `[bool] Contains($name)`
- `[string[]] GetNames()`
- `[Keypair[]] GetAllByAlgorithm($algorithm)`
- `[void] Save($path)`
- `[void] Load($path)`


