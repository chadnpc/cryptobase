# SHA-3 & Keccak (Hashing)

SHA-3 is the latest family of cryptographic hash functions standardized by NIST (FIPS 202). It is based on the Keccak permutation and is fundamentally different from the SHA-2 family.

## SHA-3 Variants

`CryptoBase` provides the following fixed-length SHA-3 variants:
- `[SHA3256]`
- `[SHA3384]`
- `[SHA3512]`

### Usage
```powershell
$data = [System.Text.Encoding]::UTF8.GetBytes("SHA-3 message")
$hash = [SHA3256]::ComputeHash($data)
```

---

## SHAKE (Extendable Output Functions)

SHAKE (Sponge Hash with Arbitrary-length output) allows you to produce a hash of any length.

- `[SHAKE128Managed]`
- `[SHAKE256Managed]`

### Usage
```powershell
# Produce a 100-byte hash using SHAKE128
$hash100 = [SHAKE128Managed]::ComputeHash($data, 100)
```

---

## KMAC (Keccak Message Authentication Code)

KMAC is a PRF and MAC based on Keccak. It is faster than HMAC-SHA3 and provides variable-length output.

### Usage
```powershell
$key = [byte[]]::new(32)
$mac = [KMAC128]::ComputeHash($key, $data, 32)
```

## Implementation Note

The `SHA-3` classes automatically use the native .NET 8+ implementation if available, falling back to a pure-PowerShell managed implementation on older versions of .NET.


## API Documentation


## Classes

### Keccak

#### Properties

- $type $KeccakB
- $type $KeccakNumberOfRounds
- $type $KeccakLaneSizeInBits
- $type $RoundConstants
- $type $keccakState
- $type $buffer
- $type $buffLength
- $type $keccakR
- $type $Padding

#### Methods

- `[int] GetKeccakR()`
- `[int] GetSizeInBytes()`
- `[int] GetHashByteLength()`
- `[void] Keccak($hashBitLength)`
- `[uint64] ROL($a, $offset)`
- `[void] AddToBuffer($array, $offset, $count)`
- `[void] Initialize()`
- `[void] HashCore($array, $ibStart, $cbSize)`
- `[byte[]] HashFinal()`

### KeccakManaged

#### Methods

- `[void] KeccakManaged($hashBitLength)`
- `[void] HashCore($array, $ibStart, $cbSize)`
- `[byte[]] HashFinal()`
- `[void] KeccakF($inb, $laneCount)`

### IdentityHash

#### Properties

- $type $digest

#### Methods

- `[void] IdentityHash()`
- `[void] Initialize()`
- `[void] HashCore($array, $ibStart, $cbSize)`
- `[byte[]] HashFinal()`

### DoubleSha256

#### Properties

- $type $_digest
- $type $_round1

#### Methods

- `[void] DoubleSha256()`
- `[void] Initialize()`
- `[void] HashCore($array, $ibStart, $cbSize)`
- `[byte[]] HashFinal()`

### SHA3256

#### Properties

- $type $_buffer

#### Methods

- `[void] SHA3256()`
- `static [byte[]] ComputeHash($Data)`
- `static [byte[]] ComputeHash($InputStream)`
- `[void] Initialize()`
- `[void] HashCore($array, $ibStart, $cbSize)`
- `[byte[]] HashFinal()`

### SHA3384

#### Properties

- $type $_buffer

#### Methods

- `[void] SHA3384()`
- `static [byte[]] ComputeHash($Data)`
- `static [byte[]] ComputeHash($InputStream)`
- `[void] Initialize()`
- `[void] HashCore($array, $ibStart, $cbSize)`
- `[byte[]] HashFinal()`

### SHA3512

#### Properties

- $type $_buffer

#### Methods

- `[void] SHA3512()`
- `static [byte[]] ComputeHash($Data)`
- `static [byte[]] ComputeHash($InputStream)`
- `[void] Initialize()`
- `[void] HashCore($array, $ibStart, $cbSize)`
- `[byte[]] HashFinal()`

### SHAKE128Managed

#### Properties

- $type $OutputLength
- $type $_keccak

#### Methods

- `[void] SHAKE128Managed()`
- `static [byte[]] ComputeHash($Data, $OutputLength)`
- `[void] Initialize()`
- `[void] HashCore($array, $ibStart, $cbSize)`
- `[byte[]] HashFinal()`

### SHAKE256Managed

#### Properties

- $type $OutputLength
- $type $_keccak

#### Methods

- `[void] SHAKE256Managed()`
- `static [byte[]] ComputeHash($Data, $OutputLength)`
- `[void] Initialize()`
- `[void] HashCore($array, $ibStart, $cbSize)`
- `[byte[]] HashFinal()`

### KMAC128

#### Properties

- $type $KeccakB
- $type $KeccakNumberOfRounds
- $type $KeccakLaneSizeInBits
- $type $RoundConstants
- $type $keccakState
- $type $buffer
- $type $buffLength
- $type $keccakR

#### Methods

- `[int] GetKeccakR()`
- `[int] GetSizeInBytes()`
- `[int] GetHashByteLength()`
- `[void] KMAC128($hashBitLength)`
- `[uint64] ROL($a, $offset)`
- `[void] AddToBuffer($array, $offset, $count)`
- `[void] Initialize()`
- `[void] HashCore($array, $ibStart, $cbSize)`
- `[byte[]] HashFinal()`
- `static [byte[]] ComputeHash($Key, $Data)`
- `static [byte[]] ComputeHash($Key, $Data, $OutputLength)`
- `static [byte[]] ComputeHash($Key, $Data, $OutputLength, $Customization)`

### FipsHmacSha256

#### Properties

- $type $rng
- $type $HMAC
- $type $key

#### Methods

- `[void] FipsHmacSha256()`
- `[void] FipsHmacSha256($key)`
- `[string] ComputeHash($data)`
- `hidden [void] _Init()`

### BLAKE3

#### Properties

- $type $IV
- $type $MSG_PERMUTATION

#### Methods

- `static hidden [uint32] RotR($x, $n)`
- `static hidden [void] G($state, $a, $b, $c, $d, $mx, $my)`
- `static hidden [void] Round($state, $m)`
- `static hidden [uint32[]] Compress($cv, $blockWords, $counter, $blockLen, $flags)`
- `static hidden [uint32[]] BuildRootWords($keyIV, $Data)`
- `static hidden [byte[]] XofOutput($outWords, $keyIV, $OutputLength)`
- `static hidden [uint32[]] KeyToIV($Key)`
- `static [byte[]] ComputeHash($Data)`
- `static [byte[]] ComputeHash($Data, $OutputLength)`
- `static [byte[]] ComputeHash($Data, $Key, $OutputLength)`
- `static [byte[]] ComputeHash($Data, $Key, $Info, $OutputLength)`



