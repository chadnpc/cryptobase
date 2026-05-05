# Blake2b

BLAKE2b is an optimized version of the BLAKE cryptographic hash function, designed for 64-bit platforms. It is widely used for its speed and security, notably in protocols like Argon2 and WireGuard.

## Features

- **High Speed**: Optimized for 64-bit CPUs.
- **Keyed Hashing**: Native MAC support.
- **Salt & Personalization**: Supports additional parameters for domain separation.
- **Variable Output**: Supports output lengths from 1 to 64 bytes.

## Usage

The `[Blake2b]` class provides static methods for hashing.

### Simple Hashing (Default 64-byte output)

```powershell
$data = [System.Text.Encoding]::UTF8.GetBytes("Hello Blake2b!")
$hash = [Blake2b]::ComputeHash($data)
```

### Variable-Length Output

```powershell
# Get a 32-byte hash
$hash32 = [Blake2b]::ComputeHash($data, 32)
```

### Keyed Hashing (MAC)

```powershell
$key = [byte[]]::new(32)
[System.Security.Cryptography.RandomNumberGenerator]::Fill($key)

$mac = [Blake2b]::ComputeHash($data, 64, $key)
```

### Advanced Hashing (Salt & Personalization)

Salts and personalization strings must be up to 16 bytes.

```powershell
$salt = [System.Text.Encoding]::UTF8.GetBytes("salty-bytes-1234")
$personal = [System.Text.Encoding]::UTF8.GetBytes("app-domain-v1.0")

$hash = [Blake2b]::ComputeHash($data, 64, $key, $salt, $personal)
```

## Comparison with BLAKE3

While **BLAKE3** is generally faster and offers infinite extendability, **BLAKE2b** is still the standard for many existing protocols and provides excellent performance on 64-bit systems.


## API Documentation


## Classes

### Blake2b

#### Properties

- $type $Blake2bIv
- $type $Blake2bSigma

#### Methods

- `static [byte[]] ComputeHash($inputbytes)`
- `static [byte[]] ComputeHash($inputbytes, $outputLength)`
- `static [byte[]] ComputeHash($inputbytes, $outputLength, $key)`
- `static [byte[]] ComputeHash($inputbytes, $outputLength, $key, $salt, $personalization)`
- `static hidden [uint64[]] GetParamWords($digestSize, $keyLength, $salt, $personalization)`
- `static hidden [void] Compress($h, $buffer, $bytesCompressed, $isLastBlock, $m, $v)`
- `static hidden [void] G($v, $a, $b, $c, $d, $x, $y)`
- `static hidden [uint64] RotateRight($value, $offset)`
- `static hidden [uint64] ReadUInt64LE($buf, $off)`
- `static hidden [void] WriteUInt64LE($buf, $off, $val)`



