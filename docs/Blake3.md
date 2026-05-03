# BLAKE3

BLAKE3 is a cryptographic hash function that is much faster than MD5, SHA-1, SHA-2, SHA-3, and BLAKE2. It is cryptographically secure and can be used for hashing files, messages, and other data.

## Features

- **Extreme Performance**: Significantly faster than most existing hash functions.
- **Keyed Hashing**: Native support for keyed hashing (PRFs).
- **Extendable Output (XOF)**: Can produce any length of output.
- **Secure**: Based on the established BLAKE2 family but improved.

## Usage

The `[BLAKE3]` class provides static methods for hashing.

### Simple Hashing (32-byte output)

```powershell
$data = [System.Text.Encoding]::UTF8.GetBytes("Hello BLAKE3!")
$hash = [BLAKE3]::ComputeHash($data)

# Convert to hex string for display
($hash | ForEach-Object { "{0:x2}" -f $_ }) -join ""
```

### Variable-Length Output (XOF)

You can specify the desired output length in bytes.

```powershell
# Get a 64-byte hash
$hash64 = [BLAKE3]::ComputeHash($data, 64)
```

### Keyed Hashing (MAC)

Use a 32-byte secret key to create a message authentication code.

```powershell
$key = [byte[]]::new(32)
[System.Security.Cryptography.RandomNumberGenerator]::Fill($key)

$mac = [BLAKE3]::ComputeHash($data, $key, 32)
```

### Keyed Hashing with Context

Derives a sub-key from a master key and context info, then hashes the data.

```powershell
$info = [System.Text.Encoding]::UTF8.GetBytes("app-context-v1")
$mac = [BLAKE3]::ComputeHash($data, $key, $info, 32)
```

## Performance Note

While this is a pure PowerShell implementation, it follows the BLAKE3 design principles. For large files, it is significantly faster than many other pure-PowerShell hash implementations.
