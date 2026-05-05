# AesCng

Leverages the Windows Cryptography Next Generation (CNG) API for high-performance AES operations.

## Usage Example

```powershell
# This provides low-level interop bounds, typically for internal module use.
$cng = [AesCng]::new()
# ... internal configuration ...
```

## Classes

### AesCng

#### Methods

- `static [byte[]] Encrypt($Bytes, $Password)`
- `static [byte[]] Encrypt($Bytes, $Password, $Salt)`
- `static [byte[]] Encrypt($Bytes, $Password, $Protect)`
- `static [byte[]] Encrypt($Bytes, $Password, $iterations)`
- `static [byte[]] Encrypt($Bytes, $Password, $Salt, $Protect)`
- `static [byte[]] Encrypt($Bytes, $Password, $Salt, $iterations)`
- `static [byte[]] Encrypt($Bytes, $Password, $Compression)`
- `static [byte[]] Encrypt($Bytes, $Password, $Salt, $Compression)`
- `static [byte[]] Encrypt($Bytes, $Password, $Salt, $Compression, $Protect)`
- `static [byte[]] Decrypt($Bytes, $Password)`
- `static [byte[]] Decrypt($Bytes, $Password, $Salt)`
- `static [byte[]] Decrypt($Bytes, $Password, $UnProtect)`
- `static [byte[]] Decrypt($Bytes, $Password, $iterations)`
- `static [byte[]] Decrypt($Bytes, $Password, $Salt, $UnProtect)`
- `static [byte[]] Decrypt($Bytes, $Password, $salt, $iterations)`
- `static [byte[]] Decrypt($Bytes, $Password, $Compression)`
- `static [byte[]] Decrypt($Bytes, $Password, $Salt, $Compression)`
- `static [byte[]] Decrypt($Bytes, $Password, $Salt, $Compression, $UnProtect)`



