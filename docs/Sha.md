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
