# TripleDES

Legacy Triple Data Encryption Algorithm (3DES). Provided for compatibility with older systems. Do not use for new applications.

## Usage Example

```powershell
$key = [byte[]]::new(24); [System.Security.Cryptography.RandomNumberGenerator]::Fill($key)
$iv = [byte[]]::new(8); [System.Security.Cryptography.RandomNumberGenerator]::Fill($iv)
$plain = [System.Text.Encoding]::UTF8.GetBytes('Legacy Block')

$cipher = [TripleDesManaged]::Encrypt($plain, $key, $iv, [System.Security.Cryptography.CipherMode]::CBC)
```

## Classes

### TripleDES

#### Properties

- $type $Object
- $type $Password
- $type $Salt

#### Methods

- `[void] TripleDES($object)`
- `[byte[]] Encrypt()`
- `[byte[]] Encrypt($iterations)`
- `[byte[]] Decrypt()`
- `[byte[]] Decrypt($iterations)`
- `static [byte[]] Encrypt($data, $Key)`
- `static [byte[]] Encrypt($data, $Key, $IV)`
- `static [byte[]] Encrypt($data, $Key, $IV, $iterations)`
- `static [byte[]] Encrypt($data, $Password)`
- `static [byte[]] Encrypt($data, $Passw0rd, $iterations)`
- `static [byte[]] Encrypt($data, $Password, $iterations)`
- `static [byte[]] Decrypt($data, $Key)`
- `static [byte[]] Decrypt($data, $Key, $IV)`
- `static [byte[]] Decrypt($data, $Key, $IV, $iterations)`
- `static [byte[]] Decrypt($data, $Password)`
- `static [byte[]] Decrypt($data, $Passw0rd, $iterations)`
- `static [byte[]] Decrypt($data, $Password, $iterations)`
- `static hidden [byte[]] Get_ED($data, $Key, $IV, $Encrypt)`



