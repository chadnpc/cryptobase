# KMACAuth

Keccak Message Authentication Code (KMAC) provides a MAC based on the SHA-3/Keccak underlying sponge function.

## Usage Example

```powershell
$key = [byte[]]::new(32); [System.Security.Cryptography.RandomNumberGenerator]::Fill($key)
$msg = [System.Text.Encoding]::UTF8.GetBytes('Data')
$custom = [System.Text.Encoding]::UTF8.GetBytes('DomainSeparationContext')

$mac = [KMACAuth]::ComputeKMAC256($key, $msg, 32, $custom)
```

## Classes

### KMAC256

#### Methods

- `static [byte[]] ComputeHash($Key, $Data, $OutputLength, $Customization)`



