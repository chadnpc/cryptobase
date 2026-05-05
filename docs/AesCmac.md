# AesCmac

AES Cipher-Based Message Authentication Code (CMAC). A block-cipher based message authentication code algorithm.

## Usage Example

```powershell
$key = [byte[]]::new(32); [System.Security.Cryptography.RandomNumberGenerator]::Fill($key)
$message = [System.Text.Encoding]::UTF8.GetBytes('Important data')

# Generate MAC
$mac = [AesCmac]::ComputeMac($key, $message)

# Verify MAC
$isValid = [AesCmac]::VerifyMac($key, $message, $mac)
```

## Classes

### AesCmac

#### Properties

- $type $BlockSize

#### Methods

- `static [byte[]] ComputeTag($data, $key)`
- `static [bool] VerifyTag($tag, $data, $key)`
- `static hidden [void] GenerateSubkeys($k1, $k2, $aes)`
- `static hidden [void] ComputeCmac($tag, $data, $k1, $k2, $aes)`
- `static hidden [void] LeftShiftOneBit($output, $input)`
- `static hidden [void] XorBlock($a, $b)`



