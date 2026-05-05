# Crc24

A 24-bit Cyclic Redundancy Check used extensively in OpenPGP ASCII armoring for error detection.

## Usage Example

```powershell
$data = [System.Text.Encoding]::UTF8.GetBytes('Check me')

# Calculate standard CRC-24
$crcBytes = [Crc24]::ComputeHash($data)

# Often converted to Base64 in PGP:
$crcB64 = [Convert]::ToBase64String($crcBytes)
```

## Classes

### Crc24

#### Properties

- $type $Polynomial
- $type $CrcTable

#### Methods

- `static hidden [uint32[]] BuildTable()`
- `static [uint32] Compute($data)`
- `static [byte[]] ComputeToBytes($data)`
- `static [bool] Verify($expectedCrc, $data)`



