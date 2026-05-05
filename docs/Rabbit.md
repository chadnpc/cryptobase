# Rabbit

An ultra-fast stream cipher known for exceptional software performance, selected as part of the eSTREAM portfolio.

## Usage Example

```powershell
$key = [byte[]]::new(16); [System.Security.Cryptography.RandomNumberGenerator]::Fill($key)
$iv = [byte[]]::new(8); [System.Security.Cryptography.RandomNumberGenerator]::Fill($iv)
$plain = [System.Text.Encoding]::UTF8.GetBytes('Real-time data stream')

$ciphertext = [RabbitManaged]::Encrypt($key, $iv, $plain)
```

## Classes

### RabbitState

#### Properties

- $type $X
- $type $C
- $type $Carry

### Rabbit

#### Properties

- $type $KEY_SIZE
- $type $IV_SIZE

#### Methods

- `static [byte[]] Encrypt($inputbytes, $key, $iv)`
- `static [byte[]] Decrypt($inputbytes, $key, $iv)`
- `static [byte[]] Transform($inputbytes, $key, $iv)`
- `static hidden [void] KeySetup($state, $key)`
- `static hidden [void] IvSetup($state, $iv)`
- `static hidden [void] NextState($state)`
- `static hidden [uint] GFunc($x, $c)`
- `static hidden [void] ExtractKeystream($state, $output)`
- `static hidden [uint] RotateLeft($value, $bits)`



