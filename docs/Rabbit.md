# Rabbit

> **Note:** This documentation was automatically generated.

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


