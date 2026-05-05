# AesCmac

> **Note:** This documentation was automatically generated.

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


