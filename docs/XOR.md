# XOR

> **Note:** This documentation was automatically generated.

## Classes

### XOR

#### Properties

- $type $Object
- $type $Password
- $type $Salt

#### Methods

- `[void] XOR($object)`
- `[byte[]] Encrypt()`
- `[byte[]] Encrypt($iterations)`
- `static [byte[]] Encrypt($Bytes, $Passw0rd)`
- `static [byte[]] Encrypt($Bytes, $password)`
- `static [byte[]] Encrypt($Bytes, $password, $iterations)`
- `static [byte[]] Encrypt($Bytes, $xorkey, $iterations)`
- `[byte[]] Decrypt()`
- `[byte[]] Decrypt($iterations)`
- `static [byte[]] Decrypt($Bytes, $Passw0rd)`
- `static [byte[]] Decrypt($Bytes, $password)`
- `static [byte[]] Decrypt($Bytes, $password, $iterations)`
- `static [byte[]] Decrypt($Bytes, $xorkey, $iterations)`
- `static hidden [byte[]] Get_ED($data, $Key, $IV, $Encrypt)`


