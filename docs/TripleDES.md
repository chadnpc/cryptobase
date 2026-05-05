# TripleDES

> **Note:** This documentation was automatically generated.

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


