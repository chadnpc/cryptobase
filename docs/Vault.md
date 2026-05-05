# Vault

> **Note:** This documentation was automatically generated.

## Classes

### VaultClient

#### Properties

- $type $Address
- $type $Token
- $type $Protocol
- $type $Url
- $type $ClientObj
- $type $releases

#### Methods

- `[void] VaultClient($address, $token, $protocol)`
- `static [void] Install()`
- `static [void] Install($version)`
- `[void] GenerateVaultClient($token)`
- `[PSCustomObject] GetVaultServer()`
- `[Hashtable] GetVaultSecret($path)`
- `[string[]] GetVaultSecretList($path)`
- `[string[]] GetVaultSecretList($path, $vault)`
- `[void] SetVaultSecret($path, $secret)`
- `[void] RemoveVaultSecret($path)`
- `[Hashtable] GetVaultGroup($name)`
- `[void] SetVaultGroup($group)`
- `[void] RemoveVaultGroup($name)`
- `[string] GetVaultPolicy($name)`
- `[void] SetVaultPolicy($name, $rules)`
- `[void] RemoveVaultPolicy($name)`
- `[string[]] GetVaultPolicyList()`


