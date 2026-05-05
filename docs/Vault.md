# Vault

Provides high-level cross-platform API for securely persisting and retrieving secrets directly from the OS credential store.

## Usage Example

```powershell
# Save secret
[Vault]::SetSecret('API_KEY', 'my-super-secret-123')

# Retrieve secret
$secretStr = [Vault]::GetSecret('API_KEY')
```

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



