# Credentials & Secret Management

Utilities for securely storing and managing credentials in the Windows Credential Manager and secure vaults.

## Credential Manager

Access and manage the Windows Credential Manager (Control Panel > User Accounts > Credential Manager).

### Usage
```powershell
# Save a credential
[CredentialManager]::Save('MyApplication', 'admin', 'super-secret-password')

# Retrieve a credential
$cred = [CredentialManager]::Read('MyApplication')
# $cred.UserName
# $cred.Password
```

---

## Vault Client

A higher-level client for managing secrets in a secure, encrypted vault.

### Usage
```powershell
$client = [VaultClient]::new($vaultPath, $password)

# Add a secret
$client.AddSecret('API_KEY', '12345-abcde')

# Get a secret
$val = $client.GetSecret('API_KEY')
```

## File Monitor

Utility for monitoring file changes securely.

### Usage
```powershell
$monitor = [FileMonitor]::new($directoryPath)
$monitor.Start()
```


## API Documentation


## Classes

### CredManaged

#### Properties

- $type $target
- $type $IsProtected
- $type $type
- $type $Scope
- $type $UserName
- $type $Password
- $type $Domain

#### Methods

- `[void] CredManaged()`
- `[void] CredManaged($target, $username, $password)`
- `[void] CredManaged($target, $username, $password, $type)`
- `[void] CredManaged($PSCredential)`
- `[void] CredManaged($target, $PSCredential)`
- `[void] Protect()`
- `[void] UnProtect()`
- `[void] SaveToVault()`
- `[string] ToString()`

### NativeCredential

#### Properties

- $type $AttributeCount
- $type $CredentialBlobSize
- $type $CredentialBlob
- $type $TargetAlias
- $type $Type
- $type $TargetName
- $type $Attributes
- $type $UserName
- $type $Persist
- $type $Comment

#### Methods

- `[void] NativeCredential($Cr3dential)`
- `[void] NativeCredential($target, $username, $password)`
- `hidden [void] _init_()`

### CredentialManager

#### Properties

- $type $LastErrorCode

#### Methods

- `[void] CredentialManager()`
- `static hidden [object] Advapi32()`
- `static [void] SaveCredential($title, $SecureString)`
- `static [void] SaveCredential($title, $UserName, $SecureString)`
- `static [void] SaveCredential($Object)`
- `static [bool] Remove($target, $type)`
- `static [CredManaged] GetCredential($target)`
- `static [CredManaged] GetCredential($target, $username)`
- `static [CredManaged] GetCredential($target, $type, $username)`
- `static [Collections.ObjectModel.Collection[CredManaged]] RetreiveAll()`
- `static hidden [Psobject[]] get_StoredCreds()`
- `static hidden [void] Init()`



