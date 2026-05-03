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
