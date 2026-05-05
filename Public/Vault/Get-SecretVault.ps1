function Get-SecretVault {
  <#
  .SYNOPSIS
  Retrieves a secure string secret from the vault.

  .DESCRIPTION
  Safely fetches a secret corresponding to the provided lookup key from the underlying vault (Windows Credential Manager / cross-platform keychain).

  .PARAMETER Key
  The unique identifier for the secret.

  .EXAMPLE
  PS C:\> $secret = Get-SecretVault -Key "API_KEY"
  #>
  [CmdletBinding()]
  [OutputType([string])]
  param(
    [Parameter(Mandatory, Position = 0)]
    [string]$Key
  )
  process {
    return [Vault]::GetSecret($Key)
  }
}
