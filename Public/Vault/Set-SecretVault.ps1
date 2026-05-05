function Set-SecretVault {
  <#
  .SYNOPSIS
  Stores a secret securely in the vault.

  .DESCRIPTION
  Saves a plain text string securely into the cross-platform vault, encrypted at rest.

  .PARAMETER Key
  The unique identifier for the secret.

  .PARAMETER Secret
  The sensitive string to securely store.

  .EXAMPLE
  PS C:\> Set-SecretVault -Key "API_KEY" -Secret "xyz123"
  #>
  [CmdletBinding()]
  param(
    [Parameter(Mandatory, Position = 0)]
    [string]$Key,

    [Parameter(Mandatory, Position = 1)]
    [string]$Secret
  )
  process {
    return [Vault]::SetSecret($Key, $Secret)
  }
}
