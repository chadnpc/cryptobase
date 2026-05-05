function Remove-SecretVault {
  <#
  .SYNOPSIS
  Removes a stored secret from the vault.

  .DESCRIPTION
  Deletes an existing credential/secret by its lookup key.

  .PARAMETER Key
  The unique identifier for the secret to remove.

  .EXAMPLE
  PS C:\> Remove-SecretVault -Key "API_KEY"
  #>
  [CmdletBinding()]
  param(
    [Parameter(Mandatory, Position = 0)]
    [string]$Key
  )
  process {
    return [Vault]::DeleteSecret($Key)
  }
}
