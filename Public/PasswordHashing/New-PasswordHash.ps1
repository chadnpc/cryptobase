function New-PasswordHash {
  <#
  .SYNOPSIS
  Hashes a password optimally for secure database storage.

  .DESCRIPTION
  Uses Argon2id parameterization to derive a highly secure string representation of the password that is safe for long-term storage and verification.

  .PARAMETER Password
  The plain text password to hash.

  .EXAMPLE
  PS C:\> $hash = New-PasswordHash -Password "SuperSecret123!"
  #>
  [CmdletBinding()]
  [OutputType([string])]
  param(
    [Parameter(Mandatory, Position = 0, ValueFromPipeline)]
    [string]$Password
  )
  process {
    [PasswordHashing]::HashPassword($Password)
  }
}
