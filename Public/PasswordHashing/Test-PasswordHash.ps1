function Test-PasswordHash {
  <#
  .SYNOPSIS
  Verifies a password against a secure hash.

  .DESCRIPTION
  Safely compares a plaintext password candidate against an Argon2/BCrypt hash string to securely check for a strong match.

  .PARAMETER Password
  The plain text candidate.

  .PARAMETER Hash
  The stored hash string.

  .EXAMPLE
  PS C:\> Test-PasswordHash -Password "SuperSecret123!" -Hash "`$argon2id`$v=19`$m=65536,t=3,p=4`$..."
  #>
  [CmdletBinding()]
  [OutputType([bool])]
  param(
    [Parameter(Mandatory, Position = 0)]
    [string]$Password,

    [Parameter(Mandatory, Position = 1)]
    [string]$Hash
  )
  process {
    [PasswordHashing]::VerifyPassword($Password, $Hash)
  }
}
