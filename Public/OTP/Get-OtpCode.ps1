function Get-OtpCode {
  <#
  .SYNOPSIS
    Generates a Time-Based One-Time Password (TOTP).

  .DESCRIPTION
    Generates the standard 6-digit TOTP code for the current time, compliant with RFC 6238.
    Suitable for multi-factor authentication parity with Google Authenticator.

  .PARAMETER Secret
    The Base32-encoded secret key assigned to the user.

  .EXAMPLE
    PS C:\> Get-OtpCode -Secret "JBSWY3DPEHPK3PXP"
  #>
  [CmdletBinding()]
  [OutputType([string])]
  param(
    [Parameter(Mandatory, Position = 0, ValueFromPipeline)]
    [string]$Secret
  )
  process {
    return [OTPKIT]::GetOtp($Secret)
  }
}
