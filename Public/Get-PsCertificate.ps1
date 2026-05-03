function Get-PsCertificate {
  # .SYNOPSIS
  #   Retrieves cryptobase certificates. (Wrapper for [CryptoBase]::GetCertificate)
  [CmdletBinding()]
  param (
    [switch]
    $Current
  )

  process {
    # Call the static method
    $certificates = [CryptoBase]::GetCertificate($Current)

    # Format output as PSCustomObject like before for consistency
    $certificates | ForEach-Object {
      [PSCustomObject]@{
        PSTypeName  = 'cryptobase.Certificate'
        Subject     = $_.Subject
        NotAfter    = $_.NotAfter
        Thumbprint  = $_.Thumbprint
        Certificate = $_ # Include the full object
      }
    }
  }
}