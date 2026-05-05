function Remove-PsContact {
  # .SYNOPSIS
  #   Remove a contact from the list of known cryptobase contacts. (Wrapper for [CryptoBase]::RemoveContact)
  [Diagnostics.CodeAnalysis.SuppressMessageAttribute("PSUseShouldProcessForStateChangingFunctions", "")]
  [CmdletBinding(SupportsShouldProcess = $true, ConfirmImpact = 'High')] # Add ShouldProcess
  param (
    [Parameter(Mandatory = $true, ValueFromPipeline = $true, ValueFromPipelineByPropertyName = $true)]
    [string[]]
    $Name # Parameter now represents the Identity (Name or Thumbprint)
  )

  process {
    foreach ($identity in $Name) {
      if ($PSCmdlet.ShouldProcess($identity, "Remove cryptobase Contact")) {
        try {
          # Call the static method directly with the identity
          [CryptoBase]::RemoveContact($identity)
          # Static method already provides verbose output
        } catch {
          # Write error if removal process itself failed unexpectedly
          $PSCmdlet.WriteError($_)
        }
      }
    }
  }
}