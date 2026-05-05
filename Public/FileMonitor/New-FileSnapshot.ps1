function New-FileSnapshot {
  <#
  .SYNOPSIS
  Takes a cryptographic snapshot of a file or directory.

  .DESCRIPTION
  Generates a high-speed cryptographic snapshot (default Blake3) mapping the structure and content of the specified path. Can be saved and compared against later to detect tampering.

  .PARAMETER Path
  The target file or directory path.

  .EXAMPLE
  PS C:\> $snapshot = New-FileSnapshot -Path "C:\SecureApp"
  #>
  [Diagnostics.CodeAnalysis.SuppressMessageAttribute("PSUseShouldProcessForStateChangingFunctions", "")]
  [CmdletBinding()]
  param(
    [Parameter(Mandatory, Position = 0)]
    [string]$Path
  )
  process {
    return [FileMonitor]::Snapshot($Path)
  }
}
