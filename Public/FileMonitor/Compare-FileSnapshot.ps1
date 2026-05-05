function Compare-FileSnapshot {
  <#
  .SYNOPSIS
  Compares a path against a previously generated cryptographic snapshot.

  .DESCRIPTION
  Detects modified, deleted, and altered files by comparing the live directory state against a stored baseline map object to strictly guarantee no illicit tampering occurred.

  .PARAMETER Path
  The target file or directory path.

  .PARAMETER Baseline
  The snapshot object returned by New-FileSnapshot.

  .EXAMPLE
  PS C:\> Compare-FileSnapshot -Path "C:\SecureApp" -Baseline $snapshot
  #>
  [CmdletBinding()]
  param(
    [Parameter(Mandatory, Position = 0)]
    [string]$Path,

    [Parameter(Mandatory, Position = 1)]
    $Baseline
  )
  process {
    [FileMonitor]::Diff($Path, $Baseline)
  }
}
