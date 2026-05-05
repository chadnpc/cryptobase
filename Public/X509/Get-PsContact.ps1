function Get-PsContact {
  # .SYNOPSIS
  #   Get a list of all contacts you have registered. (Wrapper for [CryptoBase]::GetContact)
  [CmdletBinding()][OutputType([PSCustomObject[]])]
  param (
    [string]$Name = '*'
  )
  begin {
    $c = $null
  }
  process {
    try {
      $c = [CryptoBase]::GetContact($Name)
    } catch {
      # Handle errors during contact retrieval if needed, though class method logs warnings
      $PSCmdlet.WriteError($_)
    }
  }
  end {
    return $c
  }
}