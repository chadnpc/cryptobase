function ConvertTo-Armor {
  <#
  .SYNOPSIS
  Encodes binary data into an ASCII-armored format.

  .DESCRIPTION
  Safely wraps raw byte arrays in standard OpenPGP ASCII Armor headers to ensure transmission stability.

  .PARAMETER InputData
  The raw binary data (byte array) to be armored.

  .PARAMETER HeaderType
  The ASCII envelope label (e.g. 'PGP MESSAGE', 'PGP PUBLIC KEY BLOCK').

  .EXAMPLE
  PS C:\> Get-Content cipher.bin -AsByteStream | ConvertTo-Armor -HeaderType "PGP MESSAGE"
  #>
  [CmdletBinding()]
  [OutputType([string])]
  param(
    [Parameter(Mandatory, ValueFromPipeline)]
    [byte[]]$InputData,

    [Parameter(Position = 0)]
    [string]$HeaderType = 'PGP MESSAGE'
  )
  
  begin {
    [System.Collections.Generic.List[byte]]$buffer = [System.Collections.Generic.List[byte]]::new()
  }
  process {
    $buffer.AddRange($InputData)
  }
  end {
    [Armor]::Encode($buffer.ToArray(), $HeaderType, @{})
  }
}
