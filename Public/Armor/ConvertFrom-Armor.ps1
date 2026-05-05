function ConvertFrom-Armor {
  <#
  .SYNOPSIS
  Decodes an ASCII-armored string back into its original binary data.

  .DESCRIPTION
  Takes an OpenPGP or PEM formatted ASCII armored string, strips the headers and checksums, and outputs the raw byte payload.

  .PARAMETER ArmoredString
  The ASCII-armored block of text.

  .EXAMPLE
  PS C:\> $bytes = Get-Content armored.txt -Raw | ConvertFrom-Armor
  #>
  [CmdletBinding()]
  [OutputType([byte[]])]
  param(
    [Parameter(Mandatory, ValueFromPipeline)]
    [string]$ArmoredString
  )
  
  begin {
    $buffer = ""
  }
  process {
    $buffer += $ArmoredString
  }
  end {
    [Armor]::Decode($buffer)
  }
}
