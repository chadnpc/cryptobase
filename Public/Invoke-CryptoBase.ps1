using namespace System.Management.Automation
function Invoke-CryptoBase {
  #.DESCRIPTION
  #  Creates a custom CryptoBase object and Invokes methods on it.
  # .EXAMPLE
  #  "This is my secret message" | CryptoBase SignMessage
  # .NOTES
  #  If you want more control you can directly use the [CryptoBase] class :)
  #.LINK
  #  https://github.com/chadnpc/cliHelper.CryptoBase/blob/main/Public/Invoke-CryptoBase.ps1
  [CmdletBinding()]
  [Alias('cryptobase')]
  [OutputType({ [CryptoBase]::ReturnTypes })]
  param(
    [Parameter(Mandatory = $false, Position = 0)]
    [Alias('m')][AllowEmptyString()]
    [ArgumentCompleter({
        [OutputType([System.Management.Automation.CompletionResult])]
        param(
          [string] $CommandName,
          [string] $ParameterName,
          [string] $WordToComplete,
          [System.Management.Automation.Language.CommandAst] $CommandAst,
          [System.Collections.IDictionary] $FakeBoundParameters
        )
        $CompletionResults = [System.Collections.Generic.List[CompletionResult]]::new()
        $matchingMethods = [CryptoBase]::Methods.Where({ $_.Name -like "$WordToComplete*" -and $_.CustomAttributes.AttributeType.Name -notcontains "HiddenAttribute" })
        foreach ($method in $matchingMethods) {
          $paramst = ($method.GetParameters() | Select-Object @{l = '_'; e = { "[$($_.ParameterType.Name)]`$$($_.Name)" } })._ -join ', '
          $toolTip = "[{0}] {1}({2})" -f $method.ReturnType.Name, $method.Name, $paramst
          $CompletionResults.Add([System.Management.Automation.CompletionResult]::new($method.Name, $toolTip, 'Method', $toolTip))
        }
        return $CompletionResults
      })]
    [string]$Method,

    [Parameter(Mandatory = $false, ValueFromPipeline = $true, ValueFromPipelineByPropertyName = $true)]
    [Alias('i')][ValidateNotNullOrEmpty()]
    $InputObject
  )
  begin {
    $buff = [System.Collections.Generic.List[byte]]::new()
    $meth = [string]::IsNullOrWhiteSpace($Method) ? "GetHelp" : $Method
    if ($meth -notin [CryptoBase]::Methods.Name) {
      throw "Method '$meth' not found in CryptoBase."
    }
  }
  process {
    if ($PSBoundParameters.ContainsKey('InputObject')) {
      if ($InputObject -is [byte]) { [void]$buff.Add($InputObject) }
      else {
        $r = [CryptoBase]::$meth($InputObject)
        if ($null -ne $r) { Write-Output -NoEnumerate -InputObject $r }
      }
    }
  }
  end {
    if ($buff.Count -gt 0) {
      $r = [CryptoBase]::$meth($buff.ToArray())
      if ($null -ne $r) { Write-Output -NoEnumerate -InputObject $r }
    }
    elseif (!$PSBoundParameters.ContainsKey('InputObject')) {
      $r = [CryptoBase]::$meth()
      if ($null -ne $r) { Write-Output $r }
    }
  }
}
