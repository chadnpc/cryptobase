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
    $result = $null
    $crypt = [CryptoBase]::new()
  }
  process {
    $Method = [string]::IsNullOrWhiteSpace($Method) ? "GetHelp" : $Method
    $InvalidMethods = $Method.Where({ $_ -notin [CryptoBase]::Methods.Name })
    if ($InvalidMethods.Count -gt 0) {
      $PSCmdlet.ThrowTerminatingError([System.Management.Automation.ErrorRecord]::new(
          [System.InvalidOperationException]::new("Please use valid method names. Methods ($($InvalidMethods -join ', ')) were not found.",
            [System.Management.Automation.MethodInvocationException]::new("")),
          "METHOD_NOT_FOUND",
          "InvalidArgument",
          $null
        )
      )
    }
    $result = $PSBoundParameters.ContainsKey("InputObject")? ($crypt::$Method($InputObject)) : $crypt::$Method()
  }
  end {
    return $result
  }
}
