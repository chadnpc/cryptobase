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
    $crypt = [CryptoBase]::new(); $res = $null
    $methodName = [string]::IsNullOrWhiteSpace($Method) ? "GetHelp" : $Method

    # Validate method exists
    if ($methodName -notin [CryptoBase]::Methods.Name) {
      $PSCmdlet.ThrowTerminatingError([System.Management.Automation.ErrorRecord]::new(
          [System.InvalidOperationException]::new("Method '$methodName' was not found in CryptoBase."),
          "METHOD_NOT_FOUND",
          "InvalidArgument",
          $null
        )
      )
    }
  }
  process {
    if ($PSBoundParameters.ContainsKey("InputObject")) {
      if ($InputObject -is [byte]) {
        $buffer = [System.Collections.Generic.List[byte]]::new()
        $buffer.Add($InputObject)
        # Accumulate unrolled bytes from pipeline
        $res = $crypt::$methodName(@(, $buffer.ToArray()))
      }
      else {
        # Process other types (strings, paths, or already-rolled byte[]) immediately
        $res = $crypt::$methodName($InputObject)
      }
    }
    else {
      # No parameter input: execute method without arguments (e.g., GetHelp)
      $res = $crypt::$methodName()
    }
  }
  end {
    return $res
  }
}
