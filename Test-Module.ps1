#!/usr/bin/env pwsh
using namespace System.IO
using namespace System.Collections.Generic
using namespace System.Collections.ObjectModel

# .SYNOPSIS
#   cryptobase testScript v0.1.2
# .EXAMPLE
#   ./Test-Module.ps1 -version 0.1.2
#   Will test the module in ./BuildOutput/cryptobase/0.1.2/
# .EXAMPLE
#   ./Test-Module.ps1
#   Will test the latest  module version in ./BuildOutput/cryptobase/
param (
  [Parameter(Mandatory = $false, Position = 0)]
  [Alias('Module')][string]$ModulePath = $PSScriptRoot,
  # Path Containing Tests
  [Parameter(Mandatory = $false, Position = 1)]
  [Alias('Tests')][string]$TestsPath = [IO.Path]::Combine($PSScriptRoot, 'Tests'),

  # Version string
  [Parameter(Mandatory = $false, Position = 2)]
  [ValidateScript({
      if (($_ -as 'version') -is [version]) {
        return $true
      }
      else {
        throw [InvalidDataException]::New('Please Provide a valid version')
      }
    }
  )][ArgumentCompleter({
      [OutputType([System.Management.Automation.CompletionResult])]
      param([string]$CommandName, [string]$ParameterName, [string]$WordToComplete, [System.Management.Automation.Language.CommandAst]$CommandAst, [System.Collections.IDictionary]$FakeBoundParameters)
      $CompletionResults = [List[System.Management.Automation.CompletionResult]]::new()
      $b_Path = [IO.Path]::Combine($PSScriptRoot, 'BuildOutput', 'cryptobase')
      if ((Test-Path -Path $b_Path -PathType Container -ErrorAction Ignore)) {
        [IO.DirectoryInfo]::New($b_Path).GetDirectories().Name | Where-Object { $_ -like "*$wordToComplete*" -and $_ -as 'version' -is 'version' } | ForEach-Object { [void]$CompletionResults.Add([System.Management.Automation.CompletionResult]::new($_, $_, "ParameterValue", $_)) }
      }
      return $CompletionResults
    }
  )]
  [string]$version,
  [switch]$SkipBuildOutput,
  [switch]$CleanUp
)
begin {
  $TestResults = $null;
  $BuildOutDir = $PSScriptRoot
  $BuildOutput = [IO.DirectoryInfo]::New([IO.Path]::Combine($PSScriptRoot, 'BuildOutput', 'cryptobase'))
  if (!$BuildOutput.Exists -and !$SkipBuildOutput) {
    Write-Warning "NO_Build_OutPut | Please make sure to Build the module successfully first before running Test-Module.ps1 or use -SkipBuildOutput switch to skip this check"
    throw [DirectoryNotFoundException]::New("Cannot find path '$($BuildOutput.FullName)' because it does not exist.")
  }
  if ($BuildOutput.Exists) {
    # Get latest built version
    if ([string]::IsNullOrWhiteSpace($version)) {
      $version = $BuildOutput.GetDirectories().Name -as 'version[]' | Select-Object -Last 1
    }
    $BuildOutDir = Resolve-Path $([IO.Path]::Combine($PSScriptRoot, 'BuildOutput', 'cryptobase', $version)) -ErrorAction Ignore | Get-Item -ErrorAction Ignore
    if (!$BuildOutDir.Exists) { throw [DirectoryNotFoundException]::new($BuildOutDir) }
  }
  $manifestFile = [IO.FileInfo]::New([IO.Path]::Combine($BuildOutDir, "cryptobase.psd1"))
}

process {
  Write-Host "==========================================" -ForegroundColor Cyan
  Write-Host "  Cryptobase Module - Test Suite" -ForegroundColor Cyan
  Write-Host "==========================================" -ForegroundColor Cyan
  Write-Host "[0/3] Checking Prerequisites ..." -ForegroundColor Green
  if (!$BuildOutDir.Exists) {
    $msg = 'Directory "{0}" Not Found.' -f ([IO.Path]::GetRelativePath($PSScriptRoot, $BuildOutDir))
    if ($SkipBuildOutput) {
      Write-Host $msg -ForegroundColor Yellow
    }
    else {
      throw [DirectoryNotFoundException]::New($msg)
    }
  }
  if (!$manifestFile.Exists) {
    throw [FileNotFoundException]::New("Could Not Find Module manifest File '$manifestFile'")
  }
  if (!(Test-Path -Path $([IO.Path]::Combine($PSScriptRoot, "cryptobase.psd1")) -PathType Leaf -ErrorAction Ignore)) { throw [FileNotFoundException]::New("Module manifest file Was not Found in '$BuildOutDir'.") }
  $script:fnNames = [List[string]]::New(); $testFiles = [List[IO.FileInfo]]::New()
  [void]$testFiles.Add([IO.FileInfo]::New([IO.Path]::Combine("$PSScriptRoot", 'Tests', 'cryptobase.Integration.Tests.ps1')))
  [void]$testFiles.Add([IO.FileInfo]::New([IO.Path]::Combine("$PSScriptRoot", 'Tests', 'cryptobase.Features.Tests.ps1')))
  [void]$testFiles.Add([IO.FileInfo]::New([IO.Path]::Combine("$PSScriptRoot", 'Tests', 'cryptobase.Module.Tests.ps1')))
  $missingTestFiles = $testFiles.Where({ !$_.Exists })
  if ($missingTestFiles.count -gt 0) { throw [FileNotFoundException]::new("One or more missing TestFiles! $($testFiles.BaseName -join ', ')") }
  Write-Host "[1/2] Testing ModuleManifest ..." -ForegroundColor Green
  if (!$SkipBuildOutput) {
    Test-ModuleManifest -Path $manifestFile.FullName -ErrorAction Stop -Verbose:$false
  }
  Write-Host "[2/2] Running all test files" -ForegroundColor Yellow
  $IsCorrectPesterVersion = (Get-Module Pester -ListAvailable | Select-Object -Expand Version) -le [version]"3.4.0"
  if (!$IsCorrectPesterVersion) {
    throw "Pester tests were writen on pester v3.4.0, please downgrade and try again"
  }
  $TestResults = Invoke-Pester -Path $([IO.Path]::Combine($PSScriptRoot, 'Tests')) -OutputFile ([IO.Path]::Combine("$TestsPath", "results.xml")) -OutputFormat NUnitXml -PassThru
}

end {
  return $TestResults
}
