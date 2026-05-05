function New-CryptoKeyPair {
  <#
  .SYNOPSIS
  Generates a new cryptographic keypair utilizing the specified asymmetric algorithm.

  .DESCRIPTION
  Generates robust asymmetric public and private keys with seamless formatting to PEM, XML, and other OpenSSL compatible formats using the underlying [KeypairGen] facility.

  .PARAMETER Algorithm
  The algorithm to use (e.g., RSA, Ed25519, MLKem, ECDSA).

  .PARAMETER Size
  The bit size or curve size for algorithms that vary based on size (e.g., RSA). Defaults to 2048 for RSA.

  .PARAMETER Format
  The output format requested. Defaults to PEM.

  .PARAMETER ExportPath
  If specified, the resulting formatted public and private keys will be dumped to files at the path.

  .EXAMPLE
  PS C:\> $keys = New-CryptoKeyPair -Algorithm Ed25519
  PS C:\> $keys.PublicKeyPem
  #>
  [CmdletBinding()]
  [OutputType([KeypairGenerationResult])]
  param(
    [Parameter(Mandatory, Position = 0)]
    [AsymmetricAlgorithm]$Algorithm,

    [int]$Size = 2048,

    [KeyFormat]$Format = [KeyFormat]::Pem,

    [string]$ExportPath
  )
  process {
    $result = $null
    
    # Simple delegation based on most common standard usages
    if ($Algorithm -eq [AsymmetricAlgorithm]::ED25519) {
      $result = [KeypairGen]::GenerateEd25519($Format)
    } elseif ($Algorithm -eq [AsymmetricAlgorithm]::RSA) {
      $result = [KeypairGen]::GenerateRSA($Size, $Format)
    } elseif ($Algorithm -eq [AsymmetricAlgorithm]::ECDSA) {
      $result = [KeypairGen]::GenerateEcdsa([ECCurveName]::$Size, $Format) # Assuming bit size map to curve, though simplistic in cmdlet logic
    } elseif ($Algorithm -eq [AsymmetricAlgorithm]::MLKem -or $Algorithm -eq [AsymmetricAlgorithm]::KYBER) {
      $result = [KeypairGen]::GenerateMLKem([MLKemSecurityLevel]::MLKem768, $Format)
    } else {
      # Fallback logic to generic manager
      $result = [KeypairGen]::GenerateRSA($Size, $Format) 
      Write-Warning "Fallback to RSA. Algorithm $Algorithm specific wrapper not fully exposed in pipeline wrapper yet."
    }

    if ($ExportPath) {
      $pubPath = [System.IO.Path]::Combine($ExportPath, "public.key")
      $privPath = [System.IO.Path]::Combine($ExportPath, "private.key")
      
      if ($Format -eq [KeyFormat]::Pem) {
        [System.IO.File]::WriteAllText($pubPath, $result.PublicKeyPem)
        [System.IO.File]::WriteAllText($privPath, $result.PrivateKeyPem)
      } else {
        [System.IO.File]::WriteAllBytes($pubPath, $result.PublicKeyRaw)
        [System.IO.File]::WriteAllBytes($privPath, $result.PrivateKeyRaw)
      }
    }

    return $result
  }
}
