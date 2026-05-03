#!/usr/bin/env pwsh
using namespace System
using namespace System.Security.Cryptography

using module ./Utilities.psm1

class AesCfb : CryptobaseUtils {
  static [int] $BlockSize = 16

  static [byte[]] Encrypt([byte[]]$plaintext, [byte[]]$key, [byte[]]$iv) {
  if ($null -eq $plaintext) { throw [ArgumentNullException]::new("plaintext") }
  if ($null -eq $key) { throw [ArgumentNullException]::new("key") }
  if ($null -eq $iv) { throw [ArgumentNullException]::new("iv") }
    if ($iv.Length -ne [AesCfb]::BlockSize) { throw [ArgumentException]::new("IV must be 16 bytes.") }

    $aes = [Aes]::Create()
    $aes.Key = $key
    $aes.Mode = [CipherMode]::ECB
    $aes.Padding = [PaddingMode]::None

    $result = [AesCfb]::ProcessCore($plaintext, $aes, $iv, $true)
    $aes.Dispose()
    return $result
  }

  static [byte[]] Decrypt([byte[]]$ciphertext, [byte[]]$key, [byte[]]$iv) {
    if ($null -eq $ciphertext) { throw [ArgumentNullException]::new("ciphertext") }
    if ($null -eq $key) { throw [ArgumentNullException]::new("key") }
    if ($null -eq $iv) { throw [ArgumentNullException]::new("iv") }
    if ($iv.Length -ne [AesCfb]::BlockSize) { throw [ArgumentException]::new("IV must be 16 bytes.") }

    $aes = [Aes]::Create()
    $aes.Key = $key
    $aes.Mode = [CipherMode]::ECB
    $aes.Padding = [PaddingMode]::None

    $result = [AesCfb]::ProcessCore($ciphertext, $aes, $iv, $false)
    $aes.Dispose()
    return $result
  }

  hidden static [byte[]] ProcessCore([byte[]]$inData, [Aes]$aes, [byte[]]$iv, [bool]$encrypting) {
    $output = [byte[]]::new($inData.Length)
    $fr = [byte[]]::new([AesCfb]::BlockSize) # Feedback register
    $fre = [byte[]]::new([AesCfb]::BlockSize) # Encrypted feedback register

    [Array]::Copy($iv, $fr, [AesCfb]::BlockSize)
    $encryptor = $aes.CreateEncryptor()

    $pos = 0
    while ($pos -lt $inData.Length) {
      [void]$encryptor.TransformBlock($fr, 0, [AesCfb]::BlockSize, $fre, 0)

      $bytesToProcess = [Math]::Min([AesCfb]::BlockSize, $inData.Length - $pos)
      for ($i = 0; $i -lt $bytesToProcess; $i++) {
        $output[$pos + $i] = [byte]($inData[$pos + $i] -bxor $fre[$i])
      }

      if ($encrypting) {
        [Array]::Copy($output, $pos, $fr, 0, $bytesToProcess)
      } else {
        [Array]::Copy($inData, $pos, $fr, 0, $bytesToProcess)
      }

      if ($bytesToProcess -lt [AesCfb]::BlockSize) {
        [Array]::Clear($fr, $bytesToProcess, [AesCfb]::BlockSize - $bytesToProcess)
      }

      $pos += $bytesToProcess
    }

    $encryptor.Dispose()
    return $output
  }
}
