#!/usr/bin/env pwsh
using namespace System
using namespace System.Security.Cryptography

using module ./Utilities.psm1

class AesCmac : CryptobaseUtils {
  static [int] $BlockSize = 16

  static [byte[]] ComputeTag([byte[]]$data, [byte[]]$key) {
    if ($null -eq $data) { throw [ArgumentNullException]::new("data") }
    if ($null -eq $key) { throw [ArgumentNullException]::new("key") }

    $aes = [Aes]::Create()
    $aes.Key = $key
    $aes.Mode = [CipherMode]::ECB
    $aes.Padding = [PaddingMode]::None

    $encryptor = $aes.CreateEncryptor()

    # Generate subkeys K1 and K2
    $k1 = [byte[]]::new([AesCmac]::BlockSize)
    $k2 = [byte[]]::new([AesCmac]::BlockSize)
    [AesCmac]::GenerateSubkeys($k1, $k2, $encryptor)

    $tag = [byte[]]::new([AesCmac]::BlockSize)
    [AesCmac]::ComputeCmac($tag, $data, $k1, $k2, $encryptor)

    $encryptor.Dispose()
    $aes.Dispose()

    return $tag
  }

  static [bool] VerifyTag([byte[]]$tag, [byte[]]$data, [byte[]]$key) {
    if ($null -eq $tag -or $tag.Length -ne [AesCmac]::BlockSize) { return $false }
    $computed = [AesCmac]::ComputeTag($data, $key)
    
    $diff = 0
    for ($i = 0; $i -lt [AesCmac]::BlockSize; $i++) {
      $diff = $diff -bor ($tag[$i] -bxor $computed[$i])
    }
    return $diff -eq 0
  }

  hidden static [void] GenerateSubkeys([byte[]]$k1, [byte[]]$k2, [ICryptoTransform]$aes) {
    $l = [byte[]]::new([AesCmac]::BlockSize)
    $zeros = [byte[]]::new([AesCmac]::BlockSize)
    [void]$aes.TransformBlock($zeros, 0, [AesCmac]::BlockSize, $l, 0)

    [AesCmac]::LeftShiftOneBit($k1, $l)
    if (($l[0] -band 0x80) -ne 0) {
      $k1[[AesCmac]::BlockSize - 1] = $k1[[AesCmac]::BlockSize - 1] -bxor 0x87
    }

    [AesCmac]::LeftShiftOneBit($k2, $k1)
    if (($k1[0] -band 0x80) -ne 0) {
      $k2[[AesCmac]::BlockSize - 1] = $k2[[AesCmac]::BlockSize - 1] -bxor 0x87
    }
  }

  hidden static [void] ComputeCmac([byte[]]$tag, [byte[]]$data, [byte[]]$k1, [byte[]]$k2, [ICryptoTransform]$aes) {
    $n = [int][Math]::Ceiling($data.Length / [AesCmac]::BlockSize)
    if ($n -eq 0) { $n = 1 }

    $lastBlockComplete = ($data.Length -gt 0) -and ($data.Length % [AesCmac]::BlockSize -eq 0)
    $mac = [byte[]]::new([AesCmac]::BlockSize)
    $block = [byte[]]::new([AesCmac]::BlockSize)

    for ($i = 0; $i -lt $n - 1; $i++) {
      $offset = $i * [AesCmac]::BlockSize
      [Array]::Copy($data, $offset, $block, 0, [AesCmac]::BlockSize)
      [AesCmac]::XorBlock($mac, $block)
      [void]$aes.TransformBlock($mac, 0, [AesCmac]::BlockSize, $mac, 0)
    }

    [Array]::Clear($block, 0, [AesCmac]::BlockSize)
    $lastOffset = ($n - 1) * [AesCmac]::BlockSize
    $lastLen = $data.Length - $lastOffset

    if ($lastLen -gt 0) {
      [Array]::Copy($data, $lastOffset, $block, 0, $lastLen)
    }

    if ($lastBlockComplete) {
      [AesCmac]::XorBlock($block, $k1)
    } else {
      $block[$lastLen] = 0x80
      [AesCmac]::XorBlock($block, $k2)
    }

    [AesCmac]::XorBlock($mac, $block)
    [void]$aes.TransformBlock($mac, 0, [AesCmac]::BlockSize, $mac, 0)
    [Array]::Copy($mac, $tag, [AesCmac]::BlockSize)
  }

  hidden static [void] LeftShiftOneBit([byte[]]$output, [byte[]]$input) {
    $overflow = 0
    for ($i = [AesCmac]::BlockSize - 1; $i -ge 0; $i--) {
      $output[$i] = [byte]((($input[$i] -shl 1) -bor $overflow) -band 0xFF)
      $overflow = ($input[$i] -band 0x80) ? 1 : 0
    }
  }

  hidden static [void] XorBlock([byte[]]$a, [byte[]]$b) {
    for ($i = 0; $i -lt [AesCmac]::BlockSize; $i++) {
      $a[$i] = [byte]($a[$i] -bxor $b[$i])
    }
  }
}
