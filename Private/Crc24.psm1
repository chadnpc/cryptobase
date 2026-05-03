#!/usr/bin/env pwsh
using namespace System

using module ./Utilities.psm1

class Crc24 : CryptobaseUtils {
  static hidden [uint32] $Polynomial = 0x864CFB
  static hidden [uint32[]] $CrcTable = [Crc24]::BuildTable()

  static hidden [uint32[]] BuildTable() {
    $table = [uint32[]]::new(256)
    for ($i = 0; $i -lt 256; $i++) {
      $crc = [uint32]($i -shl 16)
      for ($j = 0; $j -lt 8; $j++) {
        if (($crc -band 0x800000) -ne 0) {
          $crc = (($crc -shl 1) -bxor [Crc24]::Polynomial) -band 0xFFFFFF
        }
        else {
          $crc = ($crc -shl 1) -band 0xFFFFFF
        }
      }
      $table[$i] = $crc
    }
    return $table
  }

  static [uint32] Compute([byte[]]$data) {
    if ($null -eq $data) { return [uint32]0xB704CE }
    $crc = [uint32]0xB704CE
    foreach ($b in $data) {
      $index = (($crc -shr 16) -bxor $b) -band 0xFF
      $crc = ([Crc24]::CrcTable[$index] -bxor ($crc -shl 8)) -band 0xFFFFFF
    }
    return $crc
  }

  static [byte[]] ComputeToBytes([byte[]]$data) {
    $crc = [Crc24]::Compute($data)
    return [byte[]]@(
      [byte](($crc -shr 16) -band 0xFF),
      [byte](($crc -shr 8) -band 0xFF),
      [byte]($crc -band 0xFF)
    )
  }

  static [bool] Verify([byte[]]$expectedCrc, [byte[]]$data) {
    if ($null -eq $expectedCrc -or $expectedCrc.Count -lt 3) { return $false }
    $expected = ([uint32]$expectedCrc[0] -shl 16) -bor ([uint32]$expectedCrc[1] -shl 8) -bor [uint32]$expectedCrc[2]
    return [Crc24]::Compute($data) -eq ($expected -band 0xFFFFFF)
  }
}
