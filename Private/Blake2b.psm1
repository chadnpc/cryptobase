#!/usr/bin/env pwsh
using namespace System
using namespace System.Collections.Generic
using namespace System.Text

using module ./Utilities.psm1

class Blake2b : CryptobaseUtils {
  static [uint64[]] $Blake2bIv = @(
    [Convert]::ToUInt64('6a09e667f3bcc908',16), [Convert]::ToUInt64('bb67ae8584caa73b',16), [Convert]::ToUInt64('3c6ef372fe94f82b',16), [Convert]::ToUInt64('a54ff53a5f1d36f1',16),
    [Convert]::ToUInt64('510e527fade682d1',16), [Convert]::ToUInt64('9b05688c2b3e6c1f',16), [Convert]::ToUInt64('1f83d9abfb41bd6b',16), [Convert]::ToUInt64('5be0cd19137e2179',16)
  )

  static [byte[]] $Blake2bSigma = @(
    0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15,
    14, 10, 4, 8, 9, 15, 13, 6, 1, 12, 0, 2, 11, 7, 5, 3,
    11, 8, 12, 0, 5, 2, 15, 13, 10, 14, 3, 6, 7, 1, 9, 4,
    7, 9, 3, 1, 13, 12, 11, 14, 2, 6, 5, 10, 4, 0, 15, 8,
    9, 0, 5, 7, 2, 4, 10, 15, 14, 1, 11, 12, 6, 8, 3, 13,
    2, 12, 6, 10, 0, 11, 8, 3, 4, 13, 7, 5, 15, 14, 1, 9,
    12, 5, 1, 15, 14, 13, 4, 10, 0, 7, 6, 3, 9, 2, 8, 11,
    13, 11, 7, 14, 12, 1, 3, 9, 5, 0, 15, 4, 8, 6, 2, 10,
    6, 15, 14, 9, 11, 3, 0, 8, 12, 2, 13, 7, 1, 4, 10, 5,
    10, 2, 8, 4, 7, 6, 1, 5, 15, 11, 9, 14, 3, 12, 13, 0
  )

  static [byte[]] ComputeHash([byte[]]$inputbytes) {
    return [Blake2b]::ComputeHash($inputbytes, 64)
  }

  static [byte[]] ComputeHash([byte[]]$inputbytes, [int]$outputLength) {
    return [Blake2b]::ComputeHash($inputbytes, $outputLength, $null)
  }

  static [byte[]] ComputeHash([byte[]]$inputbytes, [int]$outputLength, [byte[]]$key) {
    return [Blake2b]::ComputeHash($inputbytes, $outputLength, $key, $null, $null)
  }

  static [byte[]] ComputeHash([byte[]]$inputbytes, [int]$outputLength, [byte[]]$key, [byte[]]$salt, [byte[]]$personalization) {
    if ($outputLength -lt 1 -or $outputLength -gt 64) { throw [ArgumentException]::new("Output length must be between 1 and 64 bytes") }
    if ($null -ne $key -and $key.Length -gt 64) { throw [ArgumentException]::new("Key length must not exceed 64 bytes") }

    $h = [uint64[]]::new(8)
    [Array]::Copy([Blake2b]::Blake2bIv, $h, 8)

    $paramWords = [Blake2b]::GetParamWords($outputLength, ($null -eq $key ? 0 : $key.Length), $salt, $personalization)
    for ($i = 0; $i -lt 8; $i++) {
      $h[$i] = $h[$i] -bxor $paramWords[$i]
    }

    $buffer = [byte[]]::new(128)
    $bufferLength = 0
    $bytesCompressed = [uint64]0

    if ($null -ne $key -and $key.Length -gt 0) {
      [Array]::Copy($key, 0, $buffer, 0, $key.Length)
      $bufferLength = 128
    }

    $m = [uint64[]]::new(16)
    $v = [uint64[]]::new(16)

    for ($i = 0; $i -lt $inputbytes.Length; $i++) {
      if ($bufferLength -eq 128) {
        $bytesCompressed = [uint64](([bigint]$bytesCompressed + 128) -band [uint64]::MaxValue)
        [Blake2b]::Compress($h, $buffer, $bytesCompressed, $false, $m, $v)
        $bufferLength = 0
        [Array]::Clear($buffer, 0, 128)
      }
      $buffer[$bufferLength++] = $inputbytes[$i]
    }

    $bytesCompressed = [uint64](([bigint]$bytesCompressed + $bufferLength) -band [uint64]::MaxValue)
    [Blake2b]::Compress($h, $buffer, $bytesCompressed, $true, $m, $v)

    $output = [byte[]]::new($outputLength)
    for ($i = 0; $i -lt [int]($outputLength / 8); $i++) {
      [Blake2b]::WriteUInt64LE($output, $i * 8, $h[$i])
    }
    if ($outputLength % 8 -ne 0) {
      $lastBytes = [byte[]]::new(8)
      [Blake2b]::WriteUInt64LE($lastBytes, 0, $h[[int]($outputLength / 8)])
      [Array]::Copy($lastBytes, 0, $output, [int]($outputLength / 8) * 8, $outputLength % 8)
    }
    return $output
  }

  hidden static [uint64[]] GetParamWords([int]$digestSize, [int]$keyLength, [byte[]]$salt, [byte[]]$personalization) {
    $paramBytes = [byte[]]::new(64)
    $paramBytes[0] = [byte]$digestSize
    $paramBytes[1] = [byte]$keyLength
    $paramBytes[2] = 1 # FanOut
    $paramBytes[3] = 1 # Depth

    if ($null -ne $salt -and $salt.Length -gt 0) {
      [Array]::Copy($salt, 0, $paramBytes, 32, [Math]::Min(16, $salt.Length))
    }
    if ($null -ne $personalization -and $personalization.Length -gt 0) {
      [Array]::Copy($personalization, 0, $paramBytes, 48, [Math]::Min(16, $personalization.Length))
    }

    $words = [uint64[]]::new(8)
    for ($i = 0; $i -lt 8; $i++) {
      $words[$i] = [Blake2b]::ReadUInt64LE($paramBytes, $i * 8)
    }
    return $words
  }

  hidden static [void] Compress([uint64[]]$h, [byte[]]$buffer, [uint64]$bytesCompressed, [bool]$isLastBlock, [uint64[]]$m, [uint64[]]$v) {
    for ($i = 0; $i -lt 16; $i++) {
      $m[$i] = [Blake2b]::ReadUInt64LE($buffer, $i * 8)
    }

    [Array]::Copy($h, $v, 8)
    [Array]::Copy([Blake2b]::Blake2bIv, 0, $v, 8, 8)

    $v[12] = $v[12] -bxor $bytesCompressed
    # v[13] counter high bits not used here
    if ($isLastBlock) {
      $v[14] = $v[14] -bxor [uint64]::MaxValue
    }

    for ($round = 0; $round -lt 12; $round++) {
      $rowOff = ($round % 10) * 16
      [Blake2b]::G($v, 0, 4, 8, 12, $m[[Blake2b]::Blake2bSigma[$rowOff + 0]], $m[[Blake2b]::Blake2bSigma[$rowOff + 1]])
      [Blake2b]::G($v, 1, 5, 9, 13, $m[[Blake2b]::Blake2bSigma[$rowOff + 2]], $m[[Blake2b]::Blake2bSigma[$rowOff + 3]])
      [Blake2b]::G($v, 2, 6, 10, 14, $m[[Blake2b]::Blake2bSigma[$rowOff + 4]], $m[[Blake2b]::Blake2bSigma[$rowOff + 5]])
      [Blake2b]::G($v, 3, 7, 11, 15, $m[[Blake2b]::Blake2bSigma[$rowOff + 6]], $m[[Blake2b]::Blake2bSigma[$rowOff + 7]])

      [Blake2b]::G($v, 0, 5, 10, 15, $m[[Blake2b]::Blake2bSigma[$rowOff + 8]], $m[[Blake2b]::Blake2bSigma[$rowOff + 9]])
      [Blake2b]::G($v, 1, 6, 11, 12, $m[[Blake2b]::Blake2bSigma[$rowOff + 10]], $m[[Blake2b]::Blake2bSigma[$rowOff + 11]])
      [Blake2b]::G($v, 2, 7, 8, 13, $m[[Blake2b]::Blake2bSigma[$rowOff + 12]], $m[[Blake2b]::Blake2bSigma[$rowOff + 13]])
      [Blake2b]::G($v, 3, 4, 9, 14, $m[[Blake2b]::Blake2bSigma[$rowOff + 14]], $m[[Blake2b]::Blake2bSigma[$rowOff + 15]])
    }

    for ($i = 0; $i -lt 8; $i++) {
      $h[$i] = $h[$i] -bxor $v[$i] -bxor $v[$i + 8]
    }
  }

  hidden static [void] G([uint64[]]$v, [int]$a, [int]$b, [int]$c, [int]$d, [uint64]$x, [uint64]$y) {
    $v[$a] = [uint64](([bigint]$v[$a] + $v[$b] + $x) -band [uint64]::MaxValue)
    $v[$d] = [Blake2b]::RotateRight($v[$d] -xor $v[$a], 32)
    $v[$c] = [uint64](([bigint]$v[$c] + $v[$d]) -band [uint64]::MaxValue)
    $v[$b] = [Blake2b]::RotateRight($v[$b] -xor $v[$c], 24)
    $v[$a] = [uint64](([bigint]$v[$a] + $v[$b] + $y) -band [uint64]::MaxValue)
    $v[$d] = [Blake2b]::RotateRight($v[$d] -xor $v[$a], 16)
    $v[$c] = [uint64](([bigint]$v[$c] + $v[$d]) -band [uint64]::MaxValue)
    $v[$b] = [Blake2b]::RotateRight($v[$b] -xor $v[$c], 63)
  }

  hidden static [uint64] RotateRight([uint64]$value, [int]$offset) {
    return ($value -shr $offset) -bor ($value -shl (64 - $offset))
  }

  hidden static [uint64] ReadUInt64LE([byte[]]$buf, [int]$off) {
    return ([uint64]$buf[$off]) -bor
    ([uint64]$buf[$off + 1] -shl 8) -bor
    ([uint64]$buf[$off + 2] -shl 16) -bor
    ([uint64]$buf[$off + 3] -shl 24) -bor
    ([uint64]$buf[$off + 4] -shl 32) -bor
    ([uint64]$buf[$off + 5] -shl 40) -bor
    ([uint64]$buf[$off + 6] -shl 48) -bor
    ([uint64]$buf[$off + 7] -shl 56)
  }

  hidden static [void] WriteUInt64LE([byte[]]$buf, [int]$off, [uint64]$val) {
    $buf[$off] = [byte]($val -band 0xFF)
    $buf[$off + 1] = [byte](($val -shr 8) -band 0xFF)
    $buf[$off + 2] = [byte](($val -shr 16) -band 0xFF)
    $buf[$off + 3] = [byte](($val -shr 24) -band 0xFF)
    $buf[$off + 4] = [byte](($val -shr 32) -band 0xFF)
    $buf[$off + 5] = [byte](($val -shr 40) -band 0xFF)
    $buf[$off + 6] = [byte](($val -shr 48) -band 0xFF)
    $buf[$off + 7] = [byte](($val -shr 56) -band 0xFF)
  }
}
