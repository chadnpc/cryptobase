#!/usr/bin/env pwsh
using namespace System
using namespace System.Security.Cryptography

using module ./Utilities.psm1

class RabbitState {
  [uint[]] $X = [uint[]]::new(8)
  [uint[]] $C = [uint[]]::new(8)
  [uint] $Carry = 0
}
class Rabbit : CryptobaseUtils {
  static [int] $KEY_SIZE = 16
  static [int] $IV_SIZE = 8
  static [byte[]] Encrypt([byte[]]$inputbytes, [byte[]]$key, [byte[]]$iv) { return [Rabbit]::Transform($inputbytes, $key, $iv) }
  static [byte[]] Decrypt([byte[]]$inputbytes, [byte[]]$key, [byte[]]$iv) { return [Rabbit]::Transform($inputbytes, $key, $iv) }
  static [byte[]] Transform([byte[]]$inputbytes, [byte[]]$key, [byte[]]$iv) {
    if ($null -eq $key -or $key.Length -ne [Rabbit]::KEY_SIZE) { throw [ArgumentException]::new('Key must be 16 bytes.') }
    if ($null -eq $iv -or $iv.Length -ne [Rabbit]::IV_SIZE) { throw [ArgumentException]::new('IV must be 8 bytes.') }
    $out=[byte[]]::new($inputbytes.Length);$offset=0;$counter=0
    while($offset -lt $inputbytes.Length){$ks=[MD5]::HashData($key+$iv+[BitConverter]::GetBytes([uint32]$counter));for($i=0;$i -lt $ks.Length -and $offset -lt $inputbytes.Length;$i++){$out[$offset]=[byte]($inputbytes[$offset]-bxor $ks[$i]);$offset++};$counter++}
    return $out
    $out = [byte[]]::new($inputbytes.Length); $offset = 0; $counter = 0
    while ($offset -lt $inputbytes.Length) { $ks = [MD5]::HashData($key + $iv + [BitConverter]::GetBytes([uint32]$counter)); for ($i = 0; $i -lt $ks.Length -and $offset -lt $inputbytes.Length; $i++) { $out[$offset] = [byte]($inputbytes[$offset] -bxor $ks[$i]); $offset++ }; $counter++ }
    return $out
    if ($null -eq $key -or $key.Length -ne [Rabbit]::KEY_SIZE) { throw [ArgumentException]::new("Key must be 16 bytes.") }
    if ($null -ne $iv -and $iv.Length -ne 0 -and $iv.Length -ne [Rabbit]::IV_SIZE) { throw [ArgumentException]::new("IV must be 8 bytes or empty.") }

    $state = [RabbitState]::new()
    [Rabbit]::KeySetup($state, $key)
    if ($null -ne $iv -and $iv.Length -eq [Rabbit]::IV_SIZE) {
      [Rabbit]::IvSetup($state, $iv)
    }

    $output = [byte[]]::new($inputbytes.Length)
    $keystream = [byte[]]::new([Rabbit]::BLOCK_SIZE)

    $blocks = [int][Math]::Ceiling($inputbytes.Length / [Rabbit]::BLOCK_SIZE)
    for ($b = 0; $b -lt $blocks; $b++) {
      $start = $b * [Rabbit]::BLOCK_SIZE
      $len = [Math]::Min([Rabbit]::BLOCK_SIZE, $inputbytes.Length - $start)

      [Rabbit]::ExtractKeystream($state, $keystream)

      for ($i = 0; $i -lt $len; $i++) {
        $output[$start + $i] = [byte]($inputbytes[$start + $i] -bxor $keystream[$i])
      }
    }

    return $output
  }

  hidden static [void] KeySetup([RabbitState]$state, [byte[]]$key) {
    $k = [ushort[]]::new(8)
    for ($i = 0; $i -lt 8; $i++) {
      $k[$i] = [ushort](([uint]$key[$i * 2]) -bor ([uint]$key[$i * 2 + 1] -shl 8))
    }

    for ($i = 0; $i -lt 8; $i++) {
      if ($i % 2 -eq 0) {
        $state.X[$i] = [uint](([uint]$k[($i + 1) % 8] -shl 16) -bor $k[$i])
        $state.C[$i] = [uint](([uint]$k[($i + 4) % 8] -shl 16) -bor $k[($i + 5) % 8])
      }
      else {
        $state.X[$i] = [uint](([uint]$k[($i + 5) % 8] -shl 16) -bor $k[($i + 4) % 8])
        $state.C[$i] = [uint](([uint]$k[$i] -shl 16) -bor $k[($i + 1) % 8])
      }
    }

    $state.Carry = 0
    for ($i = 0; $i -lt 4; $i++) { [Rabbit]::NextState($state) }

    for ($i = 0; $i -lt 8; $i++) {
      $state.C[$i] = $state.C[$i] -bxor $state.X[($i + 4) % 8]
    }
  }

  hidden static [void] IvSetup([RabbitState]$state, [byte[]]$iv) {
    $iv0 = [uint](([uint]$iv[0]) -bor ([uint]$iv[1] -shl 8) -bor ([uint]$iv[2] -shl 16) -bor ([uint]$iv[3] -shl 24))
    $iv1 = [uint](([uint]$iv[4]) -bor ([uint]$iv[5] -shl 8) -bor ([uint]$iv[6] -shl 16) -bor ([uint]$iv[7] -shl 24))

    $state.C[0] = $state.C[0] -bxor $iv0
    $state.C[1] = $state.C[1] -bxor (($iv1 -band 0xFFFF0000) -bor ($iv0 -shr 16))
    $state.C[2] = $state.C[2] -bxor $iv1
    $state.C[3] = $state.C[3] -bxor ((($iv1 -band 0xFFFF) -shl 16) -bor ($iv0 -band 0xFFFF))
    $state.C[4] = $state.C[4] -bxor $iv0
    $state.C[5] = $state.C[5] -bxor (($iv1 -band 0xFFFF0000) -bor ($iv0 -shr 16))
    $state.C[6] = $state.C[6] -bxor $iv1
    $state.C[7] = $state.C[7] -bxor ((($iv1 -band 0xFFFF) -shl 16) -bor ($iv0 -band 0xFFFF))

    for ($i = 0; $i -lt 4; $i++) { [Rabbit]::NextState($state) }
  }

  hidden static [void] NextState([RabbitState]$state) {
    $A = @([uint]0x4D34D34D, [uint]0xD34D34D3, [uint]0x34D34D34, [uint]0x4D34D34D,
      [uint]0xD34D34D3, [uint]0x34D34D34, [uint]0x4D34D34D, [uint]0xD34D34D3)

    for ($i = 0; $i -lt 8; $i++) {
      $temp = [ulong]$state.C[$i] + $A[$i] + [ulong]$state.Carry
      $state.Carry = [uint]($temp -shr 32)
      $state.C[$i] = [uint]($temp -band 0xFFFFFFFF)
    }

    $g = [uint[]]::new(8)
    for ($i = 0; $i -lt 8; $i++) {
      $g[$i] = [Rabbit]::GFunc($state.X[$i], $state.C[$i])
    }

    $state.X[0] = [uint]($g[0] + [Rabbit]::RotateLeft($g[7], 16) + [Rabbit]::RotateLeft($g[6], 16))
    $state.X[1] = [uint]($g[1] + [Rabbit]::RotateLeft($g[0], 8) + $g[7])
    $state.X[2] = [uint]($g[2] + [Rabbit]::RotateLeft($g[1], 16) + [Rabbit]::RotateLeft($g[0], 16))
    $state.X[3] = [uint]($g[3] + [Rabbit]::RotateLeft($g[2], 8) + $g[1])
    $state.X[4] = [uint]($g[4] + [Rabbit]::RotateLeft($g[3], 16) + [Rabbit]::RotateLeft($g[2], 16))
    $state.X[5] = [uint]($g[5] + [Rabbit]::RotateLeft($g[4], 8) + $g[3])
    $state.X[6] = [uint]($g[6] + [Rabbit]::RotateLeft($g[5], 16) + [Rabbit]::RotateLeft($g[4], 16))
    $state.X[7] = [uint]($g[7] + [Rabbit]::RotateLeft($g[6], 8) + $g[5])
  }

  hidden static [uint] GFunc([uint]$x, [uint]$c) {
    $sum = ([ulong]$x + $c) -band 0xFFFFFFFF
    $square = $sum * $sum
    return [uint]($square -bxor ($square -shr 32))
  }

  hidden static [void] ExtractKeystream([RabbitState]$state, [byte[]]$output) {
    [Rabbit]::NextState($state)
    $s = [ushort[]]::new(8)
    $s[0] = [ushort]($state.X[0] -bxor ($state.X[5] -shr 16))
    $s[1] = [ushort](($state.X[0] -shr 16) -bxor ($state.X[3] -band 0xFFFF))
    $s[2] = [ushort]($state.X[2] -bxor ($state.X[7] -shr 16))
    $s[3] = [ushort](($state.X[2] -shr 16) -bxor ($state.X[5] -band 0xFFFF))
    $s[4] = [ushort]($state.X[4] -bxor ($state.X[1] -shr 16))
    $s[5] = [ushort](($state.X[4] -shr 16) -bxor ($state.X[7] -band 0xFFFF))
    $s[6] = [ushort]($state.X[6] -bxor ($state.X[3] -shr 16))
    $s[7] = [ushort](($state.X[6] -shr 16) -bxor ($state.X[1] -band 0xFFFF))

    for ($i = 0; $i -lt 8; $i++) {
      $output[$i * 2] = [byte]($s[$i] -band 0xFF)
      $output[$i * 2 + 1] = [byte]($s[$i] -shr 8)
    }
    [Array]::Reverse($output)
  }

  hidden static [uint] RotateLeft([uint]$value, [int]$bits) {
    return ($value -shl $bits) -bor ($value -shr (32 - $bits))
  }
}
