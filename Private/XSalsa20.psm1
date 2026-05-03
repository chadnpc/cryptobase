#!/usr/bin/env pwsh
using namespace System

using module ./Utilities.psm1

class XSalsa20 : CryptobaseUtils {
  static [uint[]] $Constants = @([uint]0x61707865, [uint]0x3320646e, [uint]0x79622d32, [uint]0x6b206574)
  static [int] $KEY_SIZE = 32
  static [int] $NONCE_SIZE = 24
  static [int] $BLOCK_SIZE = 64

  static [byte[]] Encrypt([byte[]]$inputbytes, [byte[]]$key, [byte[]]$nonce) { return [XSalsa20]::Transform($inputbytes, $key, $nonce, 0) }
  static [byte[]] Encrypt([byte[]]$inputbytes, [byte[]]$key, [byte[]]$nonce, [uint]$counter = 0) { return [XSalsa20]::Transform($inputbytes, $key, $nonce, $counter) }
  static [byte[]] Decrypt([byte[]]$inputbytes, [byte[]]$key, [byte[]]$nonce) { return [XSalsa20]::Transform($inputbytes, $key, $nonce, 0) }
  static [byte[]] Decrypt([byte[]]$inputbytes, [byte[]]$key, [byte[]]$nonce, [uint]$counter = 0) { return [XSalsa20]::Transform($inputbytes, $key, $nonce, $counter) }

  static [byte[]] Transform([byte[]]$inputbytes, [byte[]]$key, [byte[]]$nonce, [uint]$counter = 0) {
    if ($null -eq $key -or $key.Length -ne [XSalsa20]::KEY_SIZE) { throw [ArgumentException]::new("Key must be 32 bytes.") }
    if ($null -eq $nonce -or $nonce.Length -ne [XSalsa20]::NONCE_SIZE) { throw [ArgumentException]::new("Nonce must be 24 bytes.") }

    $derivedKey = [byte[]]::new(32)
    $derivedNonce = [byte[]]::new(8)
    [XSalsa20]::DeriveKeyAndNonce($derivedKey, $derivedNonce, $key, $nonce)

    $output = [byte[]]::new($inputbytes.Length)
    $state = [uint[]]::new(16)
    $keystream = [byte[]]::new([XSalsa20]::BLOCK_SIZE)

    $blocks = [int][Math]::Ceiling($inputbytes.Length / [XSalsa20]::BLOCK_SIZE)
    for ($b = 0; $b -lt $blocks; $b++) {
      $effectiveCounter = $counter + [uint]$b
      $start = $b * [XSalsa20]::BLOCK_SIZE
      $len = [Math]::Min([XSalsa20]::BLOCK_SIZE, $inputbytes.Length - $start)

      [XSalsa20]::InitializeSalsa20State($state, $derivedKey, $derivedNonce, $effectiveCounter)
      [XSalsa20]::GenerateKeystreamBlock($keystream, $state)

      for ($i = 0; $i -lt $len; $i++) {
        $output[$start + $i] = [byte]($inputbytes[$start + $i] -bxor $keystream[$i])
      }
    }

    return $output
  }

  hidden static [void] DeriveKeyAndNonce([byte[]]$derivedKey, [byte[]]$derivedNonce, [byte[]]$key, [byte[]]$nonce) {
    $hsalsaNonce = [byte[]]::new(16)
    [Array]::Copy($nonce, 0, $hsalsaNonce, 0, 16)
    [XSalsa20]::HSalsa20($derivedKey, $key, $hsalsaNonce)
    [Array]::Copy($nonce, 16, $derivedNonce, 0, 8)
  }

  hidden static [void] HSalsa20([byte[]]$output, [byte[]]$key, [byte[]]$nonce) {
    $state = [uint[]]::new(16)
    $state[0] = [XSalsa20]::Constants[0]
    $state[1] = [XSalsa20]::Constants[1]
    $state[2] = [XSalsa20]::Constants[2]
    $state[3] = [XSalsa20]::Constants[3]
    for ($i = 0; $i -lt 8; $i++) { $state[4 + $i] = [XSalsa20]::ReadUInt32LE($key, $i * 4) }
    for ($i = 0; $i -lt 4; $i++) { $state[12 + $i] = [XSalsa20]::ReadUInt32LE($nonce, $i * 4) }

    for ($i = 0; $i -lt 10; $i++) {
      [XSalsa20]::QuarterRound($state, 0, 4, 8, 12)
      [XSalsa20]::QuarterRound($state, 5, 9, 13, 1)
      [XSalsa20]::QuarterRound($state, 10, 14, 2, 6)
      [XSalsa20]::QuarterRound($state, 15, 3, 7, 11)
      [XSalsa20]::QuarterRound($state, 0, 1, 2, 3)
      [XSalsa20]::QuarterRound($state, 5, 6, 7, 4)
      [XSalsa20]::QuarterRound($state, 10, 11, 8, 9)
      [XSalsa20]::QuarterRound($state, 15, 12, 13, 14)
    }

    [XSalsa20]::WriteUInt32LE($output, 0, $state[0])
    [XSalsa20]::WriteUInt32LE($output, 4, $state[5])
    [XSalsa20]::WriteUInt32LE($output, 8, $state[10])
    [XSalsa20]::WriteUInt32LE($output, 12, $state[15])
    [XSalsa20]::WriteUInt32LE($output, 16, $state[6])
    [XSalsa20]::WriteUInt32LE($output, 20, $state[7])
    [XSalsa20]::WriteUInt32LE($output, 24, $state[8])
    [XSalsa20]::WriteUInt32LE($output, 28, $state[9])
  }

  hidden static [void] InitializeSalsa20State([uint[]]$state, [byte[]]$key, [byte[]]$nonce, [uint]$counter) {
    $state[0] = [XSalsa20]::Constants[0]
    $state[1] = [XSalsa20]::Constants[1]
    $state[2] = [XSalsa20]::Constants[2]
    $state[3] = [XSalsa20]::Constants[3]
    for ($i = 0; $i -lt 4; $i++) { $state[4 + $i] = [XSalsa20]::ReadUInt32LE($key, $i * 4) }
    $state[8] = $counter
    $state[9] = 0
    $state[10] = [XSalsa20]::ReadUInt32LE($nonce, 0)
    $state[11] = [XSalsa20]::ReadUInt32LE($nonce, 4)
    for ($i = 0; $i -lt 4; $i++) { $state[12 + $i] = [XSalsa20]::ReadUInt32LE($key, ($i + 4) * 4) }
  }

  hidden static [void] GenerateKeystreamBlock([byte[]]$keystream, [uint[]]$state) {
    $working = [uint[]]::new(16)
    [Array]::Copy($state, $working, 16)

    for ($i = 0; $i -lt 10; $i++) {
      [XSalsa20]::QuarterRound($working, 0, 4, 8, 12)
      [XSalsa20]::QuarterRound($working, 5, 9, 13, 1)
      [XSalsa20]::QuarterRound($working, 10, 14, 2, 6)
      [XSalsa20]::QuarterRound($working, 15, 3, 7, 11)
      [XSalsa20]::QuarterRound($working, 0, 1, 2, 3)
      [XSalsa20]::QuarterRound($working, 5, 6, 7, 4)
      [XSalsa20]::QuarterRound($working, 10, 11, 8, 9)
      [XSalsa20]::QuarterRound($working, 15, 12, 13, 14)
    }

    for ($i = 0; $i -lt 16; $i++) {
      [XSalsa20]::WriteUInt32LE($keystream, $i * 4, [uint](([uint64]$working[$i] + $state[$i]) -band 0xFFFFFFFFuL))
    }
  }

  hidden static [void] QuarterRound([uint[]]$state, [int]$a, [int]$b, [int]$c, [int]$d) {
    $state[$b] = $state[$b] -bxor [XSalsa20]::RotateLeft([uint](([uint64]$state[$a] + $state[$d]) -band 0xFFFFFFFFuL), 7)
    $state[$c] = $state[$c] -bxor [XSalsa20]::RotateLeft([uint](([uint64]$state[$b] + $state[$a]) -band 0xFFFFFFFFuL), 9)
    $state[$d] = $state[$d] -bxor [XSalsa20]::RotateLeft([uint](([uint64]$state[$c] + $state[$b]) -band 0xFFFFFFFFuL), 13)
    $state[$a] = $state[$a] -bxor [XSalsa20]::RotateLeft([uint](([uint64]$state[$d] + $state[$c]) -band 0xFFFFFFFFuL), 18)
  }

  hidden static [uint] RotateLeft([uint]$value, [int]$bits) {
    return ($value -shl $bits) -bor ($value -shr (32 - $bits))
  }

  hidden static [uint] ReadUInt32LE([byte[]]$buf, [int]$off) {
    return [uint](([uint]$buf[$off]) -bor ([uint]$buf[$off + 1] -shl 8) -bor ([uint]$buf[$off + 2] -shl 16) -bor ([uint]$buf[$off + 3] -shl 24))
  }

  hidden static [void] WriteUInt32LE([byte[]]$buf, [int]$off, [uint]$val) {
    $buf[$off] = [byte]($val -band 0xFF)
    $buf[$off + 1] = [byte](($val -shr 8) -band 0xFF)
    $buf[$off + 2] = [byte](($val -shr 16) -band 0xFF)
    $buf[$off + 3] = [byte](($val -shr 24) -band 0xFF)
  }
}