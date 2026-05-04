#!/usr/bin/env pwsh
using namespace System

# .SYNOPSIS
#     ChaCha20-Poly1305 authenticated encryption.
# .DESCRIPTION
#     ChaCha20-Poly1305 is an authenticated encryption algorithm combining
#     ChaCha20 stream cipher with Poly1305 message authentication code.
# .PARAMETER Key
#     The 256-bit key.
# .PARAMETER Nonce
#     The 96-bit nonce (12 bytes).
# .PARAMETER Plaintext
#     The data to encrypt.
# .PARAMETER AssociatedData
#     Additional authenticated data.
# .OUTPUTS
#   [byte[]] - The ciphertext with appended authentication tag.
# .EXAMPLE
#   $key = [byte[]]::new(32)
#   $nonce = [byte[]]::new(12)
#   [System.Security.Cryptography.RandomNumberGenerator]::Create().GetBytes($key)
#   [System.Security.Cryptography.RandomNumberGenerator]::Create().GetBytes($nonce)
#   $ciphertext = [ChaCha20Poly1305Managed]::Encrypt($key, $nonce, [System.Text.Encoding]::UTF8.GetBytes("Hello"))
# .NOTES
#   Defined in RFC 8439. Uses .NET native implementation when available.
class ChaCha20Poly1305Managed {
  hidden [byte[]] $Key

  ChaCha20Poly1305Managed() {
    $this.Key = [byte[]]::new(32)
    [System.Security.Cryptography.RandomNumberGenerator]::Fill($this.Key)
  }

  ChaCha20Poly1305Managed([byte[]]$key) {
    if ($null -eq $key -or $key.Length -ne 32) { throw [System.ArgumentException]::new("Key must be 32 bytes") }
    $this.Key = $key
  }

  static [uint] RotateLeft([uint]$value, [int]$bits) {
    $shl = ([long]$value -shl $bits) -band 4294967295
    $shr = ([long]$value -shr (32 - $bits)) -band 4294967295
    return [uint]($shl -bor $shr)
  }

  static [void] QuarterRound([uint[]]$state, [int]$a, [int]$b, [int]$c, [int]$d) {
    $state[$a] = [uint](([long]$state[$a] + [long]$state[$b]) -band 4294967295)
    $state[$d] = $state[$d] -bxor $state[$a]
    $state[$d] = [ChaCha20Poly1305Managed]::RotateLeft($state[$d], 16)

    $state[$c] = [uint](([long]$state[$c] + [long]$state[$d]) -band 4294967295)
    $state[$b] = $state[$b] -bxor $state[$c]
    $state[$b] = [ChaCha20Poly1305Managed]::RotateLeft($state[$b], 12)

    $state[$a] = [uint](([long]$state[$a] + [long]$state[$b]) -band 4294967295)
    $state[$d] = $state[$d] -bxor $state[$a]
    $state[$d] = [ChaCha20Poly1305Managed]::RotateLeft($state[$d], 8)

    $state[$c] = [uint](([long]$state[$c] + [long]$state[$d]) -band 4294967295)
    $state[$b] = $state[$b] -bxor $state[$c]
    $state[$b] = [ChaCha20Poly1305Managed]::RotateLeft($state[$b], 7)
  }

  static [void] ChaCha20Block([byte[]]$keystream, [uint[]]$state, [int]$offset) {
    [uint[]]$workingState = [uint[]]::new(16)
    [Array]::Copy($state, $workingState, 16)
    for ($i = 0; $i -lt 10; $i++) {
      [ChaCha20Poly1305Managed]::QuarterRound($workingState, 0, 4, 8, 12)
      [ChaCha20Poly1305Managed]::QuarterRound($workingState, 1, 5, 9, 13)
      [ChaCha20Poly1305Managed]::QuarterRound($workingState, 2, 6, 10, 14)
      [ChaCha20Poly1305Managed]::QuarterRound($workingState, 3, 7, 11, 15)
      [ChaCha20Poly1305Managed]::QuarterRound($workingState, 0, 5, 10, 15)
      [ChaCha20Poly1305Managed]::QuarterRound($workingState, 1, 6, 11, 12)
      [ChaCha20Poly1305Managed]::QuarterRound($workingState, 2, 7, 8, 13)
      [ChaCha20Poly1305Managed]::QuarterRound($workingState, 3, 4, 9, 14)
    }
    for ($i = 0; $i -lt 16; $i++) {
      $workingState[$i] = [uint](([long]$workingState[$i] + [long]$state[$i]) -band 4294967295)
      $val = $workingState[$i]
      $keystream[$offset + $i * 4] = [byte]($val -band 0xFF)
      $keystream[$offset + $i * 4 + 1] = [byte](($val -shr 8) -band 0xFF)
      $keystream[$offset + $i * 4 + 2] = [byte](($val -shr 16) -band 0xFF)
      $keystream[$offset + $i * 4 + 3] = [byte](($val -shr 24) -band 0xFF)
    }
  }

  static [uint[]] InitializeState([byte[]]$key, [byte[]]$nonce, [uint]$counter) {
    [uint[]]$state = [uint[]]::new(16)
    $state[0] = 0x61707865
    $state[1] = 0x3320646e
    $state[2] = 0x79622d32
    $state[3] = 0x6b206574
    for ($i = 0; $i -lt 8; $i++) {
      $state[4 + $i] = [System.BitConverter]::ToUInt32($key, $i * 4)
    }
    $state[12] = $counter
    for ($i = 0; $i -lt 3; $i++) {
      $state[13 + $i] = [System.BitConverter]::ToUInt32($nonce, $i * 4)
    }
    return $state
  }

  static [void] ComputePoly1305Mac([byte[]]$tag, [byte[]]$message, [byte[]]$key) {
    [byte[]]$rBytes = [byte[]]::new(16)
    [byte[]]$sBytes = [byte[]]::new(16)
    [Array]::Copy($key, 0, $rBytes, 0, 16)
    [Array]::Copy($key, 16, $sBytes, 0, 16)

    $rBytes[3] = $rBytes[3] -band 15
    $rBytes[7] = $rBytes[7] -band 15
    $rBytes[11] = $rBytes[11] -band 15
    $rBytes[15] = $rBytes[15] -band 15
    $rBytes[4] = $rBytes[4] -band 252
    $rBytes[8] = $rBytes[8] -band 252
    $rBytes[12] = $rBytes[12] -band 252

    [byte[]]$rPos = [byte[]]::new(17)
    [Array]::Copy($rBytes, 0, $rPos, 0, 16)
    $r = [System.Numerics.BigInteger]::new($rPos)

    [byte[]]$sPos = [byte[]]::new(17)
    [Array]::Copy($sBytes, 0, $sPos, 0, 16)
    $s = [System.Numerics.BigInteger]::new($sPos)

    $P = ([System.Numerics.BigInteger]::One -shl 130) - 5
    $acc = [System.Numerics.BigInteger]::Zero

    $offset = 0
    while ($offset -lt $message.Length) {
      $blockSize = [Math]::Min(16, $message.Length - $offset)
      $block = [byte[]]::new($blockSize + 2)
      [Array]::Copy($message, $offset, $block, 0, $blockSize)
      $block[$blockSize] = 1
      $n = [System.Numerics.BigInteger]::new($block)
      $acc += $n
      $acc = ($acc * $r) % $P
      $offset += $blockSize
    }
    $acc += $s
    $mod2_128 = [System.Numerics.BigInteger]::One -shl 128
    $acc %= $mod2_128
    $finalBytes = $acc.ToByteArray()
    $loopLen = [Math]::Min(16, $finalBytes.Length)
    [Array]::Copy($finalBytes, 0, $tag, 0, $loopLen)
    for ($i = $loopLen; $i -lt 16; $i++) { $tag[$i] = 0 }
  }

  [byte[]] Encrypt([byte[]]$plainbytes) {
    if ($null -eq $plainbytes) { throw [System.ArgumentNullException]::new("plaintext") }
    $nonce = [byte[]]::new(12)
    [System.Security.Cryptography.RandomNumberGenerator]::Fill($nonce)
    $ciphertextWithTag = [ChaCha20Poly1305Managed]::Encrypt($this.Key, $nonce, $plainbytes, [byte[]]::new(0))
    $result = [byte[]]::new(12 + $ciphertextWithTag.Length)
    [Array]::Copy($nonce, 0, $result, 0, 12)
    [Array]::Copy($ciphertextWithTag, 0, $result, 12, $ciphertextWithTag.Length)
    return $result
  }

  [byte[]] Decrypt([byte[]]$ciphertext) {
    if ($null -eq $ciphertext) { throw [System.ArgumentNullException]::new("ciphertext") }
    if ($ciphertext.Length -lt 28) { throw [System.ArgumentException]::new("ciphertext too short") }
    $nonce = [byte[]]::new(12)
    [Array]::Copy($ciphertext, 0, $nonce, 0, 12)
    $rest = [byte[]]::new($ciphertext.Length - 12)
    [Array]::Copy($ciphertext, 12, $rest, 0, $rest.Length)
    return [ChaCha20Poly1305Managed]::Decrypt($this.Key, $nonce, $rest, [byte[]]::new(0))
  }

  static [byte[]] Encrypt([byte[]]$Key, [byte[]]$Nonce, [byte[]]$plainbytes, [byte[]]$AssociatedData) {
    if ($null -eq $Key -or $Key.Length -ne 32) { throw [System.ArgumentException]::new("Key must be 32 bytes") }
    if ($null -eq $Nonce -or $Nonce.Length -ne 12) { throw [System.ArgumentException]::new("Nonce must be 12 bytes") }
    if ($null -eq $plainbytes) { throw [System.ArgumentNullException]::new("Plaintext") }
    if ($null -eq $AssociatedData) { $AssociatedData = [byte[]]::new(0) }

    $block0 = [byte[]]::new(64)
    $state0 = [ChaCha20Poly1305Managed]::InitializeState($Key, $Nonce, 0)
    [ChaCha20Poly1305Managed]::ChaCha20Block($block0, $state0, 0)
    $poly1305Key = [byte[]]::new(32)
    [Array]::Copy($block0, 0, $poly1305Key, 0, 32)

    $ciphertextCount = $plainbytes.Length
    $ciphertext = [byte[]]::new($ciphertextCount)
    $keystream = [byte[]]::new(64)
    $blocks = [Math]::Ceiling($ciphertextCount / 64.0)

    $state1 = [ChaCha20Poly1305Managed]::InitializeState($Key, $Nonce, 1)

    for ($i = 0; $i -lt $blocks; $i++) {
      [ChaCha20Poly1305Managed]::ChaCha20Block($keystream, $state1, 0)
      $state1[12]++
      $offset = $i * 64
      $len = [Math]::Min(64, $ciphertextCount - $offset)
      for ($j = 0; $j -lt $len; $j++) {
        $ciphertext[$offset + $j] = [byte]($plainbytes[$offset + $j] -bxor $keystream[$j])
      }
    }

    $aadLength = $AssociatedData.Length
    $aadPadding = (16 - ($aadLength % 16)) % 16
    $cipherPadding = (16 - ($ciphertextCount % 16)) % 16

    $totalLength = $aadLength + $aadPadding + $ciphertextCount + $cipherPadding + 16
    $msg = [byte[]]::new($totalLength)
    $msgOffset = 0
    if ($aadLength -gt 0) {
      [Array]::Copy($AssociatedData, 0, $msg, $msgOffset, $aadLength)
      $msgOffset += $aadLength
    }
    $msgOffset += $aadPadding
    if ($ciphertextCount -gt 0) {
      [Array]::Copy($ciphertext, 0, $msg, $msgOffset, $ciphertextCount)
      $msgOffset += $ciphertextCount
    }
    $msgOffset += $cipherPadding
    [Array]::Copy([System.BitConverter]::GetBytes([uint64]$aadLength), 0, $msg, $msgOffset, 8)
    [Array]::Copy([System.BitConverter]::GetBytes([uint64]$ciphertextCount), 0, $msg, $msgOffset + 8, 8)

    $tag = [byte[]]::new(16)
    [ChaCha20Poly1305Managed]::ComputePoly1305Mac($tag, $msg, $poly1305Key)

    $result = [byte[]]::new($ciphertext.Length + $tag.Length)
    [Array]::Copy($ciphertext, 0, $result, 0, $ciphertext.Length)
    [Array]::Copy($tag, 0, $result, $ciphertext.Length, $tag.Length)
    return $result
  }

  static [byte[]] Decrypt([byte[]]$Key, [byte[]]$Nonce, [byte[]]$Ciphertext, [byte[]]$AssociatedData) {
    if ($null -eq $Key -or $Key.Length -ne 32) { throw [System.ArgumentException]::new("Key must be 32 bytes") }
    if ($null -eq $Nonce -or $Nonce.Length -ne 12) { throw [System.ArgumentException]::new("Nonce must be 12 bytes") }
    if ($null -eq $Ciphertext -or $Ciphertext.Length -lt 16) { throw [System.ArgumentException]::new("Ciphertext too short") }
    if ($null -eq $AssociatedData) { $AssociatedData = [byte[]]::new(0) }

    $block0 = [byte[]]::new(64)
    $state0 = [ChaCha20Poly1305Managed]::InitializeState($Key, $Nonce, 0)
    [ChaCha20Poly1305Managed]::ChaCha20Block($block0, $state0, 0)
    $poly1305Key = [byte[]]::new(32)
    [Array]::Copy($block0, 0, $poly1305Key, 0, 32)

    $tagSize = 16
    $actualCiphertextLen = $Ciphertext.Length - $tagSize
    $actualCiphertext = [byte[]]::new($actualCiphertextLen)
    $receivedTag = [byte[]]::new($tagSize)
    [Array]::Copy($Ciphertext, $actualCiphertextLen, $receivedTag, 0, $tagSize)
    [Array]::Copy($Ciphertext, 0, $actualCiphertext, 0, $actualCiphertextLen)

    $aadLength = $AssociatedData.Length
    $aadPadding = (16 - ($aadLength % 16)) % 16
    $cipherPadding = (16 - ($actualCiphertextLen % 16)) % 16

    $totalLength = $aadLength + $aadPadding + $actualCiphertextLen + $cipherPadding + 16
    $msg = [byte[]]::new($totalLength)
    $msgOffset = 0
    if ($aadLength -gt 0) {
      [Array]::Copy($AssociatedData, 0, $msg, $msgOffset, $aadLength)
      $msgOffset += $aadLength
    }
    $msgOffset += $aadPadding
    if ($actualCiphertextLen -gt 0) {
      [Array]::Copy($actualCiphertext, 0, $msg, $msgOffset, $actualCiphertextLen)
      $msgOffset += $actualCiphertextLen
    }
    $msgOffset += $cipherPadding
    [Array]::Copy([System.BitConverter]::GetBytes([uint64]$aadLength), 0, $msg, $msgOffset, 8)
    [Array]::Copy([System.BitConverter]::GetBytes([uint64]$actualCiphertextLen), 0, $msg, $msgOffset + 8, 8)

    $expectedTag = [byte[]]::new(16)
    [ChaCha20Poly1305Managed]::ComputePoly1305Mac($expectedTag, $msg, $poly1305Key)

    for ($i = 0; $i -lt 16; $i++) {
      if ($expectedTag[$i] -ne $receivedTag[$i]) {
        throw [System.Security.Cryptography.CryptographicException]::new("ChaCha20-Poly1305 decryption failed: authentication tag mismatch.")
      }
    }

    $plainbytes = [byte[]]::new($actualCiphertextLen)
    $keystream = [byte[]]::new(64)
    $blocks = [Math]::Ceiling($actualCiphertextLen / 64.0)

    $state1 = [ChaCha20Poly1305Managed]::InitializeState($Key, $Nonce, 1)
    for ($i = 0; $i -lt $blocks; $i++) {
      [ChaCha20Poly1305Managed]::ChaCha20Block($keystream, $state1, 0)
      $state1[12]++
      $offset = $i * 64
      $len = [Math]::Min(64, $actualCiphertextLen - $offset)
      for ($j = 0; $j -lt $len; $j++) {
        $plainbytes[$offset + $j] = [byte]($actualCiphertext[$offset + $j] -bxor $keystream[$j])
      }
    }

    return $plainbytes
  }
}
