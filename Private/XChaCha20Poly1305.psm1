#!/usr/bin/env pwsh
using namespace System

using module ./Utilities.psm1
using module ./ChaCha20.psm1

class XChaCha20Poly1305 : CryptobaseUtils {
  static [int] $KeySize = 32
  static [int] $NonceSize = 24
  static [int] $TagSize = 16

  static [byte[]] HChaCha20([byte[]]$key, [byte[]]$nonce) {
    [uint[]]$state = [uint[]]::new(16)
    $state[0] = 0x61707865
    $state[1] = 0x3320646e
    $state[2] = 0x79622d32
    $state[3] = 0x6b206574
    for ($i = 0; $i -lt 8; $i++) { $state[4 + $i] = [System.BitConverter]::ToUInt32($key, $i * 4) }
    for ($i = 0; $i -lt 4; $i++) { $state[12 + $i] = [System.BitConverter]::ToUInt32($nonce, $i * 4) }

    for ($i = 0; $i -lt 10; $i++) {
      [ChaCha20Poly1305Pure]::QuarterRound($state, 0, 4, 8, 12)
      [ChaCha20Poly1305Pure]::QuarterRound($state, 1, 5, 9, 13)
      [ChaCha20Poly1305Pure]::QuarterRound($state, 2, 6, 10, 14)
      [ChaCha20Poly1305Pure]::QuarterRound($state, 3, 7, 11, 15)
      [ChaCha20Poly1305Pure]::QuarterRound($state, 0, 5, 10, 15)
      [ChaCha20Poly1305Pure]::QuarterRound($state, 1, 6, 11, 12)
      [ChaCha20Poly1305Pure]::QuarterRound($state, 2, 7, 8, 13)
      [ChaCha20Poly1305Pure]::QuarterRound($state, 3, 4, 9, 14)
    }

    [byte[]]$result = [byte[]]::new(32)
    [Array]::Copy([System.BitConverter]::GetBytes($state[0]), 0, $result, 0, 4)
    [Array]::Copy([System.BitConverter]::GetBytes($state[1]), 0, $result, 4, 4)
    [Array]::Copy([System.BitConverter]::GetBytes($state[2]), 0, $result, 8, 4)
    [Array]::Copy([System.BitConverter]::GetBytes($state[3]), 0, $result, 12, 4)
    [Array]::Copy([System.BitConverter]::GetBytes($state[12]), 0, $result, 16, 4)
    [Array]::Copy([System.BitConverter]::GetBytes($state[13]), 0, $result, 20, 4)
    [Array]::Copy([System.BitConverter]::GetBytes($state[14]), 0, $result, 24, 4)
    [Array]::Copy([System.BitConverter]::GetBytes($state[15]), 0, $result, 28, 4)
    return $result
  }

  static [byte[]] Encrypt([byte[]]$plaintextbytes, [byte[]]$key, [byte[]]$nonce) {
    return [XChaCha20Poly1305]::Encrypt($plaintextbytes, $key, $nonce, $null)
  }

  static [byte[]] Encrypt([byte[]]$plaintextbytes, [byte[]]$key, [byte[]]$nonce, [byte[]]$aad) {
    if ($null -eq $key -or $key.Length -ne [XChaCha20Poly1305]::KeySize) { throw [ArgumentException]::new('Key must be 32 bytes.') }
    if ($null -eq $nonce -or $nonce.Length -ne [XChaCha20Poly1305]::NonceSize) { throw [ArgumentException]::new('Nonce must be 24 bytes.') }
    
    $subKey = [XChaCha20Poly1305]::HChaCha20($key, $nonce[0..15])
    $nonce12 = [byte[]]@(0, 0, 0, 0) + $nonce[16..23]
    
    return [ChaCha20Poly1305Pure]::Encrypt($subKey, $nonce12, $plaintextbytes, $aad)
  }

  static [byte[]] Decrypt([byte[]]$inputbytes, [byte[]]$key, [byte[]]$nonce) {
    return [XChaCha20Poly1305]::Decrypt($inputbytes, $key, $nonce, $null)
  }

  static [byte[]] Decrypt([byte[]]$inputbytes, [byte[]]$key, [byte[]]$nonce, [byte[]]$aad) {
    if ($null -eq $key -or $key.Length -ne [XChaCha20Poly1305]::KeySize) { throw [ArgumentException]::new('Key must be 32 bytes.') }
    if ($null -eq $nonce -or $nonce.Length -ne [XChaCha20Poly1305]::NonceSize) { throw [ArgumentException]::new('Nonce must be 24 bytes.') }
    if ($inputbytes.Length -lt [XChaCha20Poly1305]::TagSize) { throw [ArgumentException]::new('Ciphertext too short.') }
    
    $subKey = [XChaCha20Poly1305]::HChaCha20($key, $nonce[0..15])
    $nonce12 = [byte[]]@(0, 0, 0, 0) + $nonce[16..23]
    
    return [ChaCha20Poly1305Pure]::Decrypt($subKey, $nonce12, $inputbytes, $aad)
  }

  static [byte[]] Authenticate([byte[]]$plaintextbytes, [byte[]]$key, [byte[]]$nonce) {
    return [XChaCha20Poly1305]::Authenticate($plaintextbytes, $key, $nonce, $null)
  }

  static [byte[]] Authenticate([byte[]]$plaintextbytes, [byte[]]$key, [byte[]]$nonce, [byte[]]$aad) {
    $ctWithTag = [XChaCha20Poly1305]::Encrypt($plaintextbytes, $key, $nonce, $aad)
    return $ctWithTag[($ctWithTag.Length - 16)..($ctWithTag.Length - 1)]
  }

  static [bool] Verify([byte[]]$plaintextbytes, [byte[]]$tag, [byte[]]$key, [byte[]]$nonce) {
    return [XChaCha20Poly1305]::Verify($plaintextbytes, $tag, $key, $nonce, $null)
  }

  static [bool] Verify([byte[]]$plaintextbytes, [byte[]]$tag, [byte[]]$key, [byte[]]$nonce, [byte[]]$aad) {
    try {
      $computedTag = [XChaCha20Poly1305]::Authenticate($plaintextbytes, $key, $nonce, $aad)
      if ($computedTag.Length -ne $tag.Length) { return $false }
      for ($i = 0; $i -lt $tag.Length; $i++) {
        if ($computedTag[$i] -ne $tag[$i]) { return $false }
      }
      return $true
    }
    catch {
      return $false
    }
  }
}
