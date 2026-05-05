#!/usr/bin/env pwsh
using namespace System.Security.Cryptography

using module ./Exceptions.psm1

# .SYNOPSIS
#     AES-CCM (Counter with CBC-MAC) authenticated encryption.
# .DESCRIPTION
#     AES-CCM is an authenticated encryption mode combining CTR mode
#     with CBC-MAC for authentication.
# .PARAMETER Key
#     The 128, 192, or 256-bit key.
# .PARAMETER Nonce
#     The nonce (13 bytes recommended).
# .PARAMETER Plaintext
#     The data to encrypt.
# .PARAMETER TagLength
#     The authentication tag length (4-16, default 8).
#   .PARAMETER AssociatedData
# Additional authenticated data.
# .OUTPUTS
# [byte[]] - The ciphertext with appended tag.
# .EXAMPLE
#   $key = [byte[]]::new(16)
#   $nonce = [byte[]]::new(13)
#   $ciphertext = [AesCCMCore]::Encrypt($key, $nonce, [System.Text.Encoding]::UTF8.GetBytes("Hello"))
# .NOTES
#   Requires .NET 8+ native implementation.
class AesCCMCore {
  hidden [byte[]] $_key
  hidden [byte[]] $_macKey

  AesCCMCore() {
    # Generate a random 32-byte key and a separate 32-byte MAC key
    $this._key = [byte[]]::new(32)
    $this._macKey = [byte[]]::new(32)
    [System.Security.Cryptography.RandomNumberGenerator]::Fill($this._key)
    [System.Security.Cryptography.RandomNumberGenerator]::Fill($this._macKey)
  }

  [byte[]] Encrypt([byte[]]$plainbytes) {
    # AES-CBC encrypt then HMAC-SHA256 authenticate (Encrypt-then-MAC)
    $aes = [System.Security.Cryptography.Aes]::Create()
    $aes.Key = $this._key
    $aes.GenerateIV()
    $encryptor = $aes.CreateEncryptor()
    $ct = $encryptor.TransformFinalBlock($plainbytes, 0, $plainbytes.Length)
    $payload = $aes.IV + $ct
    $hmac = [System.Security.Cryptography.HMACSHA256]::new($this._macKey)
    $tag = $hmac.ComputeHash($payload)
    return $payload + $tag
  }

  [byte[]] Decrypt([byte[]]$ciphertext) {
    # Validate HMAC tag first (16-byte IV + ciphertext + 32-byte tag)
    if ($ciphertext.Length -lt 48) { throw [System.Security.Cryptography.CryptographicException]::new('Ciphertext too short') }
    $tagOff = $ciphertext.Length - 32
    $payload = $ciphertext[0..($tagOff - 1)]
    $tag = $ciphertext[$tagOff..($ciphertext.Length - 1)]
    $hmac = [System.Security.Cryptography.HMACSHA256]::new($this._macKey)
    $expectedTag = $hmac.ComputeHash($payload)
    # Constant-time comparison
    [int]$diff = 0
    for ($i = 0; $i -lt 32; $i++) { $diff = $diff -bor ($tag[$i] -bxor $expectedTag[$i]) }
    if ($diff -ne 0) { throw [System.Security.Cryptography.CryptographicException]::new('Authentication tag mismatch') }
    $aes = [System.Security.Cryptography.Aes]::Create()
    $aes.Key = $this._key
    $aes.IV = $payload[0..15]
    $decryptor = $aes.CreateDecryptor()
    return $decryptor.TransformFinalBlock($payload, 16, $payload.Length - 16)
  }

  static [byte[]] Encrypt([byte[]]$Key, [byte[]]$Nonce, [byte[]]$plainbytes, [int]$TagLength = 8, [byte[]]$AssociatedData = $null) {
    if ($null -eq $Key) { throw [System.ArgumentNullException]::new("Key") }
    if ($null -eq $Nonce) { throw [System.ArgumentNullException]::new("Nonce") }
    if ($null -eq $plainbytes) { throw [System.ArgumentNullException]::new("Plaintext") }

    $ccmType = [System.type]::GetType("System.Security.Cryptography.AesCcm, System.Security.Cryptography")
    if ($null -ne $ccmType) {
      $ccm = $ccmType::new($Key)
      try {
        $ciphertext = [byte[]]::new($plainbytes.Length)
        $tag = [byte[]]::new($TagLength)
        $ccm.Encrypt($Nonce, $plainbytes, $ciphertext, $tag, $AssociatedData)

        $result = [byte[]]::new($ciphertext.Length + $TagLength)
        [Array]::Copy($ciphertext, 0, $result, 0, $ciphertext.Length)
        [Array]::Copy($tag, 0, $result, $ciphertext.Length, $TagLength)
        return $result
      }
      finally {
        $ccm.Dispose()
      }
    }

    throw [System.PlatformNotSupportedException]::new("AesCCM requires .NET 8+")
  }

  static [byte[]] Decrypt([byte[]]$Key, [byte[]]$Nonce, [byte[]]$Ciphertext, [int]$TagLength = 8, [byte[]]$AssociatedData = $null) {
    if ($null -eq $Key) { throw [System.ArgumentNullException]::new("Key") }
    if ($null -eq $Nonce) { throw [System.ArgumentNullException]::new("Nonce") }
    if ($null -eq $Ciphertext -or $Ciphertext.Length -lt $TagLength) { throw [System.ArgumentException]::new("Ciphertext too short") }

    $ccmType = [System.type]::GetType("System.Security.Cryptography.AesCcm, System.Security.Cryptography")
    if ($null -ne $ccmType) {
      $ccm = $ccmType::new($Key)
      try {
        $plainbytes = [byte[]]::new($Ciphertext.Length - $TagLength)
        $tag = [byte[]]::new($TagLength)
        [Array]::Copy($Ciphertext, $Ciphertext.Length - $TagLength, $tag, 0, $TagLength)
        $ccm.Decrypt($Nonce, $Ciphertext[0..($Ciphertext.Length - $TagLength - 1)], $plainbytes, $tag, $AssociatedData)
        return $plainbytes
      }
      catch {
        throw [System.Security.Cryptography.CryptographicException]::new("Decryption failed")
      }
      finally {
        $ccm.Dispose()
      }
    }

    throw [System.PlatformNotSupportedException]::new("AesCCM requires .NET 8+")
  }
}
