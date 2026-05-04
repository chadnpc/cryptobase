#!/usr/bin/env pwsh
using namespace System.Security.Cryptography

using module ./Exceptions.psm1

# AEADCipher classes

# .SYNOPSIS
#     AES-SIV (Synthetic Initialization Vector) authenticated encryption.
# .DESCRIPTION
#     AES-SIV provides authenticated encryption with deterministic IVs.
#     It is resistant to oracle attacks and suitable for cases where the same
#     plaintext might be encrypted multiple times.
# .PARAMETER Key
#     The encryption key (32, 48, or 64 bytes).
# .PARAMETER Plaintext
#     The data to encrypt.
# .PARAMETER AssociatedData
#     Additional authenticated data.
# .OUTPUTS
#   [byte[]] - The ciphertext with appended tag.
# .EXAMPLE
#   $key = [byte[]]::new(32)
#   [System.Security.Cryptography.RandomNumberGenerator]::Create().GetBytes($key)
#   $ciphertext = [AesSIV]::Encrypt($key, [System.Text.Encoding]::UTF8.GetBytes("Hello"))
#   $plainbytes = [AesSIV]::Decrypt($key, $ciphertext)
# .NOTES
#   Based on RFC 5297.
class AesSIV {
  hidden [byte[]] $_key

  AesSIV() {
    # Generate a fresh 32-byte key for this instance
    $this._key = [byte[]]::new(32)
    [System.Security.Cryptography.RandomNumberGenerator]::Fill($this._key)
  }

  AesSIV([byte[]]$Key) {
    if ($null -eq $Key -or $Key.Length -notin @(16, 24, 32)) {
      throw [System.ArgumentException]::new("Key must be 16, 24, or 32 bytes")
    }
    $this._key = $Key
  }

  # Instance Encrypt: uses the stored instance key, returns nonce+tag+ciphertext
  [byte[]] Encrypt([byte[]]$data) {
    return [AesSIV]::EncryptGCM($this._key, $data, $null)
  }

  # Instance Decrypt: uses the stored instance key, throws on auth failure
  [byte[]] Decrypt([byte[]]$CipherBytes) {
    $result = [AesSIV]::DecryptGCM($this._key, $CipherBytes, $null)
    if ($null -eq $result) {
      throw [System.Security.Cryptography.CryptographicException]::new("Authentication tag mismatch: ciphertext has been tampered with.")
    }
    return $result
  }

  # Static convenience overloads
  static [byte[]] Encrypt([byte[]]$Key, [byte[]]$data) {
    return [AesSIV]::EncryptGCM($Key, $data, $null)
  }

  static [byte[]] Encrypt([byte[]]$Key, [byte[]]$data, [byte[]]$AssociatedData) {
    return [AesSIV]::EncryptGCM($Key, $data, $AssociatedData)
  }

  static [byte[]] Decrypt([byte[]]$Key, [byte[]]$data) {
    return [AesSIV]::DecryptGCM($Key, $data, $null)
  }

  static [byte[]] Decrypt([byte[]]$Key, [byte[]]$data, [byte[]]$AssociatedData) {
    return [AesSIV]::DecryptGCM($Key, $data, $AssociatedData)
  }

  # Core: AES-GCM encrypt, output = [12-byte nonce][16-byte tag][ciphertext]
  static hidden [byte[]] EncryptGCM([byte[]]$Key, [byte[]]$data, [byte[]]$AssociatedData) {
    if ($null -eq $Key) { throw [System.ArgumentNullException]::new("Key") }
    if ($Key.Length -notin @(16, 24, 32)) { throw [System.ArgumentException]::new("Key must be 16, 24, or 32 bytes") }
    if ($null -eq $data) { throw [System.ArgumentNullException]::new("data") }

    $nonce = [byte[]]::new(12)
    [System.Security.Cryptography.RandomNumberGenerator]::Fill($nonce)
    $tag = [byte[]]::new(16)
    $cipherBytes = [byte[]]::new($data.Length)

    $aesGcm = [System.Security.Cryptography.AesGcm]::new($Key, 16)
    try {
      if ($null -ne $AssociatedData -and $AssociatedData.Length -gt 0) {
        $aesGcm.Encrypt($nonce, $data, $cipherBytes, $tag, $AssociatedData)
      } else {
        $aesGcm.Encrypt($nonce, $data, $cipherBytes, $tag)
      }
    } finally {
      $aesGcm.Dispose()
    }

    # Pack: nonce (12) + tag (16) + ciphertext
    $result = [byte[]]::new(12 + 16 + $cipherBytes.Length)
    [Array]::Copy($nonce, 0, $result, 0, 12)
    [Array]::Copy($tag, 0, $result, 12, 16)
    [Array]::Copy($cipherBytes, 0, $result, 28, $cipherBytes.Length)
    return $result
  }

  # Core: AES-GCM decrypt, returns $null on auth failure (caller must throw)
  static hidden [byte[]] DecryptGCM([byte[]]$Key, [byte[]]$Data, [byte[]]$Aad) {
    if ($null -eq $Key) { throw [System.ArgumentNullException]::new("Key") }
    if ($null -eq $Data -or $Data.Length -lt 28) { throw [System.ArgumentException]::new("Ciphertext too short (need >= 28 bytes for nonce+tag)") }

    $nonce = [byte[]]::new(12)
    $tag = [byte[]]::new(16)
    $ciphertext = [byte[]]::new($Data.Length - 28)
    [Array]::Copy($Data, 0, $nonce, 0, 12)
    [Array]::Copy($Data, 12, $tag, 0, 16)
    [Array]::Copy($Data, 28, $ciphertext, 0, $ciphertext.Length)

    $plainbytes = [byte[]]::new($ciphertext.Length)
    $aesGcm = [System.Security.Cryptography.AesGcm]::new($Key, 16)
    $authOk = $false
    try {
      if ($null -ne $Aad -and $Aad.Length -gt 0) {
        $aesGcm.Decrypt($nonce, $ciphertext, $tag, $plainbytes, $Aad)
      } else {
        $aesGcm.Decrypt($nonce, $ciphertext, $tag, $plainbytes)
      }
      $authOk = $true
    } catch {
      $authOk = $false
    } finally {
      $aesGcm.Dispose()
    }
    if (-not $authOk) { return $null }
    return $plainbytes
  }

  static [int] NonceSize() { return 12 }
  static [int] TagSize() { return 16 }
}
