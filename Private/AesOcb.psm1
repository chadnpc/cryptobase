#!/usr/bin/env pwsh
using namespace System
using namespace System.Security.Cryptography

using module ./Utilities.psm1

class AesOcbCore : CryptobaseUtils {
  static [int] $BlockSize = 16
  static [int] $MinNonceSize = 1
  static [int] $MaxNonceSize = 15
  static [int] $DefaultNonceSize = 12
  static [int] $TagSize = 16

  static [void] ValidateParameters([byte[]]$Key, [byte[]]$Nonce) {
    if ($null -eq $Key) { throw [ArgumentNullException]::new('Key') }
    if ($null -eq $Nonce) { throw [ArgumentNullException]::new('Nonce') }
    if (@(16, 24, 32) -notcontains $Key.Length) {
      throw [ArgumentException]::new("Key must be 16, 24, or 32 bytes, but was $($Key.Length) bytes", 'Key')
    }
    if ($Nonce.Length -lt [AesOcbCore]::MinNonceSize -or $Nonce.Length -gt [AesOcbCore]::MaxNonceSize) {
      throw [ArgumentException]::new("Nonce size must be between 1 and 15 bytes, but was $($Nonce.Length) bytes", 'Nonce')
    }
  }

  static [void] Double([byte[]]$Output, [byte[]]$inputbytes) {
    [int]$carry = 0
    for ($i = 15; $i -ge 0; $i--) {
      [int]$newCarry = ($inputbytes[$i] -band 0x80) -shr 7
      $Output[$i] = [byte](($inputbytes[$i] -shl 1) -bor $carry)
      $carry = $newCarry
    }
    if ($carry -ne 0) {
      $Output[15] = $Output[15] -bxor 0x87
    }
  }

  static [void] GetL([byte[]]$Li, [byte[]]$LStar, [int]$i) {
    [int]$ntz = 0
    [int]$temp = $i
    while ($temp -gt 0 -and ($temp -band 1) -eq 0) {
      $ntz++
      $temp = $temp -shr 1
    }
    [Array]::Copy($LStar, 0, $Li, 0, 16)
    for ($j = 0; $j -lt $ntz; $j++) {
      [AesOcbCore]::Double($Li, $Li)
    }
  }

  static [void] XorBlock([byte[]]$Output, [byte[]]$A, [byte[]]$B) {
    for ($i = 0; $i -lt 16; $i++) {
      $Output[$i] = [byte]($A[$i] -bxor $B[$i])
    }
  }

  static [void] EncryptBlock([object]$Encryptor, [byte[]]$Output, [byte[]]$inputbytes, [byte[]]$InBuf, [byte[]]$OutBuf) {
    [Array]::Copy($inputbytes, 0, $InBuf, 0, 16)
    [void]$Encryptor.TransformBlock($InBuf, 0, 16, $OutBuf, 0)
    [Array]::Copy($OutBuf, 0, $Output, 0, 16)
  }

  static [void] DecryptBlock([object]$Decryptor, [byte[]]$Output, [byte[]]$inputbytes, [byte[]]$InBuf, [byte[]]$OutBuf) {
    [Array]::Copy($inputbytes, 0, $InBuf, 0, 16)
    [void]$Decryptor.TransformBlock($InBuf, 0, 16, $OutBuf, 0)
    [Array]::Copy($OutBuf, 0, $Output, 0, 16)
  }

  static [void] InitializeOffset([object]$Encryptor, [byte[]]$Offset, [byte[]]$Nonce, [byte[]]$LDollar, [byte[]]$InBuf, [byte[]]$OutBuf) {
    $nonceBlock = [byte[]]::new(16)
    $tagBits = ([AesOcbCore]::TagSize * 8) % 128
    $nonceBlock[0] = [byte]($tagBits -shl 1)
    $nonceStart = 16 - $Nonce.Length
    $nonceBlock[$nonceStart - 1] = $nonceBlock[$nonceStart - 1] -bor 0x01
    [Array]::Copy($Nonce, 0, $nonceBlock, $nonceStart, $Nonce.Length)

    [int]$bottom = $nonceBlock[15] -band 0x3F
    $nonceBlock[15] = $nonceBlock[15] -band 0xC0

    $ktop = [byte[]]::new(16)
    [AesOcbCore]::EncryptBlock($Encryptor, $ktop, $nonceBlock, $InBuf, $OutBuf)

    $stretch = [byte[]]::new(24)
    [Array]::Copy($ktop, 0, $stretch, 0, 16)
    for ($i = 0; $i -lt 8; $i++) {
      $stretch[16 + $i] = [byte]($ktop[$i] -bxor $ktop[$i + 1])
    }

    [int]$byteOffset = $bottom / 8
    [int]$bitShift = $bottom % 8
    if ($bitShift -eq 0) {
      [Array]::Copy($stretch, $byteOffset, $Offset, 0, 16)
    }
    else {
      for ($i = 0; $i -lt 16; $i++) {
        $Offset[$i] = [byte](($stretch[$byteOffset + $i] -shl $bitShift) -bor ($stretch[$byteOffset + $i + 1] -shr (8 - $bitShift)))
      }
    }
    [AesOcbCore]::XorBlock($Offset, $Offset, $LDollar)
  }

  static [void] ProcessAssociatedData([object]$Encryptor, [byte[]]$Auth, [byte[]]$AssociatedData, [byte[]]$LDollar, [byte[]]$InBuf, [byte[]]$OutBuf) {
    if ($null -eq $AssociatedData -or $AssociatedData.Length -eq 0) {
      [Array]::Clear($Auth, 0, 16)
      return
    }

    $lStar = [byte[]]::new(16)
    $zeros = [byte[]]::new(16)
    [AesOcbCore]::EncryptBlock($Encryptor, $lStar, $zeros, $InBuf, $OutBuf)

    $offset = [byte[]]::new(16)
    $sum = [byte[]]::new(16)
    $fullBlocks = [Math]::Floor($AssociatedData.Length / 16)
    $tempBlock = [byte[]]::new(16)
    $li = [byte[]]::new(16)
    $encrypted = [byte[]]::new(16)

    for ($i = 0; $i -lt $fullBlocks; $i++) {
      [Array]::Copy($AssociatedData, $i * 16, $tempBlock, 0, 16)
      [AesOcbCore]::GetL($li, $lStar, $i + 1)
      [AesOcbCore]::XorBlock($offset, $offset, $li)
      [AesOcbCore]::XorBlock($tempBlock, $tempBlock, $offset)
      [AesOcbCore]::EncryptBlock($Encryptor, $encrypted, $tempBlock, $InBuf, $OutBuf)
      [AesOcbCore]::XorBlock($sum, $sum, $encrypted)
    }

    $remaining = $AssociatedData.Length % 16
    if ($remaining -gt 0) {
      [AesOcbCore]::XorBlock($offset, $offset, $lStar)
      [Array]::Clear($tempBlock, 0, 16)
      [Array]::Copy($AssociatedData, $fullBlocks * 16, $tempBlock, 0, $remaining)
      $tempBlock[$remaining] = 0x80
      [AesOcbCore]::XorBlock($tempBlock, $tempBlock, $offset)
      [AesOcbCore]::EncryptBlock($Encryptor, $encrypted, $tempBlock, $InBuf, $OutBuf)
      [AesOcbCore]::XorBlock($sum, $sum, $encrypted)
    }
    [Array]::Copy($sum, 0, $Auth, 0, 16)
  }

  static [void] ComputeTag([object]$Encryptor, [byte[]]$Tag, [byte[]]$Offset, [byte[]]$Checksum, [byte[]]$LDollar, [byte[]]$AssociatedData, [byte[]]$InBuf, [byte[]]$OutBuf) {
    $auth = [byte[]]::new(16)
    [AesOcbCore]::ProcessAssociatedData($Encryptor, $auth, $AssociatedData, $LDollar, $InBuf, $OutBuf)

    $temp = [byte[]]::new(16)
    [AesOcbCore]::XorBlock($temp, $Checksum, $Offset)
    [AesOcbCore]::XorBlock($temp, $temp, $LDollar)

    $tagFull = [byte[]]::new(16)
    [AesOcbCore]::EncryptBlock($Encryptor, $tagFull, $temp, $InBuf, $OutBuf)
    [AesOcbCore]::XorBlock($tagFull, $tagFull, $auth)
    [Array]::Copy($tagFull, 0, $Tag, 0, [AesOcbCore]::TagSize)
  }

  static [bool] ConstantTimeEquals([byte[]]$A, [byte[]]$B) {
    if ($A.Length -ne $B.Length) { return $false }
    [int]$diff = 0
    for ($i = 0; $i -lt $A.Length; $i++) {
      $diff = $diff -bor ($A[$i] -bxor $B[$i])
    }
    return $diff -eq 0
  }

  static [hashtable] Encrypt([byte[]]$Plaintext, [byte[]]$Key) {
    return [AesOcbCore]::Encrypt($Plaintext, $Key, $null, $null, $false)
  }

  static [hashtable] Encrypt([byte[]]$Plaintext, [byte[]]$Key, [byte[]]$Nonce) {
    return [AesOcbCore]::Encrypt($Plaintext, $Key, $Nonce, $null, $false)
  }

  static [hashtable] Encrypt([byte[]]$Plaintext, [byte[]]$Key, [byte[]]$Nonce, [byte[]]$AssociatedData) {
    return [AesOcbCore]::Encrypt($Plaintext, $Key, $Nonce, $AssociatedData, $false)
  }

  static [hashtable] Encrypt([byte[]]$Plaintext, [byte[]]$Key, [byte[]]$Nonce, [byte[]]$AssociatedData, [bool]$DeterministicMode) {
    if ($null -eq $Plaintext) { throw [ArgumentNullException]::new('Plaintext') }
    if ($null -eq $Nonce -or $Nonce.Length -eq 0) {
      $Nonce = [byte[]]::new([AesOcbCore]::DefaultNonceSize)
      if (-not $DeterministicMode) {
        [System.Security.Cryptography.RandomNumberGenerator]::Fill($Nonce)
      }
    }
    if ($null -eq $AssociatedData) { $AssociatedData = [byte[]]::new(0) }
    [AesOcbCore]::ValidateParameters($Key, $Nonce)

    $aes = [System.Security.Cryptography.Aes]::Create()
    $aes.Key = $Key
    $aes.Mode = [System.Security.Cryptography.CipherMode]::ECB
    $aes.Padding = [System.Security.Cryptography.PaddingMode]::None

    $encryptor = $aes.CreateEncryptor()
    $inBuf = [byte[]]::new(16)
    $outBuf = [byte[]]::new(16)

    $lStar = [byte[]]::new(16)
    $zeros = [byte[]]::new(16)
    [AesOcbCore]::EncryptBlock($encryptor, $lStar, $zeros, $inBuf, $outBuf)

    $lDollar = [byte[]]::new(16)
    [AesOcbCore]::Double($lDollar, $lStar)

    $offset = [byte[]]::new(16)
    [AesOcbCore]::InitializeOffset($encryptor, $offset, $Nonce, $lDollar, $inBuf, $outBuf)

    $checksum = [byte[]]::new(16)
    $fullBlocks = [Math]::Floor($Plaintext.Length / 16)
    $ciphertext = [byte[]]::new($Plaintext.Length + [AesOcbCore]::TagSize)

    $li = [byte[]]::new(16)
    $tempBlock = [byte[]]::new(16)
    $outBlock = [byte[]]::new(16)

    for ($i = 0; $i -lt $fullBlocks; $i++) {
      [Array]::Copy($Plaintext, $i * 16, $tempBlock, 0, 16)
      [AesOcbCore]::GetL($li, $lStar, $i + 1)
      [AesOcbCore]::XorBlock($offset, $offset, $li)
      [AesOcbCore]::XorBlock($checksum, $checksum, $tempBlock)
      [AesOcbCore]::XorBlock($tempBlock, $tempBlock, $offset)
      [AesOcbCore]::EncryptBlock($encryptor, $outBlock, $tempBlock, $inBuf, $outBuf)
      [AesOcbCore]::XorBlock($outBlock, $outBlock, $offset)
      [Array]::Copy($outBlock, 0, $ciphertext, $i * 16, 16)
    }

    $remaining = $Plaintext.Length % 16
    if ($remaining -gt 0) {
      [AesOcbCore]::XorBlock($offset, $offset, $lStar)
      $pad = [byte[]]::new(16)
      [AesOcbCore]::EncryptBlock($encryptor, $pad, $offset, $inBuf, $outBuf)

      for ($i = 0; $i -lt $remaining; $i++) {
        $ciphertext[$fullBlocks * 16 + $i] = [byte]($Plaintext[$fullBlocks * 16 + $i] -bxor $pad[$i])
        $checksum[$i] = [byte]($checksum[$i] -bxor $Plaintext[$fullBlocks * 16 + $i])
      }
      $checksum[$remaining] = [byte]($checksum[$remaining] -bxor 0x80)
    }

    $tag = [byte[]]::new(16)
    [AesOcbCore]::ComputeTag($encryptor, $tag, $offset, $checksum, $lDollar, $AssociatedData, $inBuf, $outBuf)
    [Array]::Copy($tag, 0, $ciphertext, $Plaintext.Length, 16)

    $encryptor.Dispose()
    $aes.Dispose()

    return @{ Ciphertext = $ciphertext; Nonce = $Nonce; TagSize = [AesOcbCore]::TagSize }
  }

  static [byte[]] Decrypt([byte[]]$Ciphertext, [byte[]]$Key, [byte[]]$Nonce) {
    return [AesOcbCore]::Decrypt($Ciphertext, $Key, $Nonce, $null)
  }

  static [byte[]] Decrypt([byte[]]$Ciphertext, [byte[]]$Key, [byte[]]$Nonce, [byte[]]$AssociatedData) {
    if ($null -eq $Ciphertext) { throw [ArgumentNullException]::new('Ciphertext') }
    if ($Ciphertext.Length -lt [AesOcbCore]::TagSize) {
      throw [ArgumentException]::new("Ciphertext must be at least $([AesOcbCore]::TagSize) bytes", 'Ciphertext')
    }
    if ($null -eq $AssociatedData) { $AssociatedData = [byte[]]::new(0) }
    [AesOcbCore]::ValidateParameters($Key, $Nonce)

    $ptLen = $Ciphertext.Length - [AesOcbCore]::TagSize
    $aes = [System.Security.Cryptography.Aes]::Create()
    $aes.Key = $Key
    $aes.Mode = [System.Security.Cryptography.CipherMode]::ECB
    $aes.Padding = [System.Security.Cryptography.PaddingMode]::None

    $encryptor = $aes.CreateEncryptor()
    $decryptor = $aes.CreateDecryptor()
    $inBuf = [byte[]]::new(16)
    $outBuf = [byte[]]::new(16)

    $lStar = [byte[]]::new(16)
    $zeros = [byte[]]::new(16)
    [AesOcbCore]::EncryptBlock($encryptor, $lStar, $zeros, $inBuf, $outBuf)

    $lDollar = [byte[]]::new(16)
    [AesOcbCore]::Double($lDollar, $lStar)

    $offset = [byte[]]::new(16)
    [AesOcbCore]::InitializeOffset($encryptor, $offset, $Nonce, $lDollar, $inBuf, $outBuf)

    $checksum = [byte[]]::new(16)
    $fullBlocks = [Math]::Floor($ptLen / 16)
    $plaintext = [byte[]]::new($ptLen)

    $li = [byte[]]::new(16)
    $tempBlock = [byte[]]::new(16)
    $outBlock = [byte[]]::new(16)

    for ($i = 0; $i -lt $fullBlocks; $i++) {
      [Array]::Copy($Ciphertext, $i * 16, $tempBlock, 0, 16)
      [AesOcbCore]::GetL($li, $lStar, $i + 1)
      [AesOcbCore]::XorBlock($offset, $offset, $li)
      [AesOcbCore]::XorBlock($tempBlock, $tempBlock, $offset)
      [AesOcbCore]::DecryptBlock($decryptor, $outBlock, $tempBlock, $inBuf, $outBuf)
      [AesOcbCore]::XorBlock($outBlock, $outBlock, $offset)
      [Array]::Copy($outBlock, 0, $plaintext, $i * 16, 16)
      [AesOcbCore]::XorBlock($checksum, $checksum, $outBlock)
    }

    $remaining = $ptLen % 16
    if ($remaining -gt 0) {
      [AesOcbCore]::XorBlock($offset, $offset, $lStar)
      $pad = [byte[]]::new(16)
      [AesOcbCore]::EncryptBlock($encryptor, $pad, $offset, $inBuf, $outBuf)

      for ($i = 0; $i -lt $remaining; $i++) {
        $plaintext[$fullBlocks * 16 + $i] = [byte]($Ciphertext[$fullBlocks * 16 + $i] -bxor $pad[$i])
        $checksum[$i] = [byte]($checksum[$i] -bxor $plaintext[$fullBlocks * 16 + $i])
      }
      $checksum[$remaining] = [byte]($checksum[$remaining] -bxor 0x80)
    }

    $expectedTag = [byte[]]::new(16)
    [AesOcbCore]::ComputeTag($encryptor, $expectedTag, $offset, $checksum, $lDollar, $AssociatedData, $inBuf, $outBuf)

    $actualTag = [byte[]]::new(16)
    [Array]::Copy($Ciphertext, $ptLen, $actualTag, 0, 16)

    if (-not [AesOcbCore]::ConstantTimeEquals($expectedTag, $actualTag)) {
      [Array]::Clear($plaintext, 0, $plaintext.Length)
      throw [System.Security.Cryptography.CryptographicException]::new('AES-OCB decryption failed: authentication tag mismatch.')
    }

    $encryptor.Dispose()
    $decryptor.Dispose()
    $aes.Dispose()

    return $plaintext
  }
}

class AesOcb : AesOcbCore {
  hidden [byte[]] $_key
  hidden [byte[]] $_nonce
  hidden [byte[]] $_associatedData

  AesOcb() {}

  [AesOcb] WithKey([byte[]]$Key) {
    if ($null -eq $Key) { throw [ArgumentNullException]::new('Key') }
    $this._key = [byte[]]$Key.Clone()
    return $this
  }

  [AesOcb] WithNonce([byte[]]$Nonce) {
    if ($null -eq $Nonce) { throw [ArgumentNullException]::new('Nonce') }
    $this._nonce = [byte[]]$Nonce.Clone()
    return $this
  }

  [AesOcb] WithRandomNonce([int]$NonceSize = 12) {
    if ($NonceSize -lt 1) { throw [ArgumentOutOfRangeException]::new('NonceSize') }
    $this._nonce = [byte[]]::new($NonceSize)
    [System.Security.Cryptography.RandomNumberGenerator]::Fill($this._nonce)
    return $this
  }

  [AesOcb] WithAssociatedData([byte[]]$AssociatedData) {
    $this._associatedData = if ($null -eq $AssociatedData) { $null } else { [byte[]]$AssociatedData.Clone() }
    return $this
  }

  [byte[]] Encrypt([byte[]]$Plaintext) {
    if ($null -eq $this._key) { throw [InvalidOperationException]::new('Key has not been set. Use WithKey() first.') }
    if ($null -eq $this._nonce) { throw [InvalidOperationException]::new('Nonce has not been set. Use WithNonce() or WithRandomNonce() first.') }
    return [AesOcbCore]::Encrypt($Plaintext, $this._key, $this._nonce, $this._associatedData).Ciphertext
  }

  [byte[]] Decrypt([byte[]]$Ciphertext) {
    if ($null -eq $this._key) { throw [InvalidOperationException]::new('Key has not been set. Use WithKey() first.') }
    if ($null -eq $this._nonce) { throw [InvalidOperationException]::new('Nonce has not been set. Use WithNonce() or WithRandomNonce() first.') }
    return [AesOcbCore]::Decrypt($Ciphertext, $this._key, $this._nonce, $this._associatedData)
  }

  [byte[]] GetNonce() {
    if ($null -eq $this._nonce) { throw [InvalidOperationException]::new('Nonce has not been set. Use WithNonce() or WithRandomNonce() first.') }
    return [byte[]]$this._nonce.Clone()
  }
}
