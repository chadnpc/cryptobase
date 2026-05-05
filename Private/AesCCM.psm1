#!/usr/bin/env pwsh
using namespace System
using namespace System.Security.Cryptography

using module ./Exceptions.psm1

class AesCcmEncryptionResult {
    [byte[]] $Ciphertext
    [byte[]] $Nonce
    [int] $TagSize
    [int] get_CiphertextLength() { return $this.Ciphertext.Length - $this.TagSize }
}

class AesCcmCore {
    static [int[]] $SupportedKeySizes = @(16, 24, 32)
    static [int] $MinNonceSize = 7
    static [int] $MaxNonceSize = 13
    static [int] $DefaultNonceSize = 13
    static [int] $MinTagSize = 4
    static [int] $MaxTagSize = 16
    static [int] $DefaultTagSize = 16
    static [int] $BlockSize = 16

    static [void] ValidateParameters([byte[]]$key, [byte[]]$nonce, [int]$tagSize, [int]$plaintextLength) {
        if ($null -eq $key -or [AesCcmCore]::SupportedKeySizes -notcontains $key.Length) {
            $len = if ($null -eq $key) { 'null' } else { $key.Length }
            throw [ArgumentException]::new("Key must be 16, 24, or 32 bytes (AES-128/192/256), but was $len bytes")
        }

        if ($null -eq $nonce -or $nonce.Length -lt [AesCcmCore]::MinNonceSize -or $nonce.Length -gt [AesCcmCore]::MaxNonceSize) {
            $len = if ($null -eq $nonce) { 'null' } else { $nonce.Length }
            throw [ArgumentException]::new("Nonce must be $([AesCcmCore]::MinNonceSize)-$([AesCcmCore]::MaxNonceSize) bytes, but was $len bytes")
        }

        if ($tagSize -lt [AesCcmCore]::MinTagSize -or $tagSize -gt [AesCcmCore]::MaxTagSize -or $tagSize % 2 -ne 0) {
            throw [ArgumentException]::new("Tag size must be an even number between $([AesCcmCore]::MinTagSize) and $([AesCcmCore]::MaxTagSize) bytes, but was $tagSize bytes")
        }

        $L = 15 - $nonce.Length
        $maxPlaintextLength = if ($L -ge 8) { [long]::MaxValue } else { ([long]1 -shl ($L * 8)) - 1 }
        if ($plaintextLength -gt $maxPlaintextLength) {
            throw [ArgumentException]::new("Plaintext length $plaintextLength exceeds maximum $maxPlaintextLength bytes for nonce size $($nonce.Length)")
        }
    }

    static [void] WriteLength([byte[]]$buffer, [int]$offset, [int]$length, [long]$value) {
        for ($i = $length - 1; $i -ge 0; $i--) {
            $buffer[$offset + $i] = [byte]($value -band 0xFF)
            $value = $value -shr 8
        }
    }

    static [void] XorBlock([byte[]]$mac, [byte[]]$block) {
        for ($i = 0; $i -lt [AesCcmCore]::BlockSize; $i++) {
            $mac[$i] = $mac[$i] -bxor $block[$i]
        }
    }

    static [void] ComputeTag([byte[]]$tag, [byte[]]$plaintext, [byte[]]$associatedData, [byte[]]$nonce, [object]$encryptor, [int]$tagSize) {
        $L = 15 - $nonce.Length
        $M = $tagSize

        $block = [byte[]]::new([AesCcmCore]::BlockSize)
        
        [int]$aadFlag = if ($null -ne $associatedData -and $associatedData.Length -gt 0) { 0x40 } else { 0x00 }
        [int]$mPrime = [int](($M - 2) / 2)
        [int]$lPrime = $L - 1
        $flags = [byte]($aadFlag -bor ($mPrime -shl 3) -bor $lPrime)
        $block[0] = $flags

        [Array]::Copy($nonce, 0, $block, 1, $nonce.Length)
        [AesCcmCore]::WriteLength($block, [AesCcmCore]::BlockSize - $L, $L, $plaintext.Length)

        $mac = [byte[]]::new([AesCcmCore]::BlockSize)
        [void]$encryptor.TransformBlock($block, 0, [AesCcmCore]::BlockSize, $mac, 0)

        if ($null -ne $associatedData -and $associatedData.Length -gt 0) {
            $aadBlock = [byte[]]::new([AesCcmCore]::BlockSize)
            $aadOffset = 0

            if ($associatedData.Length -lt 0xFF00) {
                $aadBlock[0] = [byte]($associatedData.Length -shr 8)
                $aadBlock[1] = [byte]($associatedData.Length -band 0xFF)
                $aadOffset = 2
            } else {
                $aadBlock[0] = 0xFF
                $aadBlock[1] = 0xFE
                $aadBlock[2] = [byte]($associatedData.Length -shr 24)
                $aadBlock[3] = [byte]($associatedData.Length -shr 16)
                $aadBlock[4] = [byte]($associatedData.Length -shr 8)
                $aadBlock[5] = [byte]($associatedData.Length -band 0xFF)
                $aadOffset = 6
            }

            $aadPos = 0
            $firstBlockSpace = [AesCcmCore]::BlockSize - $aadOffset
            $copyLen = [Math]::Min($firstBlockSpace, $associatedData.Length)
            [Array]::Copy($associatedData, 0, $aadBlock, $aadOffset, $copyLen)
            $aadPos += $copyLen

            [AesCcmCore]::XorBlock($mac, $aadBlock)
            [void]$encryptor.TransformBlock($mac, 0, [AesCcmCore]::BlockSize, $mac, 0)

            while ($aadPos -lt $associatedData.Length) {
                [Array]::Clear($aadBlock, 0, [AesCcmCore]::BlockSize)
                $copyLen = [Math]::Min([AesCcmCore]::BlockSize, $associatedData.Length - $aadPos)
                [Array]::Copy($associatedData, $aadPos, $aadBlock, 0, $copyLen)
                $aadPos += $copyLen
                [AesCcmCore]::XorBlock($mac, $aadBlock)
                [void]$encryptor.TransformBlock($mac, 0, [AesCcmCore]::BlockSize, $mac, 0)
            }
        }

        $ptPos = 0
        while ($ptPos -lt $plaintext.Length) {
            [Array]::Clear($block, 0, [AesCcmCore]::BlockSize)
            $copyLen = [Math]::Min([AesCcmCore]::BlockSize, $plaintext.Length - $ptPos)
            [Array]::Copy($plaintext, $ptPos, $block, 0, $copyLen)
            $ptPos += $copyLen
            [AesCcmCore]::XorBlock($mac, $block)
            [void]$encryptor.TransformBlock($mac, 0, [AesCcmCore]::BlockSize, $mac, 0)
        }

        [Array]::Copy($mac, 0, $tag, 0, $tagSize)
    }

    static [void] EncryptCtr([byte[]]$ciphertext, [byte[]]$encryptedTag, [byte[]]$plaintext, [byte[]]$tag, [byte[]]$nonce, [object]$encryptor) {
        $L = 15 - $nonce.Length
        $flags = [byte]($L - 1)

        $counter = [byte[]]::new([AesCcmCore]::BlockSize)
        $keystream = [byte[]]::new([AesCcmCore]::BlockSize)

        $counter[0] = $flags
        [Array]::Copy($nonce, 0, $counter, 1, $nonce.Length)

        [void]$encryptor.TransformBlock($counter, 0, [AesCcmCore]::BlockSize, $keystream, 0)
        for ($i = 0; $i -lt $tag.Length; $i++) {
            $encryptedTag[$i] = [byte]($tag[$i] -bxor $keystream[$i])
        }

        $ptPos = 0
        $ctrValue = 1
        while ($ptPos -lt $plaintext.Length) {
            [Array]::Clear($counter, [AesCcmCore]::BlockSize - $L, $L)
            [AesCcmCore]::WriteLength($counter, [AesCcmCore]::BlockSize - $L, $L, $ctrValue)
            [void]$encryptor.TransformBlock($counter, 0, [AesCcmCore]::BlockSize, $keystream, 0)

            $copyLen = [Math]::Min([AesCcmCore]::BlockSize, $plaintext.Length - $ptPos)
            for ($i = 0; $i -lt $copyLen; $i++) {
                $ciphertext[$ptPos + $i] = [byte]($plaintext[$ptPos + $i] -bxor $keystream[$i])
            }
            $ptPos += $copyLen
            $ctrValue++
        }
    }

    static [AesCcmEncryptionResult] Encrypt([byte[]]$plaintext, [byte[]]$key) {
        return [AesCcmCore]::Encrypt($plaintext, $key, $null, $null, 16, $false)
    }

    static [AesCcmEncryptionResult] Encrypt([byte[]]$plaintext, [byte[]]$key, [byte[]]$nonce) {
        return [AesCcmCore]::Encrypt($plaintext, $key, $nonce, $null, 16, $false)
    }

    static [AesCcmEncryptionResult] Encrypt([byte[]]$plaintext, [byte[]]$key, [byte[]]$nonce, [byte[]]$associatedData) {
        return [AesCcmCore]::Encrypt($plaintext, $key, $nonce, $associatedData, 16, $false)
    }

    static [AesCcmEncryptionResult] Encrypt([byte[]]$plaintext, [byte[]]$key, [byte[]]$nonce, [byte[]]$associatedData, [int]$tagSize) {
        return [AesCcmCore]::Encrypt($plaintext, $key, $nonce, $associatedData, $tagSize, $false)
    }

    static [AesCcmEncryptionResult] Encrypt([byte[]]$plaintext, [byte[]]$key, [byte[]]$nonce, [byte[]]$associatedData, [int]$tagSize, [bool]$deterministicMode) {
        if ($null -eq $nonce -or $nonce.Length -eq 0) {
            $nonce = [byte[]]::new([AesCcmCore]::DefaultNonceSize)
            if (-not $deterministicMode) {
                [RandomNumberGenerator]::Fill($nonce)
            }
        }
        if ($null -eq $plaintext) { $plaintext = [byte[]]::new(0) }
        if ($null -eq $associatedData) { $associatedData = [byte[]]::new(0) }

        [AesCcmCore]::ValidateParameters($key, $nonce, $tagSize, $plaintext.Length)

        $aes = [Aes]::Create()
        $aes.Key = $key
        $aes.Mode = [CipherMode]::ECB
        $aes.Padding = [PaddingMode]::None
        $encryptor = $aes.CreateEncryptor()

        try {
            $ciphertext = [byte[]]::new($plaintext.Length + $tagSize)
            $fullTag = [byte[]]::new($tagSize)
            
            [AesCcmCore]::ComputeTag($fullTag, $plaintext, $associatedData, $nonce, $encryptor, $tagSize)
            
            $ctOnly = [byte[]]::new($plaintext.Length)
            $encTag = [byte[]]::new($tagSize)
            [AesCcmCore]::EncryptCtr($ctOnly, $encTag, $plaintext, $fullTag, $nonce, $encryptor)

            [Array]::Copy($ctOnly, 0, $ciphertext, 0, $ctOnly.Length)
            [Array]::Copy($encTag, 0, $ciphertext, $ctOnly.Length, $tagSize)

            return [AesCcmEncryptionResult]@{
                Ciphertext = $ciphertext
                Nonce = $nonce
                TagSize = $tagSize
            }
        } finally {
            $encryptor.Dispose()
            $aes.Dispose()
        }
    }

    static [byte[]] Decrypt([byte[]]$ciphertext, [byte[]]$key, [byte[]]$nonce) {
        return [AesCcmCore]::Decrypt($ciphertext, $key, $nonce, $null, 16)
    }

    static [byte[]] Decrypt([byte[]]$ciphertext, [byte[]]$key, [byte[]]$nonce, [byte[]]$associatedData) {
        return [AesCcmCore]::Decrypt($ciphertext, $key, $nonce, $associatedData, 16)
    }

    static [byte[]] Decrypt([byte[]]$ciphertext, [byte[]]$key, [byte[]]$nonce, [byte[]]$associatedData, [int]$tagSize) {
        if ($null -eq $ciphertext -or $ciphertext.Length -lt $tagSize) {
            throw [ArgumentException]::new("Ciphertext must be at least $tagSize bytes")
        }
        if ($null -eq $associatedData) { $associatedData = [byte[]]::new(0) }

        $plaintextLength = $ciphertext.Length - $tagSize
        [AesCcmCore]::ValidateParameters($key, $nonce, $tagSize, $plaintextLength)

        $aes = [Aes]::Create()
        $aes.Key = $key
        $aes.Mode = [CipherMode]::ECB
        $aes.Padding = [PaddingMode]::None
        $encryptor = $aes.CreateEncryptor()

        try {
            $ctOnly = [byte[]]::new($plaintextLength)
            [Array]::Copy($ciphertext, 0, $ctOnly, 0, $plaintextLength)
            $receivedTag = [byte[]]::new($tagSize)
            [Array]::Copy($ciphertext, $plaintextLength, $receivedTag, 0, $tagSize)

            $plaintext = [byte[]]::new($plaintextLength)
            $decryptedTag = [byte[]]::new($tagSize)

            [AesCcmCore]::EncryptCtr($plaintext, $decryptedTag, $ctOnly, $receivedTag, $nonce, $encryptor)

            $expectedTag = [byte[]]::new($tagSize)
            [AesCcmCore]::ComputeTag($expectedTag, $plaintext, $associatedData, $nonce, $encryptor, $tagSize)

            $diff = 0
            for ($i = 0; $i -lt $tagSize; $i++) {
                $diff = $diff -bor ($decryptedTag[$i] -bxor $expectedTag[$i])
            }

            if ($diff -ne 0) {
                [Array]::Clear($plaintext, 0, $plaintext.Length)
                throw [CryptographicException]::new("AES-CCM decryption failed: authentication tag mismatch.")
            }

            return $plaintext
        } finally {
            $encryptor.Dispose()
            $aes.Dispose()
        }
    }
}

class AesCcmBuilder : IDisposable {
    hidden [byte[]] $_key
    hidden [byte[]] $_nonce
    hidden [byte[]] $_associatedData
    hidden [int] $_tagSize = 16
    hidden [bool] $_disposed = $false

    AesCcmBuilder() {}

    static [AesCcmBuilder] Create() { return [AesCcmBuilder]::new() }

    [AesCcmBuilder] WithKey([byte[]]$key) {
        if ($null -eq $key) { throw [ArgumentNullException]::new("key") }
        $this._key = [byte[]]$key.Clone()
        return $this
    }

    [AesCcmBuilder] WithNonce([byte[]]$nonce) {
        if ($null -eq $nonce) { throw [ArgumentNullException]::new("nonce") }
        $this._nonce = [byte[]]$nonce.Clone()
        return $this
    }

    [AesCcmBuilder] WithRandomNonce() {
        return $this.WithRandomNonce(13)
    }

    [AesCcmBuilder] WithRandomNonce([int]$nonceSize) {
        $this._nonce = [byte[]]::new($nonceSize)
        [RandomNumberGenerator]::Fill($this._nonce)
        return $this
    }

    [AesCcmBuilder] WithAssociatedData([byte[]]$associatedData) {
        $this._associatedData = if ($null -eq $associatedData) { $null } else { [byte[]]$associatedData.Clone() }
        return $this
    }

    [AesCcmBuilder] WithTagSize([int]$tagSize) {
        $this._tagSize = $tagSize
        return $this
    }

    [byte[]] Encrypt([byte[]]$plaintext) {
        if ($this._disposed) { throw [ObjectDisposedException]::new("AesCcmBuilder") }
        if ($null -eq $this._key) { throw [InvalidOperationException]::new("Key has not been set.") }
        if ($null -eq $this._nonce) { throw [InvalidOperationException]::new("Nonce has not been set.") }
        
        $result = [AesCcmCore]::Encrypt($plaintext, $this._key, $this._nonce, $this._associatedData, $this._tagSize)
        return $result.Ciphertext
    }

    [byte[]] Decrypt([byte[]]$ciphertext) {
        if ($this._disposed) { throw [ObjectDisposedException]::new("AesCcmBuilder") }
        if ($null -eq $this._key) { throw [InvalidOperationException]::new("Key has not been set.") }
        if ($null -eq $this._nonce) { throw [InvalidOperationException]::new("Nonce has not been set.") }

        return [AesCcmCore]::Decrypt($ciphertext, $this._key, $this._nonce, $this._associatedData, $this._tagSize)
    }

    [byte[]] GetNonce() {
        if ($null -eq $this._nonce) { throw [InvalidOperationException]::new("Nonce has not been set.") }
        return [byte[]]$this._nonce.Clone()
    }

    [void] Dispose() {
        if (-not $this._disposed) {
            if ($null -ne $this._key) { [Array]::Clear($this._key, 0, $this._key.Length) }
            $this._disposed = $true
        }
    }
}
