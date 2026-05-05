#!/usr/bin/env pwsh
using namespace System
using namespace System.Collections.Generic
using namespace System.Text
using namespace System.Numerics


using module ./Enums.psm1
using module ./Utilities.psm1
using module ./Armor.psm1
using module ./S2K.psm1

#region Mpi
class Mpi {
  static [BigInteger] Read([byte[]]$data, [ref]$offset) {
    if ($data.Length -lt $offset.Value + 2) { throw [ArgumentException]::new("Data too short for MPI bit count.") }
    
    # Bit count is big-endian 2 octets
    [int]$bitCount = ([int]$data[$offset.Value] -shl 8) -bor [int]$data[$offset.Value + 1]
    [int]$byteCount = [Math]::Ceiling($bitCount / 8.0)
    
    if ($data.Length -lt $offset.Value + 2 + $byteCount) { throw [ArgumentException]::new("Data too short for MPI value.") }
    
    $mpiData = [byte[]]::new($byteCount)
    [Array]::Copy($data, $offset.Value + 2, $mpiData, 0, $byteCount)
    
    $offset.Value += 2 + $byteCount
    
    if ($byteCount -eq 0) { return [BigInteger]::Zero }
    
    # BigInteger expects little-endian, MPI is big-endian
    [Array]::Reverse($mpiData)
    
    # Ensure positive by checking high bit of original MSB (now at end of reversed array)
    if (($mpiData[$byteCount - 1] -band 0x80) -ne 0) {
      $unsignedData = [byte[]]::new($byteCount + 1)
      [Array]::Copy($mpiData, $unsignedData, $byteCount)
      # $unsignedData[$byteCount] is already 0
      return [BigInteger]::new($unsignedData)
    }
    
    return [BigInteger]::new($mpiData)
  }

  static [byte[]] Write([BigInteger]$value) {
    if ($value -lt 0) { throw [ArgumentOutOfRangeException]::new("MPI values must be non-negative.") }
    if ($value.IsZero) { return [byte[]]@(0, 0) }
    
    $bytes = $value.ToByteArray() # Little-endian
    $length = $bytes.Length
    
    # Remove trailing zero if it was added for sign bit
    if ($bytes[$length - 1] -eq 0 -and $length -gt 1) {
      $length--
    }
    
    # Calculate bit count
    $msb = $bytes[$length - 1]
    $bitsInMsb = 0
    $tempMsb = $msb
    while ($tempMsb -gt 0) {
      $tempMsb = $tempMsb -shr 1
      $bitsInMsb++
    }
    $bitCount = ($length - 1) * 8 + $bitsInMsb
    
    $res = [byte[]]::new(2 + $length)
    $res[0] = [byte]($bitCount -shr 8)
    $res[1] = [byte]($bitCount -band 0xFF)
    
    # Write bytes in big-endian
    for ($i = 0; $i -lt $length; $i++) {
      $res[2 + $i] = $bytes[$length - 1 - $i]
    }
    
    return $res
  }
}

class PgpPacketHeader {
  [PgpPacketTag] $Tag
  [PgpPacketFormat] $Format
  [long] $Length
  [bool] $IsPartial
  [int] $HeaderLength

  static [PgpPacketHeader] Read([byte[]]$data, [int]$offset) {
    if ($data.Length -le $offset) { return $null }
    
    $headerByte = $data[$offset]
    if (($headerByte -band 0x80) -eq 0) { throw [FormatException]::new("Invalid packet header: bit 7 not set.") }
    
    $header = [PgpPacketHeader]::new()
    $header.Format = ($headerByte -band 0x40) -eq 0x40 ? [PgpPacketFormat]::New : [PgpPacketFormat]::Old
    
    if ($header.Format -eq [PgpPacketFormat]::New) {
      $header.Tag = [PgpPacketTag]($headerByte -band 0x3F)
      $lenInfo = [PgpPacketHeader]::ReadNewLength($data, $offset + 1)
      $header.Length = $lenInfo.Length
      $header.IsPartial = $lenInfo.IsPartial
      $header.HeaderLength = 1 + $lenInfo.BytesConsumed
    }
    else {
      $header.Tag = [PgpPacketTag](($headerByte -band 0x3C) -shr 2)
      $lenType = $headerByte -band 0x03
      
      switch ($lenType) {
        0 {
          # 1-byte length
          $header.Length = [long]$data[$offset + 1]
          $header.HeaderLength = 2
        }
        1 {
          # 2-byte length
          $header.Length = ([long]$data[$offset + 1] -shl 8) -bor [long]$data[$offset + 2]
          $header.HeaderLength = 3
        }
        2 {
          # 4-byte length
          $header.Length = ([long]$data[$offset + 1] -shl 24) -bor ([long]$data[$offset + 2] -shl 16) -bor ([long]$data[$offset + 3] -shl 8) -bor [long]$data[$offset + 4]
          $header.HeaderLength = 5
        }
        3 {
          # Indeterminate length
          $header.Length = -1
          $header.HeaderLength = 1
        }
      }
    }
    
    return $header
  }

  static hidden [hashtable] ReadNewLength([byte[]]$data, [int]$offset) {
    $first = $data[$offset]
    if ($first -lt 192) {
      return @{ Length = [long]$first; BytesConsumed = 1; IsPartial = $false }
    }
    if ($first -lt 224) {
      $len = (([long]$first - 192) -shl 8) + [long]$data[$offset + 1] + 192
      return @{ Length = $len; BytesConsumed = 2; IsPartial = $false }
    }
    if ($first -eq 255) {
      $len = ([long]$data[$offset + 1] -shl 24) -bor ([long]$data[$offset + 2] -shl 16) -bor ([long]$data[$offset + 3] -shl 8) -bor [long]$data[$offset + 4]
      return @{ Length = $len; BytesConsumed = 5; IsPartial = $false }
    }
    # Partial body length
    $len = 1L -shl ($first -band 0x1F)
    return @{ Length = $len; BytesConsumed = 1; IsPartial = $true }
  }
}

#endregion OpenPgpCore


#region OpenPgpPackets
class PgpPublicKeyPacket {
  [byte] $Version
  [DateTimeOffset] $CreationTime
  [PgpPublicKeyAlgorithm] $Algorithm
  [byte[]] $KeyMaterial
  [bool] $IsSubkey

  PgpPublicKeyPacket([byte]$version, [DateTimeOffset]$creationTime, [PgpPublicKeyAlgorithm]$algorithm, [byte[]]$keyMaterial, [bool]$isSubkey) {
    $this.Version = $version
    $this.CreationTime = $creationTime
    $this.Algorithm = $algorithm
    $this.KeyMaterial = $keyMaterial
    $this.IsSubkey = $isSubkey
  }

  static [PgpPublicKeyPacket] Read([byte[]]$data, [bool]$isSubkey = $false) {
    if ($data.Length -lt 1) { throw [ArgumentException]::new("Data too short for public key packet.") }
    
    $v = $data[0]
    $offset = 1
    
    if ($v -eq 4) {
      if ($data.Length -lt 6) { throw [ArgumentException]::new("Data too short for V4 public key.") }
      $ts = ([long]$data[1] -shl 24) -bor ([long]$data[2] -shl 16) -bor ([long]$data[3] -shl 8) -bor [long]$data[4]
      $ct = [DateTimeOffset]::FromUnixTimeSeconds($ts)
      $alg = [PgpPublicKeyAlgorithm]$data[5]
      $material = [byte[]]::new($data.Length - 6)
      [Array]::Copy($data, 6, $material, 0, $material.Length)
      return [PgpPublicKeyPacket]::new($v, $ct, $alg, $material, $isSubkey)
    }
    elseif ($v -eq 6) {
      if ($data.Length -lt 10) { throw [ArgumentException]::new("Data too short for V6 public key.") }
      $ts = ([long]$data[1] -shl 24) -bor ([long]$data[2] -shl 16) -bor ([long]$data[3] -shl 8) -bor [long]$data[4]
      $ct = [DateTimeOffset]::FromUnixTimeSeconds($ts)
      $alg = [PgpPublicKeyAlgorithm]$data[5]
      $keyLen = ([long]$data[6] -shl 24) -bor ([long]$data[7] -shl 16) -bor ([long]$data[8] -shl 8) -bor [long]$data[9]
      if ($data.Length -lt 10 + $keyLen) { throw [ArgumentException]::new("Data too short for V6 key material.") }
      $material = [byte[]]::new($keyLen)
      [Array]::Copy($data, 10, $material, 0, $keyLen)
      return [PgpPublicKeyPacket]::new($v, $ct, $alg, $material, $isSubkey)
    }
    else {
      throw [NotSupportedException]::new("Unsupported public key version: $v")
    }
  }

  [byte[]] ToArray() {
    $res = $null
    if ($this.Version -eq 4) {
      $res = [byte[]]::new(6 + $this.KeyMaterial.Length)
      $res[0] = $this.Version
      $ts = [uint32]$this.CreationTime.ToUnixTimeSeconds()
      $res[1] = [byte](($ts -shr 24) -band 0xFF)
      $res[2] = [byte](($ts -shr 16) -band 0xFF)
      $res[3] = [byte](($ts -shr 8) -band 0xFF)
      $res[4] = [byte]($ts -band 0xFF)
      $res[5] = [byte]$this.Algorithm
      [Array]::Copy($this.KeyMaterial, 0, $res, 6, $this.KeyMaterial.Length)
    }
    elseif ($this.Version -eq 6) {
      $res = [byte[]]::new(10 + $this.KeyMaterial.Length)
      $res[0] = $this.Version
      $ts = [uint32]$this.CreationTime.ToUnixTimeSeconds()
      $res[1] = [byte](($ts -shr 24) -band 0xFF)
      $res[2] = [byte](($ts -shr 16) -band 0xFF)
      $res[3] = [byte](($ts -shr 8) -band 0xFF)
      $res[4] = [byte]($ts -band 0xFF)
      $res[5] = [byte]$this.Algorithm
      $kl = [uint32]$this.KeyMaterial.Length
      $res[6] = [byte](($kl -shr 24) -band 0xFF)
      $res[7] = [byte](($kl -shr 16) -band 0xFF)
      $res[8] = [byte](($kl -shr 8) -band 0xFF)
      $res[9] = [byte]($kl -band 0xFF)
      [Array]::Copy($this.KeyMaterial, 0, $res, 10, $this.KeyMaterial.Length)
    }
    return $res
  }
}

class PgpSecretKeyPacket {
  [PgpPublicKeyPacket] $PublicKey
  [PgpS2KUsage] $S2KUsage
  [byte] $CipherAlgorithm
  [PgpS2KSpecifier] $S2KSpecifier
  [byte[]] $IV
  [byte[]] $SecretKeyMaterial

  PgpSecretKeyPacket([PgpPublicKeyPacket]$publicKey, [PgpS2KUsage]$s2kUsage, [byte]$cipherAlgorithm, [PgpS2KSpecifier]$s2kSpecifier, [byte[]]$iv, [byte[]]$secretKeyMaterial) {
    $this.PublicKey = $publicKey
    $this.S2KUsage = $s2kUsage
    $this.CipherAlgorithm = $cipherAlgorithm
    $this.S2KSpecifier = $s2kSpecifier
    $this.IV = $iv
    $this.SecretKeyMaterial = $secretKeyMaterial
  }

  static [PgpSecretKeyPacket] Read([byte[]]$data, [bool]$isSubkey = $false) {
    # This is complex because we need to parse the public key first, but the public key length is not always known for V4
    # For V6, it is known.
    # For V4, we have to parse the public key material.
    
    $v = $data[0]
    if ($v -eq 4) {
      # Parse V4 Public Key header (6 bytes)
      $ts = ([long]$data[1] -shl 24) -bor ([long]$data[2] -shl 16) -bor ([long]$data[3] -shl 8) -bor [long]$data[4]
      $ct = [DateTimeOffset]::FromUnixTimeSeconds($ts)
      $alg = [PgpPublicKeyAlgorithm]$data[5]
      
      # Now parse MPIs to find where it ends
      $offset = [ref]6
      # This part is algorithm specific. For RSA: n, e
      $keyMaterialStart = 6
      if ($alg -eq [PgpPublicKeyAlgorithm]::RsaEncryptOrSign -or $alg -eq [PgpPublicKeyAlgorithm]::RsaEncryptOnly -or $alg -eq [PgpPublicKeyAlgorithm]::RsaSignOnly) {
        [Mpi]::Read($data, $offset) # n
        [Mpi]::Read($data, $offset) # e
      }
      else {
        throw [NotSupportedException]::new("Parsing non-RSA V4 secret keys not yet implemented.")
      }
      
      $keyMaterialLen = $offset.Value - $keyMaterialStart
      $material = [byte[]]::new($keyMaterialLen)
      [Array]::Copy($data, $keyMaterialStart, $material, 0, $keyMaterialLen)
      $pubKey = [PgpPublicKeyPacket]::new($v, $ct, $alg, $material, $isSubkey)
      
      $usage = [PgpS2KUsage]$data[$offset.Value]
      $offset.Value++
      
      $cipher = 0
      $spec = $null
      $ivData = [byte[]]::new(0)
      
      if ($usage -ne [PgpS2KUsage]::None) {
        $cipher = $data[$offset.Value]
        $offset.Value++
        $spec = [PgpS2KSpecifier]::Read($data, $offset)

        $ivSize = [PgpSecretKeyPacket]::GetCipherBlockSize($cipher)
        $ivData = [byte[]]::new($ivSize)
        [Array]::Copy($data, $offset.Value, $ivData, 0, $ivSize)
        $offset.Value += $ivSize
      }

      $secretMaterialLen = $data.Length - $offset.Value
      $secretMaterial = [byte[]]::new($secretMaterialLen)
      [Array]::Copy($data, $offset.Value, $secretMaterial, 0, $secretMaterialLen)

      return [PgpSecretKeyPacket]::new($pubKey, $usage, $cipher, $spec, $ivData, $secretMaterial)
    }
    elseif ($v -eq 6) {
      # V6 is easier because public key length is in the header
      $ts = ([long]$data[1] -shl 24) -bor ([long]$data[2] -shl 16) -bor ([long]$data[3] -shl 8) -bor [long]$data[4]
      $ct = [DateTimeOffset]::FromUnixTimeSeconds($ts)
      $alg = [PgpPublicKeyAlgorithm]$data[5]
      $pubKeyLen = ([long]$data[6] -shl 24) -bor ([long]$data[7] -shl 16) -bor ([long]$data[8] -shl 8) -bor [long]$data[9]
      
      $material = [byte[]]::new($pubKeyLen)
      [Array]::Copy($data, 10, $material, 0, $pubKeyLen)
      $pubKey = [PgpPublicKeyPacket]::new($v, $ct, $alg, $material, $isSubkey)
      
      $offset = [ref](10 + $pubKeyLen)
      $scalarOctetCount = $data[$offset.Value]
      $offset.Value++
      
      $usage = [PgpS2KUsage]::None
      $cipher = 0
      $spec = $null
      $ivData = [byte[]]::new(0)
      
      if ($scalarOctetCount -gt 0) {
        $usage = [PgpS2KUsage]$data[$offset.Value]
        $offset.Value++
        $cipher = $data[$offset.Value]
        $offset.Value++
        
        # S2K Specifier and IV are within scalarOctetCount
        $spec = [PgpS2KSpecifier]::Read($data, $offset)
        
        # Remainder of scalarOctetCount is IV
        $ivSize = (10 + $pubKeyLen + 1 + $scalarOctetCount) - $offset.Value
        $ivData = [byte[]]::new($ivSize)
        [Array]::Copy($data, $offset.Value, $ivData, 0, $ivSize)
        $offset.Value += $ivSize
      }
      
      $secretMaterialLen = $data.Length - $offset.Value
      $secretMaterial = [byte[]]::new($secretMaterialLen)
      [Array]::Copy($data, $offset.Value, $secretMaterial, 0, $secretMaterialLen)
      
      return [PgpSecretKeyPacket]::new($pubKey, $usage, $cipher, $spec, $ivData, $secretMaterial)
    }
    else {
      throw [NotSupportedException]::new("Unsupported secret key version: $v")
    }
  }

  static hidden [int] GetCipherBlockSize([byte]$cipherAlg) {
    switch ($cipherAlg) {
      7 { return 16 } # AES-128
      8 { return 16 } # AES-192
      9 { return 16 } # AES-256
      default { return 8 } # legacy ciphers
    }
    return 8
  }

  [byte[]] ToArray() {
    $pubData = $this.PublicKey.ToArray()
    $resList = [System.Collections.Generic.List[byte]]::new()
    $resList.AddRange($pubData)
    
    if ($this.PublicKey.Version -eq 4) {
      $resList.Add([byte]$this.S2KUsage)
      if ($this.S2KUsage -ne [PgpS2KUsage]::None) {
        $resList.Add($this.CipherAlgorithm)
        $resList.AddRange($this.S2KSpecifier.Write())
        $resList.AddRange($this.IV)
      }
    }
    else {
      if ($this.S2KUsage -eq [PgpS2KUsage]::None) {
        $resList.Add(0)
      }
      else {
        $s2kData = [System.Collections.Generic.List[byte]]::new()
        $s2kData.Add([byte]$this.S2KUsage)
        $s2kData.Add($this.CipherAlgorithm)
        $s2kData.AddRange($this.S2KSpecifier.Write())
        $s2kData.AddRange($this.IV)
        
        $resList.Add([byte]$s2kData.Count)
        $resList.AddRange($s2kData)
      }
    }
    
    $resList.AddRange($this.SecretKeyMaterial)
    return $resList.ToArray()
  }
}

class PgpUserIdPacket {
  [string] $UserId

  PgpUserIdPacket([string]$userId) {
    $this.UserId = $userId
  }

  static [PgpUserIdPacket] Read([byte[]]$data) {
    return [PgpUserIdPacket]::new([System.Text.Encoding]::UTF8.GetString($data))
  }

  [byte[]] ToArray() {
    return [System.Text.Encoding]::UTF8.GetBytes($this.UserId)
  }
}

class PgpLiteralDataPacket {
  [PgpLiteralDataFormat] $Format
  [string] $FileName
  [DateTimeOffset] $Date
  [byte[]] $Data

  PgpLiteralDataPacket([PgpLiteralDataFormat]$format, [string]$fileName, [DateTimeOffset]$date, [byte[]]$data) {
    $this.Format = $format
    $this.FileName = $fileName
    $this.Date = $date
    $this.Data = $data
  }

  static [PgpLiteralDataPacket] Read([byte[]]$data) {
    $fmt = [PgpLiteralDataFormat]$data[0]
    $nameLen = $data[1]
    $name = [System.Text.Encoding]::UTF8.GetString($data, 2, $nameLen)
    $tsOffset = 2 + $nameLen
    $timestamp = ([long]$data[$tsOffset] -shl 24) -bor ([long]$data[$tsOffset + 1] -shl 16) -bor ([long]$data[$tsOffset + 2] -shl 8) -bor [long]$data[$tsOffset + 3]
    $dt = [DateTimeOffset]::FromUnixTimeSeconds($timestamp)
    $dataOffset = $tsOffset + 4
    $contentLen = $data.Length - $dataOffset
    $content = [byte[]]::new($contentLen)
    [Array]::Copy($data, $dataOffset, $content, 0, $contentLen)
    return [PgpLiteralDataPacket]::new($fmt, $name, $dt, $content)
  }

  [byte[]] ToArray() {
    $nameBytes = [System.Text.Encoding]::UTF8.GetBytes($this.FileName)
    if ($nameBytes.Length -gt 255) { throw [ArgumentException]::new("Filename too long.") }
    
    $res = [byte[]]::new(1 + 1 + $nameBytes.Length + 4 + $this.Data.Length)
    $res[0] = [byte]$this.Format
    $res[1] = [byte]$nameBytes.Length
    [Array]::Copy($nameBytes, 0, $res, 2, $nameBytes.Length)
    
    $tsOffset = 2 + $nameBytes.Length
    $ts = [uint32]$this.Date.ToUnixTimeSeconds()
    $res[$tsOffset] = [byte](($ts -shr 24) -band 0xFF)
    $res[$tsOffset + 1] = [byte](($ts -shr 16) -band 0xFF)
    $res[$tsOffset + 2] = [byte](($ts -shr 8) -band 0xFF)
    $res[$tsOffset + 3] = [byte]($ts -band 0xFF)
    
    [Array]::Copy($this.Data, 0, $res, $tsOffset + 4, $this.Data.Length)
    return $res
  }
}

#endregion OpenPgpPackets


class OpenPgp : CryptobaseUtils {
  static [string] ArmorMessage([byte[]]$data, [Dictionary[string, string]]$headers) {
    return [Armor]::Encode($data, [ArmorType]::Message, $headers)
  }

  static [byte[]] DearmorMessage([string]$armoredText) {
    $decoded = [Armor]::Decode($armoredText)
    return $decoded.Data
  }
}
