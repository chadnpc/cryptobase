#!/usr/bin/env pwsh
using namespace System
using namespace System.Collections.Generic
using namespace System.Numerics
using namespace System.Text

using module ./Utilities.psm1
using module ./Enums.psm1

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
