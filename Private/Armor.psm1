#!/usr/bin/env pwsh
using namespace System
using namespace System.IO
using namespace System.Text
using namespace System.Security
using namespace System.Security.Cryptography
using namespace System.Runtime.InteropServices
using namespace System.Collections.Generic

using module ./Utilities.psm1
using module ./Enums.psm1
using module ./Crc24.psm1

class ArmorDecodeResult {
  [byte[]] $Data
  [ArmorType] $Type
  [Dictionary[string, string]] $Headers
}

class Armor : CryptobaseUtils {
  static [string[]] $LineSeparators = @("`r`n", "`n", "`r")
  static [string] $ARMOR_BEGIN = "-----BEGIN PGP "
  static [string] $ARMOR_END = "-----END PGP "
  static [string] $ARMOR_SUFFIX = "-----"
  static [int] $MAX_LINE_LENGTH = 76

  static [string] Encode([byte[]]$data, [ArmorType]$armorType, [Dictionary[string, string]]$headers) {
    $sb = [StringBuilder]::new()
    $typeName = [Armor]::GetArmorTypeName($armorType)

    [void]$sb.Append([Armor]::ARMOR_BEGIN).Append($typeName).AppendLine([Armor]::ARMOR_SUFFIX)

    if ($null -ne $headers -and $headers.Count -gt 0) {
      foreach ($kvp in $headers.GetEnumerator()) {
        [void]$sb.Append($kvp.Key).Append(": ").AppendLine($kvp.Value)
      }
    }

    [void]$sb.AppendLine()

    $base64 = [Convert]::ToBase64String($data)
    for ($i = 0; $i -lt $base64.Length; $i += [Armor]::MAX_LINE_LENGTH) {
      $lineLength = [Math]::Min([Armor]::MAX_LINE_LENGTH, $base64.Length - $i)
      [void]$sb.AppendLine($base64.Substring($i, $lineLength))
    }

    $crcBytes = [Crc24]::ComputeToBytes($data)
    [void]$sb.Append('=').AppendLine([Convert]::ToBase64String($crcBytes))

    [void]$sb.Append([Armor]::ARMOR_END).Append($typeName).Append([Armor]::ARMOR_SUFFIX)

    return $sb.ToString()
  }

  static [ArmorDecodeResult] Decode([string]$armoredText) {
    if ([string]::IsNullOrWhiteSpace($armoredText)) { throw [ArgumentNullException]::new("armoredText") }

    $lines = $armoredText.Split([Armor]::LineSeparators, [StringSplitOptions]::None)
    $lineIndex = 0

    while ($lineIndex -lt $lines.Length -and [string]::IsNullOrWhiteSpace($lines[$lineIndex])) {
      $lineIndex++
    }

    if ($lineIndex -ge $lines.Length) { throw [FormatException]::new("No armor header found.") }

    $headerLine = $lines[$lineIndex].Trim()
    if (!$headerLine.StartsWith([Armor]::ARMOR_BEGIN) -or !$headerLine.EndsWith([Armor]::ARMOR_SUFFIX)) {
      throw [FormatException]::new("Invalid armor header: $headerLine")
    }

    $typeName = $headerLine.Substring([Armor]::ARMOR_BEGIN.Length, $headerLine.Length - [Armor]::ARMOR_BEGIN.Length - [Armor]::ARMOR_SUFFIX.Length)
    $armorType = [Armor]::ParseArmorType($typeName)
    $lineIndex++

    $headers = [Dictionary[string, string]]::new()
    while ($lineIndex -lt $lines.Length) {
      $line = $lines[$lineIndex].Trim()
      if ([string]::IsNullOrEmpty($line)) {
        $lineIndex++
        break
      }

      $colonIndex = $line.IndexOf(':')
      if ($colonIndex -gt 0) {
        $key = $line.Substring(0, $colonIndex).Trim()
        $value = $line.Substring($colonIndex + 1).Trim()
        $headers[$key] = $value
      }
      $lineIndex++
    }

    $base64Builder = [StringBuilder]::new()
    [byte[]]$crcBytes = $null

    while ($lineIndex -lt $lines.Length) {
      $line = $lines[$lineIndex].Trim()

      if ($line.StartsWith([Armor]::ARMOR_END)) {
        break
      }

      if ($line.StartsWith('=') -and $line.Length -eq 5) {
        $crcBytes = [Convert]::FromBase64String($line.Substring(1))
        $lineIndex++
        continue
      }

      if (![string]::IsNullOrWhiteSpace($line)) {
        [void]$base64Builder.Append($line)
      }
      $lineIndex++
    }

    $data = [Convert]::FromBase64String($base64Builder.ToString())

    if ($null -ne $crcBytes) {
      if (![Crc24]::Verify($crcBytes, $data)) {
        throw [FormatException]::new("CRC24 checksum verification failed.")
      }
    }

    $result = [ArmorDecodeResult]::new()
    $result.Data = $data
    $result.Type = $armorType
    $result.Headers = $headers
    return $result
  }

  static hidden [string] GetArmorTypeName([ArmorType]$type) {
    [ValidateNotNull()][ArmorType]$type = $type
    $n = [string]::Empty
    $n = switch ($type) {
      ([ArmorType]::Message) { "MESSAGE"; break }
      ([ArmorType]::PublicKey) { "PUBLIC KEY BLOCK"; break }
      ([ArmorType]::PrivateKey) { "PRIVATE KEY BLOCK"; break }
      ([ArmorType]::Signature) { "SIGNATURE"; break }
      ([ArmorType]::SignedMessage) { "SIGNED MESSAGE"; break }
      default { throw [ArgumentException]::new("Unknown armor type: $type") }
    }
    return $n
  }

  static hidden [ArmorType] ParseArmorType([string]$typeName) {
    [ValidateNotNullOrWhiteSpace()][string]$typeName = $typeName
    $type = [ArmorType]::Message
    $type = switch ($typeName.ToUpperInvariant()) {
      "MESSAGE" { [ArmorType]::Message ; break }
      "PUBLIC KEY BLOCK" { [ArmorType]::PublicKey; break }
      "PRIVATE KEY BLOCK" { [ArmorType]::PrivateKey; break }
      "SECRET KEY BLOCK" { [ArmorType]::PrivateKey; break }
      "SIGNATURE" { [ArmorType]::Signature; break }
      "SIGNED MESSAGE" { [ArmorType]::SignedMessage; break }
      default { throw [FormatException]::new("Unknown armor type: $typeName") }
    }
    return $type
  }
}
