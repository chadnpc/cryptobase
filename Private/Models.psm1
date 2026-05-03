#!/usr/bin/env pwsh
using namespace System
using namespace System.IO
using namespace System.Text


using module ./Enums.psm1
using module ./Exceptions.psm1
using module ./Utilities.psm1

class Expiration {
  [Datetime]$Date
  [Timespan]$TimeSpan
  [String]$TimeStamp
  [ExpType]$Type

  Expiration() {
    $this.TimeSpan = [Timespan]::FromMilliseconds([DateTime]::Now.Millisecond)
    $this.Date = [datetime]::Now + $this.TimeSpan
    $this.setExpType($this.TimeSpan);
    $this.setTimeStamp($this.TimeSpan);
  }
  Expiration([int]$Years) {
    # ($Months, $Years) = if ($Years -eq 1) { (12, 0) }else { (0, $Years) };
    # $CrDate = [datetime]::Now;
    # $Months = [int]($CrDate.Month + $Months); if ($Months -gt 12) { $Months -= 12 };
    $this.TimeSpan = [Timespan]::new((365 * $years), 0, 0, 0);
    $this.Date = [datetime]::Now + $this.TimeSpan
    $this.setExpType($this.TimeSpan);
    $this.setTimeStamp($this.TimeSpan);
  }
  Expiration([int]$Years, [int]$Months) {
    $this.TimeSpan = [Timespan]::new((365 * $years + $Months * 30), 0, 0, 0);
    $this.Date = [datetime]::Now + $this.TimeSpan
    $this.setExpType($this.TimeSpan);
    $this.setTimeStamp($this.TimeSpan);
  }
  Expiration([datetime]$date) {
    $this.Date = $date
    $this.TimeSpan = $date - [datetime]::Now;
    $this.setExpType($this.TimeSpan);
    $this.setTimeStamp($this.TimeSpan);
  }
  Expiration([string]$dateString) {
    $this.Date = $dateString | xconvert ToDateTime
    $this.TimeSpan = $this.Date - [datetime]::Now;
    $this.setExpType($this.TimeSpan);
    $this.setTimeStamp($this.TimeSpan);
  }
  Expiration([System.TimeSpan]$TimeSpan) {
    $this.TimeSpan = $TimeSpan;
    $this.Date = [datetime]::Now + $this.TimeSpan
    $this.setExpType($this.TimeSpan);
    $this.setTimeStamp($this.TimeSpan);
  }
  Expiration([int]$hours, [int]$minutes, [int]$seconds) {
    $this.TimeSpan = [Timespan]::new($hours, $minutes, $seconds);
    $this.setExpType($this.TimeSpan);
    $this.setTimeStamp($this.TimeSpan);
  }
  Expiration([int]$days, [int]$hours, [int]$minutes, [int]$seconds) {
    $this.TimeSpan = [Timespan]::new($days, $hours, $minutes, $seconds)
    $this.Date = [datetime]::Now + $this.TimeSpan
    $this.setExpType($this.TimeSpan);
    $this.setTimeStamp($this.TimeSpan);
  }
  [void]setTimeStamp([System.TimeSpan]$TimeSpan) {
    if ($null -eq $this.Date) {
      $this.TimeStamp = [DateTime]::Now.Add([Timespan]::FromMilliseconds($TimeSpan.TotalMilliseconds)).ToString("yyyyMMddHHmmssffff");
    } else {
      $this.TimeStamp = $this.Date.ToString("yyyyMMddHHmmssffff")
    }
  }
  [void]hidden setExpType([Timespan]$TimeSpan) {
    $this.Type = switch ($true) {
      $($TimeSpan.Days -ge 365) { [ExpType]::Years; break }
      $($TimeSpan.Days -ge 30) { [ExpType]::Months; break }
      $($TimeSpan.Days -ge 1) { [ExpType]::Days; break }
      $($TimeSpan.Hours -ge 1) { [ExpType]::Hours; break }
      $($TimeSpan.Minutes -ge 1) { [ExpType]::Minutes; break }
      $($TimeSpan.Seconds -ge 1) { [ExpType]::Seconds; break }
      default { [ExpType]::Milliseconds; break }
    }
  }
  [int]GetDays () {
    return $this.TimeSpan.Days
  }
  [int]GetMonths () {
    return [int]($this.TimeSpan.Days / 30)
  }
  [int]GetYears () {
    return [int]($this.TimeSpan.Days / 365)
  }
  [string]ToString() {
    if ($null -eq $this.Date) { return [string]::Empty }
    if ($($this.Date - [datetime]::Now) -ge [timespan]::new(0)) {
      return $this.Date.ToString();
    } else {
      return 'Expired'
    }
  }
}

class HashParser {
  static [HashFormatDescriptor] $OldFormatDescriptor = [HashFormatDescriptor]::new(1)
  static [HashFormatDescriptor] $NewFormatDescriptor = [HashFormatDescriptor]::new(2)

  static [HashInformation] GetHashInformation([string]$hash) {
    $format = $null
    if (![HashParser]::IsValidHash($hash, [ref]$format)) {
      [HashParser]::ThrowInvalidHashFormat()
    }

    $workFactor = 10 * ([int]$hash[$format.WorkfactorOffset] - [int][char]'0') + ([int]$hash[$format.WorkfactorOffset + 1] - [int][char]'0')

    return [HashInformation]::new(
      $hash.Substring(0, $format.SettingLength),
      $hash.Substring(1, $format.VersionLength),
      $workFactor,
      $hash.Substring($format.HashOffset)
    )
  }

  static [int] GetWorkFactor([string]$hash) {
    $format = $null
    if (![HashParser]::IsValidHash($hash, [ref]$format)) {
      [HashParser]::ThrowInvalidHashFormat()
    }

    return 10 * ([int]$hash[$format.WorkfactorOffset] - [int][char]'0') + ([int]$hash[$format.WorkfactorOffset + 1] - [int][char]'0')
  }

  static [string] GetSalt([string]$hash) {
    $format = $null
    if (![HashParser]::IsValidHash($hash, [ref]$format)) {
      [HashParser]::ThrowInvalidHashFormat()
    }
    if ([string]::IsNullOrWhiteSpace($hash) -or $hash.Length -lt 29) {
      throw [System.ArgumentException]::new("Invalid BCrypt hash.")
    }

    return $hash.Substring(0, 22 + $format.HashOffset)
  }

  static [bool] IsValidHash([string]$hash, [ref]$format) {
    if ($null -eq $hash) {
      throw [System.ArgumentNullException]::new("hash")
    }

    if ($hash.Length -ne 59 -and $hash.Length -ne 60) {
      $format.Value = $null
      return $false
    }

    if (-not $hash.StartsWith("`$2")) {
      $format.Value = $null
      return $false
    }

    $offset = 2
    if ([HashParser]::IsValidBCryptVersionChar($hash[$offset])) {
      $offset++
      $format.Value = [HashParser]::NewFormatDescriptor
    } else {
      $format.Value = [HashParser]::OldFormatDescriptor
    }

    if ($hash[$offset] -ne [char]36) {
      $format.Value = $null
      return $false
    }
    $offset++

    if (![HashParser]::IsAsciiNumeric($hash[$offset]) -or -not [HashParser]::IsAsciiNumeric($hash[$offset + 1])) {
      $format.Value = $null
      return $false
    }
    $offset += 2

    if ($hash[$offset] -ne [char]36) {
      $format.Value = $null
      return $false
    }
    $offset++

    for ($i = $offset; $i -lt $hash.Length; $i++) {
      if (![HashParser]::IsValidBCryptBase64Char($hash[$i])) {
        $format.Value = $null
        return $false
      }
    }

    return $true
  }

  static [bool] IsValidBCryptVersionChar([char]$value) {
    return $value -eq [char]'a' -or $value -eq [char]'b' -or $value -eq [char]'x' -or $value -eq [char]'y'
  }

  static [bool] IsValidBCryptBase64Char([char]$value) {
    return $value -eq [char]'.' -or
    $value -eq [char]'/' -or
    ($value -ge [char]'0' -and $value -le [char]'9') -or
    ($value -ge [char]'A' -and $value -le [char]'Z') -or
    ($value -ge [char]'a' -and $value -le [char]'z')
  }

  static [bool] IsAsciiNumeric([char]$value) {
    return $value -ge [char]'0' -and $value -le [char]'9'
  }

  static [void] ThrowInvalidHashFormat() {
    throw [SaltParseException]::new("Invalid Hash Format")
  }
}

class HashInformation {
  [string] $Settings
  [string] $Version
  [int]    $WorkFactor
  [string] $RawHash

  HashInformation([string]$settings, [string]$version, [int]$workFactor, [string]$rawHash) {
    $this.Settings = $settings
    $this.Version = $version
    $this.WorkFactor = $workFactor
    $this.RawHash = $rawHash
  }

  [string] ToString() {
    return "Settings: $($this.Settings), Version: $($this.Version), WorkFactor: $($this.WorkFactor), RawHash: $($this.RawHash)"
  }
}

class HashFormatDescriptor {
  [int] $VersionLength
  [int] $WorkfactorOffset
  [int] $SettingLength
  [int] $HashOffset

  HashFormatDescriptor([int]$versionLength) {
    $this.VersionLength = $versionLength
    $this.WorkfactorOffset = 1 + $this.VersionLength + 1
    $this.SettingLength = $this.WorkfactorOffset + 2
    $this.HashOffset = $this.SettingLength + 1
  }
}

class CipherObject : PsObject {
  CipherObject([System.Object]$Object) {
    $types = (($Object | Get-Member).Typename | Sort-Object -Unique)
    $ogtyp = if ($types.count -eq 1) { $types -as 'type' } else { $Object.GetType() }
    $b64sb = [convert]::ToBase64String($(if ($types.Equals("System.Byte")) { [byte[]]$Object } else { $Object | xconvert ToBytes }))
    $this.PsObject.properties.add([psscriptproperty]::new('Type', [scriptblock]::Create("[Type]'$ogtyp'")))
    $this.PsObject.properties.add([psscriptproperty]::new('Bytes', [scriptblock]::Create("[Convert]::FromBase64String('$b64sb')")))
    $this.PsObject.properties.add([psscriptproperty]::new('SecScope', [scriptblock]::Create('[EncryptionScope]::User')))
    $this.PsObject.Methods.Add(
      [psscriptmethod]::new(
        'Protect', {
          $_bytes = $this.Bytes; $Entropy = [Encoding]::UTF8.GetBytes([CryptobaseUtils]::GetUniqueMachineId())[0..15]
          $_bytes = Protect-Data -Bytes $_bytes -Scope $this.SecScope -Entropy $Entropy
          $this.PsObject.properties.add([psscriptproperty]::new('Bytes', [scriptblock]::Create($_bytes)))
        }
      )
    )
    $this.PsObject.Methods.Add(
      [psscriptmethod]::new(
        'UnProtect', {
          $_bytes = $this.Bytes; $Entropy = [Encoding]::UTF8.GetBytes([CryptobaseUtils]::GetUniqueMachineId())[0..15]
          $_bytes = UnProtect-Data -Bytes $_bytes -Entropy $Entropy -Scope $this.SecScope
          $this.PsObject.properties.add([psscriptproperty]::new('Bytes', [scriptblock]::Create($_bytes)))
        }
      )
    )
    $this.PsObject.Methods.Add(
      [psscriptmethod]::new(
        'Tostring', {
          return $this.PsObject.properties.value[0].name
        }
      )
    )
  }
}

class SecretStore {
  [string]$Name
  [uri]$Url
  static hidden [ValidateNotNullOrWhiteSpace()][string]$DataPath

  SecretStore([string]$Name) {
    $this.Name = $Name
    if ([string]::IsNullOrWhiteSpace([SecretStore]::DataPath)) {
      [SecretStore]::DataPath = [IO.Path]::Combine([CryptobaseUtils]::Get_dataPath('ArgonCage', 'Data'), 'secrets')
    }
    $this.psobject.Properties.Add([psscriptproperty]::new('File', {
          return [FileInfo]::new([IO.Path]::Combine([SecretStore]::DataPath, $this.Name))
        }, {
          param($value)
          if ($value -is [IO.FileInfo]) {
            [SecretStore]::DataPath = $value.Directory.FullName
            $this.Name = $value.Name
          } else {
            throw "Invalid value assigned to File property"
          }
        }
      )
    )
    $this.psobject.Properties.Add([psscriptproperty]::new('Size', {
          if ([IO.File]::Exists($this.File.FullName)) {
            $this.File = Get-Item $this.File.FullName
            return $this.File.Length
          }
          return 0
        }, { throw "Cannot set Size property" }
      )
    )
  }
}
