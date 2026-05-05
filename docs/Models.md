# Models

> **Note:** This documentation was automatically generated.

## Classes

### Expiration

#### Properties

- $type $Date
- $type $TimeSpan
- $type $TimeStamp
- $type $Type

#### Methods

- `[void] Expiration()`
- `[void] Expiration($Years)`
- `[void] Expiration($Years, $Months)`
- `[void] Expiration($date)`
- `[void] Expiration($dateString)`
- `[void] Expiration($TimeSpan)`
- `[void] Expiration($hours, $minutes, $seconds)`
- `[void] Expiration($days, $hours, $minutes, $seconds)`
- `[void] setTimeStamp($TimeSpan)`
- `hidden [void] setExpType($TimeSpan)`
- `[int] GetDays()`
- `[int] GetMonths()`
- `[int] GetYears()`
- `[string] ToString()`

### HashParser

#### Properties

- $type $OldFormatDescriptor
- $type $NewFormatDescriptor

#### Methods

- `static [HashInformation] GetHashInformation($hash)`
- `static [int] GetWorkFactor($hash)`
- `static [string] GetSalt($hash)`
- `static [bool] IsValidHash($hash, $format)`
- `static [bool] IsValidBCryptVersionChar($value)`
- `static [bool] IsValidBCryptBase64Char($value)`
- `static [bool] IsAsciiNumeric($value)`
- `static [void] ThrowInvalidHashFormat()`

### HashInformation

#### Properties

- $type $Settings
- $type $Version
- $type $WorkFactor
- $type $RawHash

#### Methods

- `[void] HashInformation($settings, $version, $workFactor, $rawHash)`
- `[string] ToString()`

### HashFormatDescriptor

#### Properties

- $type $VersionLength
- $type $WorkfactorOffset
- $type $SettingLength
- $type $HashOffset

#### Methods

- `[void] HashFormatDescriptor($versionLength)`

### CipherObject

#### Methods

- `[void] CipherObject($Object)`

### SecretStore

#### Properties

- $type $Name
- $type $Url
- $type $DataPath

#### Methods

- `[void] SecretStore($Name)`


