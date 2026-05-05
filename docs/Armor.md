# Armor

ASCII Armoring translates binary cryptographic data into readable ASCII formats (like OpenPGP or PEM).

## Usage Example

```powershell
$data = [byte[]]::new(64); [System.Security.Cryptography.RandomNumberGenerator]::Fill($data)

# Encode to OpenPGP ASCII Armor format
$armored = [Armor]::Encode($data, 'PGP MESSAGE', @{})
Write-Host $armored

# Decode back to raw bytes
$decoded = [Armor]::Decode($armored)
```

## Classes

### ArmorDecodeResult

#### Properties

- $type $Data
- $type $Type
- $type $Headers

### Armor

#### Properties

- $type $LineSeparators
- $type $ARMOR_BEGIN
- $type $ARMOR_END
- $type $ARMOR_SUFFIX
- $type $MAX_LINE_LENGTH

#### Methods

- `static [string] Encode($data, $armorType, $headers)`
- `static [ArmorDecodeResult] Decode($armoredText)`
- `static hidden [string] GetArmorTypeName($type)`
- `static hidden [ArmorType] ParseArmorType($typeName)`



