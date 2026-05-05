# Armor

> **Note:** This documentation was automatically generated.

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


