# OpenPGP & Armor

Utilities for working with OpenPGP-compatible ASCII armor. This is used to convert binary cryptographic data into a text-based format that can be easily shared via email or chat.

## OpenPgp

Convenience class for handling PGP-armored messages.

### ArmorMessage
Converts binary data into a standard `-----BEGIN PGP MESSAGE-----` block.

```powershell
$data = [System.Text.Encoding]::UTF8.GetBytes("Secret content")
$headers = [System.Collections.Generic.Dictionary[string,string]]::new()
$headers["Version"] = "CryptoBase 1.0"

$armored = [OpenPgp]::ArmorMessage($data, $headers)
```

### DearmorMessage
Converts an armored block back into binary data.

```powershell
$binary = [OpenPgp]::DearmorMessage($armored)
```

---

## Armor

Detailed control over ASCII armoring for different types of blocks (Public Keys, Signatures, etc.).

### Usage

```powershell
# Encode a Public Key block
$pubKey = [byte[]]::new(32)
$armoredKey = [Armor]::Encode($pubKey, [ArmorType]::PublicKey, $null)

# Decode any armored block
$result = [Armor]::Decode($armoredKey)
# $result.Data    - The binary data
# $result.Type    - The ArmorType enum value
# $result.Headers - Dictionary of headers
```

### Supported Armor Types
- `Message`
- `PublicKey`
- `PrivateKey`
- `Signature`
- `SignedMessage`

## Security Note

ASCII armor includes a **CRC24** checksum at the bottom (prefixed by `=`). `CryptoBase` automatically verifies this checksum during decoding to ensure the data has not been corrupted during transport.
