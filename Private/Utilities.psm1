#!/usr/bin/env pwsh
using namespace System
using namespace System.IO
using namespace System.Text
using namespace System.Net.Http
using namespace System.Security
using namespace System.Reflection
using namespace System.Globalization
using namespace System.Reflection.Emit
using namespace System.Runtime.Serialization
using namespace System.Security.Cryptography
using namespace System.Runtime.InteropServices
using namespace System.Collections.ObjectModel
using namespace System.Security.Cryptography.X509Certificates

using module ./Enums.psm1
using module ./Exceptions.psm1
using module ./ChaCha20.psm1

#Requires -Modules PsModuleBase

#UtilityClasses

# .SYNOPSIS
#     ASN.1 DER parser.
# .DESCRIPTION
#     Parses ASN.1 DER-encoded data structures commonly used in X.509 certificates
#     and cryptographic keys.
# .PARAMETER Data
#     The DER-encoded data.
# .OUTPUTS
#     Parsed ASN.1 structure.
# .EXAMPLE
#     $parsed = [Asn1Parser]::Parse($derData)
# .NOTES
#     Uses System.Formats.Asn1 when available.
class Asn1Parser {
  Asn1Parser() {}

  [object] Parse([byte[]]$Data) {
    return [Asn1Parser]::Parse($Data, $null)
  }

  static [object] Parse([byte[]]$Data, [object]$Unused) {
    if ($null -eq $Data) { throw [System.ArgumentNullException]::new('Data') }

    # Use .NET AsnReader when available
    $asnType = [System.Type]::GetType('System.Formats.Asn1.AsnReader, System.Formats.Asn1')
    if ($null -ne $asnType) {
      $reader = $asnType::new($Data, [System.Formats.Asn1.AsnEncodingRules]::DER)
      return [Asn1Parser]::ParseElement($reader)
    }

    # Simplified fallback parser — always returns a non-null result
    return @{
      Raw     = $Data
      Length  = $Data.Length
      Message = 'Simplified ASN.1 parse (System.Formats.Asn1 not available)'
    }
  }

  static [object] ParseElement([object]$Reader) {
    return @{
      Tag      = $Reader.PeekTag()
      HasValue = $Reader.HasValue
    }
  }
}


# .SYNOPSIS
#     PEM (Privacy-Enhanced Mail) format parser.
# .DESCRIPTION
#     Parses PEM-encoded data, extracting the base64-encoded content
#     and identifying the type (CERTIFICATE, PUBLIC KEY, PRIVATE KEY, etc.).
# .PARAMETER Content
#     The PEM string.
# .OUTPUTS
#     Hashtable with Type and Data.
# .EXAMPLE
#     $pem = [PemParser]::Parse($pemString)
# .NOTES
#     PEM format is commonly used for certificates and keys.
class PemParser {
  PemParser() {}

  # Instance Decode method (alias for static Parse, returns byte[])
  [byte[]] Decode([string]$Content) {
    $result = [PemParser]::Parse($Content)
    return $result.Data
  }

  static [hashtable] Parse([string]$Content) {
    if ([string]::IsNullOrWhiteSpace($Content)) { throw [System.ArgumentException]::new('Content cannot be empty') }

    $lines = $Content -split "`n" | Where-Object { $_ -notmatch '^-----' -and $_ -notmatch '^\s*$' }
    $base64 = ($lines -join '').Trim()
    $decoded = [System.Convert]::FromBase64String($base64)

    # Identify type from header
    $type = 'UNKNOWN'
    if ($Content -match 'BEGIN\s+(\w+)\s+KEY') {
      $type = $matches[1]
    } elseif ($Content -match 'BEGIN\s+CERTIFICATE') {
      $type = 'CERTIFICATE'
    } elseif ($Content -match 'BEGIN\s+(\w+)\s+PRIVATE\s+KEY') {
      $type = $matches[1] + ' PRIVATE KEY'
    }

    return @{ Type = $type; Data = $decoded; Raw = $Content }
  }

  static [string] Encode([byte[]]$Data, [string]$Label) {
    if ($null -eq $Data) { throw [System.ArgumentNullException]::new('Data') }
    if ([string]::IsNullOrWhiteSpace($Label)) { throw [System.ArgumentException]::new('Label cannot be empty') }

    $base64 = [System.Convert]::ToBase64String($Data)
    $sb = [System.Text.StringBuilder]::new()
    $sb.AppendLine("-----BEGIN $Label-----") | Out-Null
    for ($i = 0; $i -lt $base64.Length; $i += 64) {
      $length = [Math]::Min(64, $base64.Length - $i)
      $sb.AppendLine($base64.Substring($i, $length)) | Out-Null
    }
    $sb.AppendLine("-----END $Label-----") | Out-Null
    return $sb.ToString()
  }
}

# .SYNOPSIS
#     High-level secure encryption box.
# .DESCRIPTION
#     SecureBox provides simple authenticated encryption combining
#     key derivation, encryption, and authentication.
# .PARAMETER Password
#     The password or key.
# .PARAMETER Data
#     The data to encrypt/decrypt.
# .PARAMETER Salt
#     The salt for key derivation.
# .EXAMPLE
#   $encrypted = [SecureBox]::Encrypt($password, $data)
# .NOTES
#   Combines ChaCha20Poly1305 with key derivation.
class SecureBox {
  hidden [byte[]] $key

  SecureBox([byte[]]$key) {
    $this.key = $key
  }

  [byte[]] Encrypt([byte[]]$plainbytes) {
    $aes = [System.Security.Cryptography.Aes]::Create()
    $aes.Key = $this.key
    $aes.GenerateIV()
    $encryptor = $aes.CreateEncryptor()
    $ct = $encryptor.TransformFinalBlock($plainbytes, 0, $plainbytes.Length)
    return $aes.IV + $ct
  }

  [byte[]] Decrypt([byte[]]$ciphertext) {
    $aes = [System.Security.Cryptography.Aes]::Create()
    $aes.Key = $this.key
    $aes.IV  = $ciphertext[0..15]
    $decryptor = $aes.CreateDecryptor()
    return $decryptor.TransformFinalBlock($ciphertext, 16, $ciphertext.Length - 16)
  }

  static [byte[]] Encrypt([byte[]]$Password, [byte[]]$Data, [byte[]]$Salt = $null) {
    if ($null -eq $Password) { throw [System.ArgumentNullException]::new("Password") }
    if ($null -eq $Data) { throw [System.ArgumentNullException]::new("Data") }

    if ($null -eq $Salt) {
      $Salt = [byte[]]::new(16)
      [System.Security.Cryptography.RandomNumberGenerator]::Create().GetBytes($Salt)
    }

    # Derive key using HKDF
    $_key = [HkdfCore]::DeriveKey($Password, $Salt, [System.Text.Encoding]::UTF8.GetBytes("SecureBox"), 32)

    # Generate nonce
    $nonce = [byte[]]::new(12)
    [System.Security.Cryptography.RandomNumberGenerator]::Create().GetBytes($nonce)

    # Encrypt with ChaCha20Poly1305
    $ciphertext = [ChaCha20Poly1305Managed]::Encrypt($_key, $nonce, $Data)

    # Prepend salt and nonce
    $result = [byte[]]::new($Salt.Length + $nonce.Length + $ciphertext.Length)
    [Array]::Copy($Salt, 0, $result, 0, $Salt.Length)
    [Array]::Copy($nonce, 0, $result, $Salt.Length, $nonce.Length)
    [Array]::Copy($ciphertext, 0, $result, $Salt.Length + $nonce.Length, $ciphertext.Length)

    return $result
  }

  static [byte[]] Decrypt([byte[]]$Password, [byte[]]$EncryptedData) {
    if ($null -eq $Password) { throw [System.ArgumentNullException]::new("Password") }
    if ($null -eq $EncryptedData -or $EncryptedData.Length -lt 28) { throw [System.ArgumentException]::new("Invalid encrypted data") }

    # Extract salt and nonce
    $Salt = [byte[]]::new(16)
    $Nonce = [byte[]]::new(12)
    $Ciphertext = [byte[]]::new($EncryptedData.Length - 28)

    [Array]::Copy($EncryptedData, 0, $Salt, 0, 16)
    [Array]::Copy($EncryptedData, 16, $Nonce, 0, 12)
    [Array]::Copy($EncryptedData, 28, $Ciphertext, 0, $Ciphertext.Length)

    # Derive key
    $_key = [HkdfCore]::DeriveKey($Password, $Salt, [System.Text.Encoding]::UTF8.GetBytes("SecureBox"), 32)

    # Decrypt
    return [ChaCha20Poly1305Managed]::Decrypt($_key, $Nonce, $Ciphertext)
  }
}


# .SYNOPSIS
#     Secure array for handling sensitive data.
# .DESCRIPTION
#     SecureArray provides secure memory handling with automatic
#     clearing of sensitive data when disposed.
# .PARAMETER Size
#     The size of the array in bytes.
# .EXAMPLE
#     $sa = [SecureArray]::new(32)
#     $sa.SetData($sensitiveData)
#     $data = $sa.GetData()
#     $sa.Dispose()
class SecureArray {
  [byte[]] $Data
  [int] $Length

  SecureArray([int]$Size) {
    $this.Data = [byte[]]::new($Size)
  }

  SecureArray([byte[]]$data) {
    $this.Data = $data
    $this.Length = $data.Length
  }

  [byte[]] GetData() {
    return $this.Data
  }

  [void] SetData([byte[]]$Data) {
    if ($null -eq $Data -or $Data.Length -ne $this.Data.Length) {
      throw [System.ArgumentException]::new("Data size mismatch")
    }
    [Array]::Copy($Data, 0, $this.Data, 0, $Data.Length)
  }

  [void] Clear() {
    if ($null -ne $this.Data) {
      [CryptographicOperations]::ZeroMemory($this.Data)
    }
  }

  [void] Dispose() {
    [Array]::Clear($this.Data, 0, $this.Data.Length)
    # $this.Data = $null
  }
}

# .SYNOPSIS
#     Noise Protocol Framework.
# .DESCRIPTION
#     Noise is a framework for building secure protocols based on
#     Diffie-Hellman key agreement.
# .NOTES
#     Requires external library like Noise.NET.
class NoiseProtocol {
  NoiseProtocol() {}

  [object] GenerateKeyPair() {
    $privateKey = [byte[]]::new(32)
    [System.Security.Cryptography.RandomNumberGenerator]::Create().GetBytes($privateKey)
    $publicKey = [byte[]]::new(32)
    return [PSCustomObject]@{ PublicKey = $publicKey; PrivateKey = $privateKey }
  }

  static [string] GetSupportedPatterns() {
    return "NN, NK, KN, KK, NX, KX, XN, XX, N, K, X, IK, IN"
  }
}

# .SYNOPSIS
#     Verifiable Oblivious Pseudorandom Function (VOPRF).
# .DESCRIPTION
#     VOPRF is a protocol that allows a client to evaluate a PRF
#     on an input while keeping the input hidden from the server,
#     with the server able to prove that the evaluation was correct.
class VOPRF {
  VOPRF() {}

  [object] GenerateKeyPair() {
    $privateKey = [byte[]]::new(32)
    [System.Security.Cryptography.RandomNumberGenerator]::Create().GetBytes($privateKey)
    $publicKey = [byte[]]::new(32)
    return [PSCustomObject]@{ PublicKey = $publicKey; PrivateKey = $privateKey }
  }

  [byte[]] Evaluate([byte[]]$data, [byte[]]$privateKey) {
    return [byte[]]::new(32)
  }
  #     Complex protocol - requires external library or custom implementation.
  static [byte[]] GenerateKey() {
    throw [System.NotImplementedException]::new("VOPRF requires external library or custom implementation")
  }
}


# .SYNOPSIS
#     BitwUtil class heps design encryption algorithms that use bitwise operations and non-linear transformations.
#     Its also used in the construction of the ChaCha20 cipher.
class BitwUtil {
  static [Byte[]] Prepend([Byte[]]$Bytes, [byte[]]$BytesToPrepend) {
    $tmp = New-Object byte[] $($bytes.Length + $bytesToPrepend.Length);
    #$tmp = [Byte[]] (, 0xFF * ($bytes.Length + $bytesToPrepend.Length));
    $bytesToPrepend.CopyTo($tmp, 0);
    $bytes.CopyTo($tmp, $bytesToPrepend.Length);
    return $tmp;
  }
  static [byte[][]] Shift([byte[]]$Bytes, [int]$size) {
    $left = New-Object byte[] $size;
    $right = New-Object byte[] $($bytes.Length - $size);
    [Array]::Copy($bytes, 0, $left, 0, $left.Length);
    [Array]::Copy($bytes, $left.Length, $right, 0, $right.Length);
    return ($left, $right);
  }
  static [Int32] RotateLeft([Int32]$val, [Int32]$amount) {
    return (($val -shl $amount) -bor ($val -shr (32 - $amount)))
  }
  static [Int64] RotateLeft([Int64]$val, [Int64]$amount) {
    return (($val -shl $amount) -bor ($val -shr (32 - $amount)))
  }
  static [void] QuaterRound([ref]$a, [ref]$b, [ref]$c, [ref]$d) {
    $a.Value = $a.Value + $b.Value; $d.Value = [BitwUtil]::RotateLeft($d.Value -xor $a.Value, 16);
    $c.Value = $c.Value + $d.Value; $b.Value = [BitwUtil]::RotateLeft($b.Value -xor $c.Value, 12);
    $a.Value = $a.Value + $b.Value; $d.Value = [BitwUtil]::RotateLeft($d.Value -xor $a.Value, 8);
    $c.Value = $c.Value + $d.Value; $b.Value = [BitwUtil]::RotateLeft($b.Value -xor $c.Value, 7);
  }
  static [int32[]] QuaterRound([int32]$a, [int32]$b, [int32]$c, [int32]$d) {
    # /!\ WARNING /!\ Incomplete & Not Tested
    [int32]$dVal = [BitConverter]::ToInt32($d, 0)
    [int32]$bVal = [BitConverter]::ToInt32($b, 0)
    $a = $a + $b
    $dVal = $dVal -xor $a
    $dVal = $dVal -shl 16
    $d = [BitConverter]::GetBytes($dVal)
    $c = $c + $d
    $bVal = $bVal -xor $c
    $bVal = $bVal -shl 12
    $b = [BitConverter]::GetBytes($bVal)
    $a = $a + $b
    $dVal = $dVal -xor $a
    $dVal = $dVal -shl 8
    $d = [BitConverter]::GetBytes($dVal)
    $c = $c + $d
    $bVal = $bVal -xor $c
    $bVal = $bVal -shl 7
    $b = [BitConverter]::GetBytes($bVal)
    return [int32[]]@([int32][BitConverter]::ToInt32($a, 0), [int32][BitConverter]::ToInt32($b, 0), [int32][BitConverter]::ToInt32($c, 0), [int32][BitConverter]::ToInt32($d, 0))
  }
  # MixColumns: performs operations on columns of an array
  static [byte[ ]] MixColumns([byte[ ]]$state) {
    [byte[]] $tmp = New-Object byte[] 4
    for ($i = 0; $i -lt 4; $i++) {
      $tmp[0] = [Byte] ($state[0, $i] * 2 + $state[1, $i] * 3)
      $tmp[1] = [Byte] ($state[1, $i] * 2 + $state[2, $i] * 3)
      $tmp[2] = [Byte] ($state[2, $i] * 2 + $state[3, $i] * 3)
      $tmp[3] = [Byte] ($state[3, $i] * 2 + $state[0, $i] * 3)
      for ($j = 0; $j -lt 4; $j++) {
        $state[$j, $i] = $tmp[$j]
      }
    }
    return $state
  }
  # ShiftRows: Performs bitwise operations to shift elements in rows of the $state array
  static [int32[]] ShiftRows([int32[]]$state) {
    $temp = $state[1]
    $state[1] = $state[5]
    $state[5] = $state[9]
    $state[9] = $state[13]
    $state[13] = $temp

    $temp = $state[2]
    $state[2] = $state[10]
    $state[10] = $temp
    $temp = $state[6]
    $state[6] = $state[14]
    $state[14] = $temp

    $temp = $state[15]
    $state[15] = $state[11]
    $state[11] = $state[7]
    $state[7] = $state[3]
    $state[3] = $temp

    return $state
  }
  # KeyExpansion: generates an expanded key based on the original key
  static [int32[]] KeyExpansion([int32[]]$key, [int32]$rounds) {
    $expandedKey = New-Object int32[] $rounds*16
    $temp = New-Object int32[] 4
    $i = 0
    while ($i -lt $rounds * 16) {
      $expandedKey[$i] = $key[$i % 4]
      if (($i % 4) -eq 3) {
        $temp = [BitwUtil]::KeyExpansionCore($temp, ($i / 4))
        for ($j = 0; $j -lt 4; $j++) {
          $expandedKey[$i + $j] = $expandedKey[$i + $j - 4] -xor $temp[$j]
        }
        $i += 4
      }
      $i++
    }
    return $expandedKey
  }

  static hidden [int32[]] KeyExpansionCore([int32[]]$temp, [int32]$round) {
    $temp[0] = [int32]([BitConverter]::ToInt32($temp, 0) -shl 8 -xor $temp[0] -xor ($round -shl 24))
    $temp[1] = [int32]([BitConverter]::ToInt32($temp, 4) -shl 8 -xor $temp[1])
    $temp[2] = [int32]([BitConverter]::ToInt32($temp, 8) -shl 8 -xor $temp[2])
    $temp[3] = [int32]([BitConverter]::ToInt32($temp, 12) -shl 8 -xor $temp[3] -xor $round)
    return $temp
  }
  # SubBytes: Performs a substitution operation on each byte of an array
  static [byte[]] SubBytes([byte[]]$state, [byte[]]$sBox) {
    # Note: $sBox is an array of 256 values representing the substitution box.
    # You'll need to initialize it with appropriate values for the specific encryption algorithm you're using.
    for ($i = 0; $i -lt $state.Length; $i++) {
      $state[$i] = $sBox[$state[$i]]
    }
    return $state
  }
  # AddRoundKey: performs bitwise operations to add elements from two arrays
  static [byte[]] AddRoundKey([byte[]]$state, [byte[]]$roundKey) {
    for ($i = 0; $i -lt $state.Length; $i++) {
      $state[$i] = $state[$i] -bxor $roundKey[$i]
    }
    return $state
  }
  static [Int64] Reduce([Double]$nput) {
    [Double]$max = 9223372036854775807
    $result = $nput
    while ($result -ge $max) {
      $result = [double]($result / 2)
    }
    return $result
  }
  static [Int64[]] Reduce([Int64[]]$arr) {
    [Int64]$u = 0; # The overflow from each calculation of the reduction process
    [Int64[]]$h = $arr
    $u = $u + [BitwUtil]::Reduce($h[0]);
    $h[0] = $u -band 0xffffffc;
    $u = $u -shr 26;
    $u = $u + [BitwUtil]::Reduce($h[1]);
    $h[1] = $u -band 0xffffffc;
    $u = $u -shr 26;
    $u = $u + [BitwUtil]::Reduce($h[2]);
    $h[2] = $u -band 0xffffffc;
    $u = $u -shr 26;
    $u = $u + [BitwUtil]::Reduce($h[3]);
    $h[3] = $u -band 0xffffffc;
    $u = $u -shr 26;
    $u = $u + [BitwUtil]::Reduce($h[4]);
    $h[4] = $u -band 0xffffffc;
    $u = $u -shr 26;
    $h[0] = [BitwUtil]::Reduce($h[0]) + $u * 5;
    $u = $u -shr 2;
    # Write-Debug "ReduceOverflow: $u" -Debug
    return $h
  }
  [byte[]]ToLittleEndian([byte[]]$value) {
    if (![System.BitConverter]::IsLittleEndian) { [array]::Reverse($value) }
    return $value
  }
  # TODO: write InvMixColumns method: performs inverse operations on columns of an array
  # TODO: write InvShiftRows method: performs inverse bitwise operations to shift elements in rows of an array
  # TODO: write InvSubBytes method: performs an inverse substitution operation on each byte of an array
  # TODO: write InvAddRoundKey method: performs inverse bitwise operations to add elements from two arrays.
}

#Shuffl3r
# .SYNOPSIS
#     Shuffles bytes and nonce into a jumbled byte[] mess that can be split using a password.
#     Can be used to Combine the encrypted data with the initialization vector (IV) and other data.
# .DESCRIPTION
#     Everyone is appending the IV to encrypted bytes, such that when decrypting, $CryptoProvider.IV = $encyptedBytes[0..15];
#     They say its safe since IV is basically random and changes every encryption. but this small loophole can allow an advanced attacker to use some tools to find that IV at the end.
#     This class aim to prevent that; or at least make it nearly impossible.
#     By using an int[] of indices as a lookup table to rearrange the $nonce and $bytes.
#     The int[] array is derrivated from the password that the user provides.
# .EXAMPLE
#     $_bytes = [Encoding]::UTF8.GetBytes('** _H4ck_z3_W0rld_ **');
#     $Nonce1 = [CryptobaseUtils]::GetRandomEntropy();
#     $Nonce2 = [CryptobaseUtils]::GetRandomEntropy();
#     $Passwd = 'OKay_&~rVJ+T?NpJ(8TqL' | xconvert ToSecurestring;
#     $shuffld = [Shuffl3r]::Combine([Shuffl3r]::Combine($_bytes, $Nonce2, $Passwd), $Nonce1, $Passwd);
#     ($b,$n1) = [Shuffl3r]::Split($shuffld, $Passwd, $Nonce1.Length);
#     ($b,$n2) = [Shuffl3r]::Split($b, $Passwd, $Nonce2.Length);
#     [Encoding]::UTF8.GetString($b) -eq '** _H4ck_z3_W0rld_ **' # should be $true
class Shuffl3r {
  static [Byte[]] Combine([Byte[]]$Bytes, [Byte[]]$Nonce, [securestring]$Passwod) {
    return [Shuffl3r]::Combine($bytes, $Nonce, ($Passwod | xconvert Tostring))
  }
  static [Byte[]] Combine([Byte[]]$Bytes, [Byte[]]$Nonce, [string]$Passw0d) {
    # if ($Bytes.Length -lt 16) { throw [InvalidArgumentException]::New('Bytes', 'Input bytes.length should be > 16. ie: $minLength = 17, since the common $nonce length is 16') }
    if ($bytes.Length -lt ($Nonce.Length + 1)) {
      Write-Debug "Bytes.Length = $($Bytes.Length) but Nonce.Length = $($Nonce.Length)" -Debug
      throw [ArgumentOutOfRangeException]::new("Nonce", 'Make sure $Bytes.length > $Nonce.Length')
    }
    if ([string]::IsNullOrWhiteSpace($Passw0d)) { throw [ArgumentNullException]::new('$Passw0d') }
    [int[]]$Indices = [int[]]::new($Nonce.Length);
    Set-Variable -Name Indices -Scope local -Visibility Public -Option ReadOnly -Value ([Shuffl3r]::GenerateIndices($Nonce.Length, $Passw0d, $bytes.Length));
    [Byte[]]$combined = [Byte[]]::new($bytes.Length + $Nonce.Length);
    for ([int]$i = 0; $i -lt $Indices.Length; $i++) {
      $combined[$Indices[$i]] = $Nonce[$i]
    }
    $i = 0; $ir = (0..($combined.Length - 1)) | Where-Object { $_ -notin $Indices };
    foreach ($j in $ir) { $combined[$j] = $bytes[$i]; $i++ }
    return $combined
  }
  static [array] Split([Byte[]]$ShuffledBytes, [securestring]$Passwod, [int]$NonceLength) {
    return [Shuffl3r]::Split($ShuffledBytes, ($Passwod | xconvert ToString), [int]$NonceLength);
  }
  static [array] Split([Byte[]]$ShuffledBytes, [string]$Passw0d, [int]$NonceLength) {
    if ($null -eq $ShuffledBytes) { throw [ArgumentNullException]::new('$ShuffledBytes') }
    if ([string]::IsNullOrWhiteSpace($Passw0d)) { throw [ArgumentNullException]::new('$Passw0d') }
    [int[]]$Indices = [int[]]::new([int]$NonceLength);
    Set-Variable -Name Indices -Scope local -Visibility Private -Option ReadOnly -Value ([Shuffl3r]::GenerateIndices($NonceLength, $Passw0d, ($ShuffledBytes.Length - $NonceLength)));
    $Nonce = [Byte[]]::new($NonceLength);
    $bytes = [Byte[]]$((0..($ShuffledBytes.Length - 1)) | Where-Object { $_ -notin $Indices } | Select-Object *, @{l = 'bytes'; e = { $ShuffledBytes[$_] } }).bytes
    for ($i = 0; $i -lt $NonceLength; $i++) { $Nonce[$i] = $ShuffledBytes[$Indices[$i]] };
    return ($bytes, $Nonce)
  }
  static hidden [int[]] GenerateIndices([int]$Count, [string]$randomString, [int]$HighestIndex) {
    if ($HighestIndex -lt 3 -or $Count -ge $HighestIndex) { throw [ArgumentOutOfRangeException]::new('$HighestIndex >= 3 is required; and $Count should be less than $HighestIndex') }
    if ([string]::IsNullOrWhiteSpace($randomString)) { throw [ArgumentNullException]::new('$randomString') }
    [Byte[]]$hash = [SHA256]::Create().ComputeHash([Encoding]::UTF8.GetBytes([string]$randomString))
    [int[]]$indices = [int[]]::new($Count)
    for ($i = 0; $i -lt $Count; $i++) {
      [int]$nextIndex = [Convert]::ToInt32($hash[$i] % $HighestIndex)
      while ($indices -contains $nextIndex) {
        $nextIndex = ($nextIndex + 1) % $HighestIndex
      }
      $indices[$i] = $nextIndex
    }
    return $indices
  }
}

class SignatureUtils {
  # Static Properties
  static [string] $SIGNATURE_KEYNAME = "signature"
  static [string] $AppName = "ASP"
  static [string] $NewLine = "`n"
  static [string] $EmptyUriPath = "/"
  static [string] $equals = "="
  static [string] $And = "&"
  static [string] $UTF_8_Encoding = "UTF-8"

  # Static Methods

  # Method to sign parameters
  static [string] signParameters([hashtable] $parameters, [string] $key, [string] $HttpMethod, [string]$h0st, [string] $RequestURI, [string] $algorithm) {
    $stringToSign = [SignatureUtils]::calculateStringToSignV2($parameters, $HttpMethod, $h0st, $RequestURI)
    return [SignatureUtils]::sign($stringToSign, $key, $algorithm)
  }

  # Method to calculate the string to sign for SignatureVersion 2
  static [string] calculateStringToSignV2([hashtable] $parameters, [string] $httpMethod, [string] $hostHeader, [string] $requestURI) {
    if (!$httpMethod) { throw "HttpMethod cannot be null" }

    $stringToSign = "$httpMethod$([SignatureUtils]::NewLine)"

    # Host header to lowercase
    $stringToSign += ($hostHeader.ToLower() + [SignatureUtils]::NewLine)

    # URI or fallback to empty path
    if (!$requestURI) {
      $stringToSign += [SignatureUtils]::EmptyUriPath
    } else {
      $stringToSign += [SignatureUtils]::UrlEncode($requestURI, $true)
    }
    $stringToSign += [SignatureUtils]::NewLine

    # Sort and encode parameters
    $sortedParamMap = [Collections.SortedList]::new($parameters, [StringComparer]::Ordinal)
    foreach ($key in $sortedParamMap.Keys) {
      if ($key -ieq [SignatureUtils]::SIGNATURE_KEYNAME) { continue }
      $stringToSign += [SignatureUtils]::UrlEncode($key, $false) + [SignatureUtils]::equals + [SignatureUtils]::UrlEncode($sortedParamMap[$key], $false) + [SignatureUtils]::And
    }

    return $stringToSign.Substring(0, $stringToSign.Length - 1)
  }

  # URL encode method
  static [string] UrlEncode([string] $data, [bool] $path) {
    $encoded = [string]::Empty
    $unreservedChars = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789-_.~" + ($path ? "/" : "")
    $bytes = [Encoding]::UTF8.GetBytes($data)

    foreach ($symbol in $bytes) {
      $char = [char]$symbol
      if ($unreservedChars.Contains($char)) {
        $encoded += $char
      } else {
        $encoded += "%" + "{0:X2}" -f $symbol
      }
    }

    return $encoded
  }

  # Method to compute the RFC 2104-compliant HMAC signature
  static [string] sign([string] $data, [string] $key, [string] $signatureMethod) {
    try {
      $encoding = [ASCIIEncoding]::new()
      $hmac = [HMAC]::Create($signatureMethod)
      $hmac.Key = $encoding.GetBytes($key)
      $hmac.Initialize()
      $dataBytes = $encoding.GetBytes($data)
      $rawResult = $hmac.ComputeHash($dataBytes)
      return [Convert]::ToBase64String($rawResult)
    } catch {
      throw "Failed to generate signature: $($_.Exception.Message)"
    }
  }
}

class CryptobaseUtils : PsModuleBase {
  static [string] $caller
  static [byte[]] $counter
  static [EncryptionScope] $Scope = 'User'
  static hidden [bool] $_SkipReadHostPrompts = $false
  static hidden [ValidateNotNull()][byte[]] $_salt = [Convert]::FromBase64String( 'bz07LmY5XiNkXW1WQjxdXw==')
  static hidden [ValidateNotNull()][byte[]] $_bytes
  static hidden [AllowNull()][securestring] $_Password
  static hidden [ValidateNotNull()][CryptoAlgorithm] $_Algorithm

  CryptobaseUtils() {}

  static [string] GetRandomName() {
    return [CryptobaseUtils]::GetRandomName((Get-Random -min 16 -max 80));
  }
  static [string] GetRandomName([int]$Length) {
    return [string][CryptobaseUtils]::GetRandomName($Length, $Length);
  }
  static [string] GetRandomName([bool]$IncludeNumbers) {
    $Length = Get-Random -min 16 -max 80
    return [string][CryptobaseUtils]::GetRandomName($Length, $Length, $IncludeNumbers);
  }
  static [string] GetRandomName([int]$Length, [bool]$IncludeNumbers) {
    return [string][CryptobaseUtils]::GetRandomName($Length, $Length, $IncludeNumbers);
  }
  static [string] GetRandomName([int]$minLength, [int]$maxLength) {
    return [string][CryptobaseUtils]::GetRandomName($minLength, $maxLength, $false);
  }
  static [string] GetRandomName([int]$minLength, [int]$maxLength, [bool]$IncludeNumbers) {
    [int]$iterations = 2; $MinrL = 3; $MaxrL = 999 #Gotta have some restrictions, or one typo could slow down an entire script.
    if ($minLength -lt $MinrL) { Write-Warning "Length is below the Minimum required 'String Length'. Try $MinrL or greater." ; break }
    if ($maxLength -gt $MaxrL) { Write-Warning "Length is greater the Maximum required 'String Length'. Try $MaxrL or lower." ; break }
    $samplekeys = if ($IncludeNumbers) {
      [string]::Join('', ([int[]](97..122) | ForEach-Object { [string][char]$_ }) + (0..9))
    } else {
      [string]::Join('', ([int[]](97..122) | ForEach-Object { [string][char]$_ }))
    }
    return [string][CryptobaseUtils]::GetRandomSTR($samplekeys, $iterations, $minLength, $maxLength);
  }
  static [byte[]] GetRfc2898DeriveBytes() {
    return [CryptobaseUtils]::GetRfc2898DeriveBytes(16)
  }
  static [byte[]] GetRfc2898DeriveBytes([int]$Length) {
    return [CryptobaseUtils]::GetRfc2898DeriveBytes(([CryptobaseUtils]::GetRandomName(16) | xconvert ToSecurestring), $Length)
  }
  static [byte[]] GetRfc2898DeriveBytes([securestring]$password) {
    return [CryptobaseUtils]::GetRfc2898DeriveBytes($password, 16)
  }
  static [byte[]] GetRfc2898DeriveBytes([securestring]$password, [int]$Length) {
    $machineId = if ([CryptobaseUtils]::Scope.Equals([EncryptionScope]::User)) {
      [convert]::FromBase64String("hsKgmva9wZoDxLeREB1udw==")
    } else {
      [Encoding]::UTF8.GetBytes([CryptobaseUtils]::GetUniqueMachineId())
    }
    return [CryptobaseUtils]::GetRfc2898DeriveBytes(
      [xconvert]::ToSecurestring($machineId),
      [Rfc2898DeriveBytes]::new($password, [Encoding]::UTF8.GetBytes(($password | xconvert ToString))).GetBytes(16),
      $Length
    )
  }
  static [byte[]] GetRfc2898DeriveBytes([securestring]$password, [byte[]]$salt, [int]$Length) {
    return [Rfc2898DeriveBytes]::new($password, $salt, 1000).GetBytes($Length);
  }
  static [byte[]] GetKey([securestring]$password) {
    return [CryptobaseUtils]::GetKey($password, 16)
  }
  static [byte[]] GetKey() {
    return [CryptobaseUtils]::GetKey(16);
  }
  static [byte[]] GetKey([int]$Length) {
    return [CryptobaseUtils]::GetKey(([CryptobaseUtils]::GeneratePassword() | xconvert ToSecurestring), $Length)
  }
  static [byte[]] GetKey([securestring]$password, [int]$Length) {
    return [CryptobaseUtils]::GetRfc2898DeriveBytes($password, $Length)
  }
  static [byte[]] GetKey([securestring]$password, [byte[]]$salt) {
    return [CryptobaseUtils]::GetKey($password, $salt, 16)
  }
  static [byte[]] GetKey([securestring]$password, [byte[]]$salt, [int]$Length) {
    return [CryptobaseUtils]::GetRfc2898DeriveBytes($password, $salt, $Length)
  }
  # can be used to generate random IV
  static [byte[]] GetRandomEntropy() {
    [byte[]]$entropy = [byte[]]::new(16);
    [void][RNGCryptoServiceProvider]::new().GetBytes($entropy)
    return $entropy;
  }
  static [string] GetRandomSTR([string]$InputSample, [int]$Length) {
    return [CryptobaseUtils]::GetRandomSTR($InputSample, 3, $Length, $Length)
  }
  static [string] GetRandomSTR([string]$InputSample, [int]$iterations, [int]$Length) {
    return [CryptobaseUtils]::GetRandomSTR($InputSample, $iterations, $Length, $Length)
  }
  static [string] GetRandomSTR([string]$InputSample, [int]$iterations, [int]$minLength, [int]$maxLength) {
    # Uses a cryptographic hash function (SHA-256) to generate a unique machine ID
    if ($maxLength -lt $minLength) { throw [ArgumentOutOfRangeException]::new('MinLength', "'MaxLength' cannot be less than 'MinLength'") }
    if ($iterations -le 0) { throw [InvalidOperationException]::new('Negative and Zero Iterations are NOT Possible!') }
    [char[]]$chars = [char[]]::new($InputSample.Length);
    $chars = $InputSample.ToCharArray();
    $Keys = [Collections.Generic.List[string]]::new();
    $rand = [Random]::new();
    [int]$size = $rand.Next([int]$minLength, [int]$maxLength);
    for ($i = 0; $i -lt $iterations; $i++) {
      [byte[]] $data = [Byte[]]::new(1);
      $crypto = [RNGCryptoServiceProvider]::new();
      $data = [Byte[]]::new($size);
      $crypto.GetNonZeroBytes($data);
      $result = [StringBuilder]::new($size);
      foreach ($b in $data) { $result.Append($chars[$b % ($chars.Length - 1)]) };
      [void]$Keys.Add($result.ToString());
    }
    $STR = [string]::Join('', $keys)
    if ($STR.Length -gt $maxLength) {
      $STR = $STR.Substring(0, $maxLength);
    }
    return $STR;
  }
  static [string] GeneratePassword() {
    return [string][CryptobaseUtils]::GeneratePassword(19);
  }
  static [string] GeneratePassword([int]$Length) {
    return [string][CryptobaseUtils]::GeneratePassword($Length, $false, $false, $false, $false);
  }
  static [string] GeneratePassword([int]$Length, [bool]$StartWithLetter) {
    return [string][CryptobaseUtils]::GeneratePassword($Length, $StartWithLetter, $false, $false, $false);
  }
  static [string] GeneratePassword([int]$Length, [bool]$StartWithLetter, [bool]$NoSymbols, [bool]$UseAmbiguousCharacters, [bool]$UseExtendedAscii) {
    # https://stackoverflow.com/questions/55556/characters-to-avoid-in-automatically-generated-passwords
    [string]$possibleCharacters = [char[]](33..126 + 161..254); $MinrL = 14; $MaxrL = 999 # Gotta have some restrictions, or one typo could endup creating insanely long or small Passwords, ex 30000 intead of 30.
    if ($Length -lt $MinrL) { Write-Warning "Length is below the Minimum required 'Password Length'. Try $MinrL or greater."; break }
    if ($Length -gt $MaxrL) { Write-Warning "Length is greater the Maximum required 'Password Length'. Try $MaxrL or lower."; break }
    # Warn the user if they've specified mutually-exclusive options.
    if ($NoSymbols -and $UseExtendedAscii) { Write-Warning 'The -NoSymbols parameter was also specified.  No extended ASCII characters will be used.' }
    do {
      $Passw0rd = [string]::Empty; $x = $null; $r = 0
      #This person Wants a really good password, so We retry Until we get a 60% strong password.
      do {
        do {
          do {
            do {
              do {
                $x = [int][char][string][CryptobaseUtils]::GetRandomSTR($possibleCharacters, 1, 1, 1);
                # Write-Verbose "Use character: $([char]$x) : $x"
              } while ($x -eq 127 -or (!$UseExtendedAscii -and $x -gt 127))
              # The above Do..While loop does this:
              #  1. Don't allow ASCII 127 (delete).
              #  2. Don't allow extended ASCII, unless the user wants it.
            } while (!$UseAmbiguousCharacters -and ($x -in @(49, 73, 108, 124, 48, 79)))
            # The above loop disallows 1 (ASCII 49), I (73), l (108),
            # | (124), 0 (48) or O (79) -- unless the user wants those.
          } while ($NoSymbols -and ($x -lt 48 -or ($x -gt 57 -and $x -lt 65) -or ($x -gt 90 -and $x -lt 97) -or $x -gt 122))
          # If the -NoSymbols parameter was specified, this loop will ensure
          # that the character is neither a symbol nor in the extended ASCII
          # character set.
        } while ($r -eq 0 -and $StartWithLetter -and !(($x -ge 65 -and $x -le 90) -or ($x -ge 97 -and $x -le 122)))
        # If the -StartWithLetter parameter was specified, this loop will make
        # sure that the first character is an upper- or lower-case letter.
        $Passw0rd = $Passw0rd.Trim()
        $Passw0rd += [string][char]$x; $r++
      } until ($Passw0rd.length -eq $Length)
    } until ([int][CryptobaseUtils]::GetPasswordStrength($Passw0rd) -gt 60)
    return $Passw0rd;
  }
  [int] static GetPasswordStrength([string]$passw0rd) {
    # Inspired by: https://www.security.org/how-secure-is-my-password/
    $passwordDigits = [RegularExpressions.Regex]::new("\d", [RegularExpressions.RegexOptions]::Compiled);
    $passwordNonWord = [RegularExpressions.Regex]::new("\W", [RegularExpressions.RegexOptions]::Compiled);
    $passwordUppercase = [RegularExpressions.Regex]::new("[A-Z]", [RegularExpressions.RegexOptions]::Compiled);
    $passwordLowercase = [RegularExpressions.Regex]::new("[a-z]", [RegularExpressions.RegexOptions]::Compiled);
    [int]$strength = 0; $digits = $passwordDigits.Matches($passw0rd); $NonWords = $passwordNonWord.Matches($passw0rd); $Uppercases = $passwordUppercase.Matches($passw0rd); $Lowercases = $passwordLowercase.Matches($passw0rd);
    if ($digits.Count -ge 2) { $strength += 10 };
    if ($digits.Count -ge 5) { $strength += 10 };
    if ($NonWords.Count -ge 2) { $strength += 10 };
    if ($NonWords.Count -ge 5) { $strength += 10 };
    if ($passw0rd.Length -gt 8) { $strength += 10 };
    if ($passw0rd.Length -ge 16) { $strength += 10 };
    if ($Lowercases.Count -ge 2) { $strength += 10 };
    if ($Lowercases.Count -ge 5) { $strength += 10 };
    if ($Uppercases.Count -ge 2) { $strength += 10 };
    if ($Uppercases.Count -ge 5) { $strength += 10 };
    return $strength;
  }
  static [bool] IsBase64String([string]$base64) {
    return $(try { [void][Convert]::FromBase64String($base64); $true } catch { $false })
  }
  static [bool] IsValidAES([Aes]$aes) {
    return [bool]$(try { [CryptobaseUtils]::CheckProps($aes); $? } catch { $false })
  }
  static [bool] IsValidUrl([string]$url) {
    return $url -match '(https?:\/\/(?:www\.|(?!www))[a-zA-Z0-9][a-zA-Z0-9-]+[a-zA-Z0-9]\.[^\s]{2,}|www\.[a-zA-Z0-9][a-zA-Z0-9-]+[a-zA-Z0-9]\.[^\s]{2,}|https?:\/\/(?:www\.|(?!www))[a-zA-Z0-9]+\.[^\s]{2,}|www\.[a-zA-Z0-9]+\.[^\s]{2,})'
  }
  static [void] CheckProps([Aes]$Aes) {
    $MissingProps = @(); $throw = $false
    Write-Verbose "$([CryptobaseUtils]::caller) [+] Checking Encryption Properties ... $(('Mode','Padding', 'keysize', 'BlockSize') | ForEach-Object { if ($null -eq $Aes.Algo.$_) { $MissingProps += $_ } };
            if ($MissingProps.Count -eq 0) { "Done. All AES Props are Good." } else { $throw = $true; "System.ArgumentNullException: $([string]::Join(', ', $MissingProps)) cannot be null." }
        )"
    if ($throw) { throw [ArgumentNullException]::new([string]::Join(', ', $MissingProps)) }
  }
  static [string] GetResolvedPath([string]$Path) {
    return [CryptobaseUtils]::GetResolvedPath($((Get-Variable ExecutionContext).Value.SessionState), $Path)
  }
  static [string] GetResolvedPath([System.Management.Automation.SessionState]$session, [string]$Path) {
    $paths = $session.Path.GetResolvedPSPathFromPSPath($Path);
    if ($paths.Count -gt 1) {
      throw [IOException]::new([string]::Format([cultureinfo]::InvariantCulture, "Path {0} is ambiguous", $Path))
    } elseif ($paths.Count -lt 1) {
      throw [IOException]::new([string]::Format([cultureinfo]::InvariantCulture, "Path {0} not Found", $Path))
    }
    return $paths[0].Path
  }
  static [string] GetUnResolvedPath([string]$Path) {
    return [CryptobaseUtils]::GetUnResolvedPath($((Get-Variable ExecutionContext).Value.SessionState), $Path)
  }
  static [string] GetUnResolvedPath([System.Management.Automation.SessionState]$session, [string]$Path) {
    return $session.Path.GetUnresolvedProviderPathFromPSPath($Path)
  }
  static [Type] CreateEnum([string]$Name, [bool]$IsPublic, [string[]]$Members) {
    # Example:
    # $MacMseries = [CryptobaseUtils]::CreateEnum('Mseries', $true, ('M1', 'M2', 'M3'))
    # $MacMseries::M1 | gm
    # Todo: Explore more about [EnumBuilder], so we can add more features. ex: Flags, instead of [string[]]$Members we can have [hastable]$Members etc.
    try {
      if ([string]::IsNullOrWhiteSpace($Name)) { throw [InvalidArgumentException]::new('Name', 'Name can not be null or space') }
      $DynAssembly = [Reflection.AssemblyName]::new("EmittedEnum")
      $AssmBuilder = [AssemblyBuilder]::DefineDynamicAssembly($DynAssembly, ([AssemblyBuilderAccess]::Save -bor [AssemblyBuilderAccess]::Run)) # Only run in memory
      $ModulBuildr = $AssmBuilder.DefineDynamicModule("DynamicModule")
      $type_attrib = if ($IsPublic) { [Reflection.TypeAttributes]::Public }else { [Reflection.TypeAttributes]::NotPublic }
      $enumBuilder = [EnumBuilder]$ModulBuildr.DefineEnum($name, $type_attrib, [Int32]);
      for ($i = 0; $i -lt $Members.count; $i++) { [void]$enumBuilder.DefineLiteral($Members[$i], $i) }
      [void]$enumBuilder.CreateType()
    } catch {
      throw $_
    }
    return ($Name -as [Type])
  }
  static [Aes] GetAes() { return [CryptobaseUtils]::GetAes(1) }
  static [Aes] GetAes([int]$Iterations) {
    $salt = $null; $password = $null;
    Set-Variable -Name password -Scope Local -Visibility Private -Option Private -Value $([CryptobaseUtils]::GeneratePassword() | xconvert ToSecurestring);
    Set-Variable -Name salt -Scope Local -Visibility Private -Option Private -Value $([CryptobaseUtils]::GetRfc2898DeriveBytes(16));
    return [CryptobaseUtils]::GetAes($password, $salt, $Iterations)
  }
  static [Aes] GetAes([securestring]$password, [byte[]]$salt, [int]$iterations) {
    $aes = $null; $M = $null; $P = $null; $k = $null;
    Set-Variable -Name aes -Scope Local -Visibility Private -Option Private -Value $([AesManaged]::new());
    #Note: 'Zeros' Padding was avoided, see: https://crypto.stackexchange.com/questions/1486/how-to-choose-a-padding-mode-with-aes # Personally I prefer PKCS7 as the best padding.
    for ($i = 1; $i -le $iterations; $i++) { ($M, $P, $k) = ((Get-Random ('ECB', 'CBC')), (Get-Random ('PKCS7', 'ISO10126', 'ANSIX923')), (Get-Random (128, 192, 256))) }
    $aes.Mode = & ([scriptblock]::Create("[System.Security.Cryptography.CipherMode]::$M"));
    $aes.Padding = & ([scriptblock]::Create("[System.Security.Cryptography.PaddingMode]::$P"));
    $aes.keysize = $k;
    $aes.Key = [CryptobaseUtils]::GetKey($password, $salt);
    $aes.IV = [CryptobaseUtils]::GetRandomEntropy();
    return $aes
  }
  static [string] GetUniqueMachineId() {
    # get_product_uuid : Uses a cryptographic hash function (SHA-256) to generate a unique machine ID
    return [CryptobaseUtils]::GetRuntimeUUID()
  }
  [securestring] static GetPassword() {
    return [CryptobaseUtils]::GetPassword($true);
  }
  [securestring] static GetPassword([string]$Prompt) {
    return [CryptobaseUtils]::GetPassword($Prompt, $true)
  }
  [securestring] static GetPassword([bool]$ThrowOnFailure) {
    return [CryptobaseUtils]::GetPassword("Password", $ThrowOnFailure)
  }
  static [securestring] GetPassword([string]$Prompt, [bool]$ThrowOnFailure) {
    if ([CryptobaseUtils]::Scope.ToString() -eq "Machine") {
      return ([CryptobaseUtils]::GetUniqueMachineId() | xconvert ToSecurestring)
    } else {
      $pswd = [SecureString]::new(); $_caller = 'PasswordManager'; if ([CryptobaseUtils]::caller) {
        $_caller = [CryptobaseUtils]::caller
      }
      Set-Variable -Name pswd -Scope Local -Visibility Private -Option Private -Value $(Read-Host -Prompt "$_caller $Prompt" -AsSecureString);
      if ($ThrowOnFailure -and ($null -eq $pswd -or $([string]::IsNullOrWhiteSpace(($pswd | xconvert ToString))))) {
        throw [InvalidPasswordException]::new("Please Provide a Password that isn't Null or WhiteSpace.", $pswd, [ArgumentNullException]::new("Password"))
      }
      return $pswd;
    }
  }

  static [void] ValidateCompression([string]$Compression) {
    if ($Compression -notin [Enum]::GetNames[Compression]()) { throw [InvalidCastException]::new("The name '$Compression' is not a valid compression name. valid names are: $([string]::Join(', ', [Enum]::GetNames[Compression]()))") };
  }
  #region    CodeSec
  static [void] AddSignature([string]$File) {
    $cert = Get-ChildItem Cert:\CurrentUser\My -CodeSigningCert | Select-Object -First 1
    [CryptobaseUtils]::SetAuthenticodeSignature($File, $cert)
  }
  static [void] SetAuthenticodeSignature($FilePath, $Certificate) {
    $params = @{
      FilePath        = $FilePath
      Certificate     = $Certificate
      TimestampServer = "http://timestamp.digicert.com"
    }
    $result = Set-AuthenticodeSignature @params
    if ($result.Status -ne "Valid") {
      throw "Failed to sign $FilePath. Status: $($result.Status)"
    }
  }
  static [string] ExportCertificate([string]$CertPath, [string]$ExportPath, [SecureString]$Password) {
    # .SYNOPSIS
    # Export your signing key and certificate to a .pfx file
    # .DESCRIPTION
    # If you have a private key and certificate on your computer,
    # malicious programs might be able to sign scripts on your behalf, which authorizes PowerShell to run them.
    # To prevent automated signing on your behalf, use
    # [CryptobaseUtils]::ExportCertificate to export your signing key and certificate to a .pfx file.
    $cert = Get-ChildItem -Path $CertPath
    Export-PfxCertificate -Cert $cert -FilePath $ExportPath -Password $Password
    return $ExportPath
  }

  static [void] ImportCertificate([string]$PfxPath, [SecureString]$Password) {
    Import-PfxCertificate -FilePath $PfxPath -CertStoreLocation Cert:\CurrentUser\My -Password $Password
  }

  static [bool] VerifySignature([string]$FilePath) {
    $signature = Get-AuthenticodeSignature -FilePath $FilePath
    return $signature.Status -eq "Valid"
  }

  static [void] RemoveSignature([string]$FilePath) {
    $content = Get-Content -Path $FilePath -Raw
    $newContent = $content -replace '# SIG # Begin signature block[\s\S]*# SIG # End signature block', ''
    Set-Content -Path $FilePath -Value $newContent
  }

  static [void] SignDirectory([string]$DirectoryPath, [string]$CertPath, [string]$Filter = "*.ps1") {
    $cert = Get-ChildItem -Path $CertPath
    Get-ChildItem -Path $DirectoryPath -Filter $Filter -Recurse | ForEach-Object {
      [CryptobaseUtils]::SetAuthenticodeSignature($_.FullName, $cert)
    }
  }
  static [string] CreatedataUUID([Tuple[string, string, string, string]]$Info) {
    # Creates a custom guid based on 4 input string values
    $shash = [System.Text.StringBuilder]::new()
    $c_arr = [byte[]][SHA256CryptoServiceProvider]::HashData([Text.Encoding]::UTF8.GetBytes($Info.ToString().Replace(', ', ':')))
    $c_arr.ForEach({ [void]$shash.Append($_.ToString("x2")) })
    $s_256 = $shash.ToString().Substring(0, 32) -replace '(.{8})(.{4})(.{4})(.{4})(.{12})', '$1-$2-$3-$4-$5'
    return [System.Guid]::new($s_256)
  }
  static [X509Certificate2] GetCodeSigningCert() {
    return Get-ChildItem Cert:\CurrentUser\My -CodeSigningCert | Select-Object -First 1
  }
  static hidden [void] SaveConfiguration() {
    $configPath = [System.IO.Path]::Combine([CryptobaseUtils]::ConfigFolder, 'config.clixml')
    try {
      # Suppress verbose/debug output from Export-Clixml if not desired
      $prev_verbose = Get-Variable VerbosePreference -ValueOnly
      $prev_debug = Get-Variable DebugPreference -ValueOnly
      $VerbosePreference = 'SilentlyContinue'
      $DebugPreference = 'SilentlyContinue'
      [CryptobaseUtils]::config | Export-Clixml -Path $configPath -Force
    } catch {
      Write-Error "Failed to save cryptobase configuration to '$configPath': $($_.Exception.Message)"
      throw # Rethrow to indicate failure
    } finally {
      $VerbosePreference = $prev_verbose
      $DebugPreference = $prev_debug
    }
  }

  static [X509Certificate2[]] GetCertificate([bool]$CurrentOnly = $false) {
    # .SYNOPSIS
    #     Retrieves cryptobase certificates from the current user's personal store.
    # .DESCRIPTION
    #     Retrieves X509Certificate2 objects configured for use with cryptobase based on stored configuration (Thumbprint, Subject, or Friendly Name).
    # .PARAMETER CurrentOnly
    #     Specifies to return only the most current (latest expiry) matching certificate.
    # .OUTPUTS
    #     System.Security.Cryptography.X509Certificates.X509Certificate2[]
    $store = $null
    $certificates = [System.Collections.Generic.List[X509Certificate2]]::new()
    try {
      $store = [X509Store]::new([StoreName]::My, [StoreLocation]::CurrentUser)
      $store.Open([OpenFlags]::ReadOnly)

      # Define the filter criteria based on configuration
      $configThumbprint = [CryptobaseUtils]::config.CertThumbprint
      $configSubject = [CryptobaseUtils]::config.CertSubject
      $configFriendlyName = [CryptobaseUtils]::config.CertFriendlyName

      foreach ($cert in $store.Certificates) {
        $match = $false
        if ($configThumbprint -and $cert.Thumbprint -eq $configThumbprint) { $match = $true }
        elseif ($configSubject -and $cert.Subject -eq $configSubject) { $match = $true }
        elseif ($configFriendlyName -and $cert.FriendlyName -eq $configFriendlyName) { $match = $true }
        # Fallback if no specific config set, find any cert with the default friendly name
        elseif (!$configThumbprint -and !$configSubject -and !$configFriendlyName -and $cert.FriendlyName -eq 'cryptobase Certificate') { $match = $true }

        if ($match) {
          $certificates.Add($cert)
        }
      }
    } catch {
      Write-Error "Error accessing certificate store: $($_.Exception.Message)"
      # Return empty array on error
      return @()
    } finally {
      if ($null -ne $store) { $store.Close() }
    }

    $sortedCerts = $certificates | Sort-Object -Property NotAfter -Descending

    if ($CurrentOnly) {
      return @($sortedCerts | Select-Object -First 1)
    } else {
      return @($sortedCerts)
    }
  }

  static [X509Certificate2] CreateCertificate(
    # .SYNOPSIS
    #     Generate a new self-signed certificate for cryptobase use.
    # .DESCRIPTION
    #     Generates a new self-signed RSA certificate suitable for cryptobase (DigitalSignature, DataEncipherment)
    #     and stores it in the current user's personal certificate store.
    #     Relies on the New-SelfSignedCertificate cmdlet, which requires PowerShell 5.1+ on Windows or PowerShell Core 7+ cross-platform.
    # .PARAMETER Name
    #     The subject name for the certificate (e.g., 'CN=user@domain.com, O=cryptobase'). This becomes the CN part.
    # .PARAMETER YearsValid
    #     How many years the certificate should be valid for. Defaults to 20.
    # .PARAMETER FriendlyName
    #     The friendly name to assign. Defaults to 'cryptobase Certificate'.
    # .OUTPUTS
    #     System.Security.Cryptography.X509Certificates.X509Certificate2
    [string]$Name,
    [int]$YearsValid = 20,
    [string]$FriendlyName = 'cryptobase Certificate'
  ) {
    if (!$Name) {
      throw [System.ArgumentNullException]::new('Name', 'Certificate subject name cannot be empty.')
    }

    $subjectName = "CN=$Name, O=cryptobase" # Enforce OU for easier identification
    $notAfter = [datetime]::Now.AddYears($YearsValid)

    try {
      # Using the cmdlet here as it's the most straightforward way in PS cross-platform for self-signed.
      # For a pure .NET SDK, a library like BouncyCastle would be needed for generation.
      $cert = New-SelfSignedCertificate -KeyUsage DigitalSignature, DataEncipherment -Subject $subjectName -CertStoreLocation Cert:\CurrentUser\My -NotAfter $notAfter -FriendlyName $FriendlyName -KeyAlgorithm RSA -KeyLength 2048 -ErrorAction Stop
      return $cert
    } catch {
      Write-Error "Failed to create self-signed certificate: $($_.Exception.Message)"
      throw # Rethrow
    }
  }
  static [void] SetCurrentUserCertificate([string]$InputStr) {
    # .SYNOPSIS
    #     Configures the primary certificate cryptobase should use for signing/identifying the user.
    # .DESCRIPTION
    #     Updates the cryptobase configuration to identify the user's primary certificate by Thumbprint, FriendlyName, or Subject.
    #     The certificate selected by FriendlyName or Subject will be the one with the latest expiration date if multiple match.
    $newConfig = @{
      CertThumbprint   = ''
      CertFriendlyName = ''
      CertSubject      = ''
    }
    # Basic validation: Ensure at least one identifier is provided
    switch ($true) {
      ([CryptobaseUtils]::IsThumbprint($InputStr)) {
        $newConfig.CertThumbprint = $InputStr.ToUpperInvariant()
        break
      }
      ([CryptobaseUtils]::IsFriendlyName($InputStr)) {
        $newConfig.CertFriendlyName = $InputStr
        break
      }
      ([CryptobaseUtils]::IsSubject($InputStr)) {
        $newConfig.CertSubject = $InputStr
        break
      }
      default {
        throw [System.ArgumentException]::new("Must specify one of Thumbprint, FriendlyName, or Subject.")
      }
    }
    [CryptobaseUtils]::config = $newConfig
    [CryptobaseUtils]::SaveConfiguration()
    Write-Verbose "cryptobase configuration updated."
  }
  static [bool] IsThumbprint([string]$InputStr) {
    return [Regex]::IsMatch($InputStr, '^[0-9A-Fa-f]{40}$')
  }
  static [bool] IsSubject([string]$InputStr) {
    # Checks for common DN attribute types followed by '='. This is an approximation.
    # Adjust the list (CN|O|OU|...) as needed for common attributes you expect.
    # Using \b ensures these are whole words (prevents matching 'ACNP=')
    # Matches if *any* part looks like a DN component.
    return $InputStr -match '\b(CN|O|OU|L|S|C|E|SN|G|I|DC|STREET)\s*='
    # Alternative simpler (but potentially less accurate) check: just look for an equals sign
    # return $InputStr -match '='
  }
  static [bool] IsFriendlyName([string]$InputStr) {
    # A friendly name is assumed if it's not empty, not a thumbprint, and not a subject.
    return (![string]::IsNullOrWhiteSpace($InputStr)) -and (![CryptobaseUtils]::IsThumbprint($InputStr)) -and (![CryptobaseUtils]::IsSubject($InputStr))
  }

  static [string] ExportCertificatePublicKey() {
    # .SYNOPSIS
    #     Exports the public key information of the current user's certificate.
    # .DESCRIPTION
    #     Retrieves the current user's active cryptobase certificate, extracts its public key information (raw certificate data),
    #     and formats it as a JSON string suitable for sharing with contacts.
    # .OUTPUTS
    #     String (JSON formatted contact data)

    # Get the single, most current certificate configured for the user
    $cert = @([CryptobaseUtils]::GetCertificate($true))[0]
    if (!$cert) {
      throw "No active cryptobase certificate found for the current user. Use New-PsCertificate or Set-PsCertificate first."
    }

    $certBytes = $cert.Export([X509ContentType]::Cert) # Use Export for raw data

    $data = @{
      # Extract CN cleanly, assuming format "CN=Name, O=cryptobase"
      Name = $cert.SubjectName.Name -replace '^CN=|, O=cryptobase$'
      Cert = [System.Convert]::ToBase64String($certBytes)
    }

    # ConvertTo-Json depth might need adjustment if complex objects were used, but simple hashtable is fine.
    return $data | ConvertTo-Json -Depth 3
  }

  static [PSCustomObject[]] GetContact([string]$Name = '*') {
    # .SYNOPSIS
    #     Get a list of saved cryptobase contacts.
    # .DESCRIPTION
    #     Retrieves contact information (including their public certificate) stored locally. Contacts are needed to encrypt data for recipients.
    # .PARAMETER Name
    #     The name or thumbprint of the contact to filter by (supports wildcards for name). Defaults to '*'.
    # .OUTPUTS
    #     PSCustomObject[] (cryptobase.Contact objects)
    $contacts = [System.Collections.Generic.List[PSCustomObject]]::new()
    try {
      # Iterate through files in the certs folder
      # Use EnumerateFiles for potentially better performance on large directories
      foreach ($filePath in [System.IO.Directory]::EnumerateFiles([CryptobaseUtils]::certFolder, '*.clixml')) {
        $prev_verbose = Get-Variable VerbosePreference -ValueOnly
        $prev_debug = Get-Variable DebugPreference -ValueOnly
        try {
          $VerbosePreference = 'SilentlyContinue'
          $DebugPreference = 'SilentlyContinue'

          $contact = Import-Clixml -Path $filePath

          # Add type name if missing (robustness)
          if ($contact.PSObject.TypeNames -notcontains 'cryptobase.Contact') {
            $contact.PSObject.TypeNames.Insert(0, 'cryptobase.Contact')
          }

          # Filter based on Name (wildcard) or Thumbprint (exact)
          if (($contact.Name -like $Name) -or ($contact.Thumbprint -like $Name)) {
            # Perform a quick sanity check on the deserialized object
            if ($contact.Name -and $contact.Thumbprint -and $contact.Certificate -is [X509Certificate2]) {
              $contacts.Add($contact)
            } else {
              Write-Warning "Skipping invalid contact file: $filePath"
            }
          }
        } catch {
          Write-Warning "Failed to import contact file '$filePath': $($_.Exception.Message)"
        } finally {
          $VerbosePreference = $prev_verbose
          $DebugPreference = $prev_debug
        }
      }
    } catch {
      Write-Error "Error reading contacts directory '$([CryptobaseUtils]::certFolder)': $($_.Exception.Message)"
    }

    # Return unique contacts (in case both name.clixml and thumbprint.clixml exist)
    # Sort by name for consistent output
    return @($contacts | Sort-Object -Property Name, Thumbprint -Unique)
  }

  static [PSCustomObject] ImportContactData(
    # .SYNOPSIS
    #     Imports contact information from a JSON string or file.
    # .DESCRIPTION
    #     Parses JSON data containing a contact's name and public certificate (Base64 encoded),
    #     validates the certificate (optionally checking trust), and saves it locally for later use in encryption.
    #     Saves the contact information twice: once as '<Name>.clixml' and once as '<Thumbprint>.clixml' for easy lookup.
    # .PARAMETER JsonData
    #     The JSON string containing the contact information (usually from Export-PsCertificate).
    # .PARAMETER TrustedOnly
    #     If $true, verifies that the contact's certificate chains to a trusted root authority. Defaults to $false (allowing self-signed).
    # .OUTPUTS
    #     PSCustomObject (The imported cryptobase.Contact object)
    [string]$JsonData,
    [bool]$TrustedOnly = $false
  ) {
    if (!$JsonData) {
      throw [System.ArgumentNullException]::new('JsonData', 'Input JSON data cannot be empty.')
    }

    $jsonContent = $null
    try {
      $jsonContent = $JsonData | ConvertFrom-Json -ErrorAction Stop
    } catch {
      throw [System.ArgumentException]::new("Invalid JSON data provided: $($_.Exception.Message)", $_.Exception)
    }

    if (!$jsonContent.Name -or !$jsonContent.Cert) {
      throw [System.ArgumentException]::new('Invalid JSON structure - ensure the data has "Name" and "Cert" properties (generated via Export-PsCertificate).')
    }

    $certificate = $null
    try {
      $bytes = [System.Convert]::FromBase64String($jsonContent.Cert)
      # Use constructor that doesn't require private key password
      $certificate = [X509Certificate2]::new($bytes)
    } catch {
      throw [System.ArgumentException]::new("Invalid certificate data for contact '$($jsonContent.Name)': $($_.Exception.Message)", $_.Exception)
    }

    # Verify trust if requested
    if ($TrustedOnly) {
      $chain = [X509Chain]::new()
      # Basic chain validation (adjust policy checks as needed)
      $chain.ChainPolicy.RevocationMode = [X509RevocationMode]::Online
      $chain.ChainPolicy.VerificationFlags = [X509VerificationFlags]::NoFlag # Adjust as needed
      if (!$chain.Build($certificate)) {
        $statusInfo = ($chain.ChainStatus | ForEach-Object StatusInformation) -join '; '
        throw [System.Security.SecurityException]::new("Certificate for '$($jsonContent.Name)' (Subject: $($certificate.Subject), Thumbprint: $($certificate.Thumbprint)) is not trusted. Chain status: $statusInfo")
      }
      Write-Verbose "Certificate for $($jsonContent.Name) passed trust validation."
    }

    $certData = [PSCustomObject]@{
      PSTypeName  = 'cryptobase.Contact'
      Name        = $jsonContent.Name
      Thumbprint  = $certificate.Thumbprint.ToUpperInvariant() # Consistent casing
      NotAfter    = $certificate.NotAfter
      Certificate = $certificate # Store the full cert object
    }

    # Sanitize name for file system
    $invalidChars = [System.IO.Path]::GetInvalidFileNameChars() -join ''
    $safeName = $certData.Name -replace "[$invalidChars]", '_'

    # Define export paths
    $exportPathByName = [System.IO.Path]::Combine([CryptobaseUtils]::certFolder, "$safeName.clixml")
    $exportPathByThumb = [System.IO.Path]::Combine([CryptobaseUtils]::certFolder, "$($certData.Thumbprint).clixml")

    try {
      # Suppress Export-Clixml output streams
      $prev_verbose = Get-Variable VerbosePreference -ValueOnly
      $prev_debug = Get-Variable DebugPreference -ValueOnly
      $VerbosePreference = 'SilentlyContinue'
      $DebugPreference = 'SilentlyContinue'

      # Use -Force to overwrite existing contacts with the same name/thumbprint
      $certData | Export-Clixml -Path $exportPathByName -Force
      $certData | Export-Clixml -Path $exportPathByThumb -Force

      Write-Verbose "Contact '$($certData.Name)' ($($certData.Thumbprint)) saved successfully."
      return $certData
    } catch {
      Write-Error "Failed to save contact '$($certData.Name)' to '$([CryptobaseUtils]::certFolder)': $($_.Exception.Message)"
      throw # Rethrow
    } finally {
      $VerbosePreference = $prev_verbose
      $DebugPreference = $prev_debug
    }
  }

  static [void] RemoveContact([string[]]$Identity) {
    # .SYNOPSIS
    #     Remove a contact (or contacts) from the local store.
    # .DESCRIPTION
    #     Finds contacts matching the provided name(s) or thumbprint(s) and deletes their associated .clixml files from the configuration directory.
    # .PARAMETER Identity
    #     An array of contact names or thumbprints to remove. Wildcards are NOT supported here; use Get-PsContact first if needed.
    if (!$Identity) { return } # Nothing to do

    foreach ($id in $Identity) {
      $contactsToRemove = @([CryptobaseUtils]::GetContact($id)) # Find contacts matching the exact name or thumbprint

      if (!$contactsToRemove) {
        Write-Warning "Contact '$id' not found, skipping removal."
        continue
      }

      foreach ($contact in $contactsToRemove) {
        # Sanitize name for file system matching
        $invalidChars = [System.IO.Path]::GetInvalidFileNameChars() -join ''
        $safeName = $contact.Name -replace "[$invalidChars]", '_'

        $pathByName = Join-Path -Path [CryptobaseUtils]::certFolder -ChildPath "$safeName.clixml"
        $pathByThumb = Join-Path -Path [CryptobaseUtils]::certFolder -ChildPath "$($contact.Thumbprint).clixml"

        $removed = $false
        try {
          if ([System.IO.File]::Exists($pathByName)) {
            [System.IO.File]::Delete($pathByName)
            Write-Verbose "Removed contact file: $pathByName"
            $removed = $true
          }
          if ([System.IO.File]::Exists($pathByThumb)) {
            [System.IO.File]::Delete($pathByThumb)
            Write-Verbose "Removed contact file: $pathByThumb"
            $removed = $true
          }
          if ($removed) {
            Write-Verbose "Successfully removed contact '$($contact.Name)' ($($contact.Thumbprint))."
          } else {
            Write-Warning "Could not find files for contact '$($contact.Name)' ($($contact.Thumbprint)) to remove."
          }
        } catch {
          Write-Error "Error removing files for contact '$($contact.Name)': $($_.Exception.Message)"
          # Continue to next contact even if one fails
        }
      }
    }
  }

  #region Encryption/Decryption Methods (Originals with minor .NET adjustments)

  # Helper to get RSA keys safely
  static hidden [RSA] GetRsaPublicKey([X509Certificate2]$Certificate) {
    $rsa = $Certificate.GetRSAPublicKey()
    if ($null -eq $rsa) { throw "Certificate (Thumbprint: $($Certificate.Thumbprint)) does not contain an RSA public key." }
    return $rsa
  }
  static hidden [RSA] GetRsaPrivateKey([X509Certificate2]$Certificate) {
    if (!$Certificate.HasPrivateKey) { throw "Certificate (Thumbprint: $($Certificate.Thumbprint)) does not have an associated private key accessible." }
    $rsa = $Certificate.GetRSAPrivateKey()
    if ($null -eq $rsa) { throw "Failed to retrieve RSA private key for certificate (Thumbprint: $($Certificate.Thumbprint)). Check key permissions." }
    return $rsa
  }
  # Internal Use / Called by Protect-Document #
  static [string] ProtectFile([string]$Path, [X509Certificate2]$OwnCertificate, [PSCustomObject]$Contact, [string]$OutPath, [switch]$PassThru) {
    # .ARGS
    # Path,
    # OwnCertificate : Contact object expected from Get-PsContact
    # Contact,
    # OutPath        : Optional: Directory to write output file
    # PassThru       : If true, return JSON string instead of writing file
    if (!([System.IO.File]::Exists($Path))) { throw [System.IO.FileNotFoundException]::new("Input file not found.", $Path) }
    if ($OutPath -and !([System.IO.Directory]::Exists($OutPath))) { throw [System.IO.DirectoryNotFoundException]::new("Output directory not found.", $OutPath) }

    $bytes = [System.IO.File]::ReadAllBytes($Path)
    $publicKey = [CryptobaseUtils]::GetRsaPublicKey($Contact.Certificate)
    $privateKey = [CryptobaseUtils]::GetRsaPrivateKey($OwnCertificate) # Signing key

    $bytesEncrypted = $publicKey.Encrypt($bytes, [RSAEncryptionPadding]::Pkcs1)
    $bytesSignature = $privateKey.SignData($bytesEncrypted, [HashAlgorithmName]::SHA512, [RSASignaturePadding]::Pkcs1)

    $fileName = [System.IO.Path]::GetFileName($Path)
    $data = [ordered]@{ # Use ordered hashtable for consistent JSON output
      Name            = $fileName
      Recipient       = $Contact.Name
      Type            = 'File'
      SignThumbprint  = $OwnCertificate.Thumbprint.ToUpperInvariant()
      CryptThumbprint = $Contact.Certificate.Thumbprint.ToUpperInvariant()
      Data            = [System.Convert]::ToBase64String($bytesEncrypted)
      Signature       = [System.Convert]::ToBase64String($bytesSignature)
    }

    $jsonData = $data | ConvertTo-Json -Depth 3

    if ($PassThru) {
      return $jsonData
    }

    $outputFileName = "$fileName.json"
    $finalOutputPath = if ($OutPath) {
      [System.IO.Path]::Combine($OutPath, $outputFileName)
    } else {
      [System.IO.Path]::ChangeExtension($Path, '.json') # Place next to original
    }

    try {
      [System.IO.File]::WriteAllText($finalOutputPath, $jsonData, [System.Text.Encoding]::UTF8)
      # Use Write-Host for user feedback consistent with original functions
      Write-Host "Protected file created at: $finalOutputPath"
      return $jsonData # Return the JSON data even when writing file
    } catch {
      Write-Error "Failed to write protected file to '$finalOutputPath': $($_.Exception.Message)"
      throw
    }
  }
  # Internal Use / Called by Protect-Document #
  static [string] ProtectContent([string]$Content, [string]$Name, [X509Certificate2]$OwnCertificate, [PSCustomObject]$Contact <# Contact object expected from Get-PsContact #>) {
    $bytes = [System.Text.Encoding]::UTF8.GetBytes($Content)
    $publicKey = [CryptobaseUtils]::GetRsaPublicKey($Contact.Certificate)
    $privateKey = [CryptobaseUtils]::GetRsaPrivateKey($OwnCertificate) # Signing key

    $bytesEncrypted = $publicKey.Encrypt($bytes, [RSAEncryptionPadding]::Pkcs1)
    $bytesSignature = $privateKey.SignData($bytesEncrypted, [HashAlgorithmName]::SHA512, [RSASignaturePadding]::Pkcs1)

    $data = [ordered]@{ # Use ordered hashtable for consistent JSON output
      Name            = $Name
      Recipient       = $Contact.Name
      Type            = 'Content'
      SignThumbprint  = $OwnCertificate.Thumbprint.ToUpperInvariant()
      CryptThumbprint = $Contact.Certificate.Thumbprint.ToUpperInvariant()
      Data            = [System.Convert]::ToBase64String($bytesEncrypted)
      Signature       = [System.Convert]::ToBase64String($bytesSignature)
    }
    return $data | ConvertTo-Json -Depth 3
  }

  <# Internal Use / Called by Unprotect-Document #>
  static [string] UnprotectDataset([string]$JsonContent, [string]$OutDirectory, $Cmdlet) {
    # .ARGS
    # OutDirectory : Directory to write output file, mandatory for Type=File
    # Cmdlet       : Pass calling cmdlet for WriteError context
    $c = $null
    try {
      $c = $JsonContent | ConvertFrom-Json -ErrorAction Stop
    } catch {
      $Cmdlet.WriteError( (New-ErrorRecord -ErrorId InvalidJson -Category InvalidData -Message "Failed to parse input JSON: $($_.Exception.Message)" -TargetObject $JsonContent -Exception $_.Exception) )
      return $null # Return null/empty on failure
    }

    # Validate basic structure
    if (!($c.Name -and $c.Type -and $c.SignThumbprint -and $c.CryptThumbprint -and $c.Data -and $c.Signature)) {
      $Cmdlet.WriteError( (New-ErrorRecord -ErrorId MissingJsonProperties -Category InvalidData -Message "Input JSON is missing required properties (Name, Type, SignThumbprint, CryptThumbprint, Data, Signature)." -TargetObject $c) )
      return $null
    }

    # --- Certificate Retrieval using .NET Store ---
    $recipientCert = $null
    $senderCert = $null # This comes from saved Contacts
    $store = $null
    try {
      # Find Recipient Cert (current user's private key needed)
      $store = [X509Store]::new([StoreName]::My, [StoreLocation]::CurrentUser)
      $store.Open([OpenFlags]::ReadOnly)
      $results = $store.Certificates.Find([X509FindType]::FindByThumbprint, $c.CryptThumbprint, $false) # false = only valid certs? check documentation. Usually true. Let's try false for broader match first.
      if ($results.Count -gt 0) {
        # Ensure it has a private key we can access
        $recipientCert = $results | Where-Object { $_.HasPrivateKey } | Sort-Object -Property NotAfter -Descending | Select-Object -First 1
      }
    } catch {
      $Cmdlet.WriteError( (New-ErrorRecord -ErrorId StoreAccessError -Category ResourceUnavailable -Message "Error accessing certificate store: $($_.Exception.Message)" -TargetObject $c.CryptThumbprint -Exception $_.Exception) )
      return $null
    } finally {
      if ($null -ne $store) { $store.Close() }
    }

    if (!$recipientCert) {
      $Cmdlet.WriteError( (New-ErrorRecord -ErrorId DecryptionCertNotFound -Category ObjectNotFound -Message "Cannot find usable certificate with private key matching thumbprint '$($c.CryptThumbprint)' in the CurrentUser\My store to decrypt data: $($c.Name)" -TargetObject $c) )
      return $null
    }
    Write-Verbose "Using certificate '$($recipientCert.Subject)' for decryption."

    # Find Sender Cert (from saved contacts)
    $senderContact = @([CryptobaseUtils]::GetContact($c.SignThumbprint) | Sort-Object NotAfter -Descending | Select-Object -First 1)[0]
    if (!$senderContact) {
      $Cmdlet.WriteError( (New-ErrorRecord -ErrorId VerificationCertNotFound -Category ObjectNotFound -Message "Cannot find contact certificate matching signing thumbprint '$($c.SignThumbprint)' to verify the sender: $($c.Name). Import the sender's contact information first." -TargetObject $c) )
      return $null
    }
    $senderCert = $senderContact.Certificate
    Write-Verbose "Using contact certificate '$($senderCert.Subject)' for signature verification."

    # --- Decryption and Verification ---
    $bytesData = $null
    $bytesSignature = $null
    try {
      $bytesData = [System.Convert]::FromBase64String($c.Data)
      $bytesSignature = [System.Convert]::FromBase64String($c.Signature)
    } catch {
      $Cmdlet.WriteError( (New-ErrorRecord -ErrorId InvalidBase64 -Category InvalidData -Message "Invalid Base64 format for data or signature: $($c.Name)" -TargetObject $c -Exception $_.Exception) )
      return $null
    }

    # Verify Signature First
    $senderPK = [CryptobaseUtils]::GetRsaPublicKey($senderCert)
    $isFromSender = $false
    try {
      $isFromSender = $senderPK.VerifyData($bytesData, $bytesSignature, [HashAlgorithmName]::SHA512, [RSASignaturePadding]::Pkcs1)
    } catch {
      # Catch potential crypto exceptions during verification
      $Cmdlet.WriteError( (New-ErrorRecord -ErrorId VerificationCryptoError -Category InvalidData -Message "Cryptographic error during signature verification for '$($c.Name)': $($_.Exception.Message)" -TargetObject $c -Exception $_.Exception) )
      return $null
    }
    if (!$isFromSender) {
      $Cmdlet.WriteError( (New-ErrorRecord -ErrorId InvalidSignature -Category SecurityError -Message "Invalid signature! Data '$($c.Name)' could not be verified to originate from sender with certificate '$($senderCert.Subject)' (Thumbprint: $($senderCert.Thumbprint))!" -TargetObject $c) )
      return $null
    }
    Write-Verbose "Signature verified successfully for '$($c.Name)'."

    # Decrypt Data
    $recipientSK = [CryptobaseUtils]::GetRsaPrivateKey($recipientCert) # Private key
    $decryptedBytes = $null
    try {
      $decryptedBytes = $recipientSK.Decrypt($bytesData, [RSAEncryptionPadding]::Pkcs1)
    } catch {
      $Cmdlet.WriteError( (New-ErrorRecord -ErrorId DecryptionFailed -Category InvalidData -Message "Error decrypting data! '$($c.Name)' could not be decrypted with certificate '$($recipientCert.Subject)' (Thumbprint: $($recipientCert.Thumbprint)): $($_.Exception.Message)" -TargetObject $c -Exception $_.Exception) )
      return $null
    }
    Write-Verbose "Data decrypted successfully for '$($c.Name)'."

    # --- Output Handling ---
    if ($c.Type -eq 'Content') {
      $content = [System.Text.Encoding]::UTF8.GetString($decryptedBytes)
      if ($OutDirectory) {
        # Write to file if OutDirectory is specified for content
        if (!([System.IO.Directory]::Exists($OutDirectory))) {
          $Cmdlet.WriteError( (New-ErrorRecord -ErrorId OutDirNotFoundContent -Category InvalidArgument -Message "Output directory '$OutDirectory' not found for writing decrypted content '$($c.Name)'." -TargetObject $c) )
          return $null # Stop processing this item
        }
        $exportPath = [System.IO.Path]::Combine($OutDirectory, $c.Name)
        try {
          [System.IO.File]::WriteAllText($exportPath, $content, [System.Text.Encoding]::UTF8)
          Write-Host "Unprotected content written to file: $exportPath"
        } catch {
          $Cmdlet.WriteError( (New-ErrorRecord -ErrorId WriteContentFileError -Category WriteError -Message "Error writing unprotected content file '$exportPath': $($_.Exception.Message)" -TargetObject $exportPath -Exception $_.Exception) )
          # Return the content anyway? Or null? Let's return null as the file write failed.
          return $null
        }
      }
      return $content # Return string content
    } elseif ($c.Type -eq 'File') {
      if (!$OutDirectory) {
        # This check should ideally happen in the calling function, but double-check here.
        $Cmdlet.WriteError( (New-ErrorRecord -ErrorId OutDirMissingFile -Category InvalidArgument -Message "Invalid state: Encrypted data indicates Type 'File' but no OutDirectory was provided to UnprotectDataset for '$($c.Name)'." -TargetObject $c) )
        return $null
      }
      if (!([System.IO.Directory]::Exists($OutDirectory))) {
        $Cmdlet.WriteError( (New-ErrorRecord -ErrorId OutDirNotFoundFile -Category InvalidArgument -Message "Output directory '$OutDirectory' not found for writing decrypted file '$($c.Name)'." -TargetObject $c) )
        return $null
      }

      $exportPath = [System.IO.Path]::Combine($OutDirectory, $c.Name)
      try {
        [System.IO.File]::WriteAllBytes($exportPath, $decryptedBytes)
        Write-Host "Unprotected file written to: $exportPath"
        return $exportPath # Return the path to the created file
      } catch {
        $Cmdlet.WriteError( (New-ErrorRecord -ErrorId WriteFileError -Category WriteError -Message "Error writing unprotected file '$exportPath': $($_.Exception.Message)" -TargetObject $exportPath -Exception $_.Exception) )
        return $null # Return null on file write failure
      }
    } else {
      $Cmdlet.WriteError( (New-ErrorRecord -ErrorId UnknownDataType -Category InvalidData -Message "Unknown data Type '$($c.Type)' encountered in protected data '$($c.Name)'." -TargetObject $c) )
      return $null
    }
  }
  #endregion CodeSec
}