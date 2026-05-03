#!/usr/bin/env pwsh
using namespace System
using namespace System.IO
using namespace System.Text
using namespace System.Security
using namespace System.Security.Cryptography
using namespace System.Runtime.InteropServices

using module ./Utilities.psm1

# ecc classes
# .SYNOPSIS
#     Elliptic Curve Cryptography
# .DESCRIPTION
#     Asymmetric-key encryption algorithms that are known for their strong security and efficient use of resources. They are widely used in a variety of applications, including secure communication, file encryption, and password storage.
# .EXAMPLE
#     $ecc = new ECC($publicKeyXml, $privateKeyXml)
#     $encryptedData = $ecc.Encrypt($data, $password, $salt)
#     $decryptedData = $ecc.Decrypt($encryptedData, $password, $salt)
class ECC : CryptobaseUtils {
  $publicKeyXml = [string]::Empty
  $privateKeyXml = [string]::Empty

  ECC([string]$publicKeyXml, [string]$privateKeyXml) {
    $this.publicKeyXml = $publicKeyXml
    $this.privateKeyXml = $privateKeyXml
  }
  # Encrypts the specified data using the public key.
  # The data is encrypted using AES in combination with the password and salt.
  # Normally I could use System.Security.Cryptography.ECCryptoServiceProvider but for Compatibility reasons
  # I use ECDsaCng class, which provides similar functionality.
  # The encrypted data is then encrypted using ECC.
  # Encrypts the specified data using the public key.
  # The data is encrypted using AES in combination with the password and salt.
  # The encrypted data is then encrypted using ECC.
  [byte[]] Encrypt([byte[]]$data, [securestring]$password, [byte[]]$salt) {
    # Generate the AES key and initialization vector from the password and salt
    $aesKey = [Rfc2898DeriveBytes]::new(($password | xconvert ToString), $salt, 1000).GetBytes(32);
    $aesIV = [Rfc2898DeriveBytes]::new(($password | xconvert ToString), $salt, 1000).GetBytes(16);
    # Encrypt the data using AES
    $aes = New-Object System.Security.Cryptography.AesCryptoServiceProvider
    $aes.Key = $aesKey
    $aes.IV = $aesIV
    $encryptedData = $aes.CreateEncryptor().TransformFinalBlock($data, 0, $data.Length)

    # Encrypt the AES key and initialization vector using ECC
    $ecc = New-Object System.Security.Cryptography.ECDsaCng
    $ecc.FromXmlString($this.publicKeyXml)
    $encryptedKey = $ecc.Encrypt($aesKey, $true)
    $encryptedIV = $ecc.Encrypt($aesIV, $true)

    # Concatenate the encrypted key, encrypted IV, and encrypted data
    # and return the result as a byte array
    return [byte[]]([System.Linq.Enumerable]::Concat($encryptedKey, $encryptedIV, $encryptedData))
    # or:
    # $bytes = New-Object System.Collections.Generic.List[Byte]
    # $bytes.AddRange($encryptedKey)
    # $bytes.AddRange($encryptedIV)
    # $bytes.AddRange($encryptedData)
    # return [byte[]]$Bytes
  }
  # Decrypts the specified data using the private key.
  # The data is first decrypted using ECC to obtain the AES key and initialization vector.
  # The data is then decrypted using AES.
  [byte[]] Decrypt([byte[]]$data, [securestring]$password) {
    # Extract the encrypted key, encrypted IV, and encrypted data from the input data
    $encryptedKey = $data[0..255]
    $encryptedIV = $data[256..271]
    $encryptedData = $data[272..$data.Length]

    # Decrypt the AES key and initialization vector using ECC
    $ecc = [ECDsaCng]::new();
    $ecc.FromXmlString($this.privateKeyXml)
    $aesKey = $ecc.Decrypt($encryptedKey, $true)
    $aesIV = $ecc.Decrypt($encryptedIV, $true)

    # Decrypt the data using AES
    $aes = [AesCryptoServiceProvider]::new();
    $aes.Key = $aesKey
    $aes.IV = $aesIV
    return $aes.CreateDecryptor().TransformFinalBlock($encryptedData, 0, $encryptedData.Length)
  }
  # Generates a new ECC key pair and returns the public and private keys as XML strings.
  [byte[]] GenerateKey() {
    $ecc = [ECDsaCng]::new(256)
    ($publicKey, $privateKey) = ($ecc.ToXmlString($false), $ecc.ToXmlString($true))
    return $publicKey, $privateKey
  }
  # Exports the ECC key pair to a file or string.
  # If a file path is specified, the keys are saved to the file.
  # If a string is specified, the keys are returned as a string.
  # Usage:
  # $ECC.ExportKeyPair("C:\keys.xml")
  [string] ExportKeyPair([string]$file = $null) {
    # Create the key pair XML string
    $keyPairXml = "
            <keyPair>
                <publicKey>$($this.publicKeyXml)</publicKey>
                <privateKey>$($this.privateKeyXml)</privateKey>
            </keyPair>
        "
    # Save the key pair XML to a file or return it as a string
    if ($null -ne $file) {
      $keyPairXml | Out-File -Encoding UTF8 $file
      return $null
    }
    else {
      return $keyPairXml
    }
  }
  # Imports the ECC key pair from a file or string.
  # If a file path is specified, the keys are loaded from the file.
  # If a string is specified, the keys are loaded from the string.
  [void] ImportKeyPair([string]$filePath = $null, [string]$keyPairXml = $null) {
    # Load the key pair XML from a file or string
    if (![string]::IsNullOrWhiteSpace($filePath)) {
      if ([IO.File]::Exists($filePath)) {
        $keyPairXml = Get-Content -Raw -Encoding UTF8 $filePath
      }
      else {
        throw [FileNotFoundException]::new('Unable to find the specified file.', "$filePath")
      }
    }
    else {
      throw [ArgumentNullException]::new('filePath')
    }
    # Extract the public and private key XML strings from the key pair XML
    $publicKey = ([xml]$keyPairXml).keyPair.publicKey
    $privateKey = ([xml]$keyPairXml).keyPair.privateKey

    # Set the public and private key XML strings in the ECC object
    $this.publicKeyXml = $publicKey
    $this.privateKeyXml = $privateKey
  }
}