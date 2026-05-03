#!/usr/bin/env pwsh
using namespace System
using namespace System.IO
using namespace System.Text
using namespace System.Security
using namespace System.Security.Cryptography
using namespace System.Runtime.InteropServices

using module ./Utilities.psm1

#RSA
# .SYNOPSIS
#     Powershell class implementation of RSA (Rivest-Shamir-Adleman) algorithm.
# .DESCRIPTION
#     A public-key cryptosystem that is widely used for secure data transmission. It is based on the mathematical concept of factoring large composite numbers into their prime factors. The security of the RSA algorithm is based on the difficulty of factoring large composite numbers, which makes it computationally infeasible for an attacker to determine the private key from the public key.
# .EXAMPLE
#     Test-MyTestFunction -Verbose
#     Explanation of the function or its result. You can include multiple examples with additional .EXAMPLE lines
class RSA : CryptobaseUtils {
  # Simply Encrypts the specified data using the public key.
  static [byte[]] Encrypt([byte[]]$data, [string]$publicKeyXml) {
    $rsa = [RSACryptoServiceProvider]::new()
    $rsa.FromXmlString($publicKeyXml)
    return $rsa.Encrypt($data, $true)
  }

  # Decrypts the specified data using the private key.
  static [byte[]] Decrypt([byte[]]$data, [string]$privateKeyXml) {
    $rsa = [RSACryptoServiceProvider]::new()
    $rsa.FromXmlString($privateKeyXml)
    return $rsa.Decrypt($data, $true)
  }

  # The data is encrypted using AES in combination with the password and salt.
  # The encrypted data is then encrypted using RSA.
  static [byte[]] Encrypt([byte[]]$data, [string]$PublicKeyXml, [securestring]$password, [byte[]]$salt) {
    # Generate the AES key and initialization vector from the password and salt
    $aesKey = [Rfc2898DeriveBytes]::new(($password | xconvert ToString), $salt, 1000).GetBytes(32);
    $aesIV = [Rfc2898DeriveBytes]::new(($password | xconvert ToString), $salt, 1000).GetBytes(16);

    # Encrypt the data using AES
    $aes = [AesCryptoServiceProvider]::new(); ($aes.Key, $aes.IV) = ($aesKey, $aesIV);
    $encryptedData = $aes.CreateEncryptor().TransformFinalBlock($data, 0, $data.Length)

    # Encrypt the AES key and initialization vector using RSA
    $rsa = [RSACryptoServiceProvider]::new()
    $rsa.FromXmlString($PublicKeyXml)
    $encryptedKey = $rsa.Encrypt($aesKey, $true)
    $encryptedIV = $rsa.Encrypt($aesIV, $true)

    # Concatenate the encrypted key, encrypted IV, and encrypted data
    # and return the result as a byte array
    return [byte[]]([System.Linq.Enumerable]::Concat($encryptedKey, $encryptedIV, $encryptedData));
  }

  # Decrypts the specified data using the private key.
  # The data is first decrypted using RSA to obtain the AES key and initialization vector.
  # The data is then decrypted using AES.
  static [byte[]] Decrypt([byte[]]$data, [string]$privateKeyXml, [securestring]$password) {
    # Extract the encrypted key, encrypted IV, and encrypted data from the input data
    $encryptedKey = $data[0..255]
    $encryptedIV = $data[256..271]
    $encryptedData = $data[272..$data.Length]

    # Decrypt the AES key and initialization vector using RSA
    $rsa = [RSACryptoServiceProvider]::new()
    # todo: Use the $PASSWORD to decrypt the private key so it can be used
    $rsa.FromXmlString($privateKeyXml)
    $aesKey = $rsa.Decrypt($encryptedKey, $true)
    $aesIV = $rsa.Decrypt($encryptedIV, $true)

    # Decrypt the data using AES
    $aes = [AesCryptoServiceProvider]::new()
    $aes.Key = $aesKey
    $aes.IV = $aesIV
    return $aes.CreateDecryptor().TransformFinalBlock($encryptedData, 0, $encryptedData.Length)
  }
  # Exports the key pair to a file or string. # This can be useful if you want to save the key pair to a file or string for later use.
  # If a file path is specified, the key pair will be saved to the file.
  # If no file path is specified, the key pair will be returned as a string.
  static [void] ExportKeyPair([xml]$publicKeyXml, [string]$privateKeyXml, [string]$filePath = "") {
    $keyPair = @{
      "PublicKey"  = $publicKeyXml
      "PrivateKey" = $privateKeyXml
    }

    if ([string]::IsNullOrWhiteSpace($filePath)) {
      throw 'Invalid FilePath'
    } else {
      # Save the key pair to the specified file
      $keyPair | ConvertTo-Json | Out-File -FilePath $filePath
    }
  }
  static [psobject] LoadKeyPair([string]$filePath = "" ) {
    if ([string]::IsNullOrWhiteSpace($filePath)) {
      throw [ArgumentNullException]::new('filePath')
    }
    return [RSA]::LoadKeyPair((Get-Content $filePath | ConvertFrom-Json))
  }
  static [psobject] LoadKeyPair([string]$filePath = "", [string]$keyPairString = "") {
    return $keyPairString | ConvertFrom-Json
  }

  # Generates a new RSA key pair and returns the public and private key XML strings.
  [byte[]] GenerateKey() {
    $rsa = [RSACryptoServiceProvider]::new()
    ($publicKey, $privateKey) = ($rsa.ToXmlString($false), $rsa.ToXmlString($true))
    return $publicKey, $privateKey
  }
}
