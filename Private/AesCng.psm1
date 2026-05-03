#!/usr/bin/env pwsh
using namespace System
using namespace System.IO
using namespace System.Text
using namespace System.Security
using namespace System.Security.Cryptography
using namespace System.Runtime.InteropServices

using module ./Utilities.psm1

# AesCng
# .SYNOPSIS
#     A custom System.Security.Cryptography.AesCng class, for more control on hashing, compression & other stuff.
# .DESCRIPTION
#     A symmetric-key encryption algorithm that is used to protect a variety of sensitive data, including financial transactions and government communications.
#     It is considered to be very secure, and has been adopted as a standard by many governments and organizations around the world.
#
#     Just as [AesCng], by default this class CBC ciphermode, PKCS7 padding, and 256b key & SHA1 to hash (since it has been proven to be more secure than MD5).
#     Plus there is the option to stack encryptions by iteration. (But beware when you iterate much it produces larger output)
class AesCng : CryptobaseUtils {
  static [byte[]] Encrypt([byte[]]$Bytes, [SecureString]$Password) {
    return [AesCng]::Encrypt($Bytes, $Password, [AesCng]::_salt);
  }
  static [byte[]] Encrypt([byte[]]$Bytes, [SecureString]$Password, [byte[]]$Salt) {
    return [AesCng]::Encrypt($Bytes, $Password, $Salt, 'Gzip', $false);
  }
  static [byte[]] Encrypt([byte[]]$Bytes, [SecureString]$Password, [bool]$Protect) {
    return [AesCng]::Encrypt($Bytes, $Password, [AesCng]::_salt, 'Gzip', $Protect);
  }
  static [byte[]] Encrypt([byte[]]$Bytes, [securestring]$Password, [int]$iterations) {
    return [AesCng]::Encrypt($Bytes, $Password, [AesCng]::_salt, $iterations)
  }
  static [byte[]] Encrypt([byte[]]$Bytes, [SecureString]$Password, [byte[]]$Salt, [bool]$Protect) {
    return [AesCng]::Encrypt($Bytes, $Password, $Salt, 'Gzip', $Protect);
  }
  static [byte[]] Encrypt([byte[]]$Bytes, [securestring]$Password, [byte[]]$Salt, [int]$iterations) {
    if ($null -eq $Bytes) { throw [ArgumentNullException]::new('bytes', 'Bytes Value cannot be null.') }
    $_bytes = $Bytes; if ([string]::IsNullOrWhiteSpace([AesGCM]::caller)) { [AesCng]::caller = '[AesCng]' }
    for ($i = 1; $i -lt $iterations + 1; $i++) {
      Write-Host "$([AesCng]::caller) [+] Encryption [$i/$iterations] ...$(
                $_bytes = [AesCng]::Encrypt($_bytes, $Password, $Salt)
            ) Done." -ForegroundColor Yellow
    };
    return $_bytes;
  }
  static [byte[]] Encrypt([byte[]]$Bytes, [SecureString]$Password, [string]$Compression) {
    return [AesCng]::Encrypt($Bytes, $Password, [AesCng]::_salt, $Compression, $false);
  }
  static [byte[]] Encrypt([byte[]]$Bytes, [SecureString]$Password, [byte[]]$Salt, [string]$Compression) {
    return [AesCng]::Encrypt($Bytes, $Password, $Salt, $Compression, $false);
  }
  static [byte[]] Encrypt([byte[]]$Bytes, [SecureString]$Password, [byte[]]$Salt, [string]$Compression, [bool]$Protect) {
    [int]$KeySize = 256; $CryptoProvider = $null; $EncrBytes = $null
    if ($Compression -notin ([Enum]::GetNames('Compression' -as 'Type'))) { throw [InvalidCastException]::new("The name '$Compression' is not a valid [Compression]`$typeName.") }
    Set-Variable -Name CryptoProvider -Scope Local -Visibility Private -Option Private -Value ([AesCryptoServiceProvider]::new());
    $CryptoProvider.KeySize = [int]$KeySize;
    $CryptoProvider.Padding = [PaddingMode]::PKCS7;
    $CryptoProvider.Mode = [CipherMode]::CBC;
    $CryptoProvider.Key = [Rfc2898DeriveBytes]::new(($Password | xconvert ToString), $Salt, 10000, [HashAlgorithmName]::SHA1).GetBytes($KeySize / 8);
    $CryptoProvider.IV = [Rfc2898DeriveBytes]::new(($password | xconvert ToString), $salt, 1, [HashAlgorithmName]::SHA1).GetBytes(16);
    Set-Variable -Name EncrBytes -Scope Local -Visibility Private -Option Private -Value $([Shuffl3r]::Combine($CryptoProvider.CreateEncryptor().TransformFinalBlock($Bytes, 0, $Bytes.Length), $CryptoProvider.IV, $Password));
    if ($Protect) { $EncrBytes = Protect-Data -Bytes $encrBytes -Entropy $Salt -Scope User }
    Set-Variable -Name EncrBytes -Scope Local -Visibility Private -Option Private -Value $(Expand-Data -bytes $EncrBytes -compression $Compression);
    $CryptoProvider.Clear(); $CryptoProvider.Dispose()
    return $EncrBytes
  }
  static [byte[]] Decrypt([byte[]]$Bytes, [SecureString]$Password) {
    return [AesCng]::Decrypt($bytes, $Password, 'Gzip');
  }
  static [byte[]] Decrypt([byte[]]$Bytes, [SecureString]$Password, [byte[]]$Salt) {
    return [AesCng]::Decrypt($bytes, $Password, $Salt, 'GZip', $false);
  }
  static [byte[]] Decrypt([byte[]]$Bytes, [SecureString]$Password, [bool]$UnProtect) {
    return [AesCng]::Decrypt($bytes, $Password, [AesCng]::_salt, 'GZip', $UnProtect);
  }
  static [byte[]] Decrypt([byte[]]$Bytes, [SecureString]$Password, [int]$iterations) {
    return [AesCng]::Decrypt($Bytes, $Password, [AesCng]::_salt, $iterations);
  }
  static [byte[]] Decrypt([byte[]]$Bytes, [SecureString]$Password, [byte[]]$Salt, [bool]$UnProtect) {
    return [AesCng]::Decrypt($bytes, $Password, $Salt, 'GZip', $UnProtect);
  }
  static [byte[]] Decrypt([byte[]]$Bytes, [SecureString]$Password, [byte[]]$salt, [int]$iterations) {
    if ($null -eq $bytes) { throw [ArgumentNullException]::new('bytes', 'Bytes Value cannot be null.') }
    $_bytes = $bytes; if ([string]::IsNullOrWhiteSpace([AesCng]::caller)) { [AesCng]::caller = '[AesCng]' }
    for ($i = 1; $i -lt $iterations + 1; $i++) {
      Write-Host "$([AesCng]::caller) [+] Decryption [$i/$iterations] ...$(
                $_bytes = [AesCng]::Decrypt($_bytes, $Password, $salt)
            ) Done" -ForegroundColor Yellow
    };
    return $_bytes
  }
  static [byte[]] Decrypt([byte[]]$Bytes, [SecureString]$Password, [string]$Compression) {
    return [AesCng]::Decrypt($bytes, $Password, [AesCng]::_salt, $Compression, $false);
  }
  static [byte[]] Decrypt([byte[]]$Bytes, [SecureString]$Password, [byte[]]$Salt, [string]$Compression) {
    return [AesCng]::Decrypt($bytes, $Password, $Salt, $Compression, $false);
  }
  static [byte[]] Decrypt([byte[]]$Bytes, [SecureString]$Password, [byte[]]$Salt, [string]$Compression, [bool]$UnProtect) {
    [int]$KeySize = 256; $CryptoProvider = $null; $DEcrBytes = $null; $_Bytes = $null
    $_Bytes = Expand-Data -b $bytes -c $Compression;
    if ($UnProtect) { $_Bytes = UnProtect-Data -Bytes $_Bytes -Entropy $Salt -Scope User }
    Set-Variable -Name CryptoProvider -Scope Local -Visibility Private -Option Private -Value ([AesCryptoServiceProvider]::new());
    $CryptoProvider.KeySize = $KeySize;
    $CryptoProvider.Padding = [PaddingMode]::PKCS7;
    $CryptoProvider.Mode = [CipherMode]::CBC;
    $CryptoProvider.Key = [Rfc2898DeriveBytes]::new(($Password | xconvert ToString), $Salt, 10000, [HashAlgorithmName]::SHA1).GetBytes($KeySize / 8);
    ($_Bytes, $CryptoProvider.IV) = [Shuffl3r]::Split($_Bytes, $Password, 16);
    Set-Variable -Name DEcrBytes -Scope Local -Visibility Private -Option Private -Value $($CryptoProvider.CreateDecryptor().TransformFinalBlock($_Bytes, 0, $_Bytes.Length))
    $CryptoProvider.Clear(); $CryptoProvider.Dispose();
    return $DEcrBytes
  }
}
