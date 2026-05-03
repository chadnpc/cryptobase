#!/usr/bin/env pwsh
using namespace System
using namespace System.IO
using namespace System.Text
using namespace System.Security
using namespace System.Security.Cryptography
using namespace System.Runtime.InteropServices

using module ./Utilities.psm1

# AesGCM class

# .SYNOPSIS
#     A custom AesCGM class, with nerdy Options like compression, iterrations, protection ...
# .DESCRIPTION
#     Both AesCng and AesGcm are secure encryption algorithms, but AesGcm is generally considered to be more secure than AesCng in most scenarios.
#     AesGcm is an authenticated encryption mode that provides both confidentiality and integrity protection. It uses a Galois/Counter Mode (GCM) to encrypt the data, and includes an authentication tag that protects against tampering with or forging the ciphertext.
#     AesCng, on the other hand, only provides confidentiality protection and does not include an authentication tag. This means that an attacker who can modify the ciphertext may be able to undetectably alter the decrypted plaintext.
#     Therefore, it is recommended to use AesGcm whenever possible, as it provides stronger security guarantees compared to AesCng.
# .EXAMPLE
#     $bytes = 'Text_Message1' | xconvert ToBytes; $Password = 'X-aP0jJ_:No=08TfdQ' | xconvert ToSecurestring; $salt = [CryptoBase]::GetRandomEntropy();
#     $enc = [AesGCM]::Encrypt($bytes, $Password, $salt)
#     $dec = [AesGCM]::Decrypt($enc, $Password, $salt)
#     echo ([Encoding]::UTF8.GetString($dec).Trim()) # should be: Text_Message1
# .EXAMPLE
#     $bytes = [Encoding]::UTF8.GetBytes("S3crEt message...")
#     $enc = [Aesgcm]::Encrypt($bytes, (Read-Host -AsSecureString -Prompt "Encryption Password"), 4) # encrypt 4 times!
#     $secmessage = [convert]::ToBase64String($enc)
#
#     # On recieving PC:
#     $dec = [AesGcm]::Decrypt([convert]::FromBase64String($secmessage), (Read-Host -AsSecureString -Prompt "Decryption Password"), 4)
#     echo ([Encoding]::UTF8.GetString($dec)) # should be: S3crEt message...
# .NOTES
#  Todo: Find a working/cross-platform way to protect bytes (Like DPAPI for windows but better) then
#  add static [byte[]] Encrypt([byte[]]$Bytes, [SecureString]$Password, [byte[]]$Salt, [byte[]]$associatedData, [bool]$Protect, [string]$Compression, [int]$iterations)
class AesGCM : CryptobaseUtils {
  static [byte[]] Encrypt([byte[]]$bytes) {
    return [AesGCM]::Encrypt($bytes, [AesGCM]::GetPassword());
  }
  static [byte[]] Encrypt([byte[]]$Bytes, [SecureString]$Password) {
    [byte[]]$_salt = [AesGCM]::GetRfc2898DeriveBytes($Password)
    return [AesGCM]::Encrypt($bytes, $Password, $_salt);
  }
  static [byte[]] Encrypt([byte[]]$Bytes, [SecureString]$Password, [byte[]]$Salt) {
    return [AesGCM]::Encrypt($bytes, $Password, $Salt, $null, $null, 1);
  }
  static [string] Encrypt([string]$text, [SecureString]$Password, [int]$iterations) {
    return [convert]::ToBase64String([AesGCM]::Encrypt([Encoding]::UTF8.GetBytes("$text"), $Password, $iterations));
  }
  static [byte[]] Encrypt([byte[]]$Bytes, [SecureString]$Password, [int]$iterations) {
    [byte[]]$_salt = [AesGCM]::GetRfc2898DeriveBytes($Password)
    return [AesGCM]::Encrypt($bytes, $Password, $_salt, $null, $null, $iterations);
  }
  static [byte[]] Encrypt([byte[]]$Bytes, [SecureString]$Password, [byte[]]$Salt, [int]$iterations) {
    return [AesGCM]::Encrypt($bytes, $Password, $Salt, $null, $null, $iterations);
  }
  static [byte[]] Encrypt([byte[]]$Bytes, [SecureString]$Password, [int]$iterations, [string]$Compression) {
    [byte[]]$_salt = [AesGCM]::GetRfc2898DeriveBytes($Password)
    return [AesGCM]::Encrypt($bytes, $Password, $_salt, $null, $Compression, $iterations);
  }
  static [byte[]] Encrypt([byte[]]$Bytes, [SecureString]$Password, [byte[]]$Salt, [byte[]]$associatedData, [int]$iterations) {
    return [AesGCM]::Encrypt($bytes, $Password, $Salt, $associatedData, $null, $iterations);
  }
  static [byte[]] Encrypt([byte[]]$Bytes, [SecureString]$Password, [byte[]]$Salt, [byte[]]$associatedData) {
    return [AesGCM]::Encrypt($bytes, $Password, $Salt, $associatedData, $null, 1);
  }
  static [byte[]] Encrypt([byte[]]$Bytes, [SecureString]$Password, [byte[]]$Salt, [byte[]]$associatedData, [string]$Compression, [int]$iterations) {
    [int]$IV_SIZE = 0; Set-Variable -Name IV_SIZE -Scope Local -Visibility Private -Option Private -Value 12
    [int]$TAG_SIZE = 0; Set-Variable -Name TAG_SIZE -Scope Local -Visibility Private -Option Private -Value 16
    [string]$Key = $null; Set-Variable -Name Key -Scope Local -Visibility Private -Option Private -Value $([convert]::ToBase64String([Rfc2898DeriveBytes]::new(($Password | xconvert ToString), $Salt, 10000, [HashAlgorithmName]::SHA1).GetBytes(32)));
    [IntPtr]$th = [IntPtr]::new(0); if ([string]::IsNullOrWhiteSpace([AesGCM]::caller)) { [AesGCM]::caller = '[AesGCM]' }
    Set-Variable -Name th -Scope Local -Visibility Private -Option Private -Value $([Marshal]::StringToHGlobalAnsi($TAG_SIZE));
    try {
      $_bytes = $bytes;
      $aes = $null; Set-Variable -Name aes -Scope Local -Visibility Private -Option Private -Value $([ScriptBlock]::Create("[Security.Cryptography.AesGcm]::new([convert]::FromBase64String('$Key'))").Invoke());
      for ($i = 1; $i -lt $iterations + 1; $i++) {
        # Write-Host "$([AesGCM]::caller) [+] Encryption [$i/$iterations] ... Done" -ForegroundColor Yellow
        # if ($Protect) { $_bytes = Protect-Data -bytes $_bytes -entropy $Salt -scope User }
        # Generate a random IV for each iteration:
        [byte[]]$IV = $null; Set-Variable -Name IV -Scope Local -Visibility Private -Option Private -Value ([Rfc2898DeriveBytes]::new(($password | xconvert ToString), $salt, 1, [HashAlgorithmName]::SHA1).GetBytes($IV_SIZE));
        $tag = [byte[]]::new($TAG_SIZE);
        $Encrypted = [byte[]]::new($_bytes.Length);
        [void]$aes.Encrypt($IV, $_bytes, $Encrypted, $tag, $associatedData);
        $_bytes = [Shuffl3r]::Combine([Shuffl3r]::Combine($Encrypted, $IV, $Password), $tag, $Password);
      }
    } catch {
      throw $_
    } finally {
      [void][Marshal]::ZeroFreeGlobalAllocAnsi($th);
      Remove-Variable IV_SIZE, TAG_SIZE, th -ErrorAction SilentlyContinue
    }
    if (![string]::IsNullOrWhiteSpace($Compression)) {
      $_bytes = Compress-Data -b $_bytes -c $Compression
    }
    return $_bytes
  }
  static [void] Encrypt([FileInfo]$File) {
    [AesGCM]::Encrypt($File, [AesGCM]::GetPassword());
  }
  static [void] Encrypt([FileInfo]$File, [securestring]$Password) {
    [AesGCM]::Encrypt($File, $Password, $null);
  }
  static [void] Encrypt([FileInfo]$File, [securestring]$Password, [string]$OutPath) {
    [AesGCM]::Encrypt($File, $password, $OutPath, 1, $null);
  }
  static [void] Encrypt([FileInfo]$File, [securestring]$Password, [string]$OutPath, [int]$iterations) {
    [AesGCM]::Encrypt($File, $password, $OutPath, $iterations, $null);
  }
  static [void] Encrypt([FileInfo]$File, [securestring]$Password, [string]$OutPath, [int]$iterations, [string]$Compression) {
    [ValidateNotNullOrEmpty()][FileInfo]$File = [AesGCM]::GetResolvedPath($File.FullName); if ([string]::IsNullOrWhiteSpace($OutPath)) { $OutPath = $File.FullName }
    [ValidateNotNullOrEmpty()][string]$OutPath = [AesGCM]::GetUnResolvedPath($OutPath);
    if (![string]::IsNullOrWhiteSpace($Compression)) { [AesGCM]::ValidateCompression($Compression) }
    $streamReader = [FileStream]::new($File.FullName, [FileMode]::Open)
    $ba = [byte[]]::New($streamReader.Length);
    [void]$streamReader.Read($ba, 0, [int]$streamReader.Length);
    [void]$streamReader.Close();
    Write-Verbose "$([AesGCM]::caller) Begin file encryption:"
    Write-Verbose "[-]  File    : $File"
    Write-Verbose "[-]  OutFile : $OutPath"
    [byte[]]$_salt = [AesGCM]::GetRfc2898DeriveBytes($Password);
    $encryptdbytes = [AesGCM]::Encrypt($ba, $Password, $_salt, $null, $Compression, $iterations)
    $streamWriter = [FileStream]::new($OutPath, [FileMode]::OpenOrCreate);
    [void]$streamWriter.Write($encryptdbytes, 0, $encryptdbytes.Length);
    [void]$streamWriter.Close()
    [void]$streamReader.Dispose()
    [void]$streamWriter.Dispose()
  }
  static [byte[]] Decrypt([byte[]]$bytes) {
    return [AesGCM]::Decrypt($bytes, [AesGCM]::GetPassword());
  }
  static [byte[]] Decrypt([byte[]]$Bytes, [SecureString]$Password) {
    [byte[]]$_salt = [AesGCM]::GetRfc2898DeriveBytes($Password)
    return [AesGCM]::Decrypt($bytes, $Password, $_salt);
  }
  static [byte[]] Decrypt([byte[]]$Bytes, [SecureString]$Password, [byte[]]$Salt) {
    return [AesGCM]::Decrypt($bytes, $Password, $Salt, $null, $null, 1);
  }
  static [string] Decrypt([string]$text, [SecureString]$Password, [int]$iterations) {
    return [Encoding]::UTF8.GetString([AesGCM]::Decrypt([convert]::FromBase64String($text), $Password, $iterations));
  }
  static [byte[]] Decrypt([byte[]]$Bytes, [SecureString]$Password, [int]$iterations) {
    [byte[]]$_salt = [AesGCM]::GetRfc2898DeriveBytes($Password)
    return [AesGCM]::Decrypt($bytes, $Password, $_salt, $null, $null, $iterations);
  }
  static [byte[]] Decrypt([byte[]]$Bytes, [SecureString]$Password, [byte[]]$Salt, [int]$iterations) {
    return [AesGCM]::Decrypt($bytes, $Password, $Salt, $null, $null, 1);
  }
  static [byte[]] Decrypt([byte[]]$Bytes, [SecureString]$Password, [int]$iterations, [string]$Compression) {
    [byte[]]$_salt = [AesGCM]::GetRfc2898DeriveBytes($Password)
    return [AesGCM]::Decrypt($bytes, $Password, $_salt, $null, $Compression, $iterations);
  }
  static [byte[]] Decrypt([byte[]]$Bytes, [SecureString]$Password, [byte[]]$Salt, [byte[]]$associatedData, [int]$iterations) {
    return [AesGCM]::Decrypt($bytes, $Password, $Salt, $associatedData, $null, $iterations);
  }
  static [byte[]] Decrypt([byte[]]$Bytes, [SecureString]$Password, [byte[]]$Salt, [byte[]]$associatedData) {
    return [AesGCM]::Decrypt($bytes, $Password, $Salt, $associatedData, $null, 1);
  }
  static [byte[]] Decrypt([byte[]]$Bytes, [SecureString]$Password, [byte[]]$Salt, [byte[]]$associatedData, [string]$Compression, [int]$iterations) {
    [int]$IV_SIZE = 0; Set-Variable -Name IV_SIZE -Scope Local -Visibility Private -Option Private -Value 12
    [int]$TAG_SIZE = 0; Set-Variable -Name TAG_SIZE -Scope Local -Visibility Private -Option Private -Value 16
    [string]$Key = $null; Set-Variable -Name Key -Scope Local -Visibility Private -Option Private -Value $([convert]::ToBase64String([Rfc2898DeriveBytes]::new(($Password | xconvert ToString), $Salt, 10000, [HashAlgorithmName]::SHA1).GetBytes(32)));
    [IntPtr]$th = [IntPtr]::new(0); if ([string]::IsNullOrWhiteSpace([AesGCM]::caller)) { [AesGCM]::caller = '[AesGCM]' }
    Set-Variable -Name th -Scope Local -Visibility Private -Option Private -Value $([Marshal]::StringToHGlobalAnsi($TAG_SIZE));
    try {
      $_bytes = if (![string]::IsNullOrWhiteSpace($Compression)) { Expand-Data -bytes $bytes -compression $Compression } else { $bytes }
      $aes = [ScriptBlock]::Create("[Security.Cryptography.AesGcm]::new([convert]::FromBase64String('$Key'))").Invoke()
      for ($i = 1; $i -lt $iterations + 1; $i++) {
        # Write-Host "$([AesGCM]::caller) [+] Decryption [$i/$iterations] ... Done" -ForegroundColor Yellow
        # if ($UnProtect) { $_bytes = UnProtect-Data -bytes $_bytes -entropy $Salt -scope User }
        # Split the real encrypted bytes from nonce & tags then decrypt them:
        ($b, $n1) = [Shuffl3r]::Split($_bytes, $Password, $TAG_SIZE);
        ($b, $n2) = [Shuffl3r]::Split($b, $Password, $IV_SIZE);
        $Decrypted = [byte[]]::new($b.Length);
        $aes.Decrypt($n2, $b, $n1, $Decrypted, $associatedData);
        $_bytes = $Decrypted;
      }
    } catch {
      if ($_.FullyQualifiedErrorId -eq "AuthenticationTagMismatchException") {
        Write-Host "$([AesGCM]::caller) Wrong password" -ForegroundColor Yellow
      }
      throw $_
    } finally {
      [void][Marshal]::ZeroFreeGlobalAllocAnsi($th);
      Remove-Variable IV_SIZE, TAG_SIZE, th -ErrorAction SilentlyContinue
    }
    return $_bytes
  }
  static [void] Decrypt([FileInfo]$File) {
    [AesGCM]::Decrypt($File, [AesGCM]::GetPassword());
  }
  static [void] Decrypt([FileInfo]$File, [securestring]$password) {
    [AesGCM]::Decrypt($File, $password, $null);
  }
  static [void] Decrypt([FileInfo]$File, [securestring]$Password, [string]$OutPath) {
    [AesGCM]::Decrypt($File, $password, $OutPath, 1, $null);
  }
  static [void] Decrypt([FileInfo]$File, [securestring]$Password, [string]$OutPath, [int]$iterations) {
    [AesGCM]::Decrypt($File, $password, $OutPath, $iterations, $null);
  }
  static [void] Decrypt([FileInfo]$File, [securestring]$Password, [string]$OutPath, [int]$iterations, [string]$Compression) {
    [ValidateNotNullOrEmpty()][FileInfo]$File = [AesGCM]::GetResolvedPath($File.FullName); if ([string]::IsNullOrWhiteSpace($OutPath)) { $OutPath = $File.FullName }
    [ValidateNotNullOrEmpty()][string]$OutPath = [AesGCM]::GetUnResolvedPath($OutPath);
    if (![string]::IsNullOrWhiteSpace($Compression)) { [AesGCM]::ValidateCompression($Compression) }
    $streamReader = [FileStream]::new($File.FullName, [FileMode]::Open)
    $ba = [byte[]]::New($streamReader.Length);
    [void]$streamReader.Read($ba, 0, [int]$streamReader.Length);
    [void]$streamReader.Close();
    Write-Verbose "$([AesGCM]::caller) Begin file decryption:"
    Write-Verbose "[-]  File    : $File"
    Write-Verbose "[-]  OutFile : $OutPath"
    [byte[]]$_salt = [AesGCM]::GetRfc2898DeriveBytes($Password);
    $decryptdbytes = [AesGCM]::Decrypt($ba, $Password, $_salt, $null, $Compression, $iterations)
    $streamWriter = [FileStream]::new($OutPath, [FileMode]::OpenOrCreate);
    [void]$streamWriter.Write($decryptdbytes, 0, $decryptdbytes.Length);
    [void]$streamWriter.Close()
    [void]$streamReader.Dispose()
    [void]$streamWriter.Dispose()
  }
}
