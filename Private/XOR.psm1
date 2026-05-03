#!/usr/bin/env pwsh
using namespace System
using namespace System.IO
using namespace System.Text
using namespace System.Security
using namespace System.Security.Cryptography
using namespace System.Runtime.InteropServices

using module ./Models.psm1
using module ./Utilities.psm1

# XOR
# .SYNOPSIS
#     Custom Xor implementation in Powershell
# .EXAMPLE
#     $x = [XOR]::new("hello world!")
#     $e = $x.Encrypt(5) # i.e: 5 times
#     [convert]::ToBase64String($e) > xenc.txt
#
#     # On the same PC
#     $n = [XoR]::new([convert]::FromBase64String($(Get-Content ./xenc.txt)))
#     $d = $n.Decrypt(5)
#     echo (Bytes_To_Object($d)) # should be hello world!
# .EXAMPLE
#    # Use static methods
class XOR : CryptobaseUtils {
  [ValidateNotNullOrEmpty()][CipherObject]$Object;
  [ValidateNotNullOrEmpty()][SecureString]$Password;
  static hidden [byte[]] $Salt = [Encoding]::UTF7.GetBytes('\SBOv!^L?XuCFlJ%*[6(pUVp5GeR^|U=NH3FaK#XECOaM}ExV)3_bkd:eG;Z,tWZRMg;.A!,:-k6D!CP>74G+TW7?(\6;Li]lA**2P(a2XxL}<.*oJY7bOx+lD>%DVVa');
  XOR([Object]$object) {
    $this.Object = [CipherObject]::new($object)
    $this.Password = [Encoding]::UTF7.GetString([Rfc2898DeriveBytes]::new([CryptobaseUtils]::GetUniqueMachineId(), [XOR]::Salt, 1000, [HashAlgorithmName]::SHA1).GetBytes(256 / 8)) | xconvert ToSecurestring
  }
  [byte[]] Encrypt() {
    return $this.Encrypt(1)
  }
  [byte[]] Encrypt([int]$iterations) {
    if ($null -eq $this.Object.Bytes) { throw ([System.ArgumentNullException]::new('Object.Bytes')) }
    if ($null -eq $this.Password) { throw ([System.ArgumentNullException]::new('key')) }
    $this.Object.Psobject.properties.add([psscriptproperty]::new('Bytes', [scriptblock]::Create("[Convert]::FromBase64String('$([convert]::ToBase64String([byte[]][XOR]::Encrypt($this.Object.Bytes, $this.Password, $iterations)))')")))
    return $this.Object.Bytes
  }
  static [byte[]] Encrypt([byte[]]$Bytes, [String]$Passw0rd) {
    return [XOR]::Encrypt($bytes, ([Encoding]::UTF7.GetString([Rfc2898DeriveBytes]::new($Passw0rd, [XOR]::Salt, 1000, [HashAlgorithmName]::SHA1).GetBytes(256 / 8)) | xconvert ToSecurestring), 1)
  }
  static [byte[]] Encrypt([byte[]]$Bytes, [SecureString]$password) {
    return [XOR]::Encrypt($bytes, $password, 1)
  }
  static [byte[]] Encrypt([byte[]]$Bytes, [SecureString]$password, [int]$iterations) {
    $xorkey = $password | xconvert ToString, ToBytes;
    return [XOR]::Encrypt($bytes, $xorkey, $iterations)
  }
  static [byte[]] Encrypt([byte[]]$Bytes, [byte[]]$xorkey, [int]$iterations) {
    if ($null -eq $xorkey) {
      throw ([System.ArgumentNullException]::new('xorkey'))
    }
    $_bytes = $bytes;
    for ($i = 1; $i -lt $iterations + 1; $i++) {
      $_bytes = [XOR]::Get_ED($_bytes, $xorkey);
    }; if ($_bytes.Equals($bytes)) { $_bytes = $null }
    return $_bytes
  }
  [byte[]]Decrypt() {
    return $this.Decrypt(1)
  }
  [byte[]]Decrypt([int]$iterations) {
    if ($null -eq $this.Object.Bytes) { throw ([System.ArgumentNullException]::new('Object.Bytes')) }
    if ($null -eq $this.Password) { throw ([System.ArgumentNullException]::new('Password')) }
    $this.Object.Psobject.properties.add([psscriptproperty]::new('Bytes', [scriptblock]::Create("[Convert]::FromBase64String('$([convert]::ToBase64String([byte[]][XOR]::Decrypt($this.Object.Bytes, $this.Password, $iterations)))')")));
    return $this.Object.Bytes
  }
  #!Not Recommended!
  static [byte[]] Decrypt([byte[]]$Bytes, [String]$Passw0rd) {
    return [XOR]::Decrypt($bytes, ([Encoding]::UTF7.GetString([Rfc2898DeriveBytes]::new($Passw0rd, [XOR]::Salt, 1000, [HashAlgorithmName]::SHA1).GetBytes(256 / 8)) | xconvert ToSecurestring), 1);
  }
  static [byte[]] Decrypt([byte[]]$Bytes, [SecureString]$password) {
    return [XOR]::Decrypt($bytes, $password, 1);
  }
  static [byte[]] Decrypt([byte[]]$Bytes, [SecureString]$password, [int]$iterations) {
    $xorkey = $password | xconvert ToString, ToBytes
    return [XOR]::Decrypt($bytes, $xorkey, $iterations);
  }
  static [byte[]] Decrypt([byte[]]$Bytes, [byte[]]$xorkey, [int]$iterations) {
    if ($null -eq $xorkey) {
      throw ([System.ArgumentNullException]::new('xorkey'))
    }
    $_bytes = $bytes; for ($i = 1; $i -lt $iterations + 1; $i++) {
      $_bytes = [XOR]::Get_ED($_bytes, $xorkey)
    };
    return $_bytes;
  }
  static hidden [byte[]] Get_ED([Byte[]]$data, [Byte[]]$Key, [Byte[]]$IV, [bool]$Encrypt) {
    $result = [byte[]]::new(0); $ms = [MemoryStream]::new(); $cs = $null
    try {
      $tdes = [TripleDESCryptoServiceProvider]::new()
      if ($null -eq $Key) { throw ([System.ArgumentNullException]::new('Key')) }else { $tdes.Key = $Key }
      if ($null -eq $IV) { $p4 = [CryptobaseUtils]::GetUniqueMachineId(); $tdes.IV = [Rfc2898DeriveBytes]::new($p4, [TripleDES]::Salt, [int]([int[]][char[]]$p4 | Measure-Object -Sum).Sum, [HashAlgorithmName]::SHA1).GetBytes(8) }else { $tdes.IV = $IV }
      $CryptoTransform = [ICryptoTransform]$(if ($Encrypt) { $tdes.CreateEncryptor() }else { $tdes.CreateDecryptor() })
      $cs = [CryptoStream]::new($ms, $CryptoTransform, [CryptoStreamMode]::Write)
      [void]$cs.Write($data, 0, $data.Length)
      [void]$cs.FlushFinalBlock()
      $ms.Position = 0
      $result = [Byte[]]::new($ms.Length)
      [void]$ms.Read($result, 0, $ms.Length)
    }
    catch [CryptographicException] {
      if ($_.exception.message -notlike "*data is not a complete block*") { throw $_.exception }
    }
    finally {
      Invoke-Command -ScriptBlock { $tdes.Clear(); $cs.Close(); $ms.Dispose() } -ErrorAction SilentlyContinue
    }
    return $result
  }
}