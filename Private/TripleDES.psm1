#!/usr/bin/env pwsh
using namespace System
using namespace System.IO
using namespace System.Text
using namespace System.Security
using namespace System.Security.Cryptography
using namespace System.Runtime.InteropServices

using module ./Models.psm1
using module ./Utilities.psm1


#TripleDES
# .SYNOPSIS
#     Triple Des implementation in Powershell
# .EXAMPLE
#     $t = [TripleDES]::new(3004)
#     $e = $t.Encrypt(30) # i.e: 30 times
#     [convert]::ToBase64String($e) > enc.txt
#
#     # On the same PC
#     $n = [TripleDES]::new([convert]::FromBase64String($(Get-Content ./enc.txt)))
#     $d = $n.Decrypt(30)
#     echo (Bytes_To_Object($d)) # should be 3004
# .EXAMPLE
#    # Use static methods
class TripleDES : CryptobaseUtils {
  [ValidateNotNullOrEmpty()][CipherObject]$Object;
  [ValidateNotNullOrEmpty()][SecureString]$Password;
  static hidden [byte[]] $Salt = [Encoding]::UTF7.GetBytes('@Q:j9=`M?EV/h>9_M/esau>A)Y6h>/v^q\ZVMPH\Vu5/E"P_GN`#t6Wnf;ah~[dik.fkj7vpoSqqN]-u`tSS5o26?\u).6YF-9e_5-KQ%kf)A{P4a9/67J8v]:[%i8PW');

  TripleDES([Object]$object) {
    $this.Object = [CipherObject]::new($object)
    $this.Password = [Encoding]::UTF7.GetString([Rfc2898DeriveBytes]::new([CryptobaseUtils]::GetUniqueMachineId(), [TripleDES]::Salt, 1000, [HashAlgorithmName]::SHA1).GetBytes(24)) | xconvert ToSecurestring
  }
  [byte[]]Encrypt() {
    return $this.Encrypt(1);
  }
  [byte[]]Encrypt([int]$iterations) {
    if ($null -eq $this.Object.Bytes) { throw ([System.ArgumentNullException]::new('Object.Bytes')) }
    if ($null -eq $this.Password) { throw ([System.ArgumentNullException]::new('Password')) }
    $this.Object.Psobject.properties.add([psscriptproperty]::new('Bytes', [scriptblock]::Create("[Convert]::FromBase64String('$([convert]::ToBase64String([TripleDES]::Encrypt($this.Object.Bytes, [Rfc2898DeriveBytes]::new(($this.Password | xconvert ToString), [TripleDES]::Salt, 1000, [HashAlgorithmName]::SHA1).GetBytes(24), $null, $iterations)))')")));
    return $this.Object.Bytes
  }
  [byte[]]Decrypt() {
    return $this.Decrypt(1);
  }
  [byte[]]Decrypt([int]$iterations) {
    if ($null -eq $this.Object.Bytes) { throw ([System.ArgumentNullException]::new('Object.Bytes')) }
    if ($null -eq $this.Password) { throw ([System.ArgumentNullException]::new('Password')) }
    $this.Object.Psobject.properties.add([psscriptproperty]::new('Bytes', [scriptblock]::Create("[Convert]::FromBase64String('$([convert]::ToBase64String([TripleDES]::Decrypt($this.Object.Bytes, [Rfc2898DeriveBytes]::new(($this.Password | xconvert ToString), [TripleDES]::Salt, 1000, [HashAlgorithmName]::SHA1).GetBytes(24), $null, $iterations)))')")));
    return $this.Object.Bytes
  }
  static [byte[]] Encrypt([Byte[]]$data, [Byte[]]$Key) {
    return [TripleDES]::Encrypt($data, $Key, $null, 1)
  }
  static [byte[]] Encrypt([Byte[]]$data, [Byte[]]$Key, [Byte[]]$IV) {
    return [TripleDES]::Encrypt($data, $Key, $IV, 1)
  }
  static [byte[]] Encrypt([Byte[]]$data, [Byte[]]$Key, [Byte[]]$IV, [int]$iterations) {
    for ($i = 1; $i -le $iterations; $i++) { $data = [TripleDES]::Get_ED($data, $Key, $IV, $true) }
    return $data
  }
  static [byte[]] Encrypt ([byte]$data, [securestring]$Password) {
    return [TripleDES]::Encrypt($data, $Password, 1);
  }
  static [byte[]] Encrypt ([byte]$data, [string]$Passw0rd, [int]$iterations) {
    return [TripleDES]::Encrypt($data, [Rfc2898DeriveBytes]::new($Passw0rd, [TripleDES]::Salt, 1000, [HashAlgorithmName]::SHA1).GetBytes(24), $null, $iterations);
  }
  static [byte[]] Encrypt ([byte]$data, [securestring]$Password, [int]$iterations) {
    return [TripleDES]::Encrypt($data, ($Password | xconvert ToString), $iterations)
  }
  static [byte[]] Decrypt([Byte[]]$data, [Byte[]]$Key) {
    return [TripleDES]::Decrypt($data, $Key, $null, 1);
  }
  static [byte[]] Decrypt([Byte[]]$data, [Byte[]]$Key, [Byte[]]$IV) {
    return [TripleDES]::Decrypt($data, $Key, $IV, 1);
  }
  static [byte[]] Decrypt([Byte[]]$data, [Byte[]]$Key, [Byte[]]$IV, [int]$iterations) {
    for ($i = 1; $i -le $iterations; $i++) { $data = [TripleDES]::Get_ED($data, $Key, $IV, $false) }
    return $data
  }
  static [byte[]] Decrypt ([byte]$data, [securestring]$Password) {
    return [TripleDES]::Decrypt($data, $Password, 1)
  }
  static [byte[]] Decrypt ([byte]$data, [string]$Passw0rd, [int]$iterations) {
    return [TripleDES]::Decrypt($data, [Rfc2898DeriveBytes]::new($Passw0rd, [TripleDES]::Salt, 1000, [HashAlgorithmName]::SHA1).GetBytes(24), $null, $iterations);
  }
  static [byte[]] Decrypt ([byte]$data, [securestring]$Password, [int]$iterations) {
    return [TripleDES]::Decrypt($data, ($Password | xconvert ToString), $iterations)
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
    } catch [CryptographicException] {
      if ($_.exception.message -notlike "*data is not a complete block*") { throw $_.exception }
    } finally {
      Invoke-Command -ScriptBlock { $tdes.Clear(); $cs.Close(); $ms.Dispose() } -ErrorAction SilentlyContinue
    }
    return $result
  }
}
