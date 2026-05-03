#!/usr/bin/env pwsh
using namespace System
using namespace System.IO
using namespace System.Text
using namespace System.Security
using namespace System.Security.Cryptography
using namespace System.Runtime.InteropServices

using module ./Utilities.psm1

# AesCtr
# .SYNOPSIS
#   A custom implementation of AES-ctr.
# .DESCRIPTION
#   [CipherMode]::CTR is not available in PowerShell.
#   This class implements the CTR mode manually by XOR-ing with a sequence of counter blocks generated from the given nonce (IV) and block count.
# .NOTES
#    It's awell known standard and recommended to use a more secure ciphermode mode, such as `[System.Security.Cryptography.CipherMode]::GCM` instead of a manual implementing the CTR mode.
#    thus I dont recommend using this class. what a waste!
class AesCtr : CryptobaseUtils {
  static [Byte[]] Encrypt([Byte[]]$Bytes, [byte[]]$Key, [byte[]]$IV) {
    $aes = [AesCryptoServiceProvider]::new()
    $aes.Mode = [CipherMode]::CBC
    $aes.Key = $Key
    $aes.Padding = [PaddingMode]::PKCS7
    [AesCtr]::counter = [Byte[]]::new($aes.BlockSize / 8)
    [Array]::Copy($IV, 0, [AesCtr]::counter, 0, $IV.Length)
    [BitConverter]::GetBytes([AesCtr]::counter).CopyTo([AesCtr]::counter, [AesCtr]::counter.Length - 8)
    [Byte[]]$CipherBytes = [Byte[]]::new($Bytes.Length)
    for ($i = 0; $i -lt $Bytes.Length; $i += $aes.BlockSize / 8) {
      [Byte[]]$counterBlock = $aes.CreateEncryptor().TransformFinalBlock([AesCtr]::counter, 0, [AesCtr]::counter.Length);
      [Array]::Copy($counterBlock, 0, $CipherBytes, $i, [Math]::Min($counterBlock.Length, $Bytes.Length - $i));
      [AesCtr]::counter++
      [BitConverter]::GetBytes([AesCtr]::counter).CopyTo([AesCtr]::counter, [AesCtr]::counter.Length - 8);
    }
    for ($i = 0; $i -lt $Bytes.Length; $i++) {
      $CipherBytes[$i] = $CipherBytes[$i] -bxor $Bytes[$i]
    }
    return $CipherBytes
  }
  static [Byte[]] Decrypt([Byte[]]$Bytes, [byte[]]$Key, [byte[]]$IV) {
    $aes = [AesCryptoServiceProvider]::new()
    $aes.Mode = [CipherMode]::CBC
    $aes.Key = $Key
    $aes.Padding = [PaddingMode]::PKCS7
    [AesCtr]::counter = [Byte[]]::new($aes.BlockSize / 8)
    [Array]::Copy($IV, 0, [AesCtr]::counter, 0, $IV.Length)
    [BitConverter]::GetBytes([AesCtr]::counter).CopyTo([AesCtr]::counter, [AesCtr]::counter.Length - 8)
    [Byte[]]$decrypted = [Byte[]]::new($Bytes.Length)
    for ($i = 0; $i -lt $Bytes.Length; $i += $aes.BlockSize / 8) {
      [Byte[]]$counterBlock = $aes.CreateEncryptor().TransformFinalBlock([AesCtr]::counter, 0, [AesCtr]::counter.Length)
      [Array]::Copy($counterBlock, 0, $decrypted, $i, [Math]::Min($counterBlock.Length, $Bytes.Length - $i))
      [AesCtr]::counter++
      [BitConverter]::GetBytes([AesCtr]::counter).CopyTo([AesCtr]::counter, [AesCtr]::counter.Length - 8)
    }
    for ($i = 0; $i -lt $decrypted.Length; $i++) {
      $decrypted[$i] = $Bytes[$i] -bxor $decrypted[$i]
    }
    return $decrypted
  }
}
