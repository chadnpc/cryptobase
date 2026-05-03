#!/usr/bin/env pwsh
using namespace System
using namespace System.IO
using namespace System.Text
using namespace System.Security
using namespace System.Security.Cryptography
using namespace System.Runtime.InteropServices

using module ./Utilities.psm1

class MD5 : CryptobaseUtils {
  MD5() {}
  static [byte[]] Encrypt([byte[]]$data, [string]$hash) {
    $md5 = [MD5CryptoServiceProvider]::new()
    $encoderShouldEmitUTF8Identifier = $false
    $encoder = [UTF8Encoding]::new($encoderShouldEmitUTF8Identifier)
    $keys = [byte[]]$md5.ComputeHash($encoder.GetBytes($hash));
    return [TripleDES]::Encrypt($data, $keys, $hash.Length);
  }
  static [byte[]] Decrypt([byte[]]$data, [string]$hash) {
    $md5 = [MD5CryptoServiceProvider]::new()
    $encoderShouldEmitUTF8Identifier = $false
    $encoder = [UTF8Encoding]::new($encoderShouldEmitUTF8Identifier)
    $keys = [byte[]]$md5.ComputeHash($encoder.GetBytes($hash));
    return [TripleDES]::Decrypt($data, $keys, $hash.Length);
  }
}