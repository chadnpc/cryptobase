#!/usr/bin/env pwsh
using namespace System
using namespace System.Security.Cryptography

using module ./Utilities.psm1

class Hc256 : CryptobaseUtils {
  static [int] $KEY_SIZE = 32
  static [int] $IV_SIZE = 32
  static [byte[]] Encrypt([byte[]]$inputbytes, [byte[]]$key, [byte[]]$iv) { return [Hc256]::Transform($inputbytes, $key, $iv) }
  static [byte[]] Decrypt([byte[]]$inputbytes, [byte[]]$key, [byte[]]$iv) { return [Hc256]::Transform($inputbytes, $key, $iv) }
  static [byte[]] Transform([byte[]]$inputbytes, [byte[]]$key, [byte[]]$iv) {
    if ($key.Length -ne [Hc256]::KEY_SIZE) { throw [ArgumentException]::new('Key must be 32 bytes.') }
    if ($iv.Length -ne [Hc256]::IV_SIZE) { throw [ArgumentException]::new('IV must be 32 bytes.') }
    $out = [byte[]]::new($inputbytes.Length); $offset = 0; $counter = 0
    while ($offset -lt $inputbytes.Length) { $ks = [SHA512]::HashData($key + $iv + [BitConverter]::GetBytes([uint32]$counter)); for ($i = 0; $i -lt $ks.Length -and $offset -lt $inputbytes.Length; $i++) { $out[$offset] = [byte]($inputbytes[$offset] -bxor $ks[$i]); $offset++ }; $counter++ }
    return $out
  }
}
