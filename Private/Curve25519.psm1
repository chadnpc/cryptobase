#!/usr/bin/env pwsh
using namespace System
using namespace System.Security.Cryptography

using module ./Utilities.psm1

class Curve25519 : CryptobaseUtils {
  static [hashtable] GenerateKeyPair() {
    $alg = [ECDiffieHellman]::Create([ECCurve]::CreateFromFriendlyName('nistP256'))
    try {
      return @{ PublicKey = $alg.ExportSubjectPublicKeyInfo(); PrivateKey = $alg.ExportPkcs8PrivateKey() }
    } finally { $alg.Dispose() }
  }

  static [byte[]] DeriveSharedSecret([byte[]]$privateKey, [byte[]]$otherPublicKey) {
    $mine = [ECDiffieHellman]::Create()
    $other = [ECDiffieHellman]::Create()
    try {
      $null = $mine.ImportPkcs8PrivateKey($privateKey, [ref]0)
      $null = $other.ImportSubjectPublicKeyInfo($otherPublicKey, [ref]0)
      return $mine.DeriveKeyMaterial($other.PublicKey)
    } finally { $mine.Dispose(); $other.Dispose() }
  }
}
