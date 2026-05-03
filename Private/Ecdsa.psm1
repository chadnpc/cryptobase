#!/usr/bin/env pwsh
using namespace System
using namespace System.Security.Cryptography

using module ./Utilities.psm1

class Ecdsa : CryptobaseUtils {
  static [string] $DefaultCurve = 'nistP256'

  static [hashtable] GenerateKeyPair() { return [Ecdsa]::GenerateKeyPair([Ecdsa]::DefaultCurve) }

  static [hashtable] GenerateKeyPair([string]$curveName) {
    $curve = [ECCurve]::CreateFromFriendlyName($curveName)
    $ecdsa = [System.Security.Cryptography.ECDsa]::Create($curve)
    try {
      return @{ PublicKey = $ecdsa.ExportSubjectPublicKeyInfo(); PrivateKey = $ecdsa.ExportPkcs8PrivateKey() }
    } finally { $ecdsa.Dispose() }
  }

  static [byte[]] Sign([byte[]]$data, [byte[]]$privateKey) {
    $ecdsa = [System.Security.Cryptography.ECDsa]::Create()
    try {
      $null = $ecdsa.ImportPkcs8PrivateKey($privateKey, [ref]0)
      return $ecdsa.SignData($data, [HashAlgorithmName]::SHA256)
    } finally { $ecdsa.Dispose() }
  }

  static [bool] Verify([byte[]]$data, [byte[]]$signature, [byte[]]$publicKey) {
    $ecdsa = [System.Security.Cryptography.ECDsa]::Create()
    try {
      $null = $ecdsa.ImportSubjectPublicKeyInfo($publicKey, [ref]0)
      return $ecdsa.VerifyData($data, $signature, [HashAlgorithmName]::SHA256)
    } finally { $ecdsa.Dispose() }
  }
}
