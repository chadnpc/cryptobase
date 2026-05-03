#!/usr/bin/env pwsh
using namespace System

using module ./Ecdsa.psm1

class Secp256k1 {
  static [hashtable] GenerateKeyPair() { return [Ecdsa]::GenerateKeyPair('secp256k1') }
  static [byte[]] Sign([byte[]]$data, [byte[]]$privateKey) { return [Ecdsa]::Sign($data, $privateKey) }
  static [bool] Verify([byte[]]$data, [byte[]]$signature, [byte[]]$publicKey) { return [Ecdsa]::Verify($data, $signature, $publicKey) }
}
