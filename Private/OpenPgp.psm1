#!/usr/bin/env pwsh
using namespace System
using namespace System.Collections.Generic
using namespace System.Text

using module ./Utilities.psm1
using module ./Armor.psm1
using module ./Enums.psm1
using module ./OpenPgpEnums.psm1
using module ./OpenPgpCore.psm1
using module ./OpenPgpPackets.psm1

class OpenPgp : CryptobaseUtils {
  static [string] ArmorMessage([byte[]]$data, [Dictionary[string,string]]$headers) {
    return [Armor]::Encode($data, [ArmorType]::Message, $headers)
  }

  static [byte[]] DearmorMessage([string]$armoredText) {
    $decoded = [Armor]::Decode($armoredText)
    return $decoded.Data
  }
}
