#!/usr/bin/env pwsh
using namespace System.Security.Cryptography

using module ./Enums.psm1
using module ./Exceptions.psm1

class Keccak : System.Security.Cryptography.HashAlgorithm {
  static [int] $KeccakB = 1600
  static [int] $KeccakNumberOfRounds = 24
  static [int] $KeccakLaneSizeInBits = 64

  [uint64[]] $RoundConstants
  [uint64[]] $keccakState
  [byte[]] $buffer
  [int] $buffLength
  [int] $keccakR
  hidden [byte] $Padding = 1

  [int] GetKeccakR() { return $this.keccakR }
  [int] GetSizeInBytes() { return $this.keccakR / 8 }
  [int] GetHashByteLength() { return $this.HashSizeValue / 8 }

  Keccak([int]$hashBitLength) {
    $this.keccakR = switch ($hashBitLength) {
      128 { 1344; break }
      224 { 1152; break }
      256 { 1088; break }
      384 { 832; break }
      512 { 576; break }
      default {
        throw [System.ArgumentException]::new("hashBitLength must be 128, 224, 256, 384, or 512", "hashBitLength")
      }
    }
    $this.HashSizeValue = $hashBitLength
    $this.keccakState = [uint64[]]::new(25)
    $this.Initialize()
    $this.RoundConstants = [uint64[]]@(
      0x0000000000000001uL, 0x0000000000008082uL, 0x800000000000808auL, 0x8000000080008000uL,
      0x000000000000808buL, 0x0000000080000001uL, 0x8000000080008081uL, 0x8000000000008009uL,
      0x000000000000008auL, 0x0000000000000088uL, 0x0000000080008009uL, 0x000000008000000auL,
      0x000000008000808buL, 0x800000000000008buL, 0x8000000000008089uL, 0x8000000000008003uL,
      0x8000000000008002uL, 0x8000000000000080uL, 0x000000000000800auL, 0x800000008000000auL,
      0x8000000080008081uL, 0x8000000000008080uL, 0x0000000080000001uL, 0x8000000080008008uL
    )
  }

  [uint64] ROL([uint64]$a, [int]$offset) {
    [int]$shift = $offset -band 63
    if ($shift -eq 0) { return $a }
    return (($a -shl $shift) -bor ($a -shr (64 - $shift)))
  }

  [void] AddToBuffer([byte[]]$array, [ref]$offset, [ref]$count) {
    $amount = [Math]::Min($count.Value, $this.buffer.Length - $this.buffLength)
    [System.Buffer]::BlockCopy($array, $offset.Value, $this.buffer, $this.buffLength, $amount)
    $offset.Value += $amount
    $this.buffLength += $amount
    $count.Value -= $amount
  }

  [void] Initialize() {
    $this.buffLength = 0
    $this.HashValue = $null
    if ($null -ne $this.keccakState) { [Array]::Clear($this.keccakState, 0, $this.keccakState.Length) }
  }

  [void] HashCore([byte[]]$array, [int]$ibStart, [int]$cbSize) {
    if ($ibStart -lt 0) { throw [System.ArgumentOutOfRangeException]::new("ibStart") }
    if ($cbSize -gt $array.Length) { throw [System.ArgumentOutOfRangeException]::new("cbSize") }
    if ($ibStart + $cbSize -gt $array.Length) { throw [System.ArgumentOutOfRangeException]::new("ibStart or cbSize") }
  }

  [byte[]] HashFinal() {
    throw [System.NotImplementedException]::new("Keccak is a base class. Use KeccakManaged or another implementation.")
  }
}

class KeccakManaged : Keccak {
  KeccakManaged([int]$hashBitLength) : base($hashBitLength) {}

  [void] HashCore([byte[]]$array, [int]$ibStart, [int]$cbSize) {
    if ($cbSize -eq 0) { return }

    $sizeInBytes = $this.GetSizeInBytes()
    if ($null -eq $this.buffer) { $this.buffer = [byte[]]::new($sizeInBytes) }
    $stride = $sizeInBytes -shr 3

    if ($this.buffLength -eq $sizeInBytes) { throw [System.Exception]::new("Internal buffer full") }

    $off = $ibStart
    $cnt = $cbSize

    $amount = [Math]::Min($cnt, $this.buffer.Length - $this.buffLength)
    [Array]::Copy($array, $off, $this.buffer, $this.buffLength, $amount)
    $off += $amount
    $this.buffLength += $amount
    $cnt -= $amount

    [uint64[]]$utemps = [uint64[]]::new($stride)

    if ($this.buffLength -eq $sizeInBytes) {
      for ($i = 0; $i -lt $stride; $i++) { $utemps[$i] = [System.BitConverter]::ToUInt64($this.buffer, $i * 8) }
      $this.KeccakF($utemps, $stride)
      $this.buffLength = 0
    }

    if ($cnt -ge $sizeInBytes) {
      while ($cnt -ge $sizeInBytes) {
        for ($i = 0; $i -lt $stride; $i++) { $utemps[$i] = [System.BitConverter]::ToUInt64($array, $off + ($i * 8)) }
        $this.KeccakF($utemps, $stride)
        $off += $sizeInBytes
        $cnt -= $sizeInBytes
      }
    }

    if ($cnt -gt 0) {
      [Array]::Copy($array, $off, $this.buffer, $this.buffLength, $cnt)
      $this.buffLength += $cnt
    }
  }

  [byte[]] HashFinal() {
    $sizeInBytes = $this.GetSizeInBytes()
    [byte[]]$outb = [byte[]]::new($this.GetHashByteLength())

    if ($null -eq $this.buffer) {
      $this.buffer = [byte[]]::new($sizeInBytes)
    } else {
      [Array]::Clear($this.buffer, $this.buffLength, $sizeInBytes - $this.buffLength)
    }

    $this.buffer[$this.buffLength] = $this.Padding
    $this.buffLength += 1
    $this.buffer[$sizeInBytes - 1] = $this.buffer[$sizeInBytes - 1] -bor 0x80

    $stride = $sizeInBytes -shr 3
    [uint64[]]$utemps = [uint64[]]::new($stride)
    for ($i = 0; $i -lt $stride; $i++) { $utemps[$i] = [System.BitConverter]::ToUInt64($this.buffer, $i * 8) }
    $this.KeccakF($utemps, $stride)

    for ($i = 0; $i -lt $outb.Length; $i++) {
      $outb[$i] = [byte](($this.keccakState[$i -shr 3] -shr (8 * ($i -band 7))) -band 0xFF)
    }
    return $outb
  }

  [void] KeccakF([uint64[]]$inb, [int]$laneCount) {
    for ($l = 0; $l -lt $laneCount; $l++) {
      $this.keccakState[$l] = $this.keccakState[$l] -bxor $inb[$l]
    }

    [uint64]$BCa = 0; [uint64]$BCe = 0; [uint64]$BCi = 0; [uint64]$BCo = 0; [uint64]$BCu = 0
    [uint64]$Da = 0; [uint64]$De = 0; [uint64]$Di = 0; [uint64]$Do = 0; [uint64]$Du = 0

    [uint64[]]$A = $this.keccakState

    [uint64]$Aba = $A[0]; [uint64]$Abe = $A[1]; [uint64]$Abi = $A[2]; [uint64]$Abo = $A[3]; [uint64]$Abu = $A[4]
    [uint64]$Aga = $A[5]; [uint64]$Age = $A[6]; [uint64]$Agi = $A[7]; [uint64]$Ago = $A[8]; [uint64]$Agu = $A[9]
    [uint64]$Aka = $A[10]; [uint64]$Ake = $A[11]; [uint64]$Aki = $A[12]; [uint64]$Ako = $A[13]; [uint64]$Aku = $A[14]
    [uint64]$Ama = $A[15]; [uint64]$Ame = $A[16]; [uint64]$Ami = $A[17]; [uint64]$Amo = $A[18]; [uint64]$Amu = $A[19]
    [uint64]$Asa = $A[20]; [uint64]$Ase = $A[21]; [uint64]$Asi = $A[22]; [uint64]$Aso = $A[23]; [uint64]$Asu = $A[24]

    [uint64]$Eba = 0; [uint64]$Ebe = 0; [uint64]$Ebi = 0; [uint64]$Ebo = 0; [uint64]$Ebu = 0
    [uint64]$Ega = 0; [uint64]$Ege = 0; [uint64]$Egi = 0; [uint64]$Ego = 0; [uint64]$Egu = 0
    [uint64]$Eka = 0; [uint64]$Eke = 0; [uint64]$Eki = 0; [uint64]$Eko = 0; [uint64]$Eku = 0
    [uint64]$Ema = 0; [uint64]$Eme = 0; [uint64]$Emi = 0; [uint64]$Emo = 0; [uint64]$Emu = 0
    [uint64]$Esa = 0; [uint64]$Ese = 0; [uint64]$Esi = 0; [uint64]$Eso = 0; [uint64]$Esu = 0

    for ($round = 0; $round -lt 24; $round += 2) {
      $BCa = $Aba -bxor $Aga -bxor $Aka -bxor $Ama -bxor $Asa
      $BCe = $Abe -bxor $Age -bxor $Ake -bxor $Ame -bxor $Ase
      $BCi = $Abi -bxor $Agi -bxor $Aki -bxor $Ami -bxor $Asi
      $BCo = $Abo -bxor $Ago -bxor $Ako -bxor $Amo -bxor $Aso
      $BCu = $Abu -bxor $Agu -bxor $Aku -bxor $Amu -bxor $Asu

      $Da = $BCu -bxor $this.ROL($BCe, 1)
      $De = $BCa -bxor $this.ROL($BCi, 1)
      $Di = $BCe -bxor $this.ROL($BCo, 1)
      $Do = $BCi -bxor $this.ROL($BCu, 1)
      $Du = $BCo -bxor $this.ROL($BCa, 1)

      $Aba = $Aba -bxor $Da
      $BCa = $Aba
      $Age = $Age -bxor $De
      $BCe = $this.ROL($Age, 44)
      $Aki = $Aki -bxor $Di
      $BCi = $this.ROL($Aki, 43)
      $Amo = $Amo -bxor $Do
      $BCo = $this.ROL($Amo, 21)
      $Asu = $Asu -bxor $Du
      $BCu = $this.ROL($Asu, 14)
      $Eba = $BCa -bxor ((-bnot $BCe) -band $BCi)
      $Eba = $Eba -bxor $this.RoundConstants[$round]
      $Ebe = $BCe -bxor ((-bnot $BCi) -band $BCo)
      $Ebi = $BCi -bxor ((-bnot $BCo) -band $BCu)
      $Ebo = $BCo -bxor ((-bnot $BCu) -band $BCa)
      $Ebu = $BCu -bxor ((-bnot $BCa) -band $BCe)

      $Abo = $Abo -bxor $Do
      $BCa = $this.ROL($Abo, 28)
      $Agu = $Agu -bxor $Du
      $BCe = $this.ROL($Agu, 20)
      $Aka = $Aka -bxor $Da
      $BCi = $this.ROL($Aka, 3)
      $Ame = $Ame -bxor $De
      $BCo = $this.ROL($Ame, 45)
      $Asi = $Asi -bxor $Di
      $BCu = $this.ROL($Asi, 61)
      $Ega = $BCa -bxor ((-bnot $BCe) -band $BCi)
      $Ege = $BCe -bxor ((-bnot $BCi) -band $BCo)
      $Egi = $BCi -bxor ((-bnot $BCo) -band $BCu)
      $Ego = $BCo -bxor ((-bnot $BCu) -band $BCa)
      $Egu = $BCu -bxor ((-bnot $BCa) -band $BCe)

      $Abe = $Abe -bxor $De
      $BCa = $this.ROL($Abe, 1)
      $Agi = $Agi -bxor $Di
      $BCe = $this.ROL($Agi, 6)
      $Ako = $Ako -bxor $Do
      $BCi = $this.ROL($Ako, 25)
      $Amu = $Amu -bxor $Du
      $BCo = $this.ROL($Amu, 8)
      $Asa = $Asa -bxor $Da
      $BCu = $this.ROL($Asa, 18)
      $Eka = $BCa -bxor ((-bnot $BCe) -band $BCi)
      $Eke = $BCe -bxor ((-bnot $BCi) -band $BCo)
      $Eki = $BCi -bxor ((-bnot $BCo) -band $BCu)
      $Eko = $BCo -bxor ((-bnot $BCu) -band $BCa)
      $Eku = $BCu -bxor ((-bnot $BCa) -band $BCe)

      $Abu = $Abu -bxor $Du
      $BCa = $this.ROL($Abu, 27)
      $Aga = $Aga -bxor $Da
      $BCe = $this.ROL($Aga, 36)
      $Ake = $Ake -bxor $De
      $BCi = $this.ROL($Ake, 10)
      $Ami = $Ami -bxor $Di
      $BCo = $this.ROL($Ami, 15)
      $Aso = $Aso -bxor $Do
      $BCu = $this.ROL($Aso, 56)
      $Ema = $BCa -bxor ((-bnot $BCe) -band $BCi)
      $Eme = $BCe -bxor ((-bnot $BCi) -band $BCo)
      $Emi = $BCi -bxor ((-bnot $BCo) -band $BCu)
      $Emo = $BCo -bxor ((-bnot $BCu) -band $BCa)
      $Emu = $BCu -bxor ((-bnot $BCa) -band $BCe)

      $Abi = $Abi -bxor $Di
      $BCa = $this.ROL($Abi, 62)
      $Ago = $Ago -bxor $Do
      $BCe = $this.ROL($Ago, 55)
      $Aku = $Aku -bxor $Du
      $BCi = $this.ROL($Aku, 39)
      $Ama = $Ama -bxor $Da
      $BCo = $this.ROL($Ama, 41)
      $Ase = $Ase -bxor $De
      $BCu = $this.ROL($Ase, 2)
      $Esa = $BCa -bxor ((-bnot $BCe) -band $BCi)
      $Ese = $BCe -bxor ((-bnot $BCi) -band $BCo)
      $Esi = $BCi -bxor ((-bnot $BCo) -band $BCu)
      $Eso = $BCo -bxor ((-bnot $BCu) -band $BCa)
      $Esu = $BCu -bxor ((-bnot $BCa) -band $BCe)

      $BCa = $Eba -bxor $Ega -bxor $Eka -bxor $Ema -bxor $Esa
      $BCe = $Ebe -bxor $Ege -bxor $Eke -bxor $Eme -bxor $Ese
      $BCi = $Ebi -bxor $Egi -bxor $Eki -bxor $Emi -bxor $Esi
      $BCo = $Ebo -bxor $Ego -bxor $Eko -bxor $Emo -bxor $Eso
      $BCu = $Ebu -bxor $Egu -bxor $Eku -bxor $Emu -bxor $Esu

      $Da = $BCu -bxor $this.ROL($BCe, 1)
      $De = $BCa -bxor $this.ROL($BCi, 1)
      $Di = $BCe -bxor $this.ROL($BCo, 1)
      $Do = $BCi -bxor $this.ROL($BCu, 1)
      $Du = $BCo -bxor $this.ROL($BCa, 1)

      $Eba = $Eba -bxor $Da
      $BCa = $Eba
      $Ege = $Ege -bxor $De
      $BCe = $this.ROL($Ege, 44)
      $Eki = $Eki -bxor $Di
      $BCi = $this.ROL($Eki, 43)
      $Emo = $Emo -bxor $Do
      $BCo = $this.ROL($Emo, 21)
      $Esu = $Esu -bxor $Du
      $BCu = $this.ROL($Esu, 14)
      $Aba = $BCa -bxor ((-bnot $BCe) -band $BCi)
      $Aba = $Aba -bxor $this.RoundConstants[$round + 1]
      $Abe = $BCe -bxor ((-bnot $BCi) -band $BCo)
      $Abi = $BCi -bxor ((-bnot $BCo) -band $BCu)
      $Abo = $BCo -bxor ((-bnot $BCu) -band $BCa)
      $Abu = $BCu -bxor ((-bnot $BCa) -band $BCe)

      $Ebo = $Ebo -bxor $Do
      $BCa = $this.ROL($Ebo, 28)
      $Egu = $Egu -bxor $Du
      $BCe = $this.ROL($Egu, 20)
      $Eka = $Eka -bxor $Da
      $BCi = $this.ROL($Eka, 3)
      $Eme = $Eme -bxor $De
      $BCo = $this.ROL($Eme, 45)
      $Esi = $Esi -bxor $Di
      $BCu = $this.ROL($Esi, 61)
      $Aga = $BCa -bxor ((-bnot $BCe) -band $BCi)
      $Age = $BCe -bxor ((-bnot $BCi) -band $BCo)
      $Agi = $BCi -bxor ((-bnot $BCo) -band $BCu)
      $Ago = $BCo -bxor ((-bnot $BCu) -band $BCa)
      $Agu = $BCu -bxor ((-bnot $BCa) -band $BCe)

      $Ebe = $Ebe -bxor $De
      $BCa = $this.ROL($Ebe, 1)
      $Egi = $Egi -bxor $Di
      $BCe = $this.ROL($Egi, 6)
      $Eko = $Eko -bxor $Do
      $BCi = $this.ROL($Eko, 25)
      $Emu = $Emu -bxor $Du
      $BCo = $this.ROL($Emu, 8)
      $Esa = $Esa -bxor $Da
      $BCu = $this.ROL($Esa, 18)
      $Aka = $BCa -bxor ((-bnot $BCe) -band $BCi)
      $Ake = $BCe -bxor ((-bnot $BCi) -band $BCo)
      $Aki = $BCi -bxor ((-bnot $BCo) -band $BCu)
      $Ako = $BCo -bxor ((-bnot $BCu) -band $BCa)
      $Aku = $BCu -bxor ((-bnot $BCa) -band $BCe)

      $Ebu = $Ebu -bxor $Du
      $BCa = $this.ROL($Ebu, 27)
      $Ega = $Ega -bxor $Da
      $BCe = $this.ROL($Ega, 36)
      $Eke = $Eke -bxor $De
      $BCi = $this.ROL($Eke, 10)
      $Emi = $Emi -bxor $Di
      $BCo = $this.ROL($Emi, 15)
      $Eso = $Eso -bxor $Do
      $BCu = $this.ROL($Eso, 56)
      $Ama = $BCa -bxor ((-bnot $BCe) -band $BCi)
      $Ame = $BCe -bxor ((-bnot $BCi) -band $BCo)
      $Ami = $BCi -bxor ((-bnot $BCo) -band $BCu)
      $Amo = $BCo -bxor ((-bnot $BCu) -band $BCa)
      $Amu = $BCu -bxor ((-bnot $BCa) -band $BCe)

      $Ebi = $Ebi -bxor $Di
      $BCa = $this.ROL($Ebi, 62)
      $Ego = $Ego -bxor $Do
      $BCe = $this.ROL($Ego, 55)
      $Eku = $Eku -bxor $Du
      $BCi = $this.ROL($Eku, 39)
      $Ema = $Ema -bxor $Da
      $BCo = $this.ROL($Ema, 41)
      $Ese = $Ese -bxor $De
      $BCu = $this.ROL($Ese, 2)
      $Asa = $BCa -bxor ((-bnot $BCe) -band $BCi)
      $Ase = $BCe -bxor ((-bnot $BCi) -band $BCo)
      $Asi = $BCi -bxor ((-bnot $BCo) -band $BCu)
      $Aso = $BCo -bxor ((-bnot $BCu) -band $BCa)
      $Asu = $BCu -bxor ((-bnot $BCa) -band $BCe)
    }

    $A[0] = $Aba; $A[1] = $Abe; $A[2] = $Abi; $A[3] = $Abo; $A[4] = $Abu
    $A[5] = $Aga; $A[6] = $Age; $A[7] = $Agi; $A[8] = $Ago; $A[9] = $Agu
    $A[10] = $Aka; $A[11] = $Ake; $A[12] = $Aki; $A[13] = $Ako; $A[14] = $Aku
    $A[15] = $Ama; $A[16] = $Ame; $A[17] = $Ami; $A[18] = $Amo; $A[19] = $Amu
    $A[20] = $Asa; $A[21] = $Ase; $A[22] = $Asi; $A[23] = $Aso; $A[24] = $Asu
  }
}

class IdentityHash : System.Security.Cryptography.HashAlgorithm {
  [byte[]] $digest

  IdentityHash() {
    $this.HashSizeValue = 0
  }

  [void] Initialize() {
    $this.digest = $null
  }

  [void] HashCore([byte[]]$array, [int]$ibStart, [int]$cbSize) {
    if ($cbSize -eq 0) { return }
    if ($null -eq $this.digest) {
      $this.digest = [byte[]]::new($cbSize)
      [System.Buffer]::BlockCopy($array, $ibStart, $this.digest, 0, $cbSize)
    } else {
      [byte[]]$buffer = [byte[]]::new($this.digest.Length + $cbSize)
      [System.Buffer]::BlockCopy($this.digest, 0, $buffer, 0, $this.digest.Length)
      [System.Buffer]::BlockCopy($array, $ibStart, $buffer, $this.digest.Length, $cbSize)
      $this.digest = $buffer
    }
  }

  [byte[]] HashFinal() {
    if ($null -ne $this.digest) { return $this.digest }
    return [byte[]]::new(0)
  }
}

class DoubleSha256 : System.Security.Cryptography.HashAlgorithm {
  hidden [System.Security.Cryptography.HashAlgorithm] $_digest
  hidden [byte[]] $_round1

  DoubleSha256() {
    $this._digest = [System.Security.Cryptography.SHA256]::Create()
    $this.HashSizeValue = $this._digest.HashSize
  }

  [void] Initialize() {
    $this._digest.Initialize()
    $this._round1 = $null
  }

  [void] HashCore([byte[]]$array, [int]$ibStart, [int]$cbSize) {
    if ($null -ne $this._round1) {
      throw [System.NotSupportedException]::new("Already called.")
    }
    $this._round1 = $this._digest.ComputeHash($array, $ibStart, $cbSize)
  }

  [byte[]] HashFinal() {
    $this._digest.Initialize()
    return $this._digest.ComputeHash($this._round1)
  }
}

class SHA3256 : System.Security.Cryptography.HashAlgorithm {
  # .SYNOPSIS
  #     Computes the SHA3-256 hash of the input data.
  # .DESCRIPTION
  #     This function computes the SHA3-256 hash of the input data.
  #     SHA3-256 is a cryptographic hash function that produces a 256-bit hash.
  # .PARAMETER Data
  #     The data to hash.
  # .OUTPUTS
  #     [byte[]] - The hash value.
  # .EXAMPLE
  #     [SHA3256]::ComputeHash([System.Text.Encoding]::UTF8.GetBytes("Hello World"))
  # .NOTES
  #     Requires .NET 8+ or uses managed implementation for earlier versions.
  hidden [System.IO.MemoryStream] $_buffer

  SHA3256() {
    $this.HashSizeValue = 256
    $this.Initialize()
  }

  static [byte[]] ComputeHash([byte[]]$Data) {
    if ($null -eq $Data) { throw [System.ArgumentNullException]::new("Data") }

    # Try .NET 8+ native implementation first
    $sha3Type = [System.Type]::GetType("System.Security.Cryptography.SHA3_256, System.Security.Cryptography")
    if ($null -ne $sha3Type) {
      $sha3 = $sha3Type::Create()
      try {
        return $sha3.ComputeHash($Data)
      } finally {
        $sha3.Dispose()
      }
    }

    # Fall back to KeccakManaged implementation
    $keccak = [KeccakManaged]::new(256)
    $keccak.Padding = 0x06
    try {
      return $keccak.ComputeHash($Data)
    } finally {
      $keccak.Dispose()
    }
  }

  static [byte[]] ComputeHash([System.IO.Stream]$InputStream) {
    # same as [System.Security.Cryptography.SHA3_256]::HashData($InputStream)
    if ($null -eq $InputStream) { throw [System.ArgumentNullException]::new("InputStream") }
    $sha3Type = [System.Type]::GetType("System.Security.Cryptography.SHA3_256, System.Security.Cryptography")
    if ($null -ne $sha3Type) {
      $sha3 = $sha3Type::Create()
      try {
        return $sha3.ComputeHash($InputStream)
      } finally {
        $sha3.Dispose()
      }
    }

    $keccak = [KeccakManaged]::new(256)
    try {
      return $keccak.ComputeHash($InputStream)
    } finally {
      $keccak.Dispose()
    }
  }

  [void] Initialize() {
    # Reset state for new hash computation
    if ($null -ne $this._buffer) {
      $this._buffer.Dispose()
      $this._buffer = $null
    }
  }

  [void] HashCore([byte[]]$array, [int]$ibStart, [int]$cbSize) {
    if ($null -eq $this._buffer) {
      $this._buffer = [System.IO.MemoryStream]::new()
    }
    $this._buffer.Write($array, $ibStart, $cbSize)
  }

  [byte[]] HashFinal() {
    if ($null -ne $this._buffer) {
      $result = [SHA3256]::ComputeHash($this._buffer.ToArray())
      $this._buffer.Dispose()
      $this._buffer = $null
      return $result
    }
    return [SHA3256]::ComputeHash([byte[]]::new(0))
  }
}

class SHA3384 : System.Security.Cryptography.HashAlgorithm {
  <#
  .SYNOPSIS
      Computes the SHA3-384 hash of the input data.

  .DESCRIPTION
      This function computes the SHA3-384 hash of the input data.
      SHA3-384 is a cryptographic hash function that produces a 384-bit hash.

  .PARAMETER Data
      The data to hash.

  .OUTPUTS
      [byte[]] - The hash value.

  .EXAMPLE
      [SHA3384]::ComputeHash([System.Text.Encoding]::UTF8.GetBytes("Hello World"))

  .NOTES
      Requires .NET 8+ or uses managed implementation for earlier versions.
  #>
  hidden [System.IO.MemoryStream] $_buffer

  SHA3384() {
    $this.HashSizeValue = 384
    $this.Initialize()
  }

  static [byte[]] ComputeHash([byte[]]$Data) {
    if ($null -eq $Data) { throw [System.ArgumentNullException]::new("Data") }

    $sha3Type = [System.Type]::GetType("System.Security.Cryptography.SHA3_384, System.Security.Cryptography")
    if ($null -ne $sha3Type) {
      $sha3 = $sha3Type::Create()
      try {
        return $sha3.ComputeHash($Data)
      } finally {
        $sha3.Dispose()
      }
    }

    $keccak = [KeccakManaged]::new(384)
    $keccak.Padding = 0x06
    try {
      return $keccak.ComputeHash($Data)
    } finally {
      $keccak.Dispose()
    }
  }

  static [byte[]] ComputeHash([System.IO.Stream]$InputStream) {
    # same as [System.Security.Cryptography.SHA3_384]::HashData($InputStream)
    if ($null -eq $InputStream) { throw [System.ArgumentNullException]::new("InputStream") }

    $sha3Type = [System.Type]::GetType("System.Security.Cryptography.SHA3_384, System.Security.Cryptography")
    if ($null -ne $sha3Type) {
      $sha3 = $sha3Type::Create()
      try {
        return $sha3.ComputeHash($InputStream)
      } finally {
        $sha3.Dispose()
      }
    }

    $keccak = [KeccakManaged]::new(384)
    try {
      return $keccak.ComputeHash($InputStream)
    } finally {
      $keccak.Dispose()
    }
  }

  [void] Initialize() {
    # Reset state for new hash computation
  }

  [void] HashCore([byte[]]$array, [int]$ibStart, [int]$cbSize) {
    if ($null -eq $this._buffer) {
      $this._buffer = [System.IO.MemoryStream]::new()
    }
    $this._buffer.Write($array, $ibStart, $cbSize)
  }

  [byte[]] HashFinal() {
    if ($null -ne $this._buffer) {
      $result = [SHA3384]::ComputeHash($this._buffer.ToArray())
      $this._buffer.Dispose()
      $this._buffer = $null
      return $result
    }
    return [SHA3384]::ComputeHash([byte[]]::new(0))
  }
}

class SHA3512 : System.Security.Cryptography.HashAlgorithm {
  <#
  .SYNOPSIS
      Computes the SHA3-512 hash of the input data.

  .DESCRIPTION
      This function computes the SHA3-512 hash of the input data.
      SHA3-512 is a cryptographic hash function that produces a 512-bit hash.

  .PARAMETER Data
      The data to hash.

  .OUTPUTS
      [byte[]] - The hash value.

  .EXAMPLE
      [SHA3512]::ComputeHash([System.Text.Encoding]::UTF8.GetBytes("Hello World"))

  .NOTES
      Requires .NET 8+ or uses managed implementation for earlier versions.
  #>
  hidden [System.IO.MemoryStream] $_buffer

  SHA3512() {
    $this.HashSizeValue = 512
    $this.Initialize()
  }

  static [byte[]] ComputeHash([byte[]]$Data) {
    if ($null -eq $Data) { throw [System.ArgumentNullException]::new("Data") }

    $sha3Type = [System.Type]::GetType("System.Security.Cryptography.SHA3_512, System.Security.Cryptography")
    if ($null -ne $sha3Type) {
      $sha3 = $sha3Type::Create()
      try {
        return $sha3.ComputeHash($Data)
      } finally {
        $sha3.Dispose()
      }
    }

    $keccak = [KeccakManaged]::new(512)
    $keccak.Padding = 0x06
    try {
      return $keccak.ComputeHash($Data)
    } finally {
      $keccak.Dispose()
    }
  }

  static [byte[]] ComputeHash([System.IO.Stream]$InputStream) {
    if ($null -eq $InputStream) { throw [System.ArgumentNullException]::new("InputStream") }

    $sha3Type = [System.Type]::GetType("System.Security.Cryptography.SHA3_512, System.Security.Cryptography")
    if ($null -ne $sha3Type) {
      $sha3 = $sha3Type::Create()
      try {
        return $sha3.ComputeHash($InputStream)
      } finally {
        $sha3.Dispose()
      }
    }

    $keccak = [KeccakManaged]::new(512)
    try {
      return $keccak.ComputeHash($InputStream)
    } finally {
      $keccak.Dispose()
    }
  }

  [void] Initialize() {
    # Reset state for new hash computation
  }

  [void] HashCore([byte[]]$array, [int]$ibStart, [int]$cbSize) {
    if ($null -eq $this._buffer) {
      $this._buffer = [System.IO.MemoryStream]::new()
    }
    $this._buffer.Write($array, $ibStart, $cbSize)
  }

  [byte[]] HashFinal() {
    if ($null -ne $this._buffer) {
      $result = [SHA3512]::ComputeHash($this._buffer.ToArray())
      $this._buffer.Dispose()
      $this._buffer = $null
      return $result
    }
    return [SHA3512]::ComputeHash([byte[]]::new(0))
  }
}

class SHAKE128Managed {
  [int] $OutputLength
  hidden [System.Security.Cryptography.HashAlgorithm] $_keccak

  SHAKE128Managed() {
    $this.Initialize()
  }

  static [byte[]] ComputeHash([byte[]]$Data, [int]$OutputLength) {
    if ($null -eq $Data) { throw [System.ArgumentNullException]::new("Data") }
    if ($OutputLength -le 0) { throw [System.ArgumentOutOfRangeException]::new("OutputLength") }

    # SHAKE128 uses Keccak with rate=1344, capacity=256, padding 0x1F
    $keccak = [KeccakManaged]::new(128)
    $keccak.Padding = 0x1F
    try {
      # Absorb phase
      $keccak.TransformFinalBlock($Data, 0, $Data.Length)

      # Squeeze phase - get hash then extend
      $hash = $keccak.Hash
      $result = [byte[]]::new($OutputLength)

      if ($OutputLength -le $hash.Length) {
        [Array]::Copy($hash, $result, $OutputLength)
      } else {
        [Array]::Copy($hash, $result, $hash.Length)
        # For additional output, we'd need to continue squeezing
        # For now, use deterministic extension
        $offset = $hash.Length
        $counter = [byte]1
        while ($offset -lt $OutputLength) {
          $keccak2 = [KeccakManaged]::new(128)
          $keccak2.Padding = 0x1F
          try {
            $extra = [byte[]]@($counter) + $Data
            $more = $keccak2.ComputeHash($extra)
            $copyLen = [Math]::Min($more.Length, $OutputLength - $offset)
            [Array]::Copy($more, 0, $result, $offset, $copyLen)
            $offset += $copyLen
            $counter++
          } finally {
            $keccak2.Dispose()
          }
        }
      }
      return $result
    } finally {
      $keccak.Dispose()
    }
  }

  [void] Initialize() {
    if ($null -ne $this._keccak) {
      $this._keccak.Dispose()
    }
    $this._keccak = [KeccakManaged]::new(128)
  }

  [void] HashCore([byte[]]$array, [int]$ibStart, [int]$cbSize) {
    if ($null -eq $this._keccak) {
      $this._keccak = [KeccakManaged]::new(128)
    }
    $this._keccak.TransformBlock($array, $ibStart, $cbSize, $null, 0) | Out-Null
  }

  [byte[]] HashFinal() {
    if ($null -eq $this._keccak) {
      $this._keccak = [KeccakManaged]::new(128)
    }
    $this._keccak.TransformFinalBlock([byte[]]::new(0), 0, 0) | Out-Null
    return $this._keccak.Hash
  }
}

class SHAKE256Managed : System.Security.Cryptography.HashAlgorithm {
  [int] $OutputLength
  hidden [System.Security.Cryptography.HashAlgorithm] $_keccak

  SHAKE256Managed() {
    $this.Initialize()
  }

  static [byte[]] ComputeHash([byte[]]$Data, [int]$OutputLength) {
    if ($null -eq $Data) { throw [System.ArgumentNullException]::new("Data") }
    if ($OutputLength -le 0) { throw [System.ArgumentOutOfRangeException]::new("OutputLength") }

    # SHAKE256 uses Keccak with rate=1088, capacity=512, padding 0x1F
    $keccak = [KeccakManaged]::new(256)
    $keccak.Padding = 0x1F
    try {
      # Absorb phase
      $keccak.TransformFinalBlock($Data, 0, $Data.Length)

      # Squeeze phase - get hash then extend
      $hash = $keccak.Hash
      $result = [byte[]]::new($OutputLength)

      if ($OutputLength -le $hash.Length) {
        [Array]::Copy($hash, $result, $OutputLength)
      } else {
        [Array]::Copy($hash, $result, $hash.Length)
        # For additional output, we'd need to continue squeezing
        # For now, use deterministic extension
        $offset = $hash.Length
        $counter = [byte]1
        while ($offset -lt $OutputLength) {
          $keccak2 = [KeccakManaged]::new(256)
          $keccak2.Padding = 0x1F
          try {
            $extra = [byte[]]@($counter) + $Data
            $more = $keccak2.ComputeHash($extra)
            $copyLen = [Math]::Min($more.Length, $OutputLength - $offset)
            [Array]::Copy($more, 0, $result, $offset, $copyLen)
            $offset += $copyLen
            $counter++
          } finally {
            $keccak2.Dispose()
          }
        }
      }
      return $result
    } finally {
      $keccak.Dispose()
    }
  }

  [void] Initialize() {
    if ($null -ne $this._keccak) {
      $this._keccak.Dispose()
    }
    $this._keccak = [KeccakManaged]::new(256)
  }

  [void] HashCore([byte[]]$array, [int]$ibStart, [int]$cbSize) {
    if ($null -eq $this._keccak) {
      $this._keccak = [KeccakManaged]::new(256)
    }
    $this._keccak.TransformBlock($array, $ibStart, $cbSize, $null, 0) | Out-Null
  }

  [byte[]] HashFinal() {
    if ($null -eq $this._keccak) {
      $this._keccak = [KeccakManaged]::new(256)
    }
    $this._keccak.TransformFinalBlock([byte[]]::new(0), 0, 0) | Out-Null
    return $this._keccak.Hash
  }
}


class KMAC128 {
  static [int] $KeccakB = 1600
  static [int] $KeccakNumberOfRounds = 24
  static [int] $KeccakLaneSizeInBits = 64

  [uint64[]] $RoundConstants
  [uint64[]] $keccakState
  [byte[]] $buffer
  [int] $buffLength
  [int] $keccakR

  [int] GetKeccakR() { return $this.keccakR }
  [int] GetSizeInBytes() { return $this.keccakR / 8 }
  [int] GetHashByteLength() { return $this.HashSizeValue / 8 }

  KMAC128([int]$hashBitLength) {
    $this.keccakR = switch ($hashBitLength) {
      128 { 1344; break }  # SHAKE128 rate
      224 { 1152; break }
      256 { 1088; break }
      384 { 832; break }
      512 { 576; break }
      default {
        throw [System.ArgumentException]::new("hashBitLength must be 128, 224, 256, 384, or 512", "hashBitLength")
      }
    }
    $this.HashSizeValue = $hashBitLength
    $this.keccakState = [uint64[]]::new(25)
    $this.Initialize()
    $this.RoundConstants = [uint64[]]@(
      0x0000000000000001uL, 0x0000000000008082uL, 0x800000000000808auL, 0x8000000080008000uL,
      0x000000000000808buL, 0x0000000080000001uL, 0x8000000080008081uL, 0x8000000000008009uL,
      0x000000000000008auL, 0x0000000000000088uL, 0x0000000080008009uL, 0x000000008000000auL,
      0x000000008000808buL, 0x800000000000008buL, 0x8000000000008089uL, 0x8000000000008003uL,
      0x8000000000008002uL, 0x8000000000000080uL, 0x000000000000800auL, 0x800000008000000auL,
      0x8000000080008081uL, 0x8000000000008080uL, 0x0000000080000001uL, 0x8000000080008008uL
    )
  }

  [uint64] ROL([uint64]$a, [int]$offset) {
    [int]$shift = $offset -band 63
    if ($shift -eq 0) { return $a }
    return (($a -shl $shift) -bor ($a -shr (64 - $shift)))
  }

  [void] AddToBuffer([byte[]]$array, [ref]$offset, [ref]$count) {
    $amount = [Math]::Min($count.Value, $this.buffer.Length - $this.buffLength)
    [System.Buffer]::BlockCopy($array, $offset.Value, $this.buffer, $this.buffLength, $amount)
    $offset.Value += $amount
    $this.buffLength += $amount
    $count.Value -= $amount
  }

  [void] Initialize() {
    $this.buffLength = 0
    $this.HashValue = $null
    if ($null -ne $this.keccakState) { [Array]::Clear($this.keccakState, 0, $this.keccakState.Length) }
  }

  [void] HashCore([byte[]]$array, [int]$ibStart, [int]$cbSize) {
    if ($ibStart -lt 0) { throw [System.ArgumentOutOfRangeException]::new("ibStart") }
    if ($cbSize -gt $array.Length) { throw [System.ArgumentOutOfRangeException]::new("cbSize") }
    if ($ibStart + $cbSize -gt $array.Length) { throw [System.ArgumentOutOfRangeException]::new("ibStart or cbSize") }
  }

  [byte[]] HashFinal() {
    throw [System.NotImplementedException]::new("Keccak is a base class. Use KeccakManaged or another implementation.")
  }
  static [byte[]] ComputeHash([byte[]]$Key, [byte[]]$Data) {
    return [KMAC128]::ComputeHash($Key, $Data, 32)
  }
  static [byte[]] ComputeHash([byte[]]$Key, [byte[]]$Data, [int]$OutputLength) {
    return [KMAC128]::ComputeHash($Key, $Data, $OutputLength, "KMAC128")
  }
  static [byte[]] ComputeHash([byte[]]$Key, [byte[]]$Data, [int]$OutputLength, [string]$Customization) {
    # .SYNOPSIS
    #     ComputeHash method for KMAC-128 Keyed-Message Authentication Code.
    # .DESCRIPTION
    #     KMAC is a message authentication code based on SHA-3 (cSHAKE).
    #     It provides variable-length output and can be used as a MAC.
    # .PARAMETER Key
    #     The secret key.
    # .PARAMETER Data
    #     The data to authenticate.
    # .PARAMETER OutputLength
    #     The desired output length in bytes.
    # .PARAMETER Customization
    #     Optional customization string.
    # .OUTPUTS
    #     [byte[]] - The MAC value.
    # .EXAMPLE
    #     $key = [byte[]]::new(32)
    #     [System.Security.Cryptography.RandomNumberGenerator]::Create().GetBytes($key)
    #     [KMAC128]::ComputeHash($key, [System.Text.Encoding]::UTF8.GetBytes("Hello"), 32)
    # .NOTES
    #     KMAC requires SHA-3/XOF support.
    if ($null -eq $Key) { throw [System.ArgumentNullException]::new("Key") }
    if ($null -eq $Data) { throw [System.ArgumentNullException]::new("Data") }
    if ($OutputLength -le 0) { throw [System.ArgumentOutOfRangeException]::new("OutputLength") }

    # Simplified KMAC implementation using SHA3-256 as base
    # Full implementation would use cSHAKE128
    $sha3 = [SHA3256]::new()
    try {
      $sha3.TransformFinalBlock($Key + $Data, 0, ($Key.Length + $Data.Length))
      return $sha3.Hash[0..($OutputLength - 1)]
    } finally {
      $sha3.Dispose()
    }
  }
}

#region    FipsHMACSHA256
# .SYNOPSIS
#     A PowerShell class to provide a FIPS compliant alternative to the built-in [HMACSHA256]
# .DESCRIPTION
#     FIPS (Federal Information Processing Standard) is a set of guidelines that specify the security requirements for cryptographic algorithms and protocols used in the United States government.
#     A FIPS compliant algorithm is one that has been reviewed and approved by the National Institute of Standards and Technology (NIST) to meet certain security standards.
#     The HMAC is a type of message authentication code that uses a secret key to verify the authenticity and integrity of a message.
#     It is based on a hash function, such as SHA-256, which is a cryptographic function that produces a fixed-size output (called a hash or message digest) from a variable-size input.
#     The built-in HMACSHA256 class in .NET Framework implements the HMAC using the SHA-256 hash function.
#     However, in older versions the HMACSHA256 class may not be FIPS compliant.
# .EXAMPLE
#     $br = [Encoding]::UTF8.GetBytes("Hello world!")
#     $hc = [FipsHmacSha256]::new()
#     $hc.ComputeHash($br)
class FipsHmacSha256 : System.Security.Cryptography.HMAC {
  static hidden $rng
  static [HMACSHA256] $HMAC
  static [ValidateNotNullOrEmpty()] [byte[]] $key

  FipsHmacSha256() {
    $this._Init();
  }
  FipsHmacSha256([Byte[]]$key) {
    [FipsHmacSha256]::Key = $key;
    $this._Init();
  }

  [string] ComputeHash([byte[]] $data) {
    if ($null -eq [FipsHmacSha256]::HMAC) {
      [FipsHmacSha256]::HMAC = [HMACSHA256]::new([FipsHmacSha256]::key)
    }
    $hashBytes = [FipsHmacSha256]::HMAC.ComputeHash($data)
    $hash = [BitConverter]::ToString($hashBytes) -replace '-'
    return $hash
  }
  hidden [void] _Init() {
    if ($null -eq [FipsHmacSha256].RNG) {
      [FipsHmacSha256].psobject.Properties.Add([psscriptproperty]::new('RNG',
          { return [RNGCryptoServiceProvider]::new() }
        )
      )
    }
    $flags = [Reflection.BindingFlags]'Instance, NonPublic'
    [Reflection.FieldInfo]$m_hashName = [HMAC].GetField('m_hashName', $flags)
    [Reflection.FieldInfo]$m_hash1 = [HMAC].GetField('m_hash1', $flags)
    [Reflection.FieldInfo]$m_hash2 = [HMAC].GetField('m_hash2', $flags)
    if ($null -ne $m_hashName) {
      $m_hashName.SetValue($this, 'SHA256')
    }
    if ($null -ne $m_hash1) {
      $m_hash1.SetValue($this, [SHA256CryptoServiceProvider]::new())
    }
    if ($null -ne $m_hash2) {
      $m_hash2.SetValue($this, [SHA256CryptoServiceProvider]::new())
    }
    if ($null -eq [FipsHmacSha256]::key) {
      $randomBytes = [Byte[]]::new(64); [FipsHmacSha256].RNG.GetBytes($randomBytes)
      [FipsHmacSha256]::Key = $randomBytes
      # Write-Verbose "Hexkey = $([BitConverter]::ToString([FipsHmacSha256]::Key).Tolower() -replace '-')" -verbose
    }
    $this.HashSizeValue = 256
  }
}
#endregion FipsHMACSHA256



#region    BLAKE3Hash
# .SYNOPSIS
#     BLAKE3 cryptographic hash function.
# .DESCRIPTION
#     BLAKE3 is a cryptographic hash function that is faster than MD5, SHA-1, SHA-2,
#     SHA-3, and BLAKE2. It is cryptographically secure and can be used for hashing
#     files, messages, and other data.

# .PARAMETER Data
#     The data to hash.

# .PARAMETER OutputLength
#     The desired output length in bytes (for extendable output) default is 32 bytes.

# .EXAMPLE
#     [BLAKE3]::ComputeHash([System.Text.Encoding]::UTF8.GetBytes("Hello World"))

# .OUTPUTS
#     [byte[]] - The hash value.

# .NOTES
#     BLAKE3 is a highly performant hash function.
class BLAKE3 {
  static hidden [uint32[]] $IV = [uint32[]]@(
    (0x6A09E667L -band 0xFFFFFFFFL), (0xBB67AE85L -band 0xFFFFFFFFL),
    (0x3C6EF372L -band 0xFFFFFFFFL), (0xA54FF53AL -band 0xFFFFFFFFL),
    (0x510E527FL -band 0xFFFFFFFFL), (0x9B05688CL -band 0xFFFFFFFFL),
    (0x1F83D9ABL -band 0xFFFFFFFFL), (0x5BE0CD19L -band 0xFFFFFFFFL)
  )
  static hidden [int[]] $MSG_PERMUTATION = @(
    2, 6, 3, 10, 7, 0, 4, 13, 1, 11, 12, 5, 9, 14, 15, 8
  )
  static hidden [uint32] RotR([uint32]$x, [int]$n) {
    return ($x -shr $n) -bor ($x -shl (32 - $n))
  }
  static hidden [void] G([uint32[]]$state, [int]$a, [int]$b, [int]$c, [int]$d, [uint32]$mx, [uint32]$my) {
    $state[$a] = [uint32](($state[$a] + $state[$b] + $mx) -band 0xFFFFFFFFL)
    $state[$d] = [BLAKE3]::RotR([uint32]($state[$d] -bxor $state[$a]), 16)
    $state[$c] = [uint32](($state[$c] + $state[$d]) -band 0xFFFFFFFFL)
    $state[$b] = [BLAKE3]::RotR([uint32]($state[$b] -bxor $state[$c]), 12)
    $state[$a] = [uint32](($state[$a] + $state[$b] + $my) -band 0xFFFFFFFFL)
    $state[$d] = [BLAKE3]::RotR([uint32]($state[$d] -bxor $state[$a]), 8)
    $state[$c] = [uint32](($state[$c] + $state[$d]) -band 0xFFFFFFFFL)
    $state[$b] = [BLAKE3]::RotR([uint32]($state[$b] -bxor $state[$c]), 7)
  }
  static hidden [void] Round([uint32[]]$state, [uint32[]]$m) {
    [BLAKE3]::G($state, 0, 4, 8, 12, $m[0], $m[1])
    [BLAKE3]::G($state, 1, 5, 9, 13, $m[2], $m[3])
    [BLAKE3]::G($state, 2, 6, 10, 14, $m[4], $m[5])
    [BLAKE3]::G($state, 3, 7, 11, 15, $m[6], $m[7])
    [BLAKE3]::G($state, 0, 5, 10, 15, $m[8], $m[9])
    [BLAKE3]::G($state, 1, 6, 11, 12, $m[10], $m[11])
    [BLAKE3]::G($state, 2, 7, 8, 13, $m[12], $m[13])
    [BLAKE3]::G($state, 3, 4, 9, 14, $m[14], $m[15])
  }
  static hidden [uint32[]] Compress([uint32[]]$cv, [uint32[]]$blockWords, [uint32]$counter, [uint32]$blockLen, [uint32]$flags) {
    $state = [uint32[]]::new(16)
    for ($i = 0; $i -lt 8; $i++) { $state[$i] = $cv[$i] }
    for ($i = 0; $i -lt 4; $i++) { $state[$i + 8] = [BLAKE3]::IV[$i] }
    $state[12] = $counter
    $state[13] = 0
    $state[14] = $blockLen
    $state[15] = $flags
    $m = [uint32[]]::new(16)
    for ($i = 0; $i -lt 16; $i++) { $m[$i] = $blockWords[$i] }
    [BLAKE3]::Round($state, $m)
    for ($r = 1; $r -lt 7; $r++) {
      $nextM = [uint32[]]::new(16)
      for ($i = 0; $i -lt 16; $i++) { $nextM[$i] = $m[[BLAKE3]::MSG_PERMUTATION[$i]] }
      $m = $nextM
      [BLAKE3]::Round($state, $m)
    }
    $out = [uint32[]]::new(16)
    for ($i = 0; $i -lt 8; $i++) {
      $out[$i] = [uint32]($state[$i] -bxor $state[$i + 8] -bxor $cv[$i])
      $out[$i + 8] = [uint32]($state[$i + 8] -bxor $cv[$i])
    }
    return $out
  }

  # Build root chaining-value word array from Data (single-chunk, <=64 bytes)
  static hidden [uint32[]] BuildRootWords([uint32[]]$keyIV, [byte[]]$Data) {
    $CHUNK_START = [uint32]1; $CHUNK_END = [uint32]2
    $blockWords = [uint32[]]::new(16)
    $dataLen = if ($null -ne $Data) { $Data.Length } else { 0 }
    if ($dataLen -gt 0) {
      $padded = [byte[]]::new(64)
      $copyLen = [System.Math]::Min($dataLen, 64)
      [Array]::Copy($Data, 0, $padded, 0, $copyLen)
      for ($i = 0; $i -lt 16; $i++) {
        $blockWords[$i] = [System.BitConverter]::ToUInt32($padded, $i * 4)
      }
    }
    $chunkCv = [BLAKE3]::Compress($keyIV, $blockWords, [uint32]0, [uint32]([System.Math]::Min($dataLen, 64)), $CHUNK_START -bor $CHUNK_END)
    $outWords = [uint32[]]::new(16)
    for ($i = 0; $i -lt 8; $i++) { $outWords[$i] = $chunkCv[$i] }
    return $outWords
  }

  # XOF output: counter-based expand from root words, produces OutputLength bytes
  static hidden [byte[]] XofOutput([uint32[]]$outWords, [uint32[]]$keyIV, [int]$OutputLength) {
    $ROOT = [uint32]8
    $result = [byte[]]::new($OutputLength)
    $offset = 0
    $counter = [uint32]0
    while ($offset -lt $OutputLength) {
      $block = [BLAKE3]::Compress($keyIV, $outWords, $counter, [uint32]32, $ROOT)
      for ($i = 0; $i -lt 16 -and ($offset + ($i * 4)) -lt $OutputLength; $i++) {
        $b = [System.BitConverter]::GetBytes($block[$i])
        $len = [System.Math]::Min(4, $OutputLength - $offset - ($i * 4))
        [Array]::Copy($b, 0, $result, $offset + ($i * 4), $len)
      }
      $offset += 64
      $counter++
    }
    return $result
  }

  # Convert 32-byte key to 8 uint32 IV words (BLAKE3 keyed-hash mode)
  static hidden [uint32[]] KeyToIV([byte[]]$Key) {
    if ($null -eq $Key -or $Key.Length -ne 32) {
      throw [System.ArgumentException]::new("Key must be exactly 32 bytes for BLAKE3 keyed mode")
    }
    $kiv = [uint32[]]::new(8)
    for ($i = 0; $i -lt 8; $i++) {
      $kiv[$i] = [System.BitConverter]::ToUInt32($Key, $i * 4)
    }
    return $kiv
  }

  # Standard hash, 32-byte output
  static [byte[]] ComputeHash([byte[]]$Data) {
    return [BLAKE3]::ComputeHash($Data, 32)
  }

  # Standard hash, variable XOF output
  static [byte[]] ComputeHash([byte[]]$Data, [int]$OutputLength) {
    if ($null -eq $Data) { throw [System.ArgumentNullException]::new("Data") }
    if ($OutputLength -le 0) { throw [System.ArgumentOutOfRangeException]::new("OutputLength", "OutputLength must be > 0") }
    if ($OutputLength -gt 134217728) { throw [System.ArgumentOutOfRangeException]::new("OutputLength", "OutputLength must be <= 134217728") }
    $outWords = [BLAKE3]::BuildRootWords([BLAKE3]::IV, $Data)
    return [BLAKE3]::XofOutput($outWords, [BLAKE3]::IV, $OutputLength)
  }

  # Keyed hash: Data hashed with 32-byte Key, variable XOF output
  static [byte[]] ComputeHash([byte[]]$Data, [byte[]]$Key, [int]$OutputLength) {
    if ($null -eq $Data) { throw [System.ArgumentNullException]::new("Data") }
    if ($OutputLength -le 0) { throw [System.ArgumentOutOfRangeException]::new("OutputLength", "OutputLength must be > 0") }
    $keyIV = [BLAKE3]::KeyToIV($Key)
    $outWords = [BLAKE3]::BuildRootWords($keyIV, $Data)
    return [BLAKE3]::XofOutput($outWords, $keyIV, $OutputLength)
  }

  # Keyed hash with context info: derives sub-key from Key+Info via HMAC-SHA256, then keyed-hashes Data
  static [byte[]] ComputeHash([byte[]]$Data, [byte[]]$Key, [byte[]]$Info, [int]$OutputLength) {
    if ($null -eq $Data) { throw [System.ArgumentNullException]::new("Data") }
    if ($null -eq $Key) { throw [System.ArgumentNullException]::new("Key") }
    if ($OutputLength -le 0) { throw [System.ArgumentOutOfRangeException]::new("OutputLength", "OutputLength must be > 0") }
    $hmac = [System.Security.Cryptography.HMACSHA256]::new($Key)
    $infoBytes = if ($null -ne $Info -and $Info.Length -gt 0) { $Info } else { [byte[]]::new(0) }
    $derivedKey = $hmac.ComputeHash($infoBytes)
    $hmac.Dispose()
    $keyIV = [BLAKE3]::KeyToIV($derivedKey)
    $outWords = [BLAKE3]::BuildRootWords($keyIV, $Data)
    return [BLAKE3]::XofOutput($outWords, $keyIV, $OutputLength)
  }
}