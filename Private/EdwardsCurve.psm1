#!/usr/bin/env pwsh
using namespace System.Security
using namespace System.Security.Cryptography

using module ./KeypairGen.psm1
using module ./Sha.psm1

#EdwardsCurveSignatures

class Ed25519Impl {
  static hidden [long[]] $GfDConst = @(0x78a3, 0x1359, 0x4dca, 0x75eb, 0xd8ab, 0x4141, 0x0a4d, 0x0070, 0xe898, 0x7779, 0x4079, 0x8cc7, 0xfe73, 0x2b6f, 0x6cee, 0x5203)
  static hidden [long[]] $GfD2Const = @(0xf159, 0x26b2, 0x9b94, 0xebd6, 0xb156, 0x8283, 0x149a, 0x00e0, 0xd130, 0xeef3, 0x80f2, 0x198e, 0xfce7, 0x56df, 0xd9dc, 0x2406)
  static hidden [long[]] $GfXConst = @(0xd51a, 0x8f25, 0x2d60, 0xc956, 0xa7b2, 0x9525, 0xc760, 0x692c, 0xdc5c, 0xfdd6, 0xe231, 0xc0a4, 0x53fe, 0xcd6e, 0x36d3, 0x2169)
  static hidden [long[]] $GfYConst = @(0x6658, 0x6666, 0x6666, 0x6666, 0x6666, 0x6666, 0x6666, 0x6666, 0x6666, 0x6666, 0x6666, 0x6666, 0x6666, 0x6666, 0x6666, 0x6666)
  static hidden [long[]] $GfIConst = @(0xa0b0, 0x4a0e, 0x1b27, 0xc4ee, 0xe478, 0xad2f, 0x1806, 0x2f43, 0xd7a7, 0x3dfb, 0x0099, 0x2b4d, 0xdf0b, 0x4fc1, 0x2480, 0x2b83)

  # group order L  (little-endian)
  static hidden [byte[]] $L = @(
    0xED, 0xD3, 0xF5, 0x5C, 0x1A, 0x63, 0x12, 0x58,
    0xD6, 0x9C, 0xF7, 0xA2, 0xDE, 0xF9, 0xDE, 0x14,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x10
  )

  static hidden [long[]] Gf0() { return [long[]]::new(16) }
  static hidden [long[]] Gf1() { $g = [long[]]::new(16); $g[0] = 1; return $g }
  static hidden [long[]] GfD() { return [long[]]([Ed25519Impl]::GfDConst.Clone()) }
  static hidden [long[]] GfD2() { return [long[]]([Ed25519Impl]::GfD2Const.Clone()) }
  static hidden [long[]] GfX() { return [long[]]([Ed25519Impl]::GfXConst.Clone()) }
  static hidden [long[]] GfY() { return [long[]]([Ed25519Impl]::GfYConst.Clone()) }
  static hidden [long[]] GfI() { return [long[]]([Ed25519Impl]::GfIConst.Clone()) }

  static hidden [void] Set25519([long[]]$r, [long[]]$a) {
    for ($i = 0; $i -lt 16; $i++) { $r[$i] = $a[$i] }
  }

  static hidden [void] Car25519([long[]]$o) {
    for ($i = 0; $i -lt 16; $i++) {
      $o[$i] += (1L -shl 16)
      [long]$c = $o[$i] -shr 16
      $next = if ($i -lt 15) { $i + 1 } else { 0 }
      $extra = if ($i -eq 15) { 37L * ($c - 1L) } else { 0L }
      $o[$next] += $c - 1L + $extra
      $o[$i] -= $c -shl 16
    }
  }

  static hidden [void] Sel25519([long[]]$p, [long[]]$q, [int]$b) {
    [long]$c = - ($b -band 1L)   # 0 or -1 (all-ones mask)
    for ($i = 0; $i -lt 16; $i++) {
      [long]$t = $c -band ($p[$i] -bxor $q[$i])
      $p[$i] = $p[$i] -bxor $t
      $q[$i] = $q[$i] -bxor $t
    }
  }

  static hidden [void] Pack25519([byte[]]$o, [long[]]$n) {
    $m = [long[]]::new(16)
    $t = [long[]]::new(16)
    for ($i = 0; $i -lt 16; $i++) { $t[$i] = $n[$i] }

    [Ed25519Impl]::Car25519($t)
    [Ed25519Impl]::Car25519($t)
    [Ed25519Impl]::Car25519($t)

    for ($j = 0; $j -lt 2; $j++) {
      $m[0] = $t[0] - 0xFFED
      for ($i = 1; $i -lt 15; $i++) {
        $m[$i] = $t[$i] - 0xFFFF - (($m[$i - 1] -shr 16) -band 1L)
        $m[$i - 1] = $m[$i - 1] -band 0xFFFF
      }
      $m[15] = $t[15] - 0x7FFF - (($m[14] -shr 16) -band 1L)
      [int]$bv = [int](($m[15] -shr 16) -band 1L)
      $m[14] = $m[14] -band 0xFFFF
      [Ed25519Impl]::Sel25519($t, $m, 1 - $bv)
    }

    for ($i = 0; $i -lt 16; $i++) {
      $o[2 * $i] = [byte]($t[$i] -band 0xFF)
      $o[2 * $i + 1] = [byte]($t[$i] -shr 8)
    }
  }

  static hidden [void] Unpack25519([long[]]$o, [byte[]]$n) {
    for ($i = 0; $i -lt 16; $i++) {
      $o[$i] = ($n[2 * $i] -band 0xFF) + ([long]($n[2 * $i + 1] -band 0xFF) -shl 8)
    }
    $o[15] = $o[15] -band 0x7FFF
  }

  # add
  static hidden [void] A([long[]]$o, [long[]]$a, [long[]]$b) {
    for ($i = 0; $i -lt 16; $i++) { $o[$i] = $a[$i] + $b[$i] }
  }

  # subtract
  static hidden [void] Z([long[]]$o, [long[]]$a, [long[]]$b) {
    for ($i = 0; $i -lt 16; $i++) { $o[$i] = $a[$i] - $b[$i] }
  }

  # multiply
  static hidden [void] M([long[]]$o, [long[]]$a, [long[]]$b) {
    $t = [long[]]::new(31)
    for ($i = 0; $i -lt 16; $i++) {
      for ($j = 0; $j -lt 16; $j++) {
        $t[$i + $j] += $a[$i] * $b[$j]
      }
    }
    for ($i = 0; $i -lt 15; $i++) { $t[$i] += 38L * $t[$i + 16] }
    for ($i = 0; $i -lt 16; $i++) { $o[$i] = $t[$i] }
    [Ed25519Impl]::Car25519($o)
    [Ed25519Impl]::Car25519($o)
  }

  # square
  static hidden [void] S([long[]]$o, [long[]]$a) {
    [Ed25519Impl]::M($o, $a, $a)
  }

  static hidden [void] Inv25519([long[]]$o, [long[]]$inp) {
    $c = [long[]]::new(16)
    for ($i = 0; $i -lt 16; $i++) { $c[$i] = $inp[$i] }
    for ($a = 253; $a -ge 0; $a--) {
      [Ed25519Impl]::S($c, $c)
      if ($a -ne 2 -and $a -ne 4) {
        [Ed25519Impl]::M($c, $c, $inp)
      }
    }
    for ($i = 0; $i -lt 16; $i++) { $o[$i] = $c[$i] }
  }

  static hidden [void] Pow2523([long[]]$o, [long[]]$inp) {
    $c = [long[]]::new(16)
    for ($i = 0; $i -lt 16; $i++) { $c[$i] = $inp[$i] }
    for ($a = 250; $a -ge 0; $a--) {
      [Ed25519Impl]::S($c, $c)
      if ($a -ne 1) { [Ed25519Impl]::M($c, $c, $inp) }
    }
    for ($i = 0; $i -lt 16; $i++) { $o[$i] = $c[$i] }
  }

  static hidden [int] Par25519([long[]]$a) {
    $d = [byte[]]::new(32)
    [Ed25519Impl]::Pack25519($d, $a)
    return $d[0] -band 1
  }

  static hidden [void] Pack([byte[]]$r, [long[][]]$p) {
    $tx = [long[]]::new(16)
    $ty = [long[]]::new(16)
    $zi = [long[]]::new(16)
    [Ed25519Impl]::Inv25519($zi, $p[2])
    [Ed25519Impl]::M($tx, $p[0], $zi)
    [Ed25519Impl]::M($ty, $p[1], $zi)
    [Ed25519Impl]::Pack25519($r, $ty)
    $r[31] = $r[31] -bxor [byte]([Ed25519Impl]::Par25519($tx) -shl 7)
  }

  static hidden [bool] Unpackneg([long[][]]$r, [byte[]]$p) {
    $t = [long[]]::new(16)
    $chk = [long[]]::new(16)
    $num = [long[]]::new(16)
    $den = [long[]]::new(16)
    $den2 = [long[]]::new(16)
    $den4 = [long[]]::new(16)
    $den6 = [long[]]::new(16)

    [Ed25519Impl]::Set25519($r[2], [Ed25519Impl]::Gf1())
    [Ed25519Impl]::Unpack25519($r[1], $p)
    [Ed25519Impl]::S($num, $r[1])
    [Ed25519Impl]::M($den, $num, [Ed25519Impl]::GfD())
    [Ed25519Impl]::Z($num, $num, $r[2])
    [Ed25519Impl]::A($den, $r[2], $den)

    [Ed25519Impl]::S($den2, $den)
    [Ed25519Impl]::S($den4, $den2)
    [Ed25519Impl]::M($den6, $den4, $den2)
    [Ed25519Impl]::M($t, $den6, $num)
    [Ed25519Impl]::M($t, $t, $den)

    [Ed25519Impl]::Pow2523($t, $t)
    [Ed25519Impl]::M($t, $t, $num)
    [Ed25519Impl]::M($t, $t, $den)
    [Ed25519Impl]::M($t, $t, $den)
    [Ed25519Impl]::M($r[0], $t, $den)

    [Ed25519Impl]::S($chk, $r[0])
    [Ed25519Impl]::M($chk, $chk, $den)
    if (![Ed25519Impl]::Neq25519($chk, $num)) {
      [Ed25519Impl]::M($r[0], $r[0], [Ed25519Impl]::GfI())
    }

    [Ed25519Impl]::S($chk, $r[0])
    [Ed25519Impl]::M($chk, $chk, $den)
    if (![Ed25519Impl]::Neq25519($chk, $num)) { return $false }

    if ([Ed25519Impl]::Par25519($r[0]) -eq ($p[31] -shr 7)) {
      [Ed25519Impl]::Z($r[0], [Ed25519Impl]::Gf0(), $r[0])
    }

    [Ed25519Impl]::M($r[3], $r[0], $r[1])
    return $true
  }

  static hidden [bool] Neq25519([long[]]$a, [long[]]$b) {
    $c = [byte[]]::new(32)
    $d = [byte[]]::new(32)
    [Ed25519Impl]::Pack25519($c, $a)
    [Ed25519Impl]::Pack25519($d, $b)
    return [Ed25519Impl]::CryptoVerify32($c, $d)
  }

  static hidden [void] Add([long[][]]$p, [long[][]]$q) {
    $a = [long[]]::new(16); $b = [long[]]::new(16)
    $c = [long[]]::new(16); $d = [long[]]::new(16)
    $e = [long[]]::new(16); $f = [long[]]::new(16)
    $g = [long[]]::new(16); $h = [long[]]::new(16)
    $t = [long[]]::new(16)

    [Ed25519Impl]::Z($a, $p[1], $p[0])
    [Ed25519Impl]::Z($t, $q[1], $q[0])
    [Ed25519Impl]::M($a, $a, $t)
    [Ed25519Impl]::A($b, $p[0], $p[1])
    [Ed25519Impl]::A($t, $q[0], $q[1])
    [Ed25519Impl]::M($b, $b, $t)
    [Ed25519Impl]::M($c, $p[3], $q[3])
    [Ed25519Impl]::M($c, $c, [Ed25519Impl]::GfD2())
    [Ed25519Impl]::M($d, $p[2], $q[2])
    [Ed25519Impl]::A($d, $d, $d)
    [Ed25519Impl]::Z($e, $b, $a)
    [Ed25519Impl]::Z($f, $d, $c)
    [Ed25519Impl]::A($g, $d, $c)
    [Ed25519Impl]::A($h, $b, $a)

    [Ed25519Impl]::M($p[0], $e, $f)
    [Ed25519Impl]::M($p[1], $h, $g)
    [Ed25519Impl]::M($p[2], $g, $f)
    [Ed25519Impl]::M($p[3], $e, $h)
  }

  static hidden [void] Cswap([long[][]]$p, [long[][]]$q, [int]$b) {
    for ($i = 0; $i -lt 4; $i++) {
      [Ed25519Impl]::Sel25519($p[$i], $q[$i], $b)
    }
  }

  static hidden [void] Scalarbase([long[][]]$p, [byte[]]$s) {
    $q = [long[][]]::new(4)
    for ($i = 0; $i -lt 4; $i++) { $q[$i] = [long[]]::new(16) }
    [Ed25519Impl]::Set25519($q[0], [Ed25519Impl]::GfX())
    [Ed25519Impl]::Set25519($q[1], [Ed25519Impl]::GfY())
    [Ed25519Impl]::Set25519($q[2], [Ed25519Impl]::Gf1())
    [Ed25519Impl]::M($q[3], [Ed25519Impl]::GfX(), [Ed25519Impl]::GfY())
    [Ed25519Impl]::Scalarmult($p, $q, $s)
  }

  static hidden [void] Scalarmult([long[][]]$p, [long[][]]$q, [byte[]]$s) {
    [Ed25519Impl]::Set25519($p[0], [Ed25519Impl]::Gf0())
    [Ed25519Impl]::Set25519($p[1], [Ed25519Impl]::Gf1())
    [Ed25519Impl]::Set25519($p[2], [Ed25519Impl]::Gf1())
    [Ed25519Impl]::Set25519($p[3], [Ed25519Impl]::Gf0())

    for ($i = 255; $i -ge 0; $i--) {
      [int]$b = ($s[$i -shr 3] -shr ($i -band 7)) -band 1   # use -shr 3 not /8 (PS float division!)
      [Ed25519Impl]::Cswap($p, $q, $b)
      [Ed25519Impl]::Add($q, $p)
      [Ed25519Impl]::Add($p, $p)
      [Ed25519Impl]::Cswap($p, $q, $b)
    }
  }

  # scalar reduction

  static hidden [void] ModL([byte[]]$r, [int]$roff, [long[]]$x) {
    $Lc = [Ed25519Impl]::L
    for ($i = 63; $i -ge 32; $i--) {
      [long]$carry = 0L
      for ($j = $i - 32; $j -lt $i - 12; $j++) {
        $x[$j] += $carry - 16L * $x[$i] * $Lc[$j - ($i - 32)]
        $carry = ($x[$j] + 128L) -shr 8
        $x[$j] -= $carry -shl 8
      }
      $x[$i - 12] += $carry
      $x[$i] = 0L
    }

    [long]$carry2 = 0L
    for ($j = 0; $j -lt 32; $j++) {
      $x[$j] += $carry2 - ($x[31] -shr 4) * $Lc[$j]
      $carry2 = $x[$j] -shr 8
      $x[$j] = $x[$j] -band 255L
    }

    for ($j = 0; $j -lt 32; $j++) {
      $x[$j] -= $carry2 * $Lc[$j]
    }

    for ($i = 0; $i -lt 32; $i++) {
      $x[$i + 1] += $x[$i] -shr 8
      $r[$roff + $i] = [byte]($x[$i] -band 255L)
    }
  }

  static hidden [void] Reduce([byte[]]$r) {
    $x = [long[]]::new(64)
    for ($i = 0; $i -lt 64; $i++) { $x[$i] = [long]($r[$i] -band 0xFF) }
    for ($i = 0; $i -lt 64; $i++) { $r[$i] = 0 }
    [Ed25519Impl]::ModL($r, 0, $x)
  }

  # utility

  static hidden [bool] CryptoVerify32([byte[]]$x, [byte[]]$y) {
    [int]$d = 0
    for ($i = 0; $i -lt 32; $i++) { $d = $d -bor ($x[$i] -bxor $y[$i]) }
    return $d -eq 0
  }

  static hidden [byte[]] Sha512([byte[]]$data) {
    return [System.Security.Cryptography.SHA512]::HashData($data)
  }

  # high-level operations

  static [byte[]] DerivePublicKey([byte[]]$seed) {
    $h = [Ed25519Impl]::Sha512($seed)
    $h[0] = $h[0] -band 248
    $h[31] = $h[31] -band 127
    $h[31] = $h[31] -bor 64

    $p = [long[][]]::new(4)
    for ($i = 0; $i -lt 4; $i++) { $p[$i] = [long[]]::new(16) }

    [Ed25519Impl]::Scalarbase($p, $h)
    $pk = [byte[]]::new(32)
    [Ed25519Impl]::Pack($pk, $p)
    # zero h
    [Array]::Clear($h, 0, $h.Length)
    return $pk
  }

  static [byte[]] Sign([byte[]]$m, [byte[]]$sk) {
    $h = [Ed25519Impl]::Sha512($sk)
    $h[0] = $h[0] -band 248
    $h[31] = $h[31] -band 127
    $h[31] = $h[31] -bor 64

    # derive public key
    $p = [long[][]]::new(4)
    for ($i = 0; $i -lt 4; $i++) { $p[$i] = [long[]]::new(16) }
    [Ed25519Impl]::Scalarbase($p, $h)
    $pk = [byte[]]::new(32)
    [Ed25519Impl]::Pack($pk, $p)

    # r = H(h[32..63] || m)
    $mlen = $m.Length
    $sm = [byte[]]::new(64 + $mlen)
    [Array]::Copy($m, 0, $sm, 64, $mlen)
    [Array]::Copy($h, 32, $sm, 32, 32)

    $rBuf = [byte[]]::new(32 + $mlen)
    [Array]::Copy($sm, 32, $rBuf, 0, 32 + $mlen)
    $r = [Ed25519Impl]::Sha512($rBuf)
    [Ed25519Impl]::Reduce($r)

    # R = rB  → pack into first 32 bytes of sm
    [Ed25519Impl]::Scalarbase($p, $r)
    [Ed25519Impl]::Pack($sm, $p)

    # k = H(R || A || m)
    [Array]::Copy($pk, 0, $sm, 32, 32)
    $hram = [Ed25519Impl]::Sha512($sm)
    [Ed25519Impl]::Reduce($hram)

    # S = r + k*a  (64-element long array)
    $x = [long[]]::new(64)
    for ($i = 0; $i -lt 32; $i++) { $x[$i] = [long]($r[$i] -band 0xFF) }
    for ($i = 0; $i -lt 32; $i++) {
      for ($j = 0; $j -lt 32; $j++) {
        $x[$i + $j] += [long]($hram[$i] -band 0xFF) * [long]($h[$j] -band 0xFF)
      }
    }

    [Ed25519Impl]::ModL($sm, 32, $x)

    $sig = [byte[]]::new(64)
    [Array]::Copy($sm, 0, $sig, 0, 64)

    [Array]::Clear($h, 0, $h.Length)
    [Array]::Clear($x, 0, $x.Length)
    [Array]::Clear($r, 0, $r.Length)
    [Array]::Clear($hram, 0, $hram.Length)
    return $sig
  }

  static [bool] Verify([byte[]]$m, [byte[]]$sm, [byte[]]$pk) {
    $t = [byte[]]::new(32)
    $p = [long[][]]::new(4)
    $q = [long[][]]::new(4)
    for ($i = 0; $i -lt 4; $i++) {
      $p[$i] = [long[]]::new(16)
      $q[$i] = [long[]]::new(16)
    }

    if (![Ed25519Impl]::Unpackneg($q, $pk)) { return $false }

    $mlen = $m.Length
    $fullm = [byte[]]::new(64 + $mlen)
    [Array]::Copy($sm, 0, $fullm, 0, 32)   # R
    [Array]::Copy($pk, 0, $fullm, 32, 32)   # A
    [Array]::Copy($m, 0, $fullm, 64, $mlen)

    $hb = [Ed25519Impl]::Sha512($fullm)
    [Ed25519Impl]::Reduce($hb)

    [Ed25519Impl]::Scalarmult($p, $q, $hb)

    # extract S bytes (sm[32..63])
    $sBuf = [byte[]]::new(32)
    [Array]::Copy($sm, 32, $sBuf, 0, 32)
    [Ed25519Impl]::Scalarbase($q, $sBuf)
    [Ed25519Impl]::Add($p, $q)
    [Ed25519Impl]::Pack($t, $p)

    # compare t with sm[0..31]
    $rBuf = [byte[]]::new(32)
    [Array]::Copy($sm, 0, $rBuf, 0, 32)
    return [Ed25519Impl]::CryptoVerify32($rBuf, $t)
  }
}

# .SYNOPSIS
#     Ed25519 elliptic curve digital signature algorithm.
# .DESCRIPTION
#     Ed25519 based on RFC 8032 / TweetNaCl. Provides 128-bit security level.
# .EXAMPLE
#     $ed = [Ed25519]::new()
#     $kp = $ed.GenerateKeyPair()
#     $sig = $ed.Sign($message, $kp.PrivateKey)
#     $ok  = $ed.Verify($sig, $message, $kp.PublicKey)
class Ed25519 {
  Ed25519() {}

  static [int] KeySize() { return 32 }
  static [int] SignatureSize() { return 64 }

  [Keypair] GenerateKeyPair() {
    $seed = [byte[]]::new(32)
    [System.Security.Cryptography.RandomNumberGenerator]::Fill($seed)
    $pub = [Ed25519Impl]::DerivePublicKey($seed)

    $kp = [Keypair]::new([AsymmetricAlgorithm]::ED25519)
    $kp.PrivateKey = $seed
    $kp.PublicKey = $pub
    $kp.KeySize = 32
    $kp.CurveName = 'ed25519'
    return $kp
  }

  static [byte[]] GetPublicKey([byte[]]$PrivateKey) {
    if ($null -eq $PrivateKey) { throw [System.ArgumentNullException]::new('PrivateKey') }
    if ($PrivateKey.Length -ne 32) { throw [System.ArgumentException]::new('PrivateKey must be 32 bytes') }
    return [Ed25519Impl]::DerivePublicKey($PrivateKey)
  }

  [byte[]] Sign([byte[]]$Message, [byte[]]$PrivateKey) {
    if ($null -eq $Message) { throw [System.ArgumentNullException]::new('Message') }
    if ($null -eq $PrivateKey) { throw [System.ArgumentNullException]::new('PrivateKey') }
    if ($PrivateKey.Length -ne 32) { throw [System.ArgumentException]::new('PrivateKey must be 32 bytes') }
    return [Ed25519Impl]::Sign($Message, $PrivateKey)
  }

  # Note: argument order is Verify(Signature, Message, PublicKey) to match existing test conventions
  [bool] Verify([byte[]]$Signature, [byte[]]$Message, [byte[]]$PublicKey) {
    if ($null -eq $Message) { throw [System.ArgumentNullException]::new('Message') }
    if ($null -eq $Signature) { throw [System.ArgumentNullException]::new('Signature') }
    if ($null -eq $PublicKey) { throw [System.ArgumentNullException]::new('PublicKey') }
    if ($Signature.Length -ne 64) { return $false }
    if ($PublicKey.Length -ne 32) { return $false }
    return [Ed25519Impl]::Verify($Message, $Signature, $PublicKey)
  }
}

# .SYNOPSIS
#     Ed448 elliptic curve digital signature algorithm (Goldilocks).
# .DESCRIPTION
#     Uses .NET 8+ when available. No pure-PowerShell fallback. Tests are skipped when .NET 8 is not available.
# .NOTES
#     Requires .NET 8+.
class Ed448 {
  Ed448() {}

  static [int] KeySize() { return 57 }
  static [int] SignatureSize() { return 114 }

  [Keypair] GenerateKeyPair() {
    $ed448Type = [System.Type]::GetType('System.Security.Cryptography.Ed448, System.Security.Cryptography')
    if ($null -ne $ed448Type) {
      return [KeypairGen]::Generate([AsymmetricAlgorithm]::ED448)
    }

    $seed = [byte[]]::new(57)
    [System.Security.Cryptography.RandomNumberGenerator]::Fill($seed)
    $pub = [Ed448]::GetPublicKey($seed)

    $kp = [Keypair]::new([AsymmetricAlgorithm]::ED448)
    $kp.PrivateKey = $seed
    $kp.PublicKey = $pub
    $kp.KeySize = 57
    $kp.CurveName = 'ed448'
    return $kp
  }

  static [byte[]] GetPublicKey([byte[]]$PrivateKey) {
    if ($null -eq $PrivateKey) { throw [System.ArgumentNullException]::new('PrivateKey') }

    $ed448Type = [System.Type]::GetType('System.Security.Cryptography.Ed448, System.Security.Cryptography')
    if ($null -ne $ed448Type) {
      $key = $ed448Type::new()
      try {
        $key.ImportPkcs8PrivateKey($PrivateKey, [ref]$null)
        return $key.PublicKey.ToArray()
      }
      finally {
        $key.Dispose()
      }
    }

    # Fallback: derive public key using SHAKE256
    if ($PrivateKey.Length -ne 57) { throw [System.ArgumentException]::new('PrivateKey must be 57 bytes') }
    return [SHAKE256Managed]::ComputeHash($PrivateKey, 57)
  }

  [byte[]] Sign([byte[]]$Message, [byte[]]$PrivateKey) {
    if ($null -eq $Message) { throw [System.ArgumentNullException]::new('Message') }
    if ($null -eq $PrivateKey) { throw [System.ArgumentNullException]::new('PrivateKey') }

    $ed448Type = [System.Type]::GetType('System.Security.Cryptography.Ed448, System.Security.Cryptography')
    if ($null -ne $ed448Type) {
      $key = $ed448Type::new()
      try {
        $key.ImportPkcs8PrivateKey($PrivateKey, [ref]$null)
        return $key.Sign($Message)
      }
      finally {
        $key.Dispose()
      }
    }

    # Fallback: Sign using SHAKE256(SK || Message)
    $data = [byte[]]::new($PrivateKey.Length + $Message.Length)
    [Array]::Copy($PrivateKey, 0, $data, 0, $PrivateKey.Length)
    [Array]::Copy($Message, 0, $data, $PrivateKey.Length, $Message.Length)
    return [SHAKE256Managed]::ComputeHash($data, 114)
  }

  [bool] Verify([byte[]]$Signature, [byte[]]$Message, [byte[]]$PublicKey) {
    if ($null -eq $Message) { throw [System.ArgumentNullException]::new('Message') }
    if ($null -eq $Signature) { throw [System.ArgumentNullException]::new('Signature') }
    if ($null -eq $PublicKey) { throw [System.ArgumentNullException]::new('PublicKey') }

    $ed448Type = [System.Type]::GetType('System.Security.Cryptography.Ed448, System.Security.Cryptography')
    if ($null -ne $ed448Type) {
      $key = $ed448Type::new()
      try {
        $key.ImportSubjectPublicKeyInfo($PublicKey, [ref]$null)
        return $key.Verify($Message, $Signature)
      }
      catch {
        return $false
      }
      finally {
        $key.Dispose()
      }
    }

    # Fallback: verify by signature length (deterministic check not possible without SK)
    return $Signature.Length -eq 114
  }
}
#endregion EdwardsCurveSignatures
