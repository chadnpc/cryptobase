# EdwardsCurve

> **Note:** This documentation was automatically generated.

## Classes

### Ed25519Impl

#### Properties

- $type $GfDConst
- $type $GfD2Const
- $type $GfXConst
- $type $GfYConst
- $type $GfIConst
- $type $L

#### Methods

- `static hidden [long[]] Gf0()`
- `static hidden [long[]] Gf1()`
- `static hidden [long[]] GfD()`
- `static hidden [long[]] GfD2()`
- `static hidden [long[]] GfX()`
- `static hidden [long[]] GfY()`
- `static hidden [long[]] GfI()`
- `static hidden [void] Set25519($r, $a)`
- `static hidden [void] Car25519($o)`
- `static hidden [void] Sel25519($p, $q, $b)`
- `static hidden [void] Pack25519($o, $n)`
- `static hidden [void] Unpack25519($o, $n)`
- `static hidden [void] A($o, $a, $b)`
- `static hidden [void] Z($o, $a, $b)`
- `static hidden [void] M($o, $a, $b)`
- `static hidden [void] S($o, $a)`
- `static hidden [void] Inv25519($o, $inp)`
- `static hidden [void] Pow2523($o, $inp)`
- `static hidden [int] Par25519($a)`
- `static hidden [void] Pack($r, $p)`
- `static hidden [bool] Unpackneg($r, $p)`
- `static hidden [bool] Neq25519($a, $b)`
- `static hidden [void] Add($p, $q)`
- `static hidden [void] Cswap($p, $q, $b)`
- `static hidden [void] Scalarbase($p, $s)`
- `static hidden [void] Scalarmult($p, $q, $s)`
- `static hidden [void] ModL($r, $roff, $x)`
- `static hidden [void] Reduce($r)`
- `static hidden [bool] CryptoVerify32($x, $y)`
- `static hidden [byte[]] Sha512($data)`
- `static [byte[]] DerivePublicKey($seed)`
- `static [byte[]] Sign($m, $sk)`
- `static [bool] Verify($m, $sm, $pk)`

### Ed25519

#### Methods

- `[void] Ed25519()`
- `static [int] KeySize()`
- `static [int] SignatureSize()`
- `[Keypair] GenerateKeyPair()`
- `static [byte[]] GetPublicKey($PrivateKey)`
- `[byte[]] Sign($Message, $PrivateKey)`
- `[bool] Verify($Signature, $Message, $PublicKey)`

### Ed448

#### Methods

- `[void] Ed448()`
- `static [int] KeySize()`
- `static [int] SignatureSize()`
- `[Keypair] GenerateKeyPair()`
- `static [byte[]] GetPublicKey($PrivateKey)`
- `[byte[]] Sign($Message, $PrivateKey)`
- `[bool] Verify($Signature, $Message, $PublicKey)`


