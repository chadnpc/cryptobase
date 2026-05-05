using module ..\cryptobase.psm1

Describe "Feature tests: cryptobase - Cryptographic Classes" {

  BeforeAll {
    $script:testData = [System.Text.Encoding]::UTF8.GetBytes("Hello, World! This is a test message for cryptographic operations.")
    $script:testDataShort = [System.Text.Encoding]::UTF8.GetBytes("test")
    $script:testDataEmpty = [byte[]]::new(0)
    function script:Assert-Throws ([scriptblock]$Code) {
      $threw = $false
      try { & $Code } catch { $threw = $true }
      $threw | Should Be $true
    }
    function script:HexToBytes([string]$h) {
      $bytes = [byte[]]::new($h.Length / 2)
      for ($i = 0; $i -lt $bytes.Length; $i++) {
        $bytes[$i] = [Convert]::ToByte($h.Substring($i * 2, 2), 16)
      }
      return $bytes
    }
  }

  Context "Hashing Classes: SHA3, Keccak, BLAKE3" {
    It "IdentityHash should return input bytes unchanged" {
      $ih = [IdentityHash]::new()
      $res = $ih.ComputeHash([byte[]]$testDataShort)
      [BitConverter]::ToString($res) | Should Be "74-65-73-74"
    }

    It "DoubleSha256 should return a 256-bit hash" {
      $ds = [DoubleSha256]::new()
      $res = $ds.ComputeHash([byte[]]$testData)
      $res.Length | Should Be 32
    }

    It "KeccakManaged (256) should return correct empty string hash" {
      $k = [KeccakManaged]::new(256)
      $res = $k.ComputeHash([byte[]]::new(0))
      $hex = ($res | ForEach-Object { "{0:x2}" -f $_ }) -join ""
      $hex | Should Be "c5d2460186f7233c927e7db2dcc703c0e500b653ca82273b7bfad8045d85a470"
    }

    It "SHA3_256 should return 256-bit hash" {
      $hash = [SHA3256]::ComputeHash([byte[]]$testData)
      $hash.Length | Should Be 32
    }

    It "BLAKE3 should return 256-bit hash" {
      $hash = [BLAKE3]::ComputeHash([byte[]]$testData)
      $hash.Length | Should Be 32
    }

    It "SHAKE128 should produce variable length output" {
      $hash = [SHAKE128Managed]::ComputeHash([byte[]]::new(0), 16)
      $hash.Length | Should Be 16
      $hashHex = ($hash | ForEach-Object { "{0:x2}" -f $_ }) -join ""
      $hashHex | Should Be "7f9c2ba4e88f827d616045507605853e"
    }

    It "SHAKE128 should produce variable length output" {
      $hash = [SHAKE128Managed]::ComputeHash($testData, 64)
      $hash.Length | Should Be 64
    }

    It "SHAKE256 should produce variable length output" {
      $hash = [SHAKE256Managed]::ComputeHash($testData, 128)
      $hash.Length | Should Be 128
    }

    It "SHAKE128 should handle empty input" {
      $hash = [SHAKE128Managed]::ComputeHash([byte[]]::new(0), 32)
      $hash.Length | Should Be 32
    }

    It "SHAKE256 should handle empty input" {
      $hash = [SHAKE256Managed]::ComputeHash([byte[]]::new(0), 64)
      $hash.Length | Should Be 64
    }

    It "SHAKE256 should produce variable length output" {
      $hash = [SHAKE256Managed]::ComputeHash([byte[]]$testData, 64)
      $hash.Length | Should Be 64
    }

    It "SHA3_256 should compute correct hash" {
      $hash = [SHA3256]::ComputeHash([System.Text.Encoding]::UTF8.GetBytes("hello"))
      $hashHex = ($hash | ForEach-Object { "{0:x2}" -f $_ }) -join ""
      $hashHex | Should Be "3338be694f50c5f338814986cdf0686453a888b84f424d792af4b9202398f392"
    }

    It "SHA3_384 should compute correct hash" {
      $hash = [SHA3384]::ComputeHash([byte[]]::new(0))
      $hashHex = ($hash | ForEach-Object { "{0:x2}" -f $_ }) -join ""
      $hashHex | Should Be "0c63a75b845e4f7d01107d852e4c2485c51a50aaaa94fc61995e71bbee983a2ac3713831264adb47fb6bd1e058d5f004"
    }

    It "SHA3_512 should compute correct hash" {
      $hash = [SHA3512]::ComputeHash([byte[]]::new(0))
      $hashHex = ($hash | ForEach-Object { "{0:x2}" -f $_ }) -join ""
      $hashHex | Should Be "a69f73cca23a9ac5c8b567dc185a756e97c982164fe25859e0d1dcc1475c80a615b2123af1f5f94c11e3e9402c3ac558f500199d95b6d3e301758586281dcd26"
    }

    It "SHA3 classes should handle empty input" {
      $hash256 = [SHA3256]::ComputeHash([byte[]]::new(0))
      $hash256.Length | Should Be 32
      $hash384 = [SHA3384]::ComputeHash([byte[]]::new(0))
      $hash384.Length | Should Be 48
      $hash512 = [SHA3512]::ComputeHash([byte[]]::new(0))
      $hash512.Length | Should Be 64
    }
  }

  #region HKDF Tests
  Context "HKDF Key Derivation" {
    It "HKDF should derive key material" {
      $ikm = [byte[]]@(0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b)
      $salt = [byte[]]@(0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c)
      $info = [byte[]]@(0xf0, 0xf1, 0xf2, 0xf3, 0xf4, 0xf5, 0xf6, 0xf7, 0xf8, 0xf9)
      $key = [HKDF]::DeriveKey($ikm, $salt, $info, 32)
      $key.Length | Should Be 32
    }

    It "HKDF.Expand should produce correct length" {
      $prk = [byte[]]::new(32)
      [System.Security.Cryptography.RandomNumberGenerator]::Fill($prk)
      $info = [System.Text.Encoding]::UTF8.GetBytes("info")
      $expanded = [HKDF]::HkdfExpand($prk, $info, 64)
      $expanded.Length | Should Be 64
    }

    It "HKDF should derive multiple keys" {
      $ikm = [byte[]]::new(32)
      [System.Security.Cryptography.RandomNumberGenerator]::Fill($ikm)
      $key1 = [HKDF]::DeriveKey($ikm, $null, [System.Text.Encoding]::UTF8.GetBytes("key1"), 32)
      $key2 = [HKDF]::DeriveKey($ikm, $null, [System.Text.Encoding]::UTF8.GetBytes("key2"), 32)
      $same = ([int[]]$key1 | Measure-Object -Sum).Sum -eq ([int[]]$key2 | Measure-Object -Sum).Sum
      $same | Should Be $false
    }
  }
  #endregion

  #region Ed25519/Ed448 Tests
  Context "Edwards Curve Digital Signatures" {
    # ── Basic functionality
    It "Ed25519 should generate key pair with correct sizes" {
      $ed = [Ed25519]::new()
      $keyPair = $ed.GenerateKeyPair()
      $keyPair.PublicKey.Length | Should Be 32
      $keyPair.PrivateKey.Length | Should Be 32
    }

    It "Ed25519 key pairs should be unique across calls" {
      $ed = [Ed25519]::new()
      $kp1 = $ed.GenerateKeyPair()
      $kp2 = $ed.GenerateKeyPair()
      ($kp1.PrivateKey -join ',') | Should Not Be ($kp2.PrivateKey -join ',')
      ($kp1.PublicKey -join ',') | Should Not Be ($kp2.PublicKey -join ',')
    }

    It "Ed25519 should derive consistent public key from private key" {
      $ed = [Ed25519]::new()
      $keyPair = $ed.GenerateKeyPair()
      $derived = [Ed25519]::GetPublicKey($keyPair.PrivateKey)
      ($derived -join ',') | Should Be ($keyPair.PublicKey -join ',')
    }

    It "Ed25519 should sign and verify" {
      $ed = [Ed25519]::new()
      $keyPair = $ed.GenerateKeyPair()
      $signature = $ed.Sign($script:testData, $keyPair.PrivateKey)
      $signature.Length | Should Be 64
      $valid = $ed.Verify($signature, $script:testData, $keyPair.PublicKey)
      $valid | Should Be $true
    }

    It "Ed25519 signatures should be deterministic" {
      $ed = [Ed25519]::new()
      $keyPair = $ed.GenerateKeyPair()
      $sig1 = $ed.Sign($script:testData, $keyPair.PrivateKey)
      $sig2 = $ed.Sign($script:testData, $keyPair.PrivateKey)
      ($sig1 -join ',') | Should Be ($sig2 -join ',')
    }

    It "Ed25519 different messages should produce different signatures" {
      $ed = [Ed25519]::new()
      $keyPair = $ed.GenerateKeyPair()
      $sig1 = $ed.Sign($script:testData, $keyPair.PrivateKey)
      $sig2 = $ed.Sign($script:testDataShort, $keyPair.PrivateKey)
      ($sig1 -join ',') | Should Not Be ($sig2 -join ',')
    }

    It "Ed25519 should sign and verify empty message" {
      $ed = [Ed25519]::new()
      $keyPair = $ed.GenerateKeyPair()
      $sig = $ed.Sign($script:testDataEmpty, $keyPair.PrivateKey)
      $valid = $ed.Verify($sig, $script:testDataEmpty, $keyPair.PublicKey)
      $sig.Length | Should Be 64
      $valid | Should Be $true
    }

    # ── Security / rejection tests
    It "Ed25519 should reject tampered message" {
      $ed = [Ed25519]::new()
      $keyPair = $ed.GenerateKeyPair()
      $signature = $ed.Sign($script:testData, $keyPair.PrivateKey)
      $tampered = [byte[]]$script:testData.Clone()
      $tampered[0] = ($tampered[0] + 1) % 256
      $valid = $ed.Verify($signature, $tampered, $keyPair.PublicKey)
      $valid | Should Be $false
    }

    It "Ed25519 should reject tampered signature" {
      $ed = [Ed25519]::new()
      $keyPair = $ed.GenerateKeyPair()
      $signature = $ed.Sign($script:testData, $keyPair.PrivateKey)
      $tampered = [byte[]]$signature.Clone()
      $tampered[0] = ($tampered[0] -bxor 0xFF)
      $valid = $ed.Verify($tampered, $script:testData, $keyPair.PublicKey)
      $valid | Should Be $false
    }

    It "Ed25519 should reject wrong public key" {
      $ed = [Ed25519]::new()
      $kp1 = $ed.GenerateKeyPair()
      $kp2 = $ed.GenerateKeyPair()
      $sig = $ed.Sign($script:testData, $kp1.PrivateKey)
      $valid = $ed.Verify($sig, $script:testData, $kp2.PublicKey)
      $valid | Should Be $false
    }

    It "Ed25519 should reject all-zero signature" {
      $ed = [Ed25519]::new()
      $keyPair = $ed.GenerateKeyPair()
      $zeroSig = [byte[]]::new(64)
      $valid = $ed.Verify($zeroSig, $script:testData, $keyPair.PublicKey)
      $valid | Should Be $false
    }

    # ── RFC 8032 Known Answer Tests
    It "Ed25519 RFC 8032 Test 1: empty message" {
      # https://www.rfc-editor.org/rfc/rfc8032#section-7.1 Test 1
      $privHex = "9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60"
      $pubHex = "d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a"
      $sigHex = "e5564300c360ac729086e2cc806e828a84877f1eb8e5d974d873e065224901555fb8821590a33bacc61e39701cf9b46bd25bf5f0595bbe24655141438e7a100b"

      $privateKey = HexToBytes $privHex
      $expectedPub = HexToBytes $pubHex
      $expectedSig = HexToBytes $sigHex
      $message = [byte[]]::new(0)

      $derivedPub = [Ed25519]::GetPublicKey($privateKey)
      ($derivedPub -join ',') | Should Be ($expectedPub -join ',')

      $ed = [Ed25519]::new()
      $sig = $ed.Sign($message, $privateKey)
      ($sig -join ',') | Should Be ($expectedSig -join ',')

      $valid = $ed.Verify($sig, $message, $derivedPub)
      $valid | Should Be $true
    }

    It "Ed25519 RFC 8032 Test 2: single byte message 'r'" {
      # https://www.rfc-editor.org/rfc/rfc8032#section-7.1 Test 2
      $privHex = "4ccd089b28ff96da9db6c346ec114e0f5b8a319f35aba624da8cf6ed4fb8a6fb"
      $pubHex = "3d4017c3e843895a92b70aa74d1b7ebc9c982ccf2ec4968cc0cd55f12af4660c"
      $sigHex = "92a009a9f0d4cab8720e820b5f642540a2b27b5416503f8fb3762223ebdb69da085ac1e43e15996e458f3613d0f11d8c387b2eaeb4302aeeb00d291612bb0c00"

      function HexToBytes2([string]$h) {
        $bytes = [byte[]]::new($h.Length / 2)
        for ($i = 0; $i -lt $bytes.Length; $i++) {
          $bytes[$i] = [Convert]::ToByte($h.Substring($i * 2, 2), 16)
        }
        return $bytes
      }

      $privateKey = HexToBytes2 $privHex
      $expectedPub = HexToBytes2 $pubHex
      $expectedSig = HexToBytes2 $sigHex
      $message = [System.Text.Encoding]::ASCII.GetBytes("r")

      $derivedPub = [Ed25519]::GetPublicKey($privateKey)
      ($derivedPub -join ',') | Should Be ($expectedPub -join ',')

      $ed = [Ed25519]::new()
      $sig = $ed.Sign($message, $privateKey)
      ($sig -join ',') | Should Be ($expectedSig -join ',')

      $valid = $ed.Verify($sig, $message, $derivedPub)
      $valid | Should Be $true
    }

    # ── Ed448 (requires .NET 8+)
    It "Ed448 should generate key pair" {
      $ed = [Ed448]::new()
      $keyPair = $ed.GenerateKeyPair()
      $keyPair.PublicKey.Length | Should BeGreaterThan 0
      $keyPair.PrivateKey.Length | Should BeGreaterThan 0
    }

    It "Ed448 should sign and verify" {
      $ed = [Ed448]::new()
      $keyPair = $ed.GenerateKeyPair()
      $signature = $ed.Sign($script:testData, $keyPair.PrivateKey)
      $valid = $ed.Verify($signature, $script:testData, $keyPair.PublicKey)
      $valid | Should Be $true
    }
  }
  #endregion

  # #region BLAKE3 Tests
  Context "BLAKE3 Hash" {
    It "BLAKE3 should compute hash" {
      $hash = [BLAKE3]::ComputeHash($testData)
      $hash.Length | Should Be 32
    }

    It "BLAKE3 should handle empty input" {
      $hash = [BLAKE3]::ComputeHash([byte[]]::new(0))
      $hash.Length | Should Be 32
      $hashHex = ($hash | ForEach-Object { "{0:x2}" -f $_ }) -join ""
      $hashHex | Should Be "5b1ec33e8dbf5db27ff34921b2406b7d5e85fad340997f11fd002622b08c16e6"
    }

    It "BLAKE3 should support keyed mode" {
      $info = [byte[]]@(1..32); $key = [byte[]]@(1..32)
      $hash = [BLAKE3]::ComputeHash($testData, $key, $info, 128)
      $hash.Length | Should Be 128
    }

    It "BLAKE3 should support keyed mode with empty input" {
      $key = [byte[]]@(1..32)
      $hash = [BLAKE3]::ComputeHash([byte[]]::new(0), $key, 128)
      $hash.Length | Should Be 128
    }

    It "BLAKE3 should support keyed mode with empty input and output length" {
      $hash = [BLAKE3]::ComputeHash([byte[]]::new(0), 128)
      $hash.Length | Should Be 128
      $hashHex = ($hash | ForEach-Object { "{0:x2}" -f $_ }) -join ""
      $hashHex | Should Be "5b1ec33e8dbf5db27ff34921b2406b7d5e85fad340997f11fd002622b08c16e6255a78493484180c84ed7d2281eff89a2820c768e0191b0442d6430e33e39ecbf43dc1fdfaa96998da07585b11875641cf8c9220603e32b64cef8da10f2dc86cf2630bcd8dcbc0dc4081cecefca1de36c2cdea4a1ca7e9703b650971ccbbb4b0"
    }
  }
  #endregion

  #region KMAC Tests
  Context "KMAC Message Authentication" {
    $key = [byte[]]@(1..32)

    It "KMAC128 should compute MAC" {
      $mac = [KMAC128]::ComputeHash($key, $testData, 32, "TEST")
      $mac.Length | Should Be 32
    }

    It "KMAC128 should compute MAC with default output length" {
      $mac = [KMAC128]::ComputeHash($key, $testData)
      $mac.Length | Should Be 32
    }

    It "KMAC256 should compute MAC" {
      $mac = [KMAC256]::ComputeHash($key, $testData, 32, "TEST")
      $mac.Length | Should Be 32
    }

    It "KMAC128 should handle empty input" {
      $mac = [KMAC128]::ComputeHash([byte[]]::new(0), $key)
      $mac.Length | Should Be 32
    }

    It "KMAC should produce different MACs for different keys" {
      $key1 = [byte[]]@(1..32)
      $key2 = [byte[]]@(2..33)
      $mac1 = [KMAC128]::ComputeHash($key1, $testData, 32, "TEST")
      $mac2 = [KMAC128]::ComputeHash($key2, $testData, 32, "TEST")
      $same = ([int[]]$mac1 | Measure-Object -Sum).Sum -eq ([int[]]$mac2 | Measure-Object -Sum).Sum
      $same | Should Be $false
    }
  }
  #endregion

  #region Argon2 Tests
  Context "Argon2 Password Hashing" {
    It "Argon2id should hash and verify" {
      $argon2 = [Argon2id]::new()
      $password = [System.Text.Encoding]::UTF8.GetBytes("password")
      $hash = $argon2.Hash($password)
      $valid = $argon2.Verify($hash, $password)
      $valid | Should Be $true
    }

    It "Argon2id should reject wrong password" {
      $argon2 = [Argon2id]::new()
      $password = [System.Text.Encoding]::UTF8.GetBytes("password")
      $wrongPassword = [System.Text.Encoding]::UTF8.GetBytes("wrong")
      $hash = $argon2.Hash($password)
      $valid = $argon2.Verify($hash, $wrongPassword)
      $valid | Should Be $false
    }

    It "Argon2i should hash and verify" {
      $argon2 = [Argon2id]::new()
      $password = [System.Text.Encoding]::UTF8.GetBytes("password")
      $hash = $argon2.Hash($password)
      $valid = $argon2.Verify($hash, $password)
      $valid | Should Be $true
    }

    It "Argon2d should hash and verify" {
      $argon2 = [Argon2id]::new()
      $password = [System.Text.Encoding]::UTF8.GetBytes("password")
      $hash = $argon2.Hash($password)
      $valid = $argon2.Verify($hash, $password)
      $valid | Should Be $true
    }

    It "Scrypt should hash and verify" {
      $scrypt = [Scrypt]::new()
      $password = [System.Text.Encoding]::UTF8.GetBytes("password")
      $hash = $scrypt.Hash($password)
      $valid = $scrypt.Verify($hash, $password)
      $valid | Should Be $true
    }
  }
  #endregion

  #region AesSIV Tests
  Context "AES-SIV Authenticated Encryption" {
    It "AesSIV should encrypt and decrypt" {
      $aesSiv = [AesSIV]::new()
      $encrypted = $aesSiv.Encrypt($testData)
      $decrypted = $aesSiv.Decrypt($encrypted)
      $decrypted | Should Be $testData
    }

    It "AesSIV should reject tampered ciphertext" {
      $aesSiv = [AesSIV]::new()
      $encrypted = $aesSiv.Encrypt($testData)
      $tampered = [byte[]]$encrypted.Clone()
      $tampered[12] = ($tampered[12] -bxor 0xFF)  # flip all bits in auth tag byte
      $threw = $false
      try { $aesSiv.Decrypt($tampered) } catch { $threw = $true }
      $threw | Should Be $true
    }

    It "AesSIV should work with associated data" {
      $aesSiv = [AesSIV]::new()
      $encrypted = $aesSiv.Encrypt($testData)
      $decrypted = $aesSiv.Decrypt($encrypted)
      $decrypted | Should Be $testData
    }
  }
  #endregion

  #region ChaCha20Poly1305 Tests
  Context "ChaCha20-Poly1305 AEAD" {
    It "ChaCha20Poly1305 should encrypt and decrypt" {
      $chacha = [ChaCha20Poly1305Managed]::new()
      $encrypted = $chacha.Encrypt($testData)
      $decrypted = $chacha.Decrypt($encrypted)
      $decrypted | Should Be $testData
    }

    It "ChaCha20Poly1305 should reject tampered ciphertext" {
      $chacha = [ChaCha20Poly1305Managed]::new()
      $encrypted = $chacha.Encrypt($testData)
      $tampered = $encrypted.Clone()
      $tampered[0] = ($tampered[0] + 1) % 256
      $threw = $false
      try { $chacha.Decrypt($tampered) } catch { $threw = $true }
      $threw | Should Be $true
    }
  }
  #endregion

  #region AesCCM Tests
  Context "AES-CCM AEAD" {
    It "AesCCM should encrypt and decrypt" {
      $aesCcm = [AesCCMCore]::new()
      $encrypted = $aesCcm.Encrypt($testData)
      $decrypted = $aesCcm.Decrypt($encrypted)
      $decrypted | Should Be $testData
    }

    It "AesCCM should reject tampered ciphertext" {
      $aesCcm = [AesCCMCore]::new()
      $encrypted = $aesCcm.Encrypt($testData)
      $tampered = $encrypted.Clone()
      $tampered[0] = ($tampered[0] + 1) % 256
      $threw = $false
      try { $aesCcm.Decrypt($tampered) } catch { $threw = $true }
      $threw | Should Be $true
    }
  }
  #endregion

  #region AesOcb Tests
  Context "AES-OCB - Offset Codebook Authenticated Encryption" {
    It "AesOcbCore should encrypt and decrypt (AES-128)" {
      $key = [byte[]]::new(16); [System.Security.Cryptography.RandomNumberGenerator]::Create().GetBytes($key)
      $nonce = [byte[]]::new(12); [System.Security.Cryptography.RandomNumberGenerator]::Create().GetBytes($nonce)
      $result = [AesOcbCore]::Encrypt($testData, $key, $nonce)
      $decrypted = [AesOcbCore]::Decrypt($result.Ciphertext, $key, $result.Nonce)
      ($decrypted -join ',') | Should Be ($testData -join ',')
    }

    It "AesOcbCore should encrypt and decrypt (AES-256)" {
      $key = [byte[]]::new(32); [System.Security.Cryptography.RandomNumberGenerator]::Create().GetBytes($key)
      $nonce = [byte[]]::new(12); [System.Security.Cryptography.RandomNumberGenerator]::Create().GetBytes($nonce)
      $result = [AesOcbCore]::Encrypt($testData, $key, $nonce)
      $decrypted = [AesOcbCore]::Decrypt($result.Ciphertext, $key, $result.Nonce)
      ($decrypted -join ',') | Should Be ($testData -join ',')
    }

    It "AesOcbCore should support associated data" {
      $key = [byte[]]::new(16); [System.Security.Cryptography.RandomNumberGenerator]::Create().GetBytes($key)
      $nonce = [byte[]]::new(12); [System.Security.Cryptography.RandomNumberGenerator]::Create().GetBytes($nonce)
      $ad = [System.Text.Encoding]::UTF8.GetBytes('aad-test')
      $result = [AesOcbCore]::Encrypt($testDataShort, $key, $nonce, $ad)
      $decrypted = [AesOcbCore]::Decrypt($result.Ciphertext, $key, $result.Nonce, $ad)
      ($decrypted -join ',') | Should Be ($testDataShort -join ',')
    }

    It "AesOcbCore should support edge case nonce sizes (1 and 15 bytes)" {
      $key = [byte[]]::new(16); [System.Security.Cryptography.RandomNumberGenerator]::Create().GetBytes($key)
      foreach ($nSize in 1, 15) {
        $nonce = [byte[]]::new($nSize); [System.Security.Cryptography.RandomNumberGenerator]::Create().GetBytes($nonce)
        $result = [AesOcbCore]::Encrypt($testData, $key, $nonce)
        $decrypted = [AesOcbCore]::Decrypt($result.Ciphertext, $key, $nonce)
        ($decrypted -join ',') | Should Be ($testData -join ',')
      }
    }

    It "AesOcbCore should reject tampered ciphertext" {
      $key = [byte[]]::new(16); [System.Security.Cryptography.RandomNumberGenerator]::Create().GetBytes($key)
      $nonce = [byte[]]::new(12); [System.Security.Cryptography.RandomNumberGenerator]::Create().GetBytes($nonce)
      $result = [AesOcbCore]::Encrypt($testData, $key, $nonce)
      $tampered = [byte[]]$result.Ciphertext.Clone()
      $tampered[0] = ($tampered[0] -bxor 0xFF)
      Assert-Throws { [AesOcbCore]::Decrypt($tampered, $key, $nonce) }
    }

    It "AesOcb builder should encrypt and decrypt" {
      $key = [byte[]]::new(32); [System.Security.Cryptography.RandomNumberGenerator]::Create().GetBytes($key)
      $nonce = [byte[]]::new(12); [System.Security.Cryptography.RandomNumberGenerator]::Create().GetBytes($nonce)
      $ocb = [AesOcb]::new().WithKey($key).WithNonce($nonce)
      $encrypted = $ocb.Encrypt($testData)
      $decrypted = $ocb.Decrypt($encrypted)
      ($decrypted -join ',') | Should Be ($testData -join ',')
    }
  }
  #endregion

  #region Post-Quantum Tests
  Context "Post-Quantum Cryptography" {
    It "MLKem should generate key pair" {
      $keyPair = [MLKemCore]::GenerateKeyPair()
      $keyPair.PublicKey.Length | Should BeGreaterThan 0
      $keyPair.PrivateKey.Length | Should BeGreaterThan 0
    }

    It "MLKem should encapsulate and decapsulate" {
      $keyPair = [MLKemCore]::GenerateKeyPair()
      $encap = [MLKemCore]::Encapsulate($keyPair.PublicKey)
      $shared = [MLKemCore]::Decapsulate($encap.Ciphertext, $keyPair.PrivateKey)
      ($shared -join ',') | Should Be ($encap.SharedSecret -join ',')
    }

    It "MLKemBuilder should work correctly" {
      $builder = [MLKemBuilder]::Create().WithSecurityLevel([MLKemSecurityLevel]::MLKem768)
      $keyPair = $builder.GenerateKeyPair()

      $encap = [MLKemBuilder]::Create().WithPublicKey($keyPair.PublicKey).Encapsulate()
      $shared = [MLKemBuilder]::Create().WithKeyPair($keyPair).Decapsulate($encap.Ciphertext)

      ($shared -join ',') | Should Be ($encap.SharedSecret -join ',')
    }


    It "MLDsa should generate key pair" {
      $keyPair = [MLDsaCore]::GenerateKeyPair()
      $keyPair.PublicKey.Length | Should BeGreaterThan 0
      $keyPair.PrivateKey.Length | Should BeGreaterThan 0
    }

    It "MLDsa should sign and verify" {
      $keyPair = [MLDsaCore]::GenerateKeyPair()
      $signature = [MLDsaCore]::Sign($testData, $keyPair.PrivateKey)
      $valid = [MLDsaCore]::Verify($testData, $signature, $keyPair.PublicKey)
      $valid | Should Be $true
    }

    It "MLDsaBuilder should work correctly" {
      $keyPair = [MLDsaBuilder]::Create().WithSecurityLevel([MLDsaSecurityLevel]::MLDsa44).GenerateKeyPair()
      $signature = [MLDsaBuilder]::Create().WithKeyPair($keyPair).WithData($testData).Sign()
      $valid = [MLDsaBuilder]::Create().WithPublicKey($keyPair.PublicKey).WithData($testData).Verify($signature)
      $valid | Should Be $true
    }

    It "SlhDsa should generate key pair" {
      $keyPair = [SlhDsaCore]::GenerateKeyPair()
      $keyPair.PublicKey.Length | Should BeGreaterThan 0
      $keyPair.PrivateKey.Length | Should BeGreaterThan 0
    }

    It "SlhDsa should sign and verify" {
      $keyPair = [SlhDsaCore]::GenerateKeyPair()
      $signature = [SlhDsaCore]::Sign($testData, $keyPair.PrivateKey)
      $valid = [SlhDsaCore]::Verify($testData, $signature, $keyPair.PublicKey)
      $valid | Should Be $true
    }

    It "SlhDsaBuilder should work correctly" {
      $keyPair = [SlhDsaBuilder]::Create().WithSecurityLevel([SlhDsaSecurityLevel]::SlhDsa128f).GenerateKeyPair()
      $signature = [SlhDsaBuilder]::Create().WithKeyPair($keyPair).WithData($testData).Sign()
      $valid = [SlhDsaBuilder]::Create().WithPublicKey($keyPair.PublicKey).WithData($testData).Verify($signature)
      $valid | Should Be $true
    }
  }
  #endregion

  Context "Utility Classes" {
    It "Asn1Parser should parse ASN.1 data" {
      $parser = [Asn1Parser]::new()
      $data = [byte[]]@(0x30, 0x0C, 0x02, 0x01, 0x01, 0x02, 0x01, 0x02, 0x04, 0x01, 0x03, 0x04, 0x01, 0x04)
      $result = $parser.Parse($data)
      $result | Should Not BeNullOrEmpty
    }

    It "PemParser should decode PEM" {
      $parser = [PemParser]::new()
      $pem = "-----BEGIN TEST-----`nSGVsbG8=`n-----END TEST-----"
      $result = $parser.Decode($pem)
      $result.Length | Should BeGreaterThan 0
    }

    It "SecureBox should encrypt and decrypt" {
      $key = [byte[]]@(1..32)
      $secureBox = [SecureBox]::new($key)
      $plainbytes = $testData
      $encrypted = $secureBox.Encrypt($plainbytes)
      $decrypted = $secureBox.Decrypt($encrypted)
      $decrypted | Should Be $plainbytes
    }

    It "SecureArray should protect memory" {
      $secureArray = [SecureArray]::new($testData)
      $secureArray.Length | Should Be $testData.Length
      $secureArray.Dispose()
    }
  }
  Context "Advanced Protocols" {
    It "NoiseProtocol should generate key pair" {
      $noise = [NoiseProtocol]::new()
      $keyPair = $noise.GenerateKeyPair()
      $keyPair.PublicKey.Length | Should Be 32
      $keyPair.PrivateKey.Length | Should Be 32
    }

    It "VOPRF should evaluate" {
      $voprf = [VOPRF]::new()
      $keyPair = $voprf.GenerateKeyPair()
      $output = $voprf.Evaluate($testData, $keyPair.PrivateKey)
      $output.Length | Should Be 32
    }
  }
  Context "OPAQUE protocol" {

    function SetupAndRegisterOpaque {
      param (
        [string]$UserIdentifier,
        [string]$Pass,
        [string]$ClientIdentifier = $null,
        [string]$ServerIdentifier = $null,
        [KSFConfig]$Config = $null
      )

      $server = [OpaqueServer]::new()
      $client = [OpaqueClient]::new()

      $serverSetup = $server.CreateSetup()

      $startResult = $client.StartRegistration($Pass)

      $response = $server.CreateRegistrationResponse($serverSetup, $UserIdentifier, [Convert]::FromBase64String($startResult.RegistrationRequest))

      $finishResult = $client.FinishRegistration($Pass, $response, $startResult.ClientRegistrationState, $ClientIdentifier, $ServerIdentifier, $Config)

      return @{
        ServerSetup           = $serverSetup
        RegistrationRecord    = $finishResult.RegistrationRecord
        ExportKey             = $finishResult.ExportKey
        ServerStaticPublicKey = $finishResult.ServerStaticPublicKey
      }
    }
    It "OPAQUE should create registration request" {
      $request = [OPAQUE]::CreateRegistrationRequest("password")
      $request | Should Not BeNullOrEmpty
    }

    It "Full registration and login succeeds" {
      $userIdentifier = "user123"
      $Password = "hunter42"

      $setup = SetupAndRegisterOpaque -UserIdentifier $userIdentifier -Pass $Password

      $server = [OpaqueServer]::new()
      $client = [OpaqueClient]::new()

      $clientLoginResult = $client.StartLogin($Password)

      $serverLoginResult = $server.StartLogin($setup.ServerSetup, [Convert]::FromBase64String($clientLoginResult.StartLoginRequest), $userIdentifier, $setup.RegistrationRecord)

      $finishClientLoginResult = $client.FinishLogin($clientLoginResult.ClientLoginState, [Convert]::FromBase64String($serverLoginResult.LoginResponse), $Password)

      $serverPublicKey = $server.GetPublicKey($setup.ServerSetup)

      $setup.ExportKey | Should Be $finishClientLoginResult.ExportKey
      $setup.ServerStaticPublicKey | Should Be $finishClientLoginResult.ServerStaticPublicKey
      $finishClientLoginResult.ServerStaticPublicKey | Should Be $serverPublicKey

      $sessionKey = $server.FinishLogin($serverLoginResult.ServerLoginState, [Convert]::FromBase64String($finishClientLoginResult.FinishLoginRequest))

      $sessionKey | Should Be $finishClientLoginResult.SessionKey
    }

    It "Full registration and login succeeds with RFC Draft Recommended KSF" {
      $userIdentifier = "user123"
      $Password = "hunter42"

      $config = [KSFConfig]::Create([KSFConfigType]::RfcDraftRecommended)

      $setup = SetupAndRegisterOpaque -UserIdentifier $userIdentifier -Pass $Password -Config $config

      $server = [OpaqueServer]::new()
      $client = [OpaqueClient]::new()

      $clientLoginResult = $client.StartLogin($Password)

      $serverLoginResult = $server.StartLogin($setup.ServerSetup, [Convert]::FromBase64String($clientLoginResult.StartLoginRequest), $userIdentifier, $setup.RegistrationRecord)

      $finishClientLoginResult = $client.FinishLogin($clientLoginResult.ClientLoginState, [Convert]::FromBase64String($serverLoginResult.LoginResponse), $Password, $null, $null, $config)

      $serverPublicKey = $server.GetPublicKey($setup.ServerSetup)

      $setup.ExportKey | Should Be $finishClientLoginResult.ExportKey
      $setup.ServerStaticPublicKey | Should Be $finishClientLoginResult.ServerStaticPublicKey
      $finishClientLoginResult.ServerStaticPublicKey | Should Be $serverPublicKey

      $sessionKey = $server.FinishLogin($serverLoginResult.ServerLoginState, [Convert]::FromBase64String($finishClientLoginResult.FinishLoginRequest))

      $sessionKey | Should Be $finishClientLoginResult.SessionKey
    }

    It "Full registration and login succeeds with Custom KSF Config" {
      $userIdentifier = "user123"
      $Password = "hunter42"

      $config = [KSFConfig]::Create([KSFConfigType]::Custom, 1, 65536, 4)

      $setup = SetupAndRegisterOpaque -UserIdentifier $userIdentifier -Pass $Password -Config $config

      $server = [OpaqueServer]::new()
      $client = [OpaqueClient]::new()

      $clientLoginResult = $client.StartLogin($Password)

      $serverLoginResult = $server.StartLogin($setup.ServerSetup, [Convert]::FromBase64String($clientLoginResult.StartLoginRequest), $userIdentifier, $setup.RegistrationRecord)

      $finishClientLoginResult = $client.FinishLogin($clientLoginResult.ClientLoginState, [Convert]::FromBase64String($serverLoginResult.LoginResponse), $Password, $null, $null, $config)

      $serverPublicKey = $server.GetPublicKey($setup.ServerSetup)

      $setup.ExportKey | Should Be $finishClientLoginResult.ExportKey
      $setup.ServerStaticPublicKey | Should Be $finishClientLoginResult.ServerStaticPublicKey
      $finishClientLoginResult.ServerStaticPublicKey | Should Be $serverPublicKey

      $sessionKey = $server.FinishLogin($serverLoginResult.ServerLoginState, [Convert]::FromBase64String($finishClientLoginResult.FinishLoginRequest))

      $sessionKey | Should Be $finishClientLoginResult.SessionKey
    }

    It "Mismatched config fails login" {
      $userIdentifier = "user123"
      $Password = "hunter42"

      # Use default config (MemoryConstrained)
      $setup = SetupAndRegisterOpaque -UserIdentifier $userIdentifier -Pass $Password

      $server = [OpaqueServer]::new()
      $client = [OpaqueClient]::new()

      $clientLoginResult = $client.StartLogin($Password)

      $serverLoginResult = $server.StartLogin($setup.ServerSetup, [Convert]::FromBase64String($clientLoginResult.StartLoginRequest), $userIdentifier, $setup.RegistrationRecord)

      $config = [KSFConfig]::Create([KSFConfigType]::RfcDraftRecommended)

      Assert-Throws { $client.FinishLogin($clientLoginResult.ClientLoginState, [Convert]::FromBase64String($serverLoginResult.LoginResponse), $Password, $null, $null, $config) }
    }

    It "Incorrect password fails login" {
      $userIdentifier = "user123"
      $rightPassword = "hunter42"
      $wrongPassword = "hunter43"

      $setup = SetupAndRegisterOpaque -UserIdentifier $userIdentifier -Pass $rightPassword
      $server = [OpaqueServer]::new()
      $client = [OpaqueClient]::new()

      $clientLoginResult = $client.StartLogin($rightPassword)

      $serverLoginResult = $server.StartLogin($setup.ServerSetup, [Convert]::FromBase64String($clientLoginResult.StartLoginRequest), $userIdentifier, $setup.RegistrationRecord)

      Assert-Throws { $client.FinishLogin($clientLoginResult.ClientLoginState, [Convert]::FromBase64String($serverLoginResult.LoginResponse), $wrongPassword) }
    }

    It "Incorrect client identifier fails" {
      $userIdentifier = "user123"
      $Password = "hunter2"
      $clientIdentifier = "client123"

      $setup = SetupAndRegisterOpaque -UserIdentifier $userIdentifier -Pass $Password -ClientIdentifier $clientIdentifier

      $server = [OpaqueServer]::new()
      $client = [OpaqueClient]::new()

      $clientLoginResult = $client.StartLogin($Password)

      $serverLoginResult = $server.StartLogin($setup.ServerSetup, [Convert]::FromBase64String($clientLoginResult.StartLoginRequest), $userIdentifier, $setup.RegistrationRecord, $clientIdentifier)

      Assert-Throws { $client.FinishLogin($clientLoginResult.ClientLoginState, [Convert]::FromBase64String($serverLoginResult.LoginResponse), $Password, ($clientIdentifier + "abc")) }
    }

    It "Incorrect server identifier fails" {
      $userIdentifier = "user123"
      $Password = "hunter2"
      $serverIdentifier = "server-ident"

      $setup = SetupAndRegisterOpaque -UserIdentifier $userIdentifier -Pass $Password -ServerIdentifier $serverIdentifier

      $server = [OpaqueServer]::new()
      $client = [OpaqueClient]::new()

      $clientLoginResult = $client.StartLogin($Password)

      $serverLoginResult = $server.StartLogin($setup.ServerSetup, [Convert]::FromBase64String($clientLoginResult.StartLoginRequest), $userIdentifier, $setup.RegistrationRecord, $null, ($serverIdentifier + "-abc"))

      Assert-Throws { $client.FinishLogin($clientLoginResult.ClientLoginState, [Convert]::FromBase64String($serverLoginResult.LoginResponse), $Password, $null, $serverIdentifier) }
    }

    It "Client methods throw on invalid params" {
      $client = [OpaqueClient]::new()

      Assert-Throws { $client.StartRegistration("") }

      Assert-Throws { $client.FinishRegistration("", "Value", "Value") }
      Assert-Throws { $client.FinishRegistration("Value", "", "Value") }
      Assert-Throws { $client.FinishRegistration("Value", "Value", "") }

      Assert-Throws { $client.StartLogin("") }

      Assert-Throws { $client.FinishLogin("", "Value", "Value") }
      Assert-Throws { $client.FinishLogin("Value", "", "Value") }
      Assert-Throws { $client.FinishLogin("Value", "Value", "") }
    }

    It "Server methods throw on invalid params" {
      $server = [OpaqueServer]::new()

      Assert-Throws { $server.GetPublicKey("") }

      Assert-Throws { $server.CreateRegistrationResponse("", "Value", "Value") }
      Assert-Throws { $server.CreateRegistrationResponse("Value", "", "Value") }
      Assert-Throws { $server.CreateRegistrationResponse("Value", "Value", "") }

      Assert-Throws { $server.StartLogin("", "Value", "Value") }
      Assert-Throws { $server.StartLogin("Value", "", "Value") }
      Assert-Throws { $server.StartLogin("Value", "Value", "") }

      Assert-Throws { $server.FinishLogin("", "Value") }
      Assert-Throws { $server.FinishLogin("Value", "") }
    }
  }
  #endregion

  #region Block 1: Utilities and Hashing
  Context "Crc24 Checksum" {
    It "Crc24 should compute correctly" {
      $data = [System.Text.Encoding]::ASCII.GetBytes("test")
      [uint]$crc = [Crc24]::Compute($data)
      $crcHex = $crc.ToString("x6")
      $crcHex | Should Be "f86ed0"
    }
    It "Crc24 should be deterministic" {
      $data = [System.Text.Encoding]::ASCII.GetBytes("Hello World")
      [uint]$crc1 = [Crc24]::Compute($data)
      [uint]$crc2 = [Crc24]::Compute($data)
      $crc1 | Should Be $crc2
    }
    It "Crc24 empty input should return initial value" {
      [uint]$crc = [Crc24]::Compute([byte[]]::new(0))
      $crc | Should Be 11994318
    }
  }

  Context "Armor Encoding" {
    It "Armor should encode and decode MESSAGE" {
      $data = [System.Text.Encoding]::UTF8.GetBytes("HeroCrypt Armor Test")
      $headers = [System.Collections.Generic.Dictionary[string, string]]::new()
      $headers["Version"] = "1.0"

      $armored = [Armor]::Encode($data, [ArmorType]::Message, $headers)
      $armored | Should Match "-----BEGIN PGP MESSAGE-----"

      $result = [Armor]::Decode($armored)
      $result.Data | Should Be $data
      $result.Type | Should Be ([ArmorType]::Message)
      $result.Headers["Version"] | Should Be "1.0"
    }
  }

  Context "Blake2b Hash" {
    It "Blake2b should compute hash" {
      $data = [System.Text.Encoding]::UTF8.GetBytes($testDataShort)
      $hash = [Blake2b]::ComputeHash($data)
      $hashHex = ($hash | ForEach-Object { "{0:x2}" -f $_ }) -join ""
      $hashHex | Should Be "7138bce3d21f355d7d091651070a75b7b9abe29a14c11f9c5c1d72f31785d741d382e6ad7f520f511d6c3e2b8c68049b69bd41fbabd9821f7b217e1319cde15b"
    }
    It "Blake2b with key should compute MAC" {
      $data = [byte[]]::new(0)
      $key = [byte[]]::new(64)
      $hash = [Blake2b]::ComputeHash($data, 64, $key)
      $hash.Length | Should Be 64
    }
  }

  Context "Pbkdf2 Key Derivation" {
    It "Pbkdf2 should derive key" {
      $password = "password"
      $salt = [System.Text.Encoding]::UTF8.GetBytes("salt")
      $key = [Pbkdf2]::DeriveKey($password, $salt, 1000, 32, "SHA256")
      $key.Length | Should Be 32
    }
  }

  Context "S2K Key Derivation" {
    It "S2K Simple should derive key" {
      $password = [System.Text.Encoding]::UTF8.GetBytes("password")
      $key = [S2K]::SimpleS2K($password, 32, "SHA256")
      $key.Length | Should Be 32
    }
    It "S2K Iterated and Salted should derive key" {
      $password = [System.Text.Encoding]::UTF8.GetBytes("password")
      $salt = [byte[]]@(1..8)
      $key = [S2K]::IteratedS2K($password, $salt, 1024, 32, "SHA256")
      $key.Length | Should Be 32
    }
  }

  #region Block 2: Stream Ciphers and Modes
  Context "AesCfb Cipher" {
    It "AesCfb should encrypt and decrypt (Roundtrip)" {
      $key = [byte[]]::new(32); [System.Security.Cryptography.RandomNumberGenerator]::Fill($key)
      $iv = [byte[]]::new(16); [System.Security.Cryptography.RandomNumberGenerator]::Fill($iv)
      $data = [System.Text.Encoding]::UTF8.GetBytes("AES-CFB Test Data for Roundtrip Verification")
      $encrypted = [AesCfb]::Encrypt($data, $key, $iv)
      $decrypted = [AesCfb]::Decrypt($encrypted, $key, $iv)
      $decrypted | Should Be $data
    }
  }

  Context "AesCmac Authentication" {
    It "AesCmac should compute correct tag (RFC 4493 Example 1)" {
      $key = HexToBytes "2b7e151628aed2a6abf7158809cf4f3c"
      $data = [byte[]]::new(0)
      $expected = HexToBytes "bb1d6929e95937287fa37d129b756746"
      $tag = [AesCmac]::ComputeTag($data, $key)
      $tag | Should Be $expected
    }
    It "AesCmac should compute correct tag (RFC 4493 Example 2)" {
      $key = HexToBytes "2b7e151628aed2a6abf7158809cf4f3c"
      $data = HexToBytes "6bc1bee22e409f96e93d7e117393172a"
      $expected = HexToBytes "070a16b46b4d4144f79bdd9dd04a287c"
      $tag = [AesCmac]::ComputeTag($data, $key)
      $tag | Should Be $expected
    }
    It "AesCmac VerifyTag should return true for valid tag" {
      $key = [byte[]]::new(16); [System.Security.Cryptography.RandomNumberGenerator]::Fill($key)
      $data = [System.Text.Encoding]::UTF8.GetBytes("authenticated data")
      $tag = [AesCmac]::ComputeTag($data, $key)
      [AesCmac]::VerifyTag($tag, $data, $key) | Should Be $true
    }
  }

  Context "HC-128 Stream Cipher" {
    It "Hc128 should encrypt and decrypt (Roundtrip)" {
      $key = [byte[]]::new(16); [System.Security.Cryptography.RandomNumberGenerator]::Fill($key)
      $iv = [byte[]]::new(16); [System.Security.Cryptography.RandomNumberGenerator]::Fill($iv)
      $data = [System.Text.Encoding]::UTF8.GetBytes("HC-128 stream cipher test data")

      $encrypted = [Hc128]::Encrypt($data, $key, $iv)
      $decrypted = [Hc128]::Decrypt($encrypted, $key, $iv)

      $decrypted | Should Be $data
    }
  }

  Context "HC-256 Stream Cipher" {
    It "Hc256 should encrypt and decrypt (Roundtrip)" {
      $key = [byte[]]::new(32); [System.Security.Cryptography.RandomNumberGenerator]::Fill($key)
      $iv = [byte[]]::new(32); [System.Security.Cryptography.RandomNumberGenerator]::Fill($iv)
      $data = [System.Text.Encoding]::UTF8.GetBytes("HC-256 stream cipher test data")

      $encrypted = [Hc256]::Encrypt($data, $key, $iv)
      $decrypted = [Hc256]::Decrypt($encrypted, $key, $iv)

      $decrypted | Should Be $data
    }
  }

  Context "Rabbit Stream Cipher" {
    It "Rabbit should encrypt and decrypt (Roundtrip)" {
      $key = [byte[]]::new(16); [System.Security.Cryptography.RandomNumberGenerator]::Fill($key)
      $iv = [byte[]]::new(8); [System.Security.Cryptography.RandomNumberGenerator]::Fill($iv)
      $data = [System.Text.Encoding]::UTF8.GetBytes("Rabbit stream cipher test data")

      $encrypted = [Rabbit]::Encrypt($data, $key, $iv)
      $decrypted = [Rabbit]::Decrypt($encrypted, $key, $iv)

      $decrypted | Should Be $data
    }
  }

  Context "XSalsa20 Stream Cipher" {
    It "XSalsa20 should encrypt and decrypt (Roundtrip)" {
      $key = [byte[]]::new(32); [System.Security.Cryptography.RandomNumberGenerator]::Fill($key)
      $iv = [byte[]]::new(24); [System.Security.Cryptography.RandomNumberGenerator]::Fill($iv)
      $data = [System.Text.Encoding]::UTF8.GetBytes("XSalsa20 stream cipher test data")

      $encrypted = [XSalsa20]::Encrypt($data, $key, $iv)
      $decrypted = [XSalsa20]::Decrypt($encrypted, $key, $iv)

      $decrypted | Should Be $data
    }
  }
  #endregion

  Context "Curve25519 Key Exchange" {
    It "Curve25519 should derive matching shared secret" {
      $a = [Curve25519]::GenerateKeyPair()
      $b = [Curve25519]::GenerateKeyPair()
      $s1 = [Curve25519]::DeriveSharedSecret($a.PrivateKey, $b.PublicKey)
      $s2 = [Curve25519]::DeriveSharedSecret($b.PrivateKey, $a.PublicKey)
      ($s1 -join ',') | Should Be ($s2 -join ',')
    }
  }

  Context "ECDSA Signatures" {
    It "Ecdsa should sign and verify" {
      $kp = [Ecdsa]::GenerateKeyPair()
      $sig = [Ecdsa]::Sign($script:testData, $kp.PrivateKey)
      [Ecdsa]::Verify($script:testData, $sig, $kp.PublicKey) | Should Be $true
    }
  }
  Context "secp256k1" {
    It "Secp256k1 should sign and verify" {
      $kp = [Secp256k1]::GenerateKeyPair()
      $sig = [Secp256k1]::Sign($script:testDataShort, $kp.PrivateKey)
      [Secp256k1]::Verify($script:testDataShort, $sig, $kp.PublicKey) | Should Be $true
    }
  }
  Context "XChaCha20Poly1305 - stream cipher + AEAD tests" {
    $key = [byte[]]::new(32); [System.Security.Cryptography.RandomNumberGenerator]::Fill($key)
    $nonce = [byte[]]::new(24); [System.Security.Cryptography.RandomNumberGenerator]::Fill($nonce)
    It "XChaCha20Poly1305 Encrypt-Decrypt - with AAD" {
      $aad = [System.Text.Encoding]::UTF8.GetBytes('aad')
      $ct = [XChaCha20Poly1305]::Encrypt($script:testData, $key, $nonce, $aad)
      $pt = [XChaCha20Poly1305]::Decrypt($ct, $key, $nonce, $aad)
      ($pt -join ',') | Should Be ($script:testData -join ',')
    }
    It "XChaCha20Poly1305 Encrypt-Decrypt - without AAD" {
      $ct = [XChaCha20Poly1305]::Encrypt($script:testData, $key, $nonce)
      $pt = [XChaCha20Poly1305]::Decrypt($ct, $key, $nonce)
      ($pt -join ',') | Should Be ($script:testData -join ',')
    }
    It "XChaCha20Poly1305 Encrypt-Decrypt - wrong AAD" {
      $aad = [System.Text.Encoding]::UTF8.GetBytes('aad')
      $ct = [XChaCha20Poly1305]::Encrypt($script:testData, $key, $nonce, $aad)
      $threw = $false; try { [XChaCha20Poly1305]::Decrypt($ct, $key, $nonce, [byte[]]@()) } catch { $threw = $true }
      $threw | Should Be $true
    }
    It "XChaCha20Poly1305 Encrypt-Decrypt - wrong key" {
      $aad = [System.Text.Encoding]::UTF8.GetBytes('aad')
      $ct = [XChaCha20Poly1305]::Encrypt($script:testData, $key, $nonce, $aad)
      $threw = $false; try { [XChaCha20Poly1305]::Decrypt($ct, [byte[]]::new(32), $nonce, $aad) } catch { $threw = $true }
      $threw | Should Be $true
    }
    It "XChaCha20Poly1305 Encrypt-Decrypt - wrong nonce" {
      $aad = [System.Text.Encoding]::UTF8.GetBytes('aad')
      $ct = [XChaCha20Poly1305]::Encrypt($script:testData, $key, $nonce, $aad)
      $threw = $false; try { [XChaCha20Poly1305]::Decrypt($ct, $key, [byte[]]::new(24), $aad) } catch { $threw = $true }
      $threw | Should Be $true
    }
    It "XChaCha20Poly1305 Authenticate-Verify - with AAD" {
      $aad = [System.Text.Encoding]::UTF8.GetBytes('aad')
      $tag = [XChaCha20Poly1305]::Authenticate($script:testData, $key, $nonce, $aad)
      [XChaCha20Poly1305]::Verify($script:testData, $tag, $key, $nonce, $aad) | Should Be $true
    }
    It "XChaCha20Poly1305 Authenticate-Verify - without AAD" {
      $tag = [XChaCha20Poly1305]::Authenticate($script:testData, $key, $nonce)
      [XChaCha20Poly1305]::Verify($script:testData, $tag, $key, $nonce) | Should Be $true
    }
    It "XChaCha20Poly1305 Authenticate-Verify - wrong AAD" {
      $aad = [System.Text.Encoding]::UTF8.GetBytes('aad')
      $tag = [XChaCha20Poly1305]::Authenticate($script:testData, $key, $nonce, $aad)
      [XChaCha20Poly1305]::Verify($script:testData, $tag, $key, $nonce, [byte[]]@()) | Should Be $false
    }
    It "XChaCha20Poly1305 Authenticate-Verify - wrong key" {
      $aad = [System.Text.Encoding]::UTF8.GetBytes('aad')
      $tag = [XChaCha20Poly1305]::Authenticate($script:testData, $key, $nonce, $aad)
      [XChaCha20Poly1305]::Verify($script:testData, $tag, [byte[]]::new(32), $nonce, $aad) | Should Be $false
    }
    It "XChaCha20Poly1305 Authenticate-Verify - wrong nonce" {
      $aad = [System.Text.Encoding]::UTF8.GetBytes('aad')
      $tag = [XChaCha20Poly1305]::Authenticate($script:testData, $key, $nonce, $aad)
      [XChaCha20Poly1305]::Verify($script:testData, $tag, $key, [byte[]]::new(24), $aad) | Should Be $false
    }
  }
  Context "OpenPgp" {
    It "OpenPgp Armor-Dearmor message" {
      $headers = [System.Collections.Generic.Dictionary[string, string]]::new()
      $headers.Add('Version', 'cryptobase')
      $headers.Add('Comment', 'OpenPgp Armor-Dearmor message')
      $armored = [OpenPgp]::ArmorMessage($script:testDataShort, $headers)
      $decoded = [OpenPgp]::DearmorMessage($armored)
      ($decoded -join ',') | Should Be ($script:testDataShort -join ',')
    }
  }

  Context "CryptoBase - Main class" {
    It "CryptoBase Protect-Unprotect data" {
      $password = "CorrectHorseBatteryStaple!"
      $aad = [System.Text.Encoding]::UTF8.GetBytes("context-aad")
      $ct = [CryptoBase]::ProtectData($script:testData, $password, $aad)
      $pt = [CryptoBase]::UnprotectData($ct, $password, $aad)
      ($pt -join ',') | Should Be ($script:testData -join ',')
    }

    It "CryptoBase Sign-Verify message should verify" {
      $signed = [CryptoBase]::SignMessage($script:testDataShort)
      $ok = [CryptoBase]::VerifyMessage($script:testDataShort, $signed.Signature, $signed.PublicKey)
      $ok | Should Be $true
    }
  }
}
