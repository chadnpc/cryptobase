# verify the interactions and behavior of the module's components when they are integrated together.
Describe "Integration tests: cryptobase" {
  BeforeAll {
    $script:testData = [System.Text.Encoding]::UTF8.GetBytes("hello")
  }

  Context "Hashing Classes" {
    It "IdentityHash should return input bytes unchanged" {
      $ih = [IdentityHash]::new()
      $res = $ih.ComputeHash([byte[]]$testData)
      [BitConverter]::ToString($res) | Should Be "68-65-6C-6C-6F"
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
  }
  Context "Hashing Classes" {
    It "IdentityHash should return input bytes unchanged" {
      $ih = [IdentityHash]::new()
      $res = $ih.ComputeHash([byte[]]$testData)
      [BitConverter]::ToString($res) | Should Be "68-65-6C-6C-6F"
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
      $hash = [SHAKE128]::ComputeHash([byte[]]$testData, 32)
      $hash.Length | Should Be 32
    }

    It "SHAKE256 should produce variable length output" {
      $hash = [SHAKE256]::ComputeHash([byte[]]$testData, 64)
      $hash.Length | Should Be 64
    }
  }

  Context "Signature Classes" {
    It "Ed25519 should sign and verify" {
      $ed = [Ed25519]::new()
      $keyPair = $ed.GenerateKeyPair()
      $signature = $ed.Sign($testData, $keyPair.PrivateKey)
      $valid = $ed.Verify($signature, $testData, $keyPair.PublicKey)
      $valid | Should Be $true
    }

    It "Ed448 should sign and verify" {
      $ed = [Ed448]::new()
      $keyPair = $ed.GenerateKeyPair()
      $signature = $ed.Sign($testData, $keyPair.PrivateKey)
      $valid = $ed.Verify($signature, $testData, $keyPair.PublicKey)
      $valid | Should Be $true
    }
  }

  Context "KDF Classes" {
    It "HKDF should derive key material" {
      $ikm = [byte[]]::new(32)
      [System.Security.Cryptography.RandomNumberGenerator]::Fill($ikm)
      $salt = [byte[]]::new(16)
      [System.Security.Cryptography.RandomNumberGenerator]::Fill($salt)
      $info = [System.Text.Encoding]::UTF8.GetBytes("info")
      $key = [HKDF]::DeriveKey($ikm, $salt, $info, 32)
      $key.Length | Should Be 32
    }

    It "Argon2id should hash and verify" {
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

  Context "AEAD Classes" {
    It "AesSIV should encrypt and decrypt" {
      $aesSiv = [AesSIV]::new()
      $ciphertext = $aesSiv.Encrypt($testData)
      $decrypted = $aesSiv.Decrypt($ciphertext)
      $decrypted | Should Be $testData
    }

    It "ChaCha20Poly1305 should encrypt and decrypt" {
      $chacha = [ChaCha20Poly1305]::new()
      $ciphertext = $chacha.Encrypt($testData)
      $decrypted = $chacha.Decrypt($ciphertext)
      $decrypted | Should Be $testData
    }

    It "AesCCM should encrypt and decrypt" {
      $aesCcm = [AesCCM]::new()
      $ciphertext = $aesCcm.Encrypt($testData)
      $decrypted = $aesCcm.Decrypt($ciphertext)
      $decrypted | Should Be $testData
    }
  }

  Context "Post-Quantum Classes" {
    It "MLKem should encapsulate and decapsulate" {
      $mlkem = [MLKem]::new()
      $keyPair = $mlkem.GenerateKeyPair()
      $encap = $mlkem.Encapsulate($keyPair.PublicKey)
      $shared = $mlkem.Decapsulate($encap.Ciphertext, $keyPair.PrivateKey)
      $shared | Should Be $encap.SharedSecret
    }

    It "MLDsa should sign and verify" {
      $mldsa = [MLDsa]::new()
      $keyPair = $mldsa.GenerateKeyPair()
      $signature = $mldsa.Sign($testData, $keyPair.PrivateKey)
      $valid = $mldsa.Verify($testData, $signature, $keyPair.PublicKey)
      $valid | Should Be $true
    }
  }

  Context "Utility Classes" {
    It "SecureBox should encrypt and decrypt" {
      $key = [byte[]]@(1..32)
      $secureBox = [SecureBox]::new($key)
      $plaintext = $testData
      $ciphertext = $secureBox.Encrypt($plaintext)
      $decrypted = $secureBox.Decrypt($ciphertext)
      $decrypted | Should Be $plaintext
    }

    It "Asn1Parser should parse ASN.1 data" {
      $parser = [Asn1Parser]::new()
      $data = [byte[]]@(0x30, 0x0C, 0x02, 0x01, 0x01, 0x02, 0x01, 0x02, 0x04, 0x01, 0x03, 0x04, 0x01, 0x04)
      $result = $parser.Parse($data)
      $result | Should Not BeNullOrEmpty
    }

    It "PemParser should decode PEM" {
      $parser = [PemParser]::new()
      $pem = "-----BEGIN TEST-----`nSGVsbG8=\n-----END TEST-----"
      $result = $parser.Decode($pem)
      $result.Length | Should -BeGreaterThan 0
    }
  }
}
