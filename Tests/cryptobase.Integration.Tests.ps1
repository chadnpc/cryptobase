# verify the interactions and behavior of the module's Main class methods.
Describe "Integration tests: cryptobase" {
  BeforeAll {
    $script:testData = [System.Text.Encoding]::UTF8.GetBytes("hello world 123")
  }

  Context "Main class integration tests" {
    It "GetHelp returns expected man page text" {
      $help = [CryptoBase]::GetHelp()
      $help | Should Match "NAME"
      $help | Should Match "CryptoBase \(Invoke-CryptoBase\)"
      $help | Should Match "SYNOPSIS"
      $help | Should Match "METHODS"
    }

    It "SignMessage and VerifyMessage works with strings" {
      $msg = "This is a test message"
      $signRes = [CryptoBase]::SignMessage($msg)
      $signRes.Signature.Count | Should BeGreaterThan 0
      $isValid = [CryptoBase]::VerifyMessage($msg, $signRes.Signature, $signRes.PublicKey)
      $isValid | Should Be $true
    }
    It "SignMessage works through Invoke-CryptoBase pipeline" {
      $msg = "Pipeline secret"
      $res = $msg | cryptobase SignMessage
      $res.Signature.Count | Should BeGreaterThan 0
      [CryptoBase]::VerifyMessage($msg, $res.Signature, $res.PublicKey) | Should Be $true
    }

    It "ProtectData and UnprotectData pipeline with mocked password" {
      [CryptoBase]::_SkipReadHostPrompts = $true
      [CryptoBase]::_Password = "testpassword123" | xconvert ToSecurestring

      try {
        $plaintext = "Super secret data"
        $protected = $plaintext | cryptobase ProtectData
        $protected.Count | Should BeGreaterThan 0
        $decryptedBytes = $protected | cryptobase UnprotectData
        $decryptedText = [System.Text.Encoding]::UTF8.GetString($decryptedBytes)
        $decryptedText | Should Be $plaintext
      }
      finally {
        [CryptoBase]::_SkipReadHostPrompts = $false
        [CryptoBase]::_Password = $null
      }
    }

    It "ObfuscateFile and DeobfuscateFile pipeline with mocked password" {
      [CryptoBase]::_SkipReadHostPrompts = $true
      [CryptoBase]::_Password = "obfuscation_pass" | xconvert ToSecurestring

      $testFile = "test_obfuscate.txt"
      $encFile = "test_obfuscate.txt.enc"
      Set-Content -Path $testFile -Value "File Content"

      try {
        $testFile | cryptobase ObfuscateFile
        Test-Path $encFile | Should Be $true
        Remove-Item $testFile -Force
        $encFile | cryptobase DeobfuscateFile
        Test-Path $testFile | Should Be $true
        $decryptedContent = Get-Content $testFile -Raw
        $decryptedContent.Trim() | Should Be "File Content"
      }
      finally {
        if (Test-Path $testFile) { Remove-Item $testFile -Force }
        if (Test-Path $encFile) { Remove-Item $encFile -Force }
        [CryptoBase]::_SkipReadHostPrompts = $false
        [CryptoBase]::_Password = $null
      }
    }
  }
}
