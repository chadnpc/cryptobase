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
      $res = $msg | Invoke-CryptoBase -Method SignMessage
      $res.Signature.Count | Should BeGreaterThan 0
      [CryptoBase]::VerifyMessage($msg, $res.Signature, $res.PublicKey) | Should Be $true
    }

    It "ProtectData and UnprotectData pipeline with mocked password" {
      Mock Read-Host { return (ConvertTo-SecureString "testpassword123" -AsPlainText -Force) }
      
      $plaintext = "Super secret data"
      $protected = $plaintext | Invoke-CryptoBase -Method ProtectData
      $protected.Count | Should BeGreaterThan 0

      $decryptedBytes = $protected | Invoke-CryptoBase -Method UnprotectData
      $decryptedText = [System.Text.Encoding]::UTF8.GetString($decryptedBytes)
      
      $decryptedText | Should Be $plaintext
    }

    It "ObfuscateFile and DeobfuscateFile pipeline with mocked password" {
      Mock Read-Host { return (ConvertTo-SecureString "obfuscation_pass" -AsPlainText -Force) }
      
      $testFile = "test_obfuscate.txt"
      $encFile = "test_obfuscate.txt.enc"
      Set-Content -Path $testFile -Value "File Content"
      
      try {
        $testFile | Invoke-CryptoBase -Method ObfuscateFile
        Test-Path $encFile | Should Be $true
        
        Remove-Item $testFile -Force
        
        $encFile | Invoke-CryptoBase -Method DeobfuscateFile
        Test-Path $testFile | Should Be $true
        
        $decryptedContent = Get-Content $testFile -Raw
        $decryptedContent.Trim() | Should Be "File Content"
      }
      finally {
        if (Test-Path $testFile) { Remove-Item $testFile -Force }
        if (Test-Path $encFile) { Remove-Item $encFile -Force }
      }
    }
  }
}
