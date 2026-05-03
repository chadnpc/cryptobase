#!/usr/bin/env pwsh
using namespace System.Text
using namespace System.Security.Cryptography

using module ./Sha.psm1

class OTPKIT {
  [string] $key = ""

  static [string] CreateHOTP([string]$SECRET, [int]$Phone) {
    return [OTPKIT]::CreateHOTP($phone, [OTPKIT]::GetOtp($SECRET))
  }

  static [string] CreateHOTP([int]$phone, [string]$otp) {
    return [OTPKIT]::CreateHOTP($phone, $otp, 5)
  }
  static [string] CreateHOTP([int]$phone, [string]$otp, [int]$expiresAfter) {
    $ttl = $expiresAfter * 60 * 1000
    $expires = (Get-Date).AddMilliseconds($ttl).ToString("yyyy-MM-ddTHH:mm:ss.fffZ")
    $bytes = [byte[]]::new(16)
    [RNGCryptoServiceProvider]::new().GetBytes($bytes)
    $salt = [BitConverter]::ToString($bytes) -replace '-'
    $data = "$phone.$otp.$expires.$salt"
    Write-Host "data: " -NoNewline -ForegroundColor Green; Write-Host "$data" -ForegroundColor Blue
    $hashBase = [FipsHmacSha256]::new().ComputeHash([Encoding]::ASCII.GetBytes($data))
    $hash = "$hashBase.$expires.$salt"
    # Import the Twilio module
    Import-Module -Name Twilio
    $phoneNumber = "+1234567890"
    $message = "Hello, this is a test message."
    [OTPKIT]::Send_TWILIO_SMS($phoneNumber, $message)
    return $hash
  }
  static [bool] Send_TWILIO_SMS ([string]$PhoneNumber, [string]$Message) {
    # Function to send SMS using Twilio
    # Twilio account SID and auth token
    $accountSid = "YOUR_TWILIO_ACCOUNT_SID"
    $authToken = "YOUR_TWILIO_AUTH_TOKEN"

    # Twilio phone number
    $twilioPhoneNumber = "YOUR_TWILIO_PHONE_NUMBER"

    # Create a new Twilio client
    $twilio = New-TwilioRestClient -AccountSid $accountSid -AuthToken $authToken

    # Send the SMS message
    $twilio.SendMessage($twilioPhoneNumber, $PhoneNumber, $Message)
    return $?
  }
  static [bool] VerifyHOTP([string]$otp, [int]$phone, [string]$hash) {
    if (!$hash -match "\.") {
      return $false
    }

    $hashValue, $expires, $salt = $hash -split "\."

    $now = (Get-Date).Ticks / 10000
    if ($now -gt [double]$expires) {
      return $false
    }
    $data = "$phone.$otp.$expires.$salt"
    Write-Host "data: " -NoNewline -ForegroundColor Green; Write-Host "$data" -ForegroundColor Blue
    $newCalculatedHash = [FipsHmacSha256]::new().ComputeHash([Encoding]::ASCII.GetBytes($data))

    if ($newCalculatedHash -eq $hashValue) {
      return $true
    }
    return $false
  }

  static [string] ParseOtpUrl([string]$otpURL) {
    # $otpURL can be decrypted text
    if (![System.Uri]::IsWellFormedUriString("$otpURL", "Absolute") -or $otpURL -notmatch "^otpauth://") { Write-Host "The decrypted text is not a valid OTP URL" "Error" ; $script:FileBrowser.Dispose() ; exit 1 }
    $parseOtpUrl = [scriptblock]::Create("[System.Web.HttpUtility]::ParseQueryString(([uri]::new('$otpURL')).Query)").Invoke()
    $otpType = $([uri]$otpURL).Host
    if ($otpType -eq "hotp") { Write-Warning "TOTP is only supported" }
    if ($otpType -eq "totp" ) { $otpType = "$otpType=" }
    $otpPeriod = if (![string]::IsNullOrEmpty($parseOtpUrl["period"])) { $parseOtpUrl["period"] } else { 30 }
    $otpDigits = if (![string]::IsNullOrEmpty($parseOtpUrl["digits"])) { $parseOtpUrl["digits"] } else { 6 }
    $otpSecret = $parseOtpUrl["secret"]
    return [OTPKIT]::GetOtp($otpSecret, $otpDigits, $otpPeriod)
  }

  static [string] GetOtp([string]$SECRET) {
    return [OTPKIT]::GetOtp($SECRET, 4, "5")
  }
  static [string] GetOtp([string]$SECRET, [int]$LENGTH, [string]$WINDOW) {
    $hmac = New-Object -TypeName System.Security.Cryptography.HMACSHA1
    $hmac.key = $([OTPKIT]::ConvertBase32ToHex($SECRET.ToUpper())) -replace '^0x', '' -split "(?<=\G\w{2})(?=\w{2})" | ForEach-Object { [Convert]::ToByte( $_, 16 ) }
    $timeSpan = $(New-TimeSpan -Start (Get-Date -Year 1970 -Month 1 -Day 1 -Hour 0 -Minute 0 -Second 0) -End (Get-Date).ToUniversalTime()).TotalSeconds
    $rndHash = $hmac.ComputeHash([byte[]][BitConverter]::GetBytes([Convert]::ToInt64([Math]::Floor($timeSpan / $WINDOW))))
    $toffset = $rndhash[($rndHash.Length - 1)] -band 0xf
    $fullOTP = ($rndhash[$toffset] -band 0x7f) * [math]::pow(2, 24)
    $fullOTP += ($rndHash[$toffset + 1] -band 0xff) * [math]::pow(2, 16)
    $fullOTP += ($rndHash[$toffset + 2] -band 0xff) * [math]::pow(2, 8)
    $fullOTP += ($rndHash[$toffset + 3] -band 0xff)

    $modNumber = [math]::pow(10, $LENGTH)
    $otp = $fullOTP % $modNumber
    $otp = $otp.ToString("0" * $LENGTH)
    return $otp
  }
  static [string] ConvertBase32ToHex([string]$base32) {
    $base32chars = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";
    $bits = "";
    $hex = "";

    for ($i = 0; $i -lt $base32.Length; $i++) {
      $val = $base32chars.IndexOf($base32.Chars($i));
      $binary = [Convert]::ToString($val, 2)
      $str = $binary.ToString();
      $len = 5
      $pad = '0'
      if (($len + 1) -ge $str.Length) {
        while (($len - 1) -ge $str.Length) {
          $str = ($pad + $str)
        }
      }
      $bits += $str
    }

    for ($i = 0; $i + 4 -le $bits.Length; $i += 4) {
      $chunk = $bits.Substring($i, 4)
      # Write-Host $chunk
      $intChunk = [Convert]::ToInt32($chunk, 2)
      $hexChunk = '{0:x}' -f $([int]$intChunk)
      # Write-Host $hexChunk
      $hex = $hex + $hexChunk
    }
    return $hex;
  }
}