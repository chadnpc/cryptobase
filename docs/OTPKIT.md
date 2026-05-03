# OTPKIT (One-Time Passwords)

OTPKIT provides utilities for generating and verifying One-Time Passwords (OTP), compatible with apps like Google Authenticator and Authy. It supports both Time-based OTP (TOTP) and HMAC-based OTP (HOTP).

## Usage

### Generating TOTP (Time-Based)
This is the standard 6-digit code used by most 2FA apps.

```powershell
$secret = "JBSWY3DPEHPK3PXP" # Base32 secret

# Get a 6-digit TOTP code (30-second window)
$code = [OTPKIT]::GetOtp($secret, 6, 30)
```

### Parsing OTP URLs
You can parse `otpauth://` URLs commonly found in QR codes.

```powershell
$url = "otpauth://totp/Example:alice@google.com?secret=JBSWY3DPEHPK3PXP&issuer=Example"
$code = [OTPKIT]::ParseOtpUrl($url)
```

---

## SMS Verification (Advanced)

OTPKIT also includes built-in logic for SMS-based verification codes using a signed hash approach. This allows you to verify a code without storing it in a database (by including the expiration and salt in a signed token).

### Creating a Signed HOTP
```powershell
$phone = 1234567890
$otp = "123456"
$expiresInMinutes = 5

# Generates a signed hash: "hash.expiry.salt"
$token = [OTPKIT]::CreateHOTP($phone, $otp, $expiresInMinutes)
```

### Verifying a Signed HOTP
```powershell
$isValid = [OTPKIT]::VerifyHOTP($otp, $phone, $token)
```

## Internal Utilities

- **Base32 to Hex**: `[OTPKIT]::ConvertBase32ToHex($base32)`
- **Twilio Integration**: `[OTPKIT]::Send_TWILIO_SMS($phone, $message)` (Requires Twilio credentials set in the submodule).
