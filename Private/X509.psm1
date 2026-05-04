#!/usr/bin/env pwsh
using namespace System
using namespace System.IO
using namespace System.Text
using namespace System.Security
using namespace System.Security.Cryptography
using namespace System.Runtime.InteropServices
using namespace System.Security.Cryptography.X509Certificates

using module ./Enums.psm1
using module ./Exceptions.psm1
using module ./Utilities.psm1


#region    X509
class X509 : CryptobaseUtils {
  static [X509Certificate2] CreateCertificate([string]$subject) {
    return [X509]::CreateCertificate($subject, [ECCurveName]::nistP521);
  }
  static [X509Certificate2] CreateCertificate([string]$Subject, [string]$KeyUsage) {
    $upn = if ([bool](Get-Command git -ErrorAction SilentlyContinue)) { git config user.email } else { 'work@contoso.com' }
    return [X509]::CreateCertificate($Subject, $KeyUsage, $upn)
  }
  static [X509Certificate2] CreateCertificate([string]$subject, [ECCurveName]$curveName) {
    [void][X509]::IsValidDistinguishedName($subject, $true);
    $ecdsa = [ECDsa]::Create();
    $ecdsa.GenerateKey([ECCurve]::CreateFromFriendlyName("$curveName"));
    $certRequest = [X509]::GetCertificateRequest($subject, $ecdsa, [HashAlgorithmName]::SHA256, 2048)
    return [X509]::CreateCertificate($certRequest, [FileInfo]::New([char]8) , [securestring]::New(), [DateTimeOffset]::Now.AddDays(-1).DateTime, [DateTimeOffset]::Now.AddYears(10).DateTime);
  }
  static [X509Certificate2] CreateCertificate([string]$Subject, [string]$KeyUsage, [string]$upn) {
    $pin = [CryptobaseUtils]::GetRandomSTR('01233456789', 4) | xconvert ToSecurestring
    $Extentions = @("2.5.29.17={text}upn=$upn")
    return [X509]::CreateCertificate($Subject, 2048, 60, "Cert:\CurrentUser\My", $Pin, 'ExportableEncrypted', 'Protect', $KeyUsage, $Extentions, $true)
  }
  static [X509Certificate2] CreateCertificate([string]$Subject, [string]$KeyUsage, [string[]]$Extentions) {
    $pin = [CryptobaseUtils]::GetRandomSTR('01233456789', 4) | xconvert ToSecurestring
    return [X509]::CreateCertificate($Subject, 2048, 60, "Cert:\CurrentUser\My", $Pin, 'ExportableEncrypted', 'Protect', $KeyUsage, $Extentions, $true)
  }
  static [X509Certificate2] CreateCertificate([string]$Subject, [string]$upn, [securestring]$pin, [string]$KeyUsage) {
    $Extentions = @("2.5.29.17={text}upn=$upn")
    return [X509]::CreateCertificate($Subject, 2048, 60, "Cert:\CurrentUser\My", $Pin, 'ExportableEncrypted', 'Protect', $KeyUsage, $Extentions, $true)
  }
  static [X509Certificate2] CreateCertificate([string]$Subject, [int]$keySizeInBits = 2048, [int]$ValidForInDays = 365, [string]$StoreLocation, [securestring]$Pin, [string]$KeyExportPolicy, [KeyProtection]$KeyProtection, [string]$KeyUsage, [string[]]$Extentions, [bool]$IsCritical) {
    if (!($KeyExportPolicy -as [KeyExportPolicy] -is 'KeyExportPolicy')) { throw [InvalidArgumentException]::New('[Microsoft.CertificateServices.Commands.KeyExportPolicy]$KeyExportPolicy') }
    if (!($KeyProtection -as [KeyProtection] -is 'KeyProtection')) { throw [InvalidArgumentException]::New("$KeyProtection is not a valid [Microsoft.CertificateServices.Commands.KeyProtection]. See [enum]::GetNames[KeyProtection]() for valid values") }
    if (!($keyUsage -as [KeyUsage] -is 'KeyUsage')) { throw [InvalidArgumentException]::New("$KeyUsage is not a valid X509KeyUsageFlag. See [enum]::GetNames[KeyUsage]() for valid values") }
    if (![bool]("Microsoft.CertificateServices.Commands.KeyExportPolicy" -as [Type]) -and [CryptobaseUtils]::GetHostOs() -eq "Windows") {
      Write-Verbose "[+] Load all necessary assemblies." # By Creating a dumy cert then remove it. This loads all necessary assemblies to create certificates; It worked for me!
      $DummyName = 'dummy-' + [Guid]::NewGuid().Guid; $DummyCert = New-SelfSignedCertificate -Type Custom -Subject "CN=$DummyName" -TextExtension @("2.5.29.37={text}1.3.6.1.5.5.7.3.2", "2.5.29.17={text}upn=dummy@contoso.com") -KeyExportPolicy NonExportable -KeyUsage None -KeyAlgorithm RSA -KeyLength 2048 -CertStoreLocation "Cert:\CurrentUser\My";
      $DummyCert.Dispose(); Get-ChildItem "Cert:\CurrentUser\My" | Where-Object { $_.subject -eq "CN=$DummyName" } | Remove-Item
    }
    $key = [System.Security.Cryptography.RSA]::Create($keySizeInBits)
    # Create a regular expression to match the DN (distinguishedName) format. ie: CN=CommonName,OU=OrganizationalUnit,O=Organization,L=Locality,S=State,C=Country
    $dnFormat = "^CN=.*,OU=.*,O=.*,L=.*,S=.*,C=.*"; # Ex: $subjN = "CN=My Cert Subject,OU=IT,O=MyCompany,L=MyCity,S=MyState,C=MyCountry"
    if ($subject -notmatch $dnFormat) {
      $Ip_Info = [X509]::Get_Ip_Info()
      $subject = "CN=$subject,OU=,O=,L=,S=,C=";
      $subject = $subject -replace "O=,", "O=Contoso,";
      $subject = $subject -replace "OU=,", "OU=$keyUsage,";
      $subject = $subject -replace "C=", "C=$($Ip_Info.country_name)";
      $subject = $subject -replace "L=,", "L=$($Ip_Info.location.geoname_id),";
      $subject = $subject -replace "S=,", "S=$($Ip_Info.city),"
    }
    # Set the OID (Object Identifier) for the subject name
    $distshdName = [X500DistinguishedName]::new($Subject); $distshdName.Oid = [Oid]::new("1.2.840.10045.3.1.7");
    $certRequest = [certificaterequest]::new($distshdName, $key, [HashAlgorithmName]::SHA256, [RSASignaturePadding]::Pkcs1);
    # Create an X509KeyUsageFlags object
    $X509KeyUsageFlags = [X509KeyUsageFlags]::None
    $X509KeyUsageFlags = $X509KeyUsageFlags -bor ([X509KeyUsageFlags]::$KeyUsage);
    $notBefore = [DateTimeOffset]::Now.AddDays(-1); $notAfter = [DateTimeOffset]::Now.AddDays($ValidForInDays)
    $certRequest.CertificateExtensions.Add([X509Extension][X509KeyUsageExtension]::new($X509KeyUsageFlags, $IsCritical))
    foreach ($ext in $Extentions) {
      if ([X509]::IsValidExtension($ext)) {
        $oid, $val = $ext.Split("=")
        $extensionOid = [Oid]::new($oid)
        $extsnrawData = [byte[]][Encoding]::ASCII.GetBytes($val)
        $certRequest.CertificateExtensions.Add([X509Extension]::new($extensionOid, $extsnrawData, $IsCritical))
      } else {
        throw [InvalidArgumentException]::New("$ext")
      }
    }
    $xsig = [X509Certificate2]$certRequest.CreateSelfSigned($notBefore, $notAfter);
    # Create an X509KeyStorageFlags object and set the KeyProtection value
    $t, $f = @{
      'NonExportable:None:None'                             = ('Cert', 'UserKeySet')
      'NonExportable:DataEncipherment:Protect'              = ('SerializedCertPfx', 'UserProtected')
      'ExportableEncrypted:None:Protect'                    = ('Pfx', 'Exportable')
      'ExportableEncrypted:DataEncipherment:Protect'        = ('Pfx', 'UserKeySet')
      'ExportableEncrypted:KeyEncipherment:Protect'         = ('Pfx', 'Exportable')
      'ExportableEncrypted:DataEncipherment:ProtectHigh'    = ('Pfx', 'UserProtected')
      'ExportableEncrypted:CertSign:Protect'                = ('SerializedStore', 'EphemeralKeySet')
      'Exportable:DataEncipherment:None'                    = ('Pkcs12', 'Exportable')
      'Exportable:DataEncipherment:Protect'                 = ('Pkcs12', 'UserProtected')
      'Exportable:DataEncipherment:ProtectHigh'             = ('Pkcs12', 'EphemeralKeySet')
      'Exportable:KeyEncipherment:Protect'                  = ('SerializedCertPfx', 'Exportable')
      'Exportable:KeyEncipherment:ProtectHigh'              = ('SerializedCertPfx', 'UserProtected')
      'Exportable:KeyAgreement:ProtectFingerPrint'          = ('Pkcs7', 'MachineKeySet')
      'ExportableEncrypted:DecipherOnly:ProtectFingerPrint' = ('Authenticode', 'PersistKeySet')
      'NonExportable:CRLSign:None'                          = ('SerializedStore', 'UserKeySet')
      'NonExportable:NonRepudiation:Protect'                = ('Pkcs7', 'UserProtected')
      'ExportableEncrypted:DigitalSignature:ProtectHigh'    = ('SerializedStore', 'EphemeralKeySet')
      'Exportable:EncipherOnly:ProtectFingerPrint'          = ('Pkcs7', 'UserProtected')
    }[[string]::Join(':', $KeyExportPolicy, $KeyUsage, $KeyProtection)]
    $x509ContentType, $x509KeyStorageFlags = ($t -and $f) ? ($t, $f) : ('Cert', 'DefaultKeySet')
    [ValidateNotNullOrEmpty()][X509ContentType]$x509ContentType = [X509ContentType]::$x509ContentType
    $x509KeyStorageFlags = [X509KeyStorageFlags]::$x509KeyStorageFlags
    # if ($null -eq $Pin) { [securestring]$Pin = Read-Host -Prompt "New Certificate PIN" -AsSecureString }
    [byte[]]$certData = $xsig.Export($x509ContentType, $Pin);
    $cert = [X509Certificate2]::new($certData, $Pin, $x509KeyStorageFlags)
    # TODO : test if this gives same result on windows:
    # if on Windows, Import the certificate from the byte array and return the imported certificate
    # if ([X509]::GetHostOs() -eq "Windows") {[void]$xsig.Import($certData, $Pin, $x509KeyStorageFlags); $cert = $xsig }

    $store = [X509Store]::new([StoreLocation]::CurrentUser) # save the certificate to the personal store
    [void]$store.Open([OpenFlags]::ReadWrite)
    [void]$store.Add($cert)
    [void]$store.Close()
    Write-Debug "[+] Created $StoreLocation\$($cert.Thumbprint)"
    return $cert
  }
  static [X509Certificate2] CreateCertificate([string]$subject, [string]$pfxFile, [securestring]$password) {
    return [X509]::CreateCertificate($subject, [FileInfo]::new($pfxFile), $password);
  }
  static [X509Certificate2] CreateCertificate([string]$subject, [FileInfo]$pfxFile, [securestring]$password) {
    return [X509]::CreateCertificate($subject, $pfxFile, $password, 2048, [datetime]::Now.AddDays(-1), [datetime]::Now.AddYears(10));
  }
  static [X509Certificate2] CreateCertificate([string]$subject, [FileInfo]$pfxFile, [securestring]$password, [int]$keySizeInBits, [datetime]$notBefore, [datetime]$notAfter) {
    [void][X509]::IsValidDistinguishedName($subject, $true);
    $certificate = [X509]::CreateCertificate($pfxFile, $password, $false);
    if ($null -ne $certificate) { return $certificate }
    $certificateRequest = [X509]::GetCertificateRequest($subject, [Object]::new(), [HashAlgorithmName]::SHA256, $keySizeInBits)
    return [X509]::CreateCertificate($certificateRequest, $pfxFile , $password, $notBefore, $notAfter);
  }
  static [X509Certificate2] CreateCertificate([FileInfo]$pfxFile, [securestring]$password, [bool]$throwOnFailure) {
    $Cert = $null; if ($pfxFile.Exists) {
      if ($null -ne $password) {
        [X509Certificate2]::new($pfxFile.FullName, $password)
      } else { [X509Certificate2]::new($pfxFile.FullName) }
    } elseif ($throwOnFailure) {
      throw [FileNotFoundException]::New($pfxFile.FullName)
    }; return $Cert
  }
  static [X509Certificate2] CreateCertificate([CertificateRequest]$certificateRequest, [FileInfo]$pfxFile, [securestring]$password, [datetime]$notBefore, [datetime]$notAfter) {
    $certResult = [X509Certificate2]$certificateRequest.CreateSelfSigned($notBefore, $notAfter);
    $certRawData = if (![string]::IsNullOrWhiteSpace([Pscredential]::new(' ', $password).GetNetworkCredential().Password)) {
      $certResult.Export([X509ContentType]::Pfx, $password)
    } else {
      $certResult.Export([X509ContentType]::Pfx)
    }
    # Return it in PFX form to prevent windows throwing a security credentials not found error during sslStream.connectAsClient or HttpClient request.
    $Certificate = [X509Certificate2]::new([byte[]]$certRawData);
    $certResult.Dispose(); if ($pfxFile -and $pfxFile.BaseName -ne ([string][char]8)) { [IO.File]::WriteAllBytes($pfxFile.FullName, $certRawData) }
    return $certificate
  }
  static [X509Certificate2Collection] ShowCertificate([X509Certificate2[]]$Certificate, [bool]$Multipick) {
    $certs = [X509Certificate2Collection]::new()
    [void]$certs.AddRange($Certificate)
    if ($Multipick) {
      return [X509Certificate2UI]::SelectFromCollection(
        $certs,
        "Select a certificate",
        "Select a certificate or certificates from the list",
        "MultiSelection"
      )
    } else {
      return [X509Certificate2UI]::SelectFromCollection(
        $certs,
        "Select a certificate",
        "Select a certificate from the list",
        "SingleSelection"
      )
    }
  }
  static [byte[]] Encrypt([byte[]]$PlainBytes, [X509Certificate2]$Cert) {
    $encryptor = $Cert.GetRSAPublicKey().CreateEncryptor()
    $cipherBytes = $encryptor.TransformFinalBlock($PlainBytes, 0, $PlainBytes.Length)
    return $cipherBytes
  }
  static [byte[]] Encrypt([byte[]]$PlainBytes, [X509Certificate2]$Cert, [RSAEncryptionPadding]$KeyPadding) {
    $encryptor = $Cert.GetRSAPublicKey().CreateEncryptor($KeyPadding)
    $cipherBytes = $encryptor.TransformFinalBlock($PlainBytes, 0, $PlainBytes.Length)
    return $cipherBytes
  }
  static [byte[]] Decrypt([byte[]]$CipherBytes, [X509Certificate2]$Cert) {
    $decryptor = $Cert.GetRSAPrivateKey().CreateDecryptor()
    $plainBytes = $decryptor.TransformFinalBlock($CipherBytes, 0, $CipherBytes.Length)
    [Array]::Clear($decryptor, 0, $decryptor.Length)
    return $plainBytes
  }
  static [byte[]] Decrypt([byte[]]$CipherBytes, [X509Certificate2]$Cert, [RSAEncryptionPadding]$KeyPadding) {
    $decryptor = $Cert.GetRSAPrivateKey().CreateDecryptor($KeyPadding)
    $plainBytes = $decryptor.TransformFinalBlock($CipherBytes, 0, $CipherBytes.Length)
    [Array]::Clear($decryptor, 0, $decryptor.Length)
    return $plainBytes
  }
  static [bool]IsValidExtension([string] $extension) {
    # Regular expression to match the format of an extension string: "oid={text}value"
    $extensionFormat = "^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}={text}.*"
    return $extension -match $extensionFormat
  }
  static [CertificateRequest] GetCertificateRequest([string]$subject) {
    return [X509]::GetCertificateRequest($subject, [Object]::new(), [HashAlgorithmName]::SHA256, 2048)
  }
  static [CertificateRequest] GetCertificateRequest([string]$subject, $key, [HashAlgorithmName]$hashAlgorithm, [int]$keySizeInBits) {
    [void][X509]::IsValidDistinguishedName($subject, $true);
    $certificateRequest = if ($key.GetType().Name -eq 'System.Security. Cryptography.ECDsa') {
      $ecdsa = [ECDsa]::Create(); $ecdsa.GenerateKey([ECCurve]::CreateFromFriendlyName("brainpoolP512r1")); $ecdsa.KeySize = $keySizeInBits
      [CertificateRequest]::new($subject, $ecdsa, $hashAlgorithm);
    } else {
      [CertificateRequest]::new($subject, [System.Security.Cryptography.RSA]::Create($keySizeInBits), $hashAlgorithm, [RSASignaturePadding]::Pkcs1);
    }
    $certificateRequest.CertificateExtensions.Add([X509BasicConstraintsExtension]::new($true, $false, 0, $true));
    $certificateRequest.CertificateExtensions.Add([X509SubjectKeyIdentifierExtension]::new($certificateRequest.PublicKey, $false));
    $certificateRequest.CertificateExtensions.Add([X509KeyUsageExtension]::new([X509KeyUsageFlags]::DataEncipherment, $true));
    return $certificateRequest
  }
  static [string] GetThumbPrint([string]$certSubject, [string]$FriendlyName) {
    $CertStore = [X509Store]::new([StoreName]::My, [StoreLocation]::CurrentUser)
    $CertStore.Open([OpenFlags]::ReadOnly); $Thumbprints = $CertStore.Certificates.Where({ $_.Subject -eq $certSubject -and $_.FriendlyName -eq $FriendlyName }).Thumbprint
    if ($Thumbprints.count -gt 1) { Write-Warning 'Ambiguous certs' };
    $CertStore.Close();
    return $Thumbprints[0];
  }
  static [string] GetThumbprint([X509Certificate2]$certificate) {
    return $certificate.Thumbprint
  }

  static [void] SaveSelfSignedCertificate([X509Certificate2]$X509Cert2) {
    # Stores X509Cert2 in certificate store.
    $CertStore = [X509Store]::new([StoreName]::My, [StoreLocation]::CurrentUser);
    $CertStore.Open([OpenFlags]::ReadWrite);
    $CertStore.Add($X509Cert2);
    $CertStore.Close()
  }
  static [byte[]] Export([X509Certificate2]$certificate) {
    # By DEFAULT it Exports the certificate data in DER format.
    return [X509]::Export($certificate, [X509ContentType]::Cert)
  }
  static [byte[]] Export([X509Certificate2]$certificate, [X509ContentType]$contenttype) {
    return $certificate.Export($contenttype)
  }
  static [X509Certificate2] GetCertificate([byte[]]$rawData) {
    # do stuff here
    return [X509Certificate2]::new($rawData)
  }
  static [X509Certificate2] GetPfxCertificate([byte[]]$pfxData, [securestring]$password) {
    return [X509Certificate2]::new($pfxData, $password)
  }
  static [bool] TestCertificate([X509Certificate2]$certificate) {
    $passed_all_tests = $true
    # Check if the certificate has expired
    if ($certificate.NotAfter -lt [DateTime]::Now) {
      $passed_all_tests = $false
      Write-Host "Certificate has expired!"
    }
    # Check if the certificate has a specific key usage extension
    $keyUsageExtension = $certificate.Extensions | Where-Object { $_.Oid.Value -eq "2.5.29.15" }
    if ($keyUsageExtension) {
      $keyUsageFlags = $keyUsageExtension.Format($false) -replace ".*?\((.*)\).*", '$1'
      if ($keyUsageFlags -notlike "*DigitalSignature*") {
        $passed_all_tests = $false
        Write-Host "Certificate does not have DigitalSignature key usage!"
      }
    } else {
      $passed_all_tests = $false
      Write-Host "Certificate does not have KeyUsage extension!"
    }
    # Check if the certificate has a specific extended key usage
    $extendedKeyUsage = $certificate.Extensions | Where-Object { $_.Oid.Value -eq "2.5.29.37" }
    if ($extendedKeyUsage) {
      $extendedKeyUsageOids = $extendedKeyUsage.Format($false) -replace ".*?\((.*)\).*", '$1'
      if ($extendedKeyUsageOids -notlike "*1.3.6.1.5.5.7.3.1*") {
        $passed_all_tests = $false
        Write-Host "Certificate does not have Server Authentication extended key usage!"
      }
    } else {
      $passed_all_tests = $false
      Write-Host "Certificate does not have ExtendedKeyUsage extension!"
    }
    # More Custom Tests:
    $passed_all_tests = $passed_all_tests -and [X509]::IsCertificateRevoked($certificate) -and
    [X509]::IsKeyLengthValid($certificate) -and
    [X509]::IsSignatureAlgorithmValid($certificate) -and
    [X509]::ValidateCertificateChain($certificate)
    [X509]::IsSANsValid($certificate, ('', ''))

    return $passed_all_tests
  }
  static [string] GetOUname([string]$X500DistinguishedName) {
    $ou = [string]::Empty
    $rx = [RegularExpressions.Regex]::new("^(((CN=.*?))?)OU=(?<OUName>.*?(?=,))", "IgnoreCase")
    if ($rx.IsMatch($X500DistinguishedName) ) {
      $ou = $rx.Match($X500DistinguishedName).groups["OUName"].Value
    }
    return $ou
  }
  static [bool] IsValidDistinguishedName([string]$X500DistinguishedName) {
    return [X509]::IsValidDistinguishedName($X500DistinguishedName, $false)
  }
  static [bool] IsValidDistinguishedName([string]$X500DistinguishedName, [bool]$throwOnFailure) {
    # .DESCRIPTION
    # A valid distinguished name string must follow a specific format, where each attribute is identified by a key and a value, separated by an equal sign =, and each attribute is separated by a comma , . For example, "CN=ddd" is a valid distinguished name string because it has a key CN and a value ddd separated by an equal sign =.
    $IsValid = ![string]::IsNullOrWhiteSpace($X500DistinguishedName) -and [regex]::IsMatch($X500DistinguishedName, '^(?:(?:\s*[a-zA-Z][a-zA-Z0-9-]*\s*=\s*[a-zA-Z0-9\s]*\s*,\s*)*(?:\s*[a-zA-Z][a-zA-Z0-9-]*\s*=\s*[a-zA-Z0-9\s]*\s*))?$')
    if (!$IsValid -and $throwOnFailure) {
      throw 'Please Provide a valid certificate subject Name. eX: CN="name"'
    }
    return $IsValid
  }
  static [bool] IsCertificateRevoked([X509Certificate2]$certificate) {
    # .DESCRIPTION
    # Certificate Revocation Check: Perform a certificate revocation check by verifying if the certificate is listed in any certificate revocation lists (CRLs)
    # or if it has been revoked by the issuing certificate authority (CA).

    # Get the certificate chain:
    $chainPolicy = [X509ChainPolicy]::new();
    $chainPolicy.RevocationFlag = [X509RevocationFlag]::EntireChain
    $chainPolicy.RevocationMode = [X509RevocationMode]::Online

    $certificateChain = [X509Chain]::new();
    $certificateChain.ChainPolicy = $chainPolicy
    $certificateChain.Build($certificate)

    # Check if any certificate in the chain is revoked
    foreach ($element in $certificateChain.ChainElements) {
      foreach ($status in $element.ChainElementStatus) {
        if ($status.Status -eq [X509ChainStatusFlags]::Revoked) {
          Write-Host "Certificate is revoked" -ForegroundColor Green
          return $true
        }
      }
    }
    Write-Host "Certificate is not revoked" -ForegroundColor Red
    return $false
  }
  static [bool] IsKeyLengthValid([X509Certificate2]$certificate, [int]$minKeyLength) {
    # .DESCRIPTION
    # Key Length Check: Check the length of the public key in the certificate and ensure it meets your desired security requirements.
    # For example, you can check if the key length is at least 2048 bits for RSA certificates.
    $publicKey = $certificate.GetPublicKey();
    $publicKeyLength = $publicKey.Length * 8  # Convert byte length to bit length
    if ($publicKeyLength -ge $minKeyLength) {
      Write-Host "Key length is valid" -ForegroundColor Green
      return $true
    } else {
      Write-Host "Key length is not valid" -ForegroundColor Red
      return $false
    }
  }
  static [bool] IsSignatureAlgorithmValid([X509Certificate2]$certificate, [string]$requiredAlgorithm) {
    # .DESCRIPTION
    # Validate the signature algorithm used to sign the certificate.
    # Ensure it meets your desired security standards. Ex: you can check if the certificate is signed using a strong algorithm like SHA-256.
    # $requiredAlgorithm can be "SHA256", "SHA384", or "SHA512", among others.
    if ($certificate.SignatureAlgorithm.FriendlyName -eq $requiredAlgorithm) {
      Write-Host "Signature algorithm is valid" -ForegroundColor Green
      return $true
    } else {
      Write-Host "Signature algorithm is not valid" -ForegroundColor Red
      return $false
    }
  }
  static [bool] ValidateCertificateChain([X509Certificate2]$certificate) {
    # .DESCRIPTION
    # Validate the entire certificate chain up to the trusted root certificate.
    # Ensure that all intermediate certificates are present and correctly ordered in the chain, and that each certificate in the chain is valid and not expired.
    $chainPolicy = [X509ChainPolicy]::new();
    $chainPolicy.RevocationFlag = [X509RevocationFlag]::EntireChain
    $chainPolicy.RevocationMode = [X509RevocationMode]::Online
    $chainPolicy.VerificationFlags = [X509VerificationFlags]::NoFlag

    $certificateChain = [X509Chain]::new();
    $certificateChain.ChainPolicy = $chainPolicy
    $certificateChain.ChainPolicy.ExtraStore.Add($certificate)
    $certificateChain.Build($certificate)

    if ($certificateChain.ChainStatus.Length -eq 0) {
      Write-Host "Certificate chain is valid" -ForegroundColor Green
      return $true
    } else {
      Write-Host "Certificate chain is not valid" -ForegroundColor Red
      return $false
    }
  }
  static [bool] IsSANsValid([X509Certificate2]$certificate, [string[]]$requiredSANs) {
    #  Check if the certificate includes the required Subject Alternative Names (SANs) for your specific use case, such as DNS names, IP addresses, or email addresses.
    # Ex:
    # $requiredSANs = @(
    #     "www.example.com",
    #     "subdomain.example.com",
    #     "192.168.0.1"
    # )
    $certificateSANs = $certificate.Extensions.Where({ $_.Oid.FriendlyName -eq "Subject Alternative Name" }).Foreach({ $_.Format($false) -split ', ' });
    foreach ($requiredSAN in $requiredSANs) {
      if ($certificateSANs -contains $requiredSAN) {
        return $true  # Required SAN found in the certificate
      }
    }
    return $false  # Required SAN not found in the certificate
  }
  static [bool] IsCertificatePolicyValid([X509Certificate2]$certificate, [string]$requiredPolicy) {
    # Validate if the certificate adheres to specific certificate policies defined by your organization or industry standards.
    # /!\ Not sure how to write this one!

    $certificatePolicies = $certificate.Extensions | Where-Object { $_.Oid.FriendlyName -eq "Certificate Policies" } | ForEach-Object { $_.Format($false) -split ', ' }

    if ($certificatePolicies -contains $requiredPolicy) {
      return $true  # Required certificate policy is found
    } else {
      return $false  # Required certificate policy is not found
    }
  }
  static [bool] IsExtendedValidationValid([X509Certificate2]$certificate, [Oid]$ValidationOID) {
    # If you are dealing with Extended Validation (EV) certificates, perform additional checks specific to EV requirements,
    # such as verifying the presence of the EV OID in the certificate.
    $extendedValidationOID = $ValidationOID.Value
    $certificateExtensions = $certificate.Extensions
    foreach ($extension in $certificateExtensions) {
      if ($extension.Oid.Value -eq $extendedValidationOID) {
        Write-Host "Extended Validation flag is present" -ForegroundColor Green
        return $true
      }
    }
    Write-Host "Extended Validation flag is not present" -ForegroundColor Red
    return $false
  }
  static [RSAEncryptionPadding]GetRSAPadding () {
    return $(& ([ScriptBlock]::Create("[System.Security.Cryptography.RSAEncryptionPadding]::$([Enum]::GetNames([RSAPadding]) | Get-Random)")))
  }
  static [RSAEncryptionPadding]GetRSAPadding([string]$Padding) {
    if (!(($Padding -as 'RSAPadding') -is [RSAPadding])) {
      throw "Value Not in Validateset."
    }
    return $(& ([ScriptBlock]::Create("[System.Security.Cryptography.RSAEncryptionPadding]::$Padding")))
  }
  static [RSAEncryptionPadding]GetRSAPadding([RSAEncryptionPadding]$Padding) {
    [RSAEncryptionPadding[]]$validPaddings = [Enum]::GetNames([RSAPadding]) | ForEach-Object { & ([ScriptBlock]::Create("[System.Security.Cryptography.RSAEncryptionPadding]::$_")) }
    if ($Padding -notin $validPaddings) {
      throw "Value Not in Validateset."
    }
    return $Padding
  }
  static [X509Certificate2] Import([string]$FilePath, [securestring]$Password) {
    return [X509Certificate2]::new($FilePath, $Password);
  }

  static [void] Export([X509Certificate2]$Cert, [string]$FilePath, [string]$Passw0rd) {
    $Cert.Export([X509ContentType]::Pfx, $Passw0rd) | Set-Content -Path $FilePath -Encoding byte
  }
  static [IO.FileInfo] GetOpenssl () {
    # Return the path to openssl executable file & Will install it if not found :)
    $file = [IO.FileInfo](Get-Command -Name OpenSSL -Type Application -ErrorAction Ignore).Source
    if (!$file -or !$file.Exists) {
      if (!(Get-Command -Name Install-OpenSSL -Type ExternalScript -ErrorAction Ignore)) { Install-Script -Name Install-OpenSSL -Repository PSGallery -Scope CurrentUser }
      Install-OpenSSL
    }
    return $file
  }
}
# static [void]Import() {}
# static [string]Export([X509Certificate2]$cert, [X509ContentType]$contentType) {
#     # Ex:
#     if ($contentType -eq 'PEM') {
#         $InsertLineBreaks = 1
#         $oMachineCert = Get-Item Cert:\LocalMachine\My\1C0381278083E3CB026E46A7FF09FC4B79543D
#         $oPem = New-Object System.Text.StringBuilder
#         $oPem.AppendLine("-----BEGIN CERTIFICATE-----")
#         $oPem.AppendLine([System.Convert]::ToBase64String($oMachineCert.RawData, $InsertLineBreaks))
#         $oPem.AppendLine("-----END CERTIFICATE-----")
#         $oPem.ToString() | Out-File D:\Temp\my.pem

#         # Or load a certificate from a file and convert it to pem format
#         $InsertLineBreaks = 1
#         $sMyCert = "D:\temp\myCert.der"
#         $oMyCert = New-Object System.Security.Cryptography.X509Certificates.X509Certificate2($sMyCert)
#         $oPem = New-Object System.Text.StringBuilder
#         $oPem.AppendLine("-----BEGIN CERTIFICATE-----")
#         $oPem.AppendLine([System.Convert]::ToBase64String($oMyCert.RawData, $InsertLineBreaks))
#         $oPem.AppendLine("-----END CERTIFICATE-----")
#         $oPem.ToString() | Out-File D:\Temp\my.pem
#     }
#     # $cert.Issuer = Get-CimInstance -ClassName Win32_UserAccount -Verbose:$false | Where-Object { $_.Name -eq $(whoami) } | Select-Object -ExpandProperty FullName
#     # X509Certificate2 pfxGeneratedCert = new X509Certificate2(generatedCert.Export(X509ContentType.Pfx));
#     # has to be turned into pfx or Windows at least throws a security credentials not found during sslStream.connectAsClient or HttpClient request...
#     # return pfxGeneratedCert;
#     return ''
# }
#endregion X509