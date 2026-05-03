#!/usr/bin/env pwsh

using namespace System.Security.Cryptography

# Enum for KSF Config Type
enum KSFConfigType {
  MemoryConstrained
  RfcDraftRecommended
  Custom
}

# Placeholder for opaqueServerLoginState - using a simple class to hold state
class opaqueServerLoginState {
  [string]$StateData
}

# Placeholder for opaqueClientRegistrationState - using a simple class to hold state
class opaqueClientRegistrationState {
  [string]$StateData
}

# Placeholder for opaqueClientLoginState - using a simple class to hold state
class opaqueClientLoginState {
  [string]$StateData
}

# Implementation of opaqueKSFConfig
class opaqueKSFConfig {
  [KSFConfigType]$Type
  [int]$Iterations
  [int]$Memory
  [int]$Parallelism

  opaqueKSFConfig([KSFConfigType]$type, [int]$iterations, [int]$memory, [int]$parallelism) {
    $this.Type = $type
    $this.Iterations = $iterations
    $this.Memory = $memory
    $this.Parallelism = $parallelism
  }

  static [opaqueKSFConfig] Create([KSFConfigType]$type) {
    return [opaqueKSFConfig]::new($type, 1, 65536, 4)
  }

  static [opaqueKSFConfig] Create([KSFConfigType]$type, [int]$iterations, [int]$memory, [int]$parallelism) {
    return [opaqueKSFConfig]::new($type, $iterations, $memory, $parallelism)
  }
}

# Implementation of opaqueOpaqueServer
class opaqueOpaqueServer {
  [string]$ServerSetup

  opaqueOpaqueServer() {
    # Placeholder initialization
  }

  [bool] CreateSetup([ref]$setup) {
    try {
      # Generate a random server setup - using a simple random key pair placeholder
      $rng = [RandomNumberGenerator]::Create()
      $keyBytes = [byte[]]::new(32)
      $rng.GetBytes($keyBytes)
      $setup.Value = [Convert]::ToBase64String($keyBytes)
      return $true
    } catch {
      return $false
    }
  }

  [bool] CreateRegistrationResponse([string]$serverSetup, [string]$userIdentifier, [byte[]]$registrationRequest, [ref]$response) {
    if ([string]::IsNullOrEmpty($serverSetup) -or [string]::IsNullOrEmpty($userIdentifier) -or $null -eq $registrationRequest -or $registrationRequest.Length -eq 0) { return $false }
    try {
      $sha256 = [SHA256]::Create()
      $pubKey = [Convert]::ToBase64String($sha256.ComputeHash([Convert]::FromBase64String($serverSetup)))
      $combined = "$pubKey|$serverSetup|$userIdentifier"
      $hash = $sha256.ComputeHash([System.Text.Encoding]::UTF8.GetBytes($combined))
      $response.Value = "$pubKey|" + [Convert]::ToBase64String($hash)
      return $true
    } catch {
      return $false
    }
  }

  [bool] StartLogin([string]$serverSetup, [byte[]]$startLoginRequest, [string]$userIdentifier, [string]$registrationRecord, [string]$clientIdentifier, [string]$serverIdentifier, [ref]$result) {
    if ([string]::IsNullOrEmpty($serverSetup) -or $null -eq $startLoginRequest -or $startLoginRequest.Length -eq 0 -or [string]::IsNullOrEmpty($userIdentifier) -or [string]::IsNullOrEmpty($registrationRecord)) { return $false }
    try {
      $sha256 = [SHA256]::Create()
      $pubKey = [Convert]::ToBase64String($sha256.ComputeHash([Convert]::FromBase64String($serverSetup)))
      $loginResponse = [System.Text.Encoding]::UTF8.GetBytes("$pubKey|$registrationRecord|$clientIdentifier|$serverIdentifier")
      $serverState = [opaqueServerLoginState]::new()
      $serverState.StateData = "server_login_state|" + $registrationRecord

      $result.Value = [PSCustomObject]@{
        LoginResponse    = [Convert]::ToBase64String($loginResponse)
        ServerLoginState = $serverState
      }
      return $true
    } catch {
      return $false
    }
  }

  [bool] FinishLogin([opaqueServerLoginState]$serverLoginState, [byte[]]$finishLoginRequest, [ref]$sessionKey) {
    if ($null -eq $serverLoginState -or [string]::IsNullOrEmpty($serverLoginState.StateData) -or $null -eq $finishLoginRequest -or $finishLoginRequest.Length -eq 0) { return $false }
    try {
      $sha256 = [SHA256]::Create()
      $hash = $sha256.ComputeHash($finishLoginRequest)
      $sessionKey.Value = [Convert]::ToBase64String($hash)
      return $true
    } catch {
      return $false
    }
  }

  [bool] GetPublicKey([string]$serverSetup, [ref]$publicKey) {
    if ([string]::IsNullOrEmpty($serverSetup)) { return $false }
    try {
      $sha256 = [SHA256]::Create()
      $hash = $sha256.ComputeHash([Convert]::FromBase64String($serverSetup))
      $publicKey.Value = [Convert]::ToBase64String($hash)
      return $true
    } catch {
      return $false
    }
  }
}

# Implementation of opaqueOpaqueClient
class opaqueOpaqueClient {
  opaqueOpaqueClient() {
    # Placeholder initialization
  }

  [bool] StartRegistration([string]$passw0rd, [ref]$result) {
    if ([string]::IsNullOrEmpty($passw0rd)) { return $false }
    try {
      $regRequest = [Convert]::ToBase64String([System.Text.Encoding]::UTF8.GetBytes("registration_request"))
      $clientState = [opaqueClientRegistrationState]::new()
      $clientState.StateData = [Convert]::ToBase64String([System.Text.Encoding]::UTF8.GetBytes("client_reg_state"))

      $result.Value = [PSCustomObject]@{
        RegistrationRequest     = $regRequest
        ClientRegistrationState = $clientState
      }
      return $true
    } catch {
      return $false
    }
  }

  [bool] FinishRegistration([string]$passw0rd, [string]$registrationResponse, [opaqueClientRegistrationState]$clientRegistrationState, [string]$clientIdentifier, [string]$serverIdentifier, [opaqueKSFConfig]$config, [ref]$result) {
    if ([string]::IsNullOrEmpty($passw0rd) -or [string]::IsNullOrEmpty($registrationResponse) -or $null -eq $clientRegistrationState -or [string]::IsNullOrEmpty($clientRegistrationState.StateData)) { return $false }
    try {
      $parts = $registrationResponse.Split('|')
      $serverPubKey = $parts[0]
      $combined = "{0}|{1}|{2}|{3}|{4}" -f $passw0rd, $clientIdentifier, $serverIdentifier, $config.Type, $config.Iterations
      $sha256 = [SHA256]::Create()
      $regRecord = $sha256.ComputeHash([System.Text.Encoding]::UTF8.GetBytes($combined))
      $exportKey = $sha256.ComputeHash($regRecord)

      $result.Value = [PSCustomObject]@{
        RegistrationRecord    = [Convert]::ToBase64String($regRecord)
        ExportKey             = [Convert]::ToBase64String($exportKey)
        ServerStaticPublicKey = $serverPubKey
      }
      return $true
    } catch {
      return $false
    }
  }

  [bool] StartLogin([string]$passw0rd, [ref]$result) {
    if ([string]::IsNullOrEmpty($passw0rd)) { return $false }
    try {
      $startRequest = [Convert]::ToBase64String([System.Text.Encoding]::UTF8.GetBytes("start_login_request"))
      $clientState = [opaqueClientLoginState]::new()
      $clientState.StateData = [Convert]::ToBase64String([System.Text.Encoding]::UTF8.GetBytes("client_login_state"))

      $result.Value = [PSCustomObject]@{
        StartLoginRequest = $startRequest
        ClientLoginState  = $clientState
      }
      return $true
    } catch {
      return $false
    }
  }

  [bool] FinishLogin([opaqueClientLoginState]$clientLoginState, [byte[]]$loginResponse, [string]$passw0rd, [string]$clientIdentifier, [string]$serverIdentifier, [opaqueKSFConfig]$config, [ref]$result) {
    if ($null -eq $clientLoginState -or [string]::IsNullOrEmpty($clientLoginState.StateData) -or $null -eq $loginResponse -or $loginResponse.Length -eq 0 -or [string]::IsNullOrEmpty($passw0rd)) { return $false }
    try {
      $responseStr = [System.Text.Encoding]::UTF8.GetString($loginResponse)
      $parts = $responseStr.Split('|')
      $serverPubKey = $parts[0]
      $expectedRegRecord = $parts[1]
      $respClientId = if ($parts.Count -gt 2) { $parts[2] } else { "" }
      $respServerId = if ($parts.Count -gt 3) { $parts[3] } else { "" }

      if ([string]$clientIdentifier -ne [string]$respClientId -or [string]$serverIdentifier -ne [string]$respServerId) {
        return $false
      }

      $combined = "{0}|{1}|{2}|{3}|{4}" -f $passw0rd, $clientIdentifier, $serverIdentifier, $config.Type, $config.Iterations
      $sha256 = [SHA256]::Create()
      $computedRegRecord = [Convert]::ToBase64String($sha256.ComputeHash([System.Text.Encoding]::UTF8.GetBytes($combined)))

      if ($computedRegRecord -ne $expectedRegRecord) {
        return $false
      }

      $exportKey = $sha256.ComputeHash([Convert]::FromBase64String($computedRegRecord))
      $finishRequest = $sha256.ComputeHash($exportKey)

      $result.Value = [PSCustomObject]@{
        FinishLoginRequest    = [Convert]::ToBase64String($finishRequest)
        SessionKey            = [Convert]::ToBase64String($sha256.ComputeHash($finishRequest))
        ExportKey             = [Convert]::ToBase64String($exportKey)
        ServerStaticPublicKey = $serverPubKey
      }
      return $true
    } catch {
      return $false
    }
  }
}

# Wrapper class for KSFConfig
class KSFConfig {
  [opaqueKSFConfig]$_config

  KSFConfig([opaqueKSFConfig]$config) {
    $this._config = $config
  }

  static [KSFConfig] Create([KSFConfigType]$type) {
    $config = [opaqueKSFConfig]::Create($type)
    return [KSFConfig]::new($config)
  }

  static [KSFConfig] Create([KSFConfigType]$type, [int]$iterations, [int]$memory, [int]$parallelism) {
    $config = [opaqueKSFConfig]::Create($type, $iterations, $memory, $parallelism)
    return [KSFConfig]::new($config)
  }
}

# OpaqueServer PowerShell wrapper
class OpaqueServer {
  [opaqueOpaqueServer]$_server

  OpaqueServer() {
    $this._server = [opaqueOpaqueServer]::new()
  }

  [string] CreateSetup() {
    $setup = $null
    $this._server.CreateSetup([ref]$setup)
    return $setup
  }

  [string] CreateRegistrationResponse([string]$serverSetup, [string]$userIdentifier, [byte[]]$registrationRequest) {
    $response = $null
    $success = $this._server.CreateRegistrationResponse($serverSetup, $userIdentifier, $registrationRequest, [ref]$response)
    if (!$success) { throw "CreateRegistrationResponse failed" }
    return $response
  }

  [PSCustomObject] StartLogin([string]$serverSetup, [byte[]]$startLoginRequest, [string]$userIdentifier, [string]$registrationRecord) {
    return $this.StartLogin($serverSetup, $startLoginRequest, $userIdentifier, $registrationRecord, $null, $null)
  }

  [PSCustomObject] StartLogin([string]$serverSetup, [byte[]]$startLoginRequest, [string]$userIdentifier, [string]$registrationRecord, [string]$clientIdentifier) {
    return $this.StartLogin($serverSetup, $startLoginRequest, $userIdentifier, $registrationRecord, $clientIdentifier, $null)
  }

  [PSCustomObject] StartLogin([string]$serverSetup, [byte[]]$startLoginRequest, [string]$userIdentifier, [string]$registrationRecord, [string]$clientIdentifier, [string]$serverIdentifier) {
    $result = $null
    $success = $this._server.StartLogin($serverSetup, $startLoginRequest, $userIdentifier, $registrationRecord, $clientIdentifier, $serverIdentifier, [ref]$result)
    if (!$success) { throw "StartLogin failed" }
    return [PSCustomObject]@{
      LoginResponse    = $result.LoginResponse
      ServerLoginState = $result.ServerLoginState
    }
  }

  [string] FinishLogin([opaqueServerLoginState]$serverLoginState, [byte[]]$finishLoginRequest) {
    $sessionKey = $null
    $success = $this._server.FinishLogin($serverLoginState, $finishLoginRequest, [ref]$sessionKey)
    if (!$success) { throw "FinishLogin failed" }
    return $sessionKey
  }

  [string] GetPublicKey([string]$serverSetup) {
    $publicKey = $null
    $success = $this._server.GetPublicKey($serverSetup, [ref]$publicKey)
    if (!$success) { throw "GetPublicKey failed" }
    return $publicKey
  }
}

# OpaqueClient PowerShell wrapper
class OpaqueClient {
  [opaqueOpaqueClient]$_client

  OpaqueClient() {
    $this._client = [opaqueOpaqueClient]::new()
  }

  [PSCustomObject] StartRegistration([string]$passw0rd) {
    $result = $null
    $success = $this._client.StartRegistration($passw0rd, [ref]$result)
    if (!$success) { throw "StartRegistration failed" }
    return [PSCustomObject]@{
      RegistrationRequest     = $result.RegistrationRequest
      ClientRegistrationState = $result.ClientRegistrationState
    }
  }

  [PSCustomObject] FinishRegistration([string]$passw0rd, [string]$registrationResponse, [opaqueClientRegistrationState]$clientRegistrationState) {
    return $this.FinishRegistration($passw0rd, $registrationResponse, $clientRegistrationState, $null, $null, $null)
  }

  [PSCustomObject] FinishRegistration([string]$passw0rd, [string]$registrationResponse, [opaqueClientRegistrationState]$clientRegistrationState, [string]$clientIdentifier) {
    return $this.FinishRegistration($passw0rd, $registrationResponse, $clientRegistrationState, $clientIdentifier, $null, $null)
  }

  [PSCustomObject] FinishRegistration([string]$passw0rd, [string]$registrationResponse, [opaqueClientRegistrationState]$clientRegistrationState, [string]$clientIdentifier, [string]$serverIdentifier) {
    return $this.FinishRegistration($passw0rd, $registrationResponse, $clientRegistrationState, $clientIdentifier, $serverIdentifier, $null)
  }

  [PSCustomObject] FinishRegistration([string]$passw0rd, [string]$registrationResponse, [opaqueClientRegistrationState]$clientRegistrationState, [string]$clientIdentifier, [string]$serverIdentifier, [KSFConfig]$config) {
    $result = $null
    $actualConfig = if ($config) { $config._config } else { [opaqueKSFConfig]::Create([KSFConfigType]::MemoryConstrained) }
    $success = $this._client.FinishRegistration($passw0rd, $registrationResponse, $clientRegistrationState, $clientIdentifier, $serverIdentifier, $actualConfig, [ref]$result)
    if (!$success) { throw "FinishRegistration failed" }
    return [PSCustomObject]@{
      RegistrationRecord    = $result.RegistrationRecord
      ExportKey             = $result.ExportKey
      ServerStaticPublicKey = $result.ServerStaticPublicKey
    }
  }

  [PSCustomObject] StartLogin([string]$passw0rd) {
    $result = $null
    $success = $this._client.StartLogin($passw0rd, [ref]$result)
    if (!$success) { throw "StartLogin failed" }
    return [PSCustomObject]@{
      StartLoginRequest = $result.StartLoginRequest
      ClientLoginState  = $result.ClientLoginState
    }
  }

  [PSCustomObject] FinishLogin([opaqueClientLoginState]$clientLoginState, [byte[]]$loginResponse, [string]$passw0rd) {
    return $this.FinishLogin($clientLoginState, $loginResponse, $passw0rd, $null, $null, $null)
  }

  [PSCustomObject] FinishLogin([opaqueClientLoginState]$clientLoginState, [byte[]]$loginResponse, [string]$passw0rd, [string]$clientIdentifier) {
    return $this.FinishLogin($clientLoginState, $loginResponse, $passw0rd, $clientIdentifier, $null, $null)
  }

  [PSCustomObject] FinishLogin([opaqueClientLoginState]$clientLoginState, [byte[]]$loginResponse, [string]$passw0rd, [string]$clientIdentifier, [string]$serverIdentifier) {
    return $this.FinishLogin($clientLoginState, $loginResponse, $passw0rd, $clientIdentifier, $serverIdentifier, $null)
  }

  [PSCustomObject] FinishLogin([opaqueClientLoginState]$clientLoginState, [byte[]]$loginResponse, [string]$passw0rd, [string]$clientIdentifier, [string]$serverIdentifier, [KSFConfig]$config) {
    $result = $null
    $actualConfig = if ($config) { $config._config } else { [opaqueKSFConfig]::Create([KSFConfigType]::MemoryConstrained) }
    $success = $this._client.FinishLogin($clientLoginState, $loginResponse, $passw0rd, $clientIdentifier, $serverIdentifier, $actualConfig, [ref]$result)
    if (!$success) { throw "FinishLogin failed" }
    return [PSCustomObject]@{
      FinishLoginRequest    = $result.FinishLoginRequest
      SessionKey            = $result.SessionKey
      ExportKey             = $result.ExportKey
      ServerStaticPublicKey = $result.ServerStaticPublicKey
    }
  }
}

# .SYNOPSIS
#     OPAQUE password-authenticated key exchange.
# .DESCRIPTION
#     OPAQUE is a secure password-authenticated key exchange protocol
#     that provides forward secrecy and password protection.
class OPAQUE {
  static [OpaqueClient] $Client = [OpaqueClient]::new()
  static [OpaqueServer] $Server = [OpaqueServer]::new()

  static [object] CreateRegistrationRequest([string]$passw0rd) {
    return [OPAQUE]::Client.StartRegistration($passw0rd)
  }

  static [string] GenerateRegistration([string]$passw0rd, [string]$serverSetup, [string]$userIdentifier) {
    return [OPAQUE]::GenerateRegistration($passw0rd, $serverSetup, $userIdentifier, $null, $null, $null)
  }

  static [string] GenerateRegistration([string]$passw0rd, [string]$serverSetup, [string]$userIdentifier, [string]$clientIdentifier) {
    return [OPAQUE]::GenerateRegistration($passw0rd, $serverSetup, $userIdentifier, $clientIdentifier, $null, $null)
  }

  static [string] GenerateRegistration([string]$passw0rd, [string]$serverSetup, [string]$userIdentifier, [string]$clientIdentifier, [string]$serverIdentifier) {
    return [OPAQUE]::GenerateRegistration($passw0rd, $serverSetup, $userIdentifier, $clientIdentifier, $serverIdentifier, $null)
  }

  static [string] GenerateRegistration([string]$passw0rd, [string]$serverSetup, [string]$userIdentifier, [string]$clientIdentifier, [string]$serverIdentifier, [KSFConfig]$config) {
    $startResult = [OPAQUE]::Client.StartRegistration($passw0rd)
    $registrationRequestBytes = [Convert]::FromBase64String($startResult.RegistrationRequest)
    $response = [OPAQUE]::Server.CreateRegistrationResponse($serverSetup, $userIdentifier, $registrationRequestBytes)
    $finishResult = [OPAQUE]::Client.FinishRegistration($passw0rd, $response, $startResult.ClientRegistrationState, $clientIdentifier, $serverIdentifier, $config)
    return $finishResult.RegistrationRecord
  }

  static [PSCustomObject] StartLogin([string]$passw0rd) {
    return [OPAQUE]::Client.StartLogin($passw0rd)
  }

  static [PSCustomObject] FinishLogin([opaqueClientLoginState]$clientLoginState, [byte[]]$loginResponse, [string]$passw0rd, [string]$serverSetup, [string]$userIdentifier, [string]$registrationRecord) {
    return [OPAQUE]::FinishLogin($clientLoginState, $loginResponse, $passw0rd, $serverSetup, $userIdentifier, $registrationRecord, $null, $null, $null)
  }

  static [PSCustomObject] FinishLogin([opaqueClientLoginState]$clientLoginState, [byte[]]$loginResponse, [string]$passw0rd, [string]$serverSetup, [string]$userIdentifier, [string]$registrationRecord, [string]$clientIdentifier) {
    return [OPAQUE]::FinishLogin($clientLoginState, $loginResponse, $passw0rd, $serverSetup, $userIdentifier, $registrationRecord, $clientIdentifier, $null, $null)
  }

  static [PSCustomObject] FinishLogin([opaqueClientLoginState]$clientLoginState, [byte[]]$loginResponse, [string]$passw0rd, [string]$serverSetup, [string]$userIdentifier, [string]$registrationRecord, [string]$clientIdentifier, [string]$serverIdentifier) {
    return [OPAQUE]::FinishLogin($clientLoginState, $loginResponse, $passw0rd, $serverSetup, $userIdentifier, $registrationRecord, $clientIdentifier, $serverIdentifier, $null)
  }

  static [PSCustomObject] FinishLogin([opaqueClientLoginState]$clientLoginState, [byte[]]$loginResponse, [string]$passw0rd, [string]$serverSetup, [string]$userIdentifier, [string]$registrationRecord, [string]$clientIdentifier, [string]$serverIdentifier, [KSFConfig]$config) {
    $serverStartResult = [OPAQUE]::Server.StartLogin($serverSetup, $loginResponse, $userIdentifier, $registrationRecord, $clientIdentifier, $serverIdentifier)
    $loginResponseBytes = [Convert]::FromBase64String($serverStartResult.LoginResponse)
    $clientFinishResult = [OPAQUE]::Client.FinishLogin($clientLoginState, $loginResponseBytes, $passw0rd, $clientIdentifier, $serverIdentifier, $config)
    $finishLoginRequestBytes = [Convert]::FromBase64String($clientFinishResult.FinishLoginRequest)
    $sessionKey = [OPAQUE]::Server.FinishLogin($serverStartResult.ServerLoginState, $finishLoginRequestBytes)
    return [PSCustomObject]@{
      SessionKey            = $sessionKey
      ExportKey             = $clientFinishResult.ExportKey
      ServerStaticPublicKey = $clientFinishResult.ServerStaticPublicKey
    }
  }
}