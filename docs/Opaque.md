# OPAQUE Protocol

Secure password-based client-server authentication without the server ever obtaining knowledge of the password.

A PowerShell implementation of the [OPAQUE protocol](https://datatracker.ietf.org/doc/draft-irtf-cfrg-opaque/) using pure-PowerShell cryptographic primitives.

## Benefits

- **No Passwords on Server**: The server stores a registration record but never sees the actual password.
- **Resistant to Pre-computation**: Protects against dictionary and rainbow table attacks even if the server database is leaked.
- **Mutual Authentication**: Both client and server prove their identity to each other.
- **Exported Key**: Generates a stable `exportKey` for the client to use for other tasks (like local data encryption).

## Basic Usage

The API is exposed through the `[OPAQUE]` convenience class, or the individual `[OpaqueServer]` and `[OpaqueClient]` classes.

### 1. Server Setup
The server must generate a long-term setup string once.

```powershell
$serverSetup = [OPAQUE]::Server.CreateSetup()
```

### 2. Registration Flow

```powershell
# -- Client side --
$password = "user-secret-password"
$regReq = [OPAQUE]::Client.StartRegistration($password)

# -- Server side --
$userIdentifier = "user@example.com"
$regResp = [OPAQUE]::Server.CreateRegistrationResponse($serverSetup, $userIdentifier, [Convert]::FromBase64String($regReq.RegistrationRequest))

# -- Client side --
$finishResult = [OPAQUE]::Client.FinishRegistration($password, $regResp, $regReq.ClientRegistrationState)
# send $finishResult.RegistrationRecord back to server to store
```

### 3. Login Flow

```powershell
# -- Client side --
$loginReq = [OPAQUE]::Client.StartLogin($password)

# -- Server side --
$serverStart = [OPAQUE]::Server.StartLogin($serverSetup, [Convert]::FromBase64String($loginReq.StartLoginRequest), $userIdentifier, $storedRegistrationRecord)

# -- Client side --
$clientFinish = [OPAQUE]::Client.FinishLogin($loginReq.ClientLoginState, [Convert]::FromBase64String($serverStart.LoginResponse), $password)

# -- Server side --
$sessionKey = [OPAQUE]::Server.FinishLogin($serverStart.ServerLoginState, [Convert]::FromBase64String($clientFinish.FinishLoginRequest))
```

## Advanced Features

### Exported Key
After registration or login, the client has access to a private `ExportKey`. This key is stable and unique to the user/password/server combination.

```powershell
$clientFinish.ExportKey # Base64 string
```

### Key Stretching (Argon2)
The password is key-stretched using Argon2id. You can customize the cost using `[KSFConfig]`.

```powershell
$config = [KSFConfig]::Create([KSFConfigType]::RfcDraftRecommended)
$finishResult = [OPAQUE]::Client.FinishRegistration(..., $config)
```

Available Config Types:
- `MemoryConstrained` (Default: 64MB, 3 iterations)
- `RfcDraftRecommended` (2GB, 1 iteration)
- `Custom` (Specify iterations, memory, parallelism)

## API Documentation


## Enums

### KSFConfigType
`powershell
enum KSFConfigType {
  MemoryConstrained
  RfcDraftRecommended
  Custom
}
``n
## Classes

### opaqueServerLoginState

#### Properties

- $type $StateData

### opaqueClientRegistrationState

#### Properties

- $type $StateData

### opaqueClientLoginState

#### Properties

- $type $StateData

### opaqueKSFConfig

#### Properties

- $type $Type
- $type $Iterations
- $type $Memory
- $type $Parallelism

#### Methods

- `[void] opaqueKSFConfig($type, $iterations, $memory, $parallelism)`
- `static [opaqueKSFConfig] Create($type)`
- `static [opaqueKSFConfig] Create($type, $iterations, $memory, $parallelism)`

### opaqueOpaqueServer

#### Properties

- $type $ServerSetup

#### Methods

- `[void] opaqueOpaqueServer()`
- `[bool] CreateSetup($setup)`
- `[bool] CreateRegistrationResponse($serverSetup, $userIdentifier, $registrationRequest, $response)`
- `[bool] StartLogin($serverSetup, $startLoginRequest, $userIdentifier, $registrationRecord, $clientIdentifier, $serverIdentifier, $result)`
- `[bool] FinishLogin($serverLoginState, $finishLoginRequest, $sessionKey)`
- `[bool] GetPublicKey($serverSetup, $publicKey)`

### opaqueOpaqueClient

#### Methods

- `[void] opaqueOpaqueClient()`
- `[bool] StartRegistration($passw0rd, $result)`
- `[bool] FinishRegistration($passw0rd, $registrationResponse, $clientRegistrationState, $clientIdentifier, $serverIdentifier, $config, $result)`
- `[bool] StartLogin($passw0rd, $result)`
- `[bool] FinishLogin($clientLoginState, $loginResponse, $passw0rd, $clientIdentifier, $serverIdentifier, $config, $result)`

### KSFConfig

#### Properties

- $type $_config

#### Methods

- `[void] KSFConfig($config)`
- `static [KSFConfig] Create($type)`
- `static [KSFConfig] Create($type, $iterations, $memory, $parallelism)`

### OpaqueServer

#### Properties

- $type $_server

#### Methods

- `[void] OpaqueServer()`
- `[string] CreateSetup()`
- `[string] CreateRegistrationResponse($serverSetup, $userIdentifier, $registrationRequest)`
- `[PSCustomObject] StartLogin($serverSetup, $startLoginRequest, $userIdentifier, $registrationRecord)`
- `[PSCustomObject] StartLogin($serverSetup, $startLoginRequest, $userIdentifier, $registrationRecord, $clientIdentifier)`
- `[PSCustomObject] StartLogin($serverSetup, $startLoginRequest, $userIdentifier, $registrationRecord, $clientIdentifier, $serverIdentifier)`
- `[string] FinishLogin($serverLoginState, $finishLoginRequest)`
- `[string] GetPublicKey($serverSetup)`

### OpaqueClient

#### Properties

- $type $_client

#### Methods

- `[void] OpaqueClient()`
- `[PSCustomObject] StartRegistration($passw0rd)`
- `[PSCustomObject] FinishRegistration($passw0rd, $registrationResponse, $clientRegistrationState)`
- `[PSCustomObject] FinishRegistration($passw0rd, $registrationResponse, $clientRegistrationState, $clientIdentifier)`
- `[PSCustomObject] FinishRegistration($passw0rd, $registrationResponse, $clientRegistrationState, $clientIdentifier, $serverIdentifier)`
- `[PSCustomObject] FinishRegistration($passw0rd, $registrationResponse, $clientRegistrationState, $clientIdentifier, $serverIdentifier, $config)`
- `[PSCustomObject] StartLogin($passw0rd)`
- `[PSCustomObject] FinishLogin($clientLoginState, $loginResponse, $passw0rd)`
- `[PSCustomObject] FinishLogin($clientLoginState, $loginResponse, $passw0rd, $clientIdentifier)`
- `[PSCustomObject] FinishLogin($clientLoginState, $loginResponse, $passw0rd, $clientIdentifier, $serverIdentifier)`
- `[PSCustomObject] FinishLogin($clientLoginState, $loginResponse, $passw0rd, $clientIdentifier, $serverIdentifier, $config)`

### OPAQUE

#### Properties

- $type $Client
- $type $Server

#### Methods

- `static [object] CreateRegistrationRequest($passw0rd)`
- `static [string] GenerateRegistration($passw0rd, $serverSetup, $userIdentifier)`
- `static [string] GenerateRegistration($passw0rd, $serverSetup, $userIdentifier, $clientIdentifier)`
- `static [string] GenerateRegistration($passw0rd, $serverSetup, $userIdentifier, $clientIdentifier, $serverIdentifier)`
- `static [string] GenerateRegistration($passw0rd, $serverSetup, $userIdentifier, $clientIdentifier, $serverIdentifier, $config)`
- `static [PSCustomObject] StartLogin($passw0rd)`
- `static [PSCustomObject] FinishLogin($clientLoginState, $loginResponse, $passw0rd, $serverSetup, $userIdentifier, $registrationRecord)`
- `static [PSCustomObject] FinishLogin($clientLoginState, $loginResponse, $passw0rd, $serverSetup, $userIdentifier, $registrationRecord, $clientIdentifier)`
- `static [PSCustomObject] FinishLogin($clientLoginState, $loginResponse, $passw0rd, $serverSetup, $userIdentifier, $registrationRecord, $clientIdentifier, $serverIdentifier)`
- `static [PSCustomObject] FinishLogin($clientLoginState, $loginResponse, $passw0rd, $serverSetup, $userIdentifier, $registrationRecord, $clientIdentifier, $serverIdentifier, $config)`



