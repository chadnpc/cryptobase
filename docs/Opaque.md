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