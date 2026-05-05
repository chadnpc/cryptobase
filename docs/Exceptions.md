# Exceptions

> **Note:** This documentation was automatically generated.

## Classes

### InvalidArgumentException

#### Properties

- $type $paramName
- $type $Message

#### Methods

- `[void] InvalidArgumentException()`
- `[void] InvalidArgumentException($paramName)`
- `[void] InvalidArgumentException($paramName, $message)`

### CredentialNotFoundException

#### Properties

- $type $Message
- $type $InnerException
- $type $Info
- $type $Context

#### Methods

- `[void] CredentialNotFoundException()`
- `[void] CredentialNotFoundException($message)`
- `[void] CredentialNotFoundException($message, $InnerException)`
- `[void] CredentialNotFoundException($info, $context)`

### IntegrityCheckFailedException

#### Properties

- $type $Message
- $type $InnerException

#### Methods

- `[void] IntegrityCheckFailedException()`
- `[void] IntegrityCheckFailedException($message)`
- `[void] IntegrityCheckFailedException($message, $innerException)`

### InvalidPasswordException

#### Properties

- $type $Message
- $type $Passw0rd
- $type $Password
- $type $InnerException

#### Methods

- `[void] InvalidPasswordException()`
- `[void] InvalidPasswordException($Message)`
- `[void] InvalidPasswordException($Message, $Passw0rd)`
- `[void] InvalidPasswordException($Message, $Password)`
- `[void] InvalidPasswordException($Message, $Passw0rd, $InnerException)`
- `[void] InvalidPasswordException($Message, $Password, $InnerException)`

### SaltParseException

#### Methods

- `[void] SaltParseException()`
- `[void] SaltParseException($message)`
- `[void] SaltParseException($message, $innerException)`

### BcryptAuthenticationException

#### Methods

- `[void] BcryptAuthenticationException()`
- `[void] BcryptAuthenticationException($message)`
- `[void] BcryptAuthenticationException($message, $innerException)`

### HashInformationException

#### Methods

- `[void] HashInformationException()`
- `[void] HashInformationException($message)`
- `[void] HashInformationException($message, $innerException)`

### KeypairException

#### Properties

- $type $Algorithm

#### Methods

- `[void] KeypairException($message)`
- `[void] KeypairException($message, $inner)`
- `[void] KeypairException($message, $algorithm)`

### KeyGenerationException

#### Methods

- `[void] KeyGenerationException($message)`
- `[void] KeyGenerationException($message, $algorithm)`

### KeyImportException

#### Properties

- $type $Format

#### Methods

- `[void] KeyImportException($message)`
- `[void] KeyImportException($message, $format)`


