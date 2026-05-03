#!/usr/bin/env pwsh

using module ./Enums.psm1

class InvalidArgumentException : System.Exception {
  [string]$paramName
  [string]$Message
  InvalidArgumentException() {
    $this.message = 'Invalid argument'
  }
  InvalidArgumentException([string]$paramName) {
    $this.paramName = $paramName
    $this.message = "Invalid argument: $paramName"
  }
  InvalidArgumentException([string]$paramName, [string]$message) {
    $this.paramName = $paramName
    $this.message = $message
  }
}

# Static class for calling the native credential functions
class CredentialNotFoundException : System.Exception, System.Runtime.Serialization.ISerializable {
  [string]$Message; [Exception]$InnerException; hidden $Info; hidden $Context
  CredentialNotFoundException() { $this.Message = 'CredentialNotFound' }
  CredentialNotFoundException([string]$message) { $this.Message = $message }
  CredentialNotFoundException([string]$message, [Exception]$InnerException) { ($this.Message, $this.InnerException) = ($message, $InnerException) }
  CredentialNotFoundException([System.Runtime.Serialization.SerializationInfo]$info, [Runtime.Serialization.StreamingContext]$context) { ($this.Info, $this.Context) = ($info, $context) }
}
class IntegrityCheckFailedException : System.Exception {
  [string]$Message; [Exception]$InnerException;
  IntegrityCheckFailedException() { }
  IntegrityCheckFailedException([string]$message) { $this.Message = $message }
  IntegrityCheckFailedException([string]$message, [Exception]$innerException) { $this.Message = $message; $this.InnerException = $innerException }
}
class InvalidPasswordException : System.Exception {
  [string]$Message; [string]hidden $Passw0rd; [securestring]hidden $Password; [Exception]$InnerException
  InvalidPasswordException() { $this.Message = "Invalid password" }
  InvalidPasswordException([string]$Message) { $this.message = $Message }
  InvalidPasswordException([string]$Message, [string]$Passw0rd) { ($this.message, $this.Passw0rd, $this.InnerException) = ($Message, $Passw0rd, [Exception]::new($Message)) }
  InvalidPasswordException([string]$Message, [securestring]$Password) { ($this.message, $this.Password, $this.InnerException) = ($Message, $Password, [Exception]::new($Message)) }
  InvalidPasswordException([string]$Message, [string]$Passw0rd, [Exception]$InnerException) { ($this.message, $this.Passw0rd, $this.InnerException) = ($Message, $Passw0rd, $InnerException) }
  InvalidPasswordException([string]$Message, [securestring]$Password, [Exception]$InnerException) { ($this.message, $this.Password, $this.InnerException) = ($Message, $Password, $InnerException) }
}

class SaltParseException : System.Exception {
  SaltParseException() : base() {}
  SaltParseException([string]$message) : base($message) {}
  SaltParseException([string]$message, [System.Exception]$innerException) : base($message, $innerException) {}
}

class BcryptAuthenticationException : System.Exception {
  BcryptAuthenticationException() : base() {}
  BcryptAuthenticationException([string]$message) : base($message) {}
  BcryptAuthenticationException([string]$message, [System.Exception]$innerException) : base($message, $innerException) {}
}

class HashInformationException : System.Exception {
  HashInformationException() : base() {}
  HashInformationException([string]$message) : base($message) {}
  HashInformationException([string]$message, [System.Exception]$innerException) : base($message, $innerException) {}
}

#region KeypairGen_Exceptions

class KeypairException : System.Exception {
  [AsymmetricAlgorithm] $Algorithm
  KeypairException([string]$message) : base($message) {}
  KeypairException([string]$message, [System.Exception]$inner) : base($message, $inner) {}
  KeypairException([string]$message, [AsymmetricAlgorithm]$algorithm) : base($message) {
    $this.Algorithm = $algorithm
  }
}

class KeyGenerationException : KeypairException {
  KeyGenerationException([string]$message) : base($message) {}
  KeyGenerationException([string]$message, [AsymmetricAlgorithm]$algorithm) : base($message, $algorithm) {}
}

class KeyImportException : KeypairException {
  [KeyFormat] $Format
  KeyImportException([string]$message) : base($message) {}
  KeyImportException([string]$message, [KeyFormat]$format) : base($message) {
    $this.Format = $format
  }
}