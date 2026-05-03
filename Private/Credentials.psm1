#!/usr/bin/env pwsh
using namespace System.Security.Cryptography
using namespace System.Runtime.InteropServices

using module ./Enums.psm1
using module ./Exceptions.psm1

#Requires -Modules PsModuleBase

# A managed credential object. Makes it easy to protect, convert, save and stuff ..
class CredManaged {
  [string] $target
  hidden [bool] $IsProtected = $false;
  hidden [CredType] $type = [CredType]1;
  hidden [EncryptionScope] $Scope = 'User';
  [ValidateNotNullOrEmpty()][string]$UserName = $(whoami);
  [ValidateNotNullOrEmpty()][securestring]$Password = [securestring]::new();
  [ValidateNotNullOrEmpty()][string]$Domain = [Environment]::UserDomainName;

  CredManaged() {}
  CredManaged([string]$target, [string]$username, [SecureString]$password) {
    ($this.target, $this.username, $this.password) = ($target, $username, $password)
  }
  CredManaged([string]$target, [string]$username, [SecureString]$password, [CredType]$type) {
    ($this.target, $this.username, $this.password, $this.type) = ($target, $username, $password, $type)
  }
  CredManaged([PSCredential]$PSCredential) {
    ($this.UserName, $this.Password) = ($PSCredential.UserName, $PSCredential.Password)
  }
  CredManaged([string]$target, [PSCredential]$PSCredential) {
    ($this.target, $this.UserName, $this.Password) = ($target, $PSCredential.UserName, $PSCredential.Password)
  }
  [void] Protect() {
    $_scope_ = [EncryptionScope]$this.Scope
    $_Props_ = @($this | Get-Member -Force | Where-Object { $_.MemberType -eq 'Property' -and $_.Name -ne 'Scope' } | Select-Object -ExpandProperty Name)
    foreach ($n in $_Props_) {
      $OBJ = $this.$n
      if ($n.Equals('Password')) {
        $this.$n = $(Protect-Data -MSG ($OBJ | xconvert ToString) -Scope $_scope_) | xconvert ToBase85, ToSecurestring
      } else {
        $this.$n = Protect-Data -MSG $OBJ -Scope $_scope_
      }
    }
    Invoke-Command -InputObject $this.IsProtected -NoNewScope -ScriptBlock $([ScriptBlock]::Create({
          $this.psobject.Properties.Add([psscriptproperty]::new('IsProtected', { return $true }))
        }
      )
    )
  }
  [void] UnProtect() {
    $_scope_ = [EncryptionScope]$this.Scope
    $_Props_ = @($this | Get-Member -Force | Where-Object { $_.MemberType -eq 'Property' -and $_.Name -ne 'Scope' } | Select-Object -ExpandProperty Name)
    foreach ($n in $_Props_) {
      $OBJ = $this.$n
      if ($n.Equals('Password')) {
        $this.$n = UnProtect-Data -MSG ($OBJ | xconvert ToString, FromBase85, ToString) -Scope $_scope_ | xconvert ToSecurestring;
      } else {
        $this.$n = UnProtect-Data -MSG $OBJ -Scope $_scope_;
      }
    }
    Invoke-Command -InputObject $this.IsProtected -NoNewScope -ScriptBlock $([ScriptBlock]::Create({
          $this.psobject.Properties.Add([psscriptproperty]::new('IsProtected', { return $false }))
        }
      )
    )
  }
  [void] SaveToVault() {
    $CredMan = [CredentialManager]::new();
    [void]$CredMan.SaveCredential($this.target, $this.UserName, $this.Password);
  }
  [string]ToString() {
    $str = $this.UserName
    if ($str.Length -gt 9) { $str = $str.Substring(0, 6) + '...' }
    return $str
  }
}
class NativeCredential {
  [Int32]$AttributeCount
  [UInt32]$CredentialBlobSize
  [IntPtr]$CredentialBlob
  [IntPtr]$TargetAlias
  [Int32]$Type
  [IntPtr]$TargetName
  [IntPtr]$Attributes
  [IntPtr]$UserName
  [UInt32]$Persist
  [IntPtr]$Comment

  NativeCredential([CredManaged]$Cr3dential) {
    $this._init_();
    $this.CredentialBlobSize = [UInt32](($Cr3dential.password.Length + 1) * 2)
    $this.TargetName = [Marshal]::StringToCoTaskMemUni($Cr3dential.target)
    $this.CredentialBlob = [Marshal]::SecureStringToCoTaskMemUnicode($Cr3dential.password)
    $this.UserName = [Marshal]::StringToCoTaskMemUni($Cr3dential.username)
  }
  NativeCredential([string]$target, [string]$username, [securestring]$password) {
    $this._init_();
    $this.CredentialBlobSize = [UInt32](($password.Length + 1) * 2);
    $this.TargetName = [Marshal]::StringToCoTaskMemUni($target);
    $this.CredentialBlob = [Marshal]::SecureStringToCoTaskMemUnicode($password);
    $this.UserName = [Marshal]::StringToCoTaskMemUni($username);
  }
  hidden _init_() {
    $this.AttributeCount = 0
    $this.Comment = [IntPtr]::Zero
    $this.Attributes = [IntPtr]::Zero
    $this.TargetAlias = [IntPtr]::Zero
    $this.Type = [CredType]::Generic.value__
    $this.Persist = [UInt32][CredentialPersistence]::LocalComputer
  }
}
# Windows credential manager
class CredentialManager {
  static $LastErrorCode
  CredentialManager() { $this::Init() }
  [object] static hidden Advapi32() {
    return (New-Object -TypeName CredentialManager.Advapi32)
  }
  static [void] SaveCredential([string]$title, [SecureString]$SecureString) {
    $UserName = [Environment]::GetEnvironmentVariable('UserName');
    [CredentialManager]::SaveCredential([CredManaged]::new($title, $UserName, $SecureString));
  }
  static [void] SaveCredential([string]$title, [string]$UserName, [SecureString]$SecureString) {
    [CredentialManager]::SaveCredential([CredManaged]::new($title, $UserName, $SecureString));
  }
  static [void] SaveCredential([CredManaged]$Object) {
    if ($null -eq [CredentialManager].CONSTANTS) { [CredentialManager]::Init() }
    # Create the native credential object.
    $NativeCredential = New-Object -TypeName CredentialManager.Advapi32+NativeCredential;
    foreach ($prop in ([NativeCredential]::new($Object).PsObject.properties)) {
      $NativeCredential."$($prop.Name)" = $prop.Value
    }
    # Save Generic credential to the Windows Credential Vault.
    $result = [CredentialManager]::Advapi32()::CredWrite([ref]$NativeCredential, 0)
    [CredentialManager]::LastErrorCode = [Marshal]::GetLastWin32Error();
    if (!$result) {
      throw [Exception]::new("Error saving credential: 0x" + "{0}" -f [CredentialManager]::LastErrorCode)
    }
    # Clean up memory allocated for the native credential object.
    [Marshal]::ZeroFreeCoTaskMemUnicode($NativeCredential.TargetName)
    [Marshal]::ZeroFreeCoTaskMemUnicode($NativeCredential.CredentialBlob)
    [Marshal]::ZeroFreeCoTaskMemUnicode($NativeCredential.UserName)
  }
  static [bool] Remove([string]$target, [CredType]$type) {
    if ($null -eq [CredentialManager].CONSTANTS) { [CredentialManager]::Init() }
    $Isdeleted = [CredentialManager]::Advapi32()::CredDelete($target, $type, 0);
    [CredentialManager]::LastErrorCode = [Marshal]::GetLastWin32Error();
    if (!$Isdeleted) {
      if ([CredentialManager]::LastErrorCode -eq [CredentialManager].CONSTANTS.ERROR_NOT_FOUND) {
        throw [CredentialNotFoundException]::new("DeleteCred failed with the error code $([CredentialManager]::LastErrorCode) (credential not found).");
      } else {
        throw [Exception]::new("DeleteCred failed with the error code $([CredentialManager]::LastErrorCode).");
      }
    }
    return $Isdeleted
  }
  [CredManaged] static GetCredential([string]$target) {
    #uses the default $(whoami)
    return [CredentialManager]::GetCredential($target, (Get-Item Env:\USERNAME).Value);
  }
  [CredManaged] static GetCredential([string]$target, [string]$username) {
    return [CredentialManager]::GetCredential($target, [CredType]::Generic, $username);
  }
  # Method for retrieving a saved credential from the Windows Credential Vault.
  [CredManaged] static GetCredential([string]$target, [CredType]$type, [string]$username) {
    if ($null -eq [CredentialManager].CONSTANTS) { [CredentialManager]::Init() }
    $NativeCredential = New-Object -TypeName CredentialManager.Advapi32+NativeCredential;
    foreach ($prop in ([NativeCredential]::new($target, $username, [securestring]::new()).PsObject.properties)) {
      $NativeCredential."$($prop.Name)" = $prop.Value
    }
    # Declare variables
    $AdvAPI32 = [CredentialManager]::Advapi32()
    $outCredential = [IntPtr]::Zero # To hold the retrieved native credential object.
    # Try to retrieve the credential from the Windows Credential Vault.
    $result = $AdvAPI32::CredRead($target, $type.value__, 0, [ref]$outCredential)
    [CredentialManager]::LastErrorCode = [Marshal]::GetLastWin32Error();
    if (!$result) {
      $errorCode = [CredentialManager]::LastErrorCode
      if ($errorCode -eq [CredentialManager].CONSTANTS.ERROR_NOT_FOUND) {
        $(Get-Variable host).value.UI.WriteErrorLine("`nERROR_NOT_FOUND: Credential '$target' not found in Windows Credential Vault. Returning Empty Object ...`n");
        return [CredManaged]::new();
      } else {
        throw [Exception]::new("Error reading '{0}' in Windows Credential Vault. ErrorCode: 0x{1}" -f $target, $errorCode)
      }
    }
    # Convert the retrieved native credential object to a managed Credential object & Get the Credential from the mem location
    $NativeCredential = [Marshal]::PtrToStructure($outCredential, [Type]"CredentialManager.Advapi32+NativeCredential") -as 'CredentialManager.Advapi32+NativeCredential'
    [GC]::Collect();
    $target = [Marshal]::PtrToStringUni($NativeCredential.TargetName)
    $password = [Runtime.InteropServices.Marshal]::PtrToStringUni($NativeCredential.CredentialBlob)
    $targetuser = [Marshal]::PtrToStringUni($NativeCredential.UserName)
    $credential = [CredManaged]::new($target, $targetuser, ($password | xconvert ToSecurestring));
    # Clean up memory allocated for the native credential object.
    [void]$AdvAPI32::CredFree($outCredential); [CredentialManager]::LastErrorCode = [Marshal]::GetLastWin32Error();
    # Return the managed Credential object.
    return $credential
  }
  [Collections.ObjectModel.Collection[CredManaged]] static RetreiveAll() {
    $Credentials = [Collections.ObjectModel.Collection[CredManaged]]::new();
    # CredEnumerate is slow af so, I ditched it.
    $credList = [CredentialManager]::get_StoredCreds();
    foreach ($cred in $credList) {
      Write-Verbose "CredentialManager.GetCredential($($cred.Target))";
      $Credentials.Add([CredManaged]([CredentialManager]::GetCredential($cred.Target, $cred.Type, $cred.User)));
    }
    return $Credentials
  }
  [Psobject[]] static hidden get_StoredCreds() {
    $_Host_OS = [PsModuleBase]::GetHostOs()
    if ($_Host_OS -in ('Linux', 'MacOs')) {
      throw [Exception]::new('UnsupportedPlatform: get_StoredCreds() works on Windows Only.')
    }
    # until I know the existance of a [wrapper module](https://learn.microsoft.com/en-us/powershell/utility-modules/crescendo/overview?view=ps-modules), I'll stick to this Hack.
    $cmdkey = (Get-Command cmdkey -ErrorAction SilentlyContinue).Source
    if ([string]::IsNullOrEmpty($cmdkey)) { throw [Exception]::new('get_StoredCreds() Failed.') }
    $outputLines = (&$cmdkey /list) -split "`n"
    [CredentialManager]::LastErrorCode = [Marshal]::GetLastWin32Error();
    if ($outputLines) {
    } else {
      throw $error[0].Exception.Message
    }
    $target = $type = $user = $perst = $null
    $credList = $(foreach ($line in $outputLines) {
        if ($line -match "^\s*Target:\s*(.+)$") {
          $target = $matches[1]
        } elseif ($line -match "^\s*Type:\s*(.+)$") {
          $type = $matches[1]
        } elseif ($line -match "^\s*User:\s*(.+)$") {
          $user = $matches[1]
        } elseif ($line -match "^\s*Local machine persistence$") {
          $perst = "LocalComputer"
        } elseif ($line -match "^\s*Enterprise persistence$") {
          $perst = 'Enterprise'
        }
        if ($target -and $type -and $user -and ![string]::IsNullOrEmpty($perst)) {
          [PSCustomObject]@{
            Target      = [string]$target
            Type        = [CredType]$type
            User        = [string]$user
            Persistence = [CredentialPersistence]$perst
          }
          $target = $type = $user = $perst = $null
        }
      }
    ) | Select-Object @{l = 'Target'; e = { $_.target.replace('LegacyGeneric:target=', '').replace('WindowsLive:target=', '') } }, Type, User, Persistence | Where-Object { $_.target -ne 'virtualapp/didlogical' };
    return $credList
  }
  static hidden [void] Init() {
    $Host_OS = $(if ($(Get-Variable PSVersionTable -Value).PSVersion.Major -le 5 -or $(Get-Variable IsWindows -Value)) { "Windows" }elseif ($(Get-Variable IsLinux -Value)) { "Linux" }elseif ($(Get-Variable IsMacOS -Value)) { "macOS" }else { "UNKNOWN" });
    if ($Host_OS -ne "Windows") {
      throw [System.PlatformNotSupportedException]::new("'$Host_OS' is not supported. CredentialManager class works on windows only.")
    }
    $CONSTANTS = [psobject]::new()
    $CONSTANTS.psobject.Properties.Add([psscriptproperty]::new('ERROR_SUCCESS', { return 0 }))
    $CONSTANTS.psobject.Properties.Add([psscriptproperty]::new('ERROR_NOT_FOUND', { return 1168 }))
    $CONSTANTS.psobject.Properties.Add([psscriptproperty]::new('ERROR_INVALID_FLAGS', { return 1004 }))
    $CONSTANTS.psobject.Properties.Add([psscriptproperty]::new('CRED_PERSIST_LOCAL_MACHINE', { return 2 }))
    $CONSTANTS.psobject.Properties.Add([psscriptproperty]::new('CRED_MAX_USERNAME_LENGTH', { return 514 }))
    $CONSTANTS.psobject.Properties.Add([psscriptproperty]::new('CRED_MAX_CREDENTIAL_BLOB_SIZE', { return 512 }))
    $CONSTANTS.psobject.Properties.Add([psscriptproperty]::new('CRED_MAX_GENERIC_TARGET_LENGTH', { return 32767 }))
    [CredentialManager].psobject.Properties.Add([psscriptproperty]::new('CONSTANTS', { return $CONSTANTS }))
    # Import native functions from Advapi32.dll
    # No other choice but to use Add-Type. ie: https://stackoverflow.com/questions/64405866/invoke-runtime-interopservices-dllimportattribute
    # So CredentialManager.Advapi32+functionName it is!
    if (![bool]('CredentialManager.Advapi32' -as 'type')) { Add-Type -Namespace CredentialManager -Name Advapi32 -MemberDefinition $(Expand-Data -str 'H4sIAAAAAAAEALVUS2/aQBC+91eMOIFqWQT6kIo4UB4VKkQohuYQ5bDYA1lpvUt31zSk6n/vrB+AMW1a2vhge+f5ffONDQCwSZaCh4AyiaGvMZrvNggfIOHSwvdXkF+fUKKmsC5ceTBQMeNyxoz5pnREtlZh66O2fMVDZpHM7cL8hRu+FHiU8cYrSpZT3hYpw0eLMkIX+86DKXvkMQHswvv9YfhIx3rheQ1XzWazkQL+kd5Pic1QG25slVuAxnAlM24TFTIxZeEDl5gxG0qLeqO5SSkdNbgLrE5CO2E7ldh69vjMZeQH+DVBaTkTHvQfmA7QUmr+5i8kD1WEjftjlCYtleLMMg/w8ogU9EiwtekUpr1c7tY5KsXlGuZMr9Fes7ji6as4piZ784BGP+cxwoQZe6u5pcl3Sm1JOKdbwJ8qxQpN9/ZgZyzGNIMwoVK77AWDLDo7VHKO5cmfZQA9S/nLxGJfJUfIx9LOrD54zfkh9ARnFdfCoE6n87KKXjPLt3jQFS4XNmd7RtjccypsLsUNjYzk9cdukdUmQL3lIRqfwl1944/Gk+F8PB3+egEO+D8KtSztQdG7FHGyPv9F0hL9sqS566ykAyHG8UZpW6/1oi3b8HbLj4SopR+23s2UA9OFmiNwgyy6rf1GYo822LopDbVWmvwkMul+0JzUpl8O/bu0hKVSAoqy9buxvC92z6YcPEhte7Et3XKbw6SR6GwxcqvhAW1iQTPcj5pOjc7f03QS4wvwTOtmRDWuqqufEKHDMae6IFbtFqzcB3AJmZFGrF2G16VmcKuTdS3wD6Z7pu85lAMU+MzMn4Wb1fi3RWp0fgKYas6b9AcAAA==') }
    if (Get-Service vaultsvc -ErrorAction SilentlyContinue) { Start-Service vaultsvc -ErrorAction Stop }
  }
}