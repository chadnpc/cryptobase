#!/usr/bin/env pwsh
using namespace System.IO
using namespace System.Web
using namespace System.Text
using namespace System.Security
using namespace System.Security.Cryptography

#VaultStuff

# .DESCRIPTION
#     Hashicorp VaultClient helper class for interacting with a Vault server by the Vault API.
#     To use this class, you will need to have access to a running instance of Hashicorp Vault.
#     You can download it from from the Hashicorp website at https://www.hashicorp.com/products/vault/.
# .EXAMPLE
#     $vaucl = [VaultClient]::new('<VAULT_ADDRESS>', '<VAULT_TOKEN>', '<VAULT_PROTOCOL>')
#     $vault = $vaucl.GetVaultServer()
#     $secrets = $vaucl.GetVaultSecretList('<VAULT_PATH>')
#     $vaucl.SetVaultSecret('<VAULT_PATH>', @{key = 'value'})
class VaultClient {
  # Properties
  [string] $Address # This is the URL or IP address of your Vault server, including the port number if applicable. You can find this value in the api_addr field of the vault.hcl configuration file, or you can use the vault status command to display the current address of the Vault server.
  [string] $Token # This is a token that is used to authenticate with the Vault server. You can generate a new token using the vault token create command, or you can use the vault status command to display the current token of the Vault server.
  [string] $Protocol # This is the protocol that will be used to communicate with the Vault server. The most common value is https, but you can also use http if you have configured your Vault server to use an insecure connection. You can find this value in the api_addr field of the vault.hcl configuration file, or you can use the vault status command to display the current protocol of the Vault server.
  [string] $Url = [string]::Empty
  hidden [PSCustomObject] $ClientObj = $null
  static hidden $releases # ie: [Microsoft.PowerShell.Commands.HtmlWebResponseObject]

  # Constructor for the VaultClient class
  VaultClient([string]$address, [string]$token, [string]$protocol) {
    $this.Address = $address
    $this.Token = $token
    $this.Protocol = $protocol
    # Set the Vault URL
    $this.Url = "{0}://{1}/v1/" -f $protocol, $address
    # Generate the vaultClient object
    $this.GenerateVaultClient($token)
  }
  # Download and Install the latest Vault
  static [void] Install() {
    [console]::Write("Check Latest Version ...")
    [VaultClient]::releases = Invoke-WebRequest "https://releases.hashicorp.com/vault/" -Verbose:$false
    [string]$latestver = $([VaultClient]::releases.Links | ForEach-Object { $_.outerText.split('-')[0].split('_')[1] -as 'version' } | Sort-Object -Descending)[0].tostring()
    [VaultClient]::Install($latestver)
  }
  static [void] Install([string]$version) {
    [console]::WriteLine(" Found vault version: $version")
    if ($null -eq [VaultClient]::releases) { [VaultClient]::releases = Invoke-WebRequest "https://releases.hashicorp.com/vault/" -Verbose:$false }
    [string]$latest_dl = $(Invoke-WebRequest ("https://releases.hashicorp.com" + ([VaultClient]::releases.Links | Where-Object { $_.href -like "*/$version/*" } | Select-Object -ExpandProperty href)) -Verbose:$false).Links.href | Where-Object { $_ -like "*windows_386*" }
    $p = Get-Variable progressPreference -ValueOnly; $progressPreference = "SilentlyContinue"
    $Outfile = [FileInfo]::new([PsModuleBase]::GetUnResolvedPath("vault_$version.zip"));
    try {
      $should_download = $true
      if ($Outfile.Exists()) {
        #TODO: Check version of the file, if the version is lower, then $should_download = $true
      }
      if ($should_download) {
        $Outfile = [scriptblock]::Create("[NetworkManager]::DownloadFile([uri]::new('$latest_dl'), '$($Outfile.FullName)')").Invoke()
      }
      if ($Outfile.Exists()) {
        Expand-Archive -Path $Outfile.FullName -DestinationPath "C:\Program Files\Vault\"
      }
      [void][System.Environment]::SetEnvironmentVariable("PATH", $env:PATH + ";C:\Program Files\Vault\", "Machine")
    } catch {
      throw $_
    } finally {
      Remove-Item $Outfile -Force -ErrorAction SilentlyContinue
      $progressPreference = $p
    }
    # refresh env: like Update-SessionEnvironment from choco~
  }
  # Method to generate the vaultClient object
  [void] GenerateVaultClient([string]$token) {
    # Set the Vault token
    $this.ClientObj = @{
      Token   = $token
      Headers = @{ 'X-Vault-Token' = $token }
      BaseUri = $this.Url
    }
  }

  # Method to get a Vault server
  [PSCustomObject] GetVaultServer() {
    # Create a custom object with the vaultClient object
    $vault = New-Object -TypeName PSObject -Property $this.ClientObj
    # Return the custom object
    return $vault
  }

  # Method to get a Vault secret
  [Hashtable] GetVaultSecret([string]$path) {
    # Get the server
    $vault = $this.GetVaultServer()
    # Get the secret at the specified path
    $uri = $vault.BaseUri + $path
    $secret = Invoke-WebRequest -Uri $uri -Headers $vault.Headers | Select-Object -ExpandProperty Content | ConvertFrom-Json | Select-Object -ExpandProperty data
    # Return the secret
    return $secret
  }

  # Method to get a list of Vault secrets
  [string[]] GetVaultSecretList([string]$path) {
    return $this.GetVaultSecretList($path, $null)
  }
  # Method to get a list of Vault secrets
  [string[]] GetVaultSecretList([string]$path, [PSCustomObject]$vault = $null) {
    # Get the server
    if (!$vault) { $vault = $this.GetVaultServer() }
    # Get the list of secrets
    $uri = $vault.BaseUri + $path
    $secrets = Invoke-WebRequest -Uri $uri -Headers $vault.Headers -CustomMethod 'list' | Select-Object -ExpandProperty Content | ConvertFrom-Json | Select-Object -ExpandProperty data | Select-Object -ExpandProperty keys | ForEach-Object {
      if ($_ -like '*/') {
        $this.GetVaultSecretList($("$path/$_").Trim("/"), $vault)
      } else {
        "$path/$_"
      }
    }
    # Return the list of secrets
    return $secrets
  }

  # Method to set a Vault secret
  [void] SetVaultSecret([string]$path, [Hashtable]$secret) {
    $vault = $this.GetVaultServer()
    # Set the secret at the specified path
    $uri = $vault.BaseUri + $path
    $data = @{data = $secret } | ConvertTo-Json
    Invoke-WebRequest -Uri $uri -Headers $vault.Headers -Method 'POST' -Body $data | Select-Object -ExpandProperty Content | ConvertFrom-Json | Select-Object -ExpandProperty data
  }
  # Method to remove a Vault secret
  [void] RemoveVaultSecret([string]$path) {
    $vault = $this.GetVaultServer()
    # Remove the secret at the specified path
    $uri = $vault.BaseUri + $path
    Invoke-WebRequest -Uri $uri -Headers $vault.Headers -Method 'DELETE'
  }

  # Method to get a Vault group
  [Hashtable] GetVaultGroup([string]$name) {
    $vault = $this.GetVaultServer()
    # Get the group with the specified name
    $uri = $vault.BaseUri + "identity/group/name/$name"
    $group = Invoke-WebRequest -Uri $uri -Headers $vault.Headers | Select-Object -ExpandProperty Content | ConvertFrom-Json | Select-Object -ExpandProperty data

    # Return the group
    return $group
  }

  # Method to set a Vault group
  [void] SetVaultGroup([Hashtable]$group) {
    $vault = $this.GetVaultServer()
    # Set the group
    $uri = $vault.BaseUri + "identity/group"
    $data = $group | ConvertTo-Json
    Invoke-WebRequest -Uri $uri -Headers $vault.Headers -Method 'POST' -Body $data
  }

  # Method to remove a Vault group
  [void] RemoveVaultGroup([string]$name) {
    $vault = $this.GetVaultServer()
    # Remove the group with the specified name
    $uri = $vault.BaseUri + "identity/group/name/$name"
    Invoke-WebRequest -Uri $uri -Headers $vault.Headers -Method 'DELETE'
  }

  # Method to get a Vault policy
  [string] GetVaultPolicy([string]$name) {
    $vault = $this.GetVaultServer()
    # Get the policy with the specified name
    $uri = $vault.BaseUri + "sys/policy/$name"
    $policy = Invoke-WebRequest -Uri $uri -Headers $vault.Headers | Select-Object -ExpandProperty Content | ConvertFrom-Json | Select-Object -ExpandProperty data | Select-Object -ExpandProperty rules

    # Return the policy
    return $policy
  }

  # Method to set a Vault policy
  [void] SetVaultPolicy([string]$name, [string]$rules) {
    $vault = $this.GetVaultServer()
    # Set the policy with the specified name
    $uri = $vault.BaseUri + "sys/policy/$name"
    $data = @{rules = $rules } | ConvertTo-Json
    Invoke-WebRequest -Uri $uri -Headers $vault.Headers -Method 'POST' -Body $data
  }

  # Method to remove a Vault policy
  [void] RemoveVaultPolicy([string]$name) {
    $vault = $this.GetVaultServer()
    # Remove the policy with the specified name
    $uri = $vault.BaseUri + "sys/policy/$name"
    Invoke-WebRequest -Uri $uri -Headers $vault.Headers -Method 'DELETE'
  }

  # Method to get a list of Vault policies
  [string[]] GetVaultPolicyList() {
    $vault = $this.GetVaultServer()
    # Get the list of policies
    $uri = $vault.BaseUri + "sys/policy"
    $policies = Invoke-WebRequest -Uri $uri -Headers $vault.Headers | Select-Object -ExpandProperty Content | ConvertFrom-Json | Select-Object -ExpandProperty data | Select-Object -ExpandProperty keys

    # Return the list of policies
    return $policies
  }
}
