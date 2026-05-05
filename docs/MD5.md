# MD5

Legacy MD5 hashing algorithm. Included for backwards compatibility or checksumming non-sensitive data. NOT secure for cryptography.

## Usage Example

```powershell
$data = [System.Text.Encoding]::UTF8.GetBytes('legacy')
$hash = [MD5]::HashData($data)
```

## Classes

### MD5

#### Methods

- `[void] MD5()`
- `static [byte[]] Encrypt($data, $hash)`
- `static [byte[]] Decrypt($data, $hash)`



