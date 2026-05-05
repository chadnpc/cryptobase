# FileMonitor

Provides cryptographic monitoring of files to detect unauthorized modification using fast hashes like Blake3.

## Usage Example

```powershell
# Take a snapshot of a directory
$baseline = [FileMonitor]::Snapshot('C:\Sensitive')

# Later, compare to detect changes
$changes = [FileMonitor]::Diff('C:\Sensitive', $baseline)
```

## Classes

### FileMonitor

#### Properties

- $type $FileClosed
- $type $FileLocked
- $type $Keys
- $type $FileTowatch
- $type $LogvariableName

#### Methods

- `static [FileSystemWatcher] MonitorFile($File)`
- `static [FileSystemWatcher] MonitorFile($File, $Action)`
- `static [PsObject] MonitorFileAsync($filePath)`
- `static [string] GetLogSummary()`
- `static [string] GetLogSummary($LogvariableName)`
- `static [bool] IsFileOpenInVim($file)`
- `static [bool] IsFileLocked($filePath)`



