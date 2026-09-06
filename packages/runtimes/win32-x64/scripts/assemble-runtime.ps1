[CmdletBinding()]
param(
  [string] $ScratchDirectory = [System.IO.Path]::GetTempPath()
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

$PythonVersion = '3.14.7'
$PythonUrl = "https://www.python.org/ftp/python/$PythonVersion/python-$PythonVersion-embed-amd64.zip"
$PythonSha256 = 'd297e5ff019966817ad8502465176139f2d3d840fa4ed84b13bed399a6ab1f15'

$PipVersion = '26.2.1'
$PipUrl = 'https://files.pythonhosted.org/packages/f3/6e/1736e5b4ae2b778ef2f81c47d797de9f891d4d8acb047a24ca37a60294dd/pip-26.2.1-py3-none-any.whl'
$PipSha256 = '71138adf1f4ca900cdb7d289c21b7494329f2332b6d85f0e1c42108c0384ed3e'

$SemgrepVersion = '1.175.0'

function Get-NormalizedPath([string] $Path) {
  return [System.IO.Path]::GetFullPath($Path).TrimEnd(
    [System.IO.Path]::DirectorySeparatorChar,
    [System.IO.Path]::AltDirectorySeparatorChar
  )
}

function Get-VerifiedDownload(
  [string] $Uri,
  [string] $Destination,
  [string] $ExpectedSha256
) {
  Invoke-WebRequest -Uri $Uri -OutFile $Destination -UseBasicParsing
  $actualSha256 = (Get-FileHash -LiteralPath $Destination -Algorithm SHA256).Hash.ToLowerInvariant()
  if ($actualSha256 -ne $ExpectedSha256) {
    throw "SHA-256 mismatch for $Uri`: expected $ExpectedSha256, received $actualSha256"
  }
}

$PackageRoot = Get-NormalizedPath (Join-Path $PSScriptRoot '..')
$RuntimeDirectory = Get-NormalizedPath (Join-Path $PackageRoot 'runtime')
$RequirementsLock = Get-NormalizedPath (Join-Path $PackageRoot 'requirements.lock')
$ExpectedRuntimeDirectory = Get-NormalizedPath (
  Join-Path $PSScriptRoot '..\runtime'
)
if ($RuntimeDirectory -ne $ExpectedRuntimeDirectory) {
  throw 'Refusing to assemble outside the win32-x64 runtime package'
}
$RuntimeExists = Test-Path -LiteralPath $RuntimeDirectory
$RuntimeEntryCount = if ($RuntimeExists) {
  @(Get-ChildItem -LiteralPath $RuntimeDirectory -Force).Count
} else {
  0
}
if ($RuntimeExists -and $RuntimeEntryCount -ne 0) {
  throw "Runtime output directory must be empty: $RuntimeDirectory"
}
if (-not (Test-Path -LiteralPath $RequirementsLock -PathType Leaf)) {
  throw "Dependency lock file does not exist: $RequirementsLock"
}

$ScratchRoot = Get-NormalizedPath $ScratchDirectory
$BuildDirectory = Join-Path $ScratchRoot ("dsh-semgrep-runtime-" + [guid]::NewGuid().ToString('N'))
$StagedRuntime = Join-Path $BuildDirectory 'runtime'
$PythonDirectory = Join-Path $StagedRuntime 'python'
$SitePackages = Join-Path $PythonDirectory 'Lib\site-packages'
$PythonArchive = Join-Path $BuildDirectory "python-$PythonVersion-embed-amd64.zip"
$PipWheel = Join-Path $BuildDirectory "pip-$PipVersion-py3-none-any.whl"

New-Item -ItemType Directory -Path $PythonDirectory -Force | Out-Null
New-Item -ItemType Directory -Path $SitePackages -Force | Out-Null

try {
  Get-VerifiedDownload $PythonUrl $PythonArchive $PythonSha256
  Get-VerifiedDownload $PipUrl $PipWheel $PipSha256

  Expand-Archive -LiteralPath $PythonArchive -DestinationPath $PythonDirectory
  [System.IO.Compression.ZipFile]::ExtractToDirectory($PipWheel, $SitePackages)

  $PythonPathFile = Join-Path $PythonDirectory 'python314._pth'
  @(
    'python314.zip'
    '.'
    'Lib\site-packages'
    'import site'
  ) | Set-Content -LiteralPath $PythonPathFile -Encoding ascii

  $PythonExecutable = Join-Path $PythonDirectory 'python.exe'
  & $PythonExecutable -m pip install `
    --disable-pip-version-check `
    --no-cache-dir `
    --no-compile `
    --only-binary=:all: `
    --require-hashes `
    --target $SitePackages `
    --requirement $RequirementsLock
  if ($LASTEXITCODE -ne 0) {
    throw "pip failed with exit code $LASTEXITCODE"
  }

  $InstalledVersion = (& $PythonExecutable -m semgrep --version).Trim()
  if ($LASTEXITCODE -ne 0 -or $InstalledVersion -ne $SemgrepVersion) {
    throw "Expected Semgrep $SemgrepVersion, received $InstalledVersion"
  }

  if (Test-Path -LiteralPath $RuntimeDirectory) {
    Remove-Item -LiteralPath $RuntimeDirectory
  }
  Move-Item -LiteralPath $StagedRuntime -Destination $RuntimeDirectory
  Write-Output "Assembled Semgrep $SemgrepVersion with Python $PythonVersion at $RuntimeDirectory"
}
finally {
  if (Test-Path -LiteralPath $BuildDirectory) {
    Remove-Item -LiteralPath $BuildDirectory -Recurse -Force
  }
}
