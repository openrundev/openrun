#!/usr/bin/env pwsh

# Copyright (c) ClaceIO, LLC
# SPDX-License-Identifier: Apache-2.0

$ErrorActionPreference = 'Stop'

# The version to install can be set with $v (e.g. $v="v0.18.5") before invoking
# this script, or passed as the first argument when running a downloaded copy.
# Defaults to the latest release. The leading v on the version is optional.
$Version = if ($v) {
  $v
} elseif ($args.Length -eq 1) {
  $args.Get(0)
} else {
  "latest"
}

$OpenRunInstall = $env:OPENRUN_HOME
if (!$OpenRunInstall) {
  $OpenRunInstall = "$Home\openrun"
}

$BinDir = "$OpenRunInstall\bin"
$OpenRunExe = "$BinDir\openrun.exe"
$OpenRunConfig = "$OpenRunInstall\openrun.toml"

# GitHub require TLS 1.2
[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12

if ($Version -eq "latest") {
  # Resolve the latest release tag from the release page redirect. This avoids
  # the GitHub API, which is rate limited per IP for unauthenticated requests
  try {
    $Request = [System.Net.WebRequest]::Create("https://github.com/openrundev/openrun/releases/latest")
    $Request.AllowAutoRedirect = $false
    $Response = $Request.GetResponse()
    $Location = $Response.Headers['Location']
    $Response.Close()
    $Version = ($Location -split '/')[-1]
    if (!$Version -or $Version -eq "latest") {
      throw "no release tag found in redirect from releases/latest"
    }
  } catch {
    Write-Error "Unable to find the latest openrun release: $_ - see github.com/openrundev/openrun/releases for all versions"
    Exit 1
  }
} elseif ($Version -notmatch '^v') {
  # Release tags are v-prefixed, like v0.18.5
  $Version = "v$Version"
}

$ZipName = "openrun-$Version-windows-amd64.zip"
$OpenRunUri = "https://github.com/openrundev/openrun/releases/download/$Version/$ZipName"
$ChecksumUri = "https://github.com/openrundev/openrun/releases/download/$Version/SHA256SUMS"

if (!(Test-Path $BinDir)) {
  New-Item $BinDir -ItemType Directory | Out-Null
}

# Download and extract under a temp directory, only the exe is moved into
# place. Keeps partial downloads and the extracted archive out of $OpenRunInstall
$TmpDir = Join-Path ([System.IO.Path]::GetTempPath()) "openrun-install-$PID"
if (Test-Path $TmpDir) {
  Remove-Item $TmpDir -Recurse -Force
}
New-Item $TmpDir -ItemType Directory | Out-Null
$OpenRunZip = Join-Path $TmpDir $ZipName
$ChecksumFile = Join-Path $TmpDir "SHA256SUMS"

try {
  $prevProgressPreference = $ProgressPreference
  try {
    # Avoid perf issues with progress bar
    if ($PSVersionTable.PSVersion.Major -lt 7) {
      Write-Output "Downloading openrun $Version..."
      $ProgressPreference = "SilentlyContinue"
    }

    try {
      Invoke-WebRequest $OpenRunUri -OutFile $OpenRunZip -UseBasicParsing
    } catch {
      Write-Error "Unable to download openrun $Version from $OpenRunUri : $_ - see github.com/openrundev/openrun/releases for all versions"
      Exit 1
    }
    Invoke-WebRequest $ChecksumUri -OutFile $ChecksumFile -UseBasicParsing
  } finally {
    $ProgressPreference = $prevProgressPreference
  }

  # Verify the download against the published checksums
  $ChecksumLine = Select-String -Path $ChecksumFile -Pattern $ZipName -SimpleMatch | Select-Object -First 1
  if (!$ChecksumLine) {
    Write-Error "No checksum found for $ZipName in $ChecksumUri"
    Exit 1
  }
  $ExpectedHash = ($ChecksumLine.Line.Trim() -split '\s+')[0]
  $ActualHash = (Get-FileHash $OpenRunZip -Algorithm SHA256).Hash
  if ($ActualHash -ine $ExpectedHash) {
    Write-Error "Checksum mismatch for ${ZipName}: expected $ExpectedHash, got $ActualHash"
    Exit 1
  }

  if (Get-Command Expand-Archive -ErrorAction SilentlyContinue) {
    Expand-Archive $OpenRunZip -Destination $TmpDir -Force
  } else {
    Add-Type -AssemblyName System.IO.Compression.FileSystem
    [IO.Compression.ZipFile]::ExtractToDirectory($OpenRunZip, $TmpDir)
  }

  try {
    Move-Item -Path (Join-Path $TmpDir "openrun-$Version-windows-amd64\openrun.exe") -Destination "$OpenRunExe" -Force
  } catch {
    Write-Output "Error - File move to $OpenRunExe failed: $_"
    Write-Output "Stop openrun server if it is running"
    Exit 1
  }
} finally {
  Remove-Item $TmpDir -Recurse -Force -ErrorAction SilentlyContinue
}

# Add BinDir to the user PATH. Read and write the raw registry value so that
# unexpanded %VAR% references in existing PATH entries are preserved
# ([Environment]::SetEnvironmentVariable would store them expanded)
$RegKey = [Microsoft.Win32.Registry]::CurrentUser.OpenSubKey('Environment', $true)
try {
  $RawPath = [string]$RegKey.GetValue('Path', '', [Microsoft.Win32.RegistryValueOptions]::DoNotExpandEnvironmentNames)
  $PathEntries = @($RawPath -split ';' | Where-Object { $_ })
  if ($PathEntries -notcontains $BinDir) {
    $RegKey.SetValue('Path', (($PathEntries + $BinDir) -join ';'), [Microsoft.Win32.RegistryValueKind]::ExpandString)
  }
} finally {
  $RegKey.Close()
}
if (@($Env:Path -split ';') -notcontains $BinDir) {
  $Env:Path += ";$BinDir"
}

# Setting OPENRUN_HOME also broadcasts the environment change to the system
[Environment]::SetEnvironmentVariable('OPENRUN_HOME', "$OpenRunInstall", [EnvironmentVariableTarget]::User)
$Env:OPENRUN_HOME = "$OpenRunInstall"

# Create the password config file entry if not already present
if (Test-Path -Path $OpenRunConfig -PathType Leaf) {
  Write-Output "Config file $OpenRunConfig already exists, not generating password"
} else {
  & "$OpenRunExe" "password" | Out-File -FilePath "$OpenRunConfig" -Encoding utf8
  Write-Output ""
  Write-Output "Password config has been setup, save the above password, username:admin"
}


Write-Output "openrun $Version was installed successfully to $OpenRunExe."
Write-Output "Open new command shell and run 'openrun' to get started."
Write-Output "See https://openrun.dev/docs/quickstart/ for quick start guide."
