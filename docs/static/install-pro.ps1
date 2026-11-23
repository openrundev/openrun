#!/usr/bin/env pwsh

# Copyright (c) ClaceIO, LLC
# SPDX-License-Identifier: Apache-2.0

$ErrorActionPreference = 'Stop'

# Installs an OpenRun Pro release. install.ps1 installs the Tip releases.
#
# The version to install can be set with $v before invoking this script, or
# passed as the first argument when running a downloaded copy:
#   (not set)   highest Pro release across all maintenance lines
#   1.3         latest patch release of the Pro 1.3 line
#   v1.3.2      that exact Pro release, the leading v is optional
#
# Pro versions are vMAJOR.MINOR.PATCH. Their release assets are named
# openrun-pro, the installed binary is openrun.
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

$Version = $Version -replace '^v', ''
if ($Version -match '^\d+\.\d+\.\d+$') {
  $Version = "v$Version"
} elseif ($Version -eq "latest" -or $Version -match '^\d+\.\d+$') {
  # Pro releases are found by their openrun-pro asset and ordered by version,
  # since the release dates of two maintenance lines interleave. Every page
  # has to be read for that, a failed request fails the lookup
  $ProLine = if ($Version -eq "latest") { "" } else { $Version }
  $ProVersions = @()
  $Complete = $false
  try {
    for ($Page = 1; $Page -le 20; $Page++) {
      # Assigned directly: Invoke-RestMethod writes a JSON array to the
      # pipeline as one object, so @(Invoke-RestMethod ...) has a count of 1
      # even for an empty page
      $Releases = Invoke-RestMethod "https://api.github.com/repos/openrundev/openrun/releases?per_page=100&page=$Page" -UseBasicParsing
      $Releases = @($Releases | Where-Object { $_ -and $_.tag_name })
      # The page after the last one is an empty list
      if ($Releases.Count -eq 0) {
        $Complete = $true
        break
      }
      foreach ($Release in $Releases) {
        foreach ($Asset in $Release.assets) {
          if ($Asset.name -match '^openrun-pro-v(\d+\.\d+\.\d+)-windows-amd64\.zip$') {
            $ProVersions += $Matches[1]
          }
        }
      }
    }
  } catch {
    Write-Error "Unable to list openrun releases: $_ - see github.com/openrundev/openrun/releases for all versions"
    Exit 1
  }
  if (!$Complete) {
    Write-Error "Unable to list openrun releases: more than 20 pages - see github.com/openrundev/openrun/releases for all versions"
    Exit 1
  }
  if ($ProLine) {
    $ProVersions = @($ProVersions | Where-Object { $_.StartsWith("$ProLine.") })
  }
  if ($ProVersions.Count -eq 0) {
    Write-Error "No Pro release found - see github.com/openrundev/openrun/releases for all versions"
    Exit 1
  }
  $Version = "v" + ($ProVersions | Sort-Object { [version]$_ } | Select-Object -Last 1)
} else {
  Write-Error "Invalid version '$Version', pass a Pro line like 1.3 or a version like v1.3.2"
  Exit 1
}

$ZipName = "openrun-pro-$Version-windows-amd64.zip"
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
      Write-Output "Downloading openrun pro $Version..."
      $ProgressPreference = "SilentlyContinue"
    }

    try {
      Invoke-WebRequest $OpenRunUri -OutFile $OpenRunZip -UseBasicParsing
    } catch {
      Write-Error "Unable to download openrun pro $Version from $OpenRunUri : $_ - see github.com/openrundev/openrun/releases for all versions"
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
    Move-Item -Path (Join-Path $TmpDir "openrun-pro-$Version-windows-amd64\openrun.exe") -Destination "$OpenRunExe" -Force
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


Write-Output "openrun pro $Version was installed successfully to $OpenRunExe."
Write-Output "Open new command shell and run 'openrun' to get started."
Write-Output "See https://openrun.dev/docs/quickstart/ for quick start guide."
