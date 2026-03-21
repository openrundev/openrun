#!/usr/bin/env pwsh

# Copyright (c) ClaceIO, LLC
# SPDX-License-Identifier: Apache-2.0

$ErrorActionPreference = 'Stop'

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
$OpenRunZip = "$BinDir\openrun.zip"
$OpenRunExe = "$BinDir\openrun.exe"
$OpenRunConfig = "$OpenRunInstall\openrun.toml"
$OpenRunUri = "https://github.com/openrundev/openrun/releases/download/$Version/openrun-$Version-windows-amd64.zip"

# GitHub require TLS 1.2
[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12

if ( $Version -eq "latest") {
  try {
    $Response = Invoke-WebRequest "https://api.github.com/repos/openrundev/openrun/releases/$Version"
    $jsonResponse = $Response.Content | ConvertFrom-Json
    $Version = $jsonResponse.tag_name
    $OpenRunUri = "https://github.com/openrundev/openrun/releases/download/$Version/openrun-$Version-windows-amd64.zip"
  }
  catch {
    $StatusCode = $_.Exception.Response.StatusCode.value__
    if ($StatusCode -eq 404) {
      Write-Error "Unable to find a openrun release on GitHub for version:$Version - see github.com/openrundev/openrun/releases for all versions"
    } else {
      $Request = $_.Exception
      Write-Error "Error while fetching releases: $Request"
    }
    Exit 1
  }
}

if (!(Test-Path $BinDir)) {
  New-Item $BinDir -ItemType Directory | Out-Null
}

$prevProgressPreference = $ProgressPreference
try {
  # Avoid perf issues with progress bar
  if ($PSVersionTable.PSVersion.Major -lt 7) {
    Write-Output "Downloading openrun..."
    $ProgressPreference = "SilentlyContinue"
  }

  Invoke-WebRequest $OpenRunUri -OutFile $OpenRunZip -UseBasicParsing
} finally {
  $ProgressPreference = $prevProgressPreference
}

if (Get-Command Expand-Archive -ErrorAction SilentlyContinue) {
  Expand-Archive $OpenRunZip -Destination $OpenRunInstall -Force
} else {
  Add-Type -AssemblyName System.IO.Compression.FileSystem
  [IO.Compression.ZipFile]::ExtractToDirectory($OpenRunZip, $OpenRunInstall)
}

try {
  Move-Item -Path "$OpenRunInstall\openrun-$Version-windows-amd64\openrun.exe" -Destination "$OpenRunExe" -Force
} catch {
  Write-Output "Error - File move to $OpenRunExe failed: $_"
  Write-Output "Stop openrun server if it is running"
  Exit 1
}
Remove-Item $OpenRunZip

$User = [EnvironmentVariableTarget]::User
$Path = [Environment]::GetEnvironmentVariable('Path', $User)
if (!(";$Path;".ToLower() -like "*;$BinDir;*".ToLower())) {
  [Environment]::SetEnvironmentVariable('Path', "$Path;$BinDir", $User)
  $Env:Path += ";$BinDir"
}

[Environment]::SetEnvironmentVariable('OPENRUN_HOME', "$OpenRunInstall", $User)
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

