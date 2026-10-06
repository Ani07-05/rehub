$ErrorActionPreference = "Stop"

$Repo = if ($env:REHUB_REPO) { $env:REHUB_REPO } else { "https://github.com/Ani07-05/rehub.git" }
$Src = if ($env:REHUB_SRC) { $env:REHUB_SRC } else { Join-Path $HOME ".rehub\src" }
$Bin = if ($env:REHUB_BIN) { $env:REHUB_BIN } else { Join-Path $HOME ".local\bin" }
$Ref = $env:REHUB_REF

function Say($msg) { Write-Host "==> $msg" -ForegroundColor Cyan }
function Die($msg) { Write-Host "error: $msg" -ForegroundColor Red; exit 1 }
function Need($exit) { if ($exit -ne 0) { Die "a step failed (exit $exit)" } }

if (-not (Get-Command git -ErrorAction SilentlyContinue)) { Die "git is required" }
if (-not (Get-Command docker -ErrorAction SilentlyContinue)) { Die "Docker is required. Install Docker Desktop, start it, then run this again." }
docker info *> $null
if ($LASTEXITCODE -ne 0) { Die "Docker is installed but not running. Start Docker Desktop, then run this again." }

if (-not (Get-Command uv -ErrorAction SilentlyContinue)) {
    Say "Installing uv"
    powershell -ExecutionPolicy ByPass -c "irm https://astral.sh/uv/install.ps1 | iex"
    $env:Path = "$HOME\.local\bin;$HOME\.cargo\bin;$env:Path"
    if (-not (Get-Command uv -ErrorAction SilentlyContinue)) { Die "uv installed but not on PATH; open a new terminal and run this again" }
}

if (Test-Path (Join-Path $Src ".git")) {
    Say "Updating $Src"
    if ($Ref) {
        git -C $Src fetch --tags origin; Need $LASTEXITCODE
        git -C $Src checkout $Ref; Need $LASTEXITCODE
    } else {
        git -C $Src pull --ff-only; Need $LASTEXITCODE
    }
} else {
    Say "Cloning rehub to $Src"
    New-Item -ItemType Directory -Force -Path (Split-Path $Src) | Out-Null
    if ($Ref) {
        git clone $Repo $Src; Need $LASTEXITCODE
        git -C $Src checkout $Ref; Need $LASTEXITCODE
    } else {
        git clone --depth 1 $Repo $Src; Need $LASTEXITCODE
    }
}

Say "Installing rehub"
Push-Location $Src
uv sync --frozen; Need $LASTEXITCODE
Pop-Location

New-Item -ItemType Directory -Force -Path $Bin | Out-Null
Set-Content -Path (Join-Path $Bin "rehub.cmd") -Encoding ascii -Value "@echo off`r`nuv run --frozen --project `"$Src`" rehub %*"
$env:Path = "$Bin;$env:Path"

Say "Creating ~/.rehub"
rehub init

Say "Getting the tool image (a local build can take several minutes)"
rehub setup; Need $LASTEXITCODE

Say "Checking the tools behave as pinned"
rehub doctor; Need $LASTEXITCODE

$userPath = [Environment]::GetEnvironmentVariable("Path", "User")
if (($userPath -split ";") -notcontains $Bin) {
    Write-Host "`nAdd $Bin to your PATH to use `"rehub`" from any terminal."
}

Say "Opening the interface (Ctrl+C to stop)"
rehub web --open
