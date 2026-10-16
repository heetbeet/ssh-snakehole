# Run in a normal, non-administrator PowerShell window.
$ErrorActionPreference = 'Stop'
$uv = Join-Path $env:TEMP 'ssh-snakehole-uv\uv.exe'

if (!(Test-Path -LiteralPath $uv -PathType Leaf)) {
    $env:UV_UNMANAGED_INSTALL = Split-Path $uv
    Invoke-RestMethod https://astral.sh/uv/install.ps1 | Invoke-Expression
    if (!(Test-Path -LiteralPath $uv -PathType Leaf)) {
        throw 'uv installation failed.'
    }
}

& $uv run --no-project --refresh `
    --python 'cpython>=3.11,<3.15' `
    --with https://github.com/heetbeet/ssh-snakehole/archive/master.zip `
    python -I -m ssh_snakehole open
exit $LASTEXITCODE
