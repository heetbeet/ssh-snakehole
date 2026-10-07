param([Parameter(ValueFromRemainingArguments=$true)][string[]]$Command)
$ErrorActionPreference = 'Stop'
$Python = $null
foreach ($Name in 'py','python','python3') {
    $Candidate = Get-Command $Name -ErrorAction SilentlyContinue
    if (!$Candidate) { continue }
    if ($Candidate.Source -match '\\Microsoft\\WindowsApps\\') { continue }
    $Prefix = @(); if ($Name -eq 'py') { $Prefix = @('-3') }
    & $Candidate.Source @Prefix -c 'import sys;sys.exit(not (sys.implementation.name==''cpython'' and (3,12,14)<=sys.version_info[:3]<(3,15,0)))' 2>$null
    if ($LASTEXITCODE -eq 0) { $Python = $Candidate.Source; break }
}
if (!$Python) { throw 'Install CPython 3.12.14 or newer (through 3.14), then run this command again.' }
$Target = Join-Path ([IO.Path]::GetTempPath()) ('ssh-snakehole-' + [Guid]::NewGuid().ToString('N') + '.pyz')
Invoke-WebRequest 'https://github.com/heetbeet/ssh-snakehole/releases/latest/download/ssh-snakehole.pyz' -OutFile $Target -UseBasicParsing
if (!$Command) { $Command = @('open') }
& $Python @Prefix $Target @Command
if ($LASTEXITCODE -ne 0) { throw "ssh-snakehole exited with $LASTEXITCODE" }
