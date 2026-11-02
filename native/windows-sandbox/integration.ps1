param(
    [Parameter(Mandatory = $true)][string]$Helper,
    [string]$Bash = 'C:\Program Files\Git\bin\bash.exe',
    [string]$Pwsh = (Get-Command pwsh.exe -ErrorAction Stop).Source
)
$ErrorActionPreference = 'Stop'
$root = Join-Path $env:TEMP ('opencode-windows-sandbox-test-' + [guid]::NewGuid().ToString('N'))
$workspace = Join-Path $root 'workspace'
$outside = Join-Path $root 'outside'
$scratch = Join-Path $workspace 'scratch-base'
$results = [System.Collections.Generic.List[string]]::new()

function Assert-True([bool]$Condition, [string]$Message) {
    if (-not $Condition) { throw $Message }
}

function New-Policy([string]$Profile = 'workspace') {
    return @{
        version = 1
        profile = $Profile
        cwd = $workspace
        scratch = $scratch
        readRoots = @($workspace)
        writeRoots = @($workspace)
        denyRead = @((Join-Path $workspace 'secret'))
        denyWrite = @((Join-Path $workspace 'frozen'), (Join-Path $workspace 'payload.exe'))
        network = $false
    }
}

function Start-Sandbox([string]$Shell, [string[]]$Arguments, [hashtable]$Policy, [hashtable]$ExtraEnvironment = @{}) {
    $info = [Diagnostics.ProcessStartInfo]::new($Helper)
    $info.UseShellExecute = $false
    $info.CreateNoWindow = $true
    $info.RedirectStandardOutput = $true
    $info.RedirectStandardError = $true
    foreach ($argument in $Arguments) { $info.ArgumentList.Add($argument) }
    $info.Environment['OPENCODE_REAL_SHELL'] = $Shell
    $info.Environment['OPENCODE_WINDOWS_SANDBOX_POLICY'] = ConvertTo-Json -InputObject $Policy -Compress -Depth 5
    $info.Environment['INTEGRATION_SECRET_CANARY'] = 'not-a-real-secret'
    $info.Environment['TOTALLY_CUSTOM_CANARY'] = 'not-a-real-secret-either'
    foreach ($entry in $ExtraEnvironment.GetEnumerator()) { $info.Environment[$entry.Key] = $entry.Value }
    $process = [Diagnostics.Process]::Start($info)
    return $process
}

function Complete-Sandbox($Process, [int]$Expected = 0) {
    $shell = $Process.StartInfo.Environment['OPENCODE_REAL_SHELL']
    $stdoutTask = $Process.StandardOutput.ReadToEndAsync()
    $stderrTask = $Process.StandardError.ReadToEndAsync()
    if (-not $Process.WaitForExit(60000)) {
        $Process.Kill()
        throw "Shell $shell fixture timed out"
    }
    $stdout = $stdoutTask.GetAwaiter().GetResult()
    $stderr = $stderrTask.GetAwaiter().GetResult()
    Assert-True ($Process.ExitCode -eq $Expected) "Shell $shell expected exit $Expected, got $($Process.ExitCode): $stderr $stdout"
    return @{ stdout = $stdout; stderr = $stderr }
}

try {
    foreach ($directory in @($workspace, $outside, $scratch, (Join-Path $workspace 'secret'), (Join-Path $workspace 'frozen'))) {
        New-Item -ItemType Directory -Path $directory -Force | Out-Null
    }
    Set-Content (Join-Path $workspace 'allowed.txt') 'original'
    Set-Content (Join-Path $workspace 'secret\secret.txt') 'fixture secret'
    Set-Content (Join-Path $workspace 'frozen\frozen.txt') 'frozen'
    Set-Content (Join-Path $outside 'outside.txt') 'outside'
    $payload = Join-Path $workspace 'payload.exe'
    & rustc --edition 2024 -O -o $payload (Join-Path $PSScriptRoot 'tests\payload.rs')
    Assert-True ($LASTEXITCODE -eq 0) 'Cannot compile the native integration payload'
    $originalAcl = (Get-Acl $workspace).Sddl
    $probe = & $Helper --probe | ConvertFrom-Json
    Assert-True ($probe.available -eq $true) "LPAC probe unavailable: $($probe.reason)"

    $ipv4 = [Net.Sockets.TcpListener]::new([Net.IPAddress]::Loopback, 0)
    $ipv6 = [Net.Sockets.TcpListener]::new([Net.IPAddress]::IPv6Loopback, 0)
    $ipv4.Start()
    $ipv6.Start()
    $endpoints = @("127.0.0.1:$($ipv4.LocalEndpoint.Port)", "[::1]:$($ipv6.LocalEndpoint.Port)", '1.1.1.1:443', '[2606:4700:4700::1111]:443')
    try {
        $check = Complete-Sandbox (Start-Sandbox $payload (@('check', $workspace, $outside) + $endpoints) (New-Policy))
        Write-Output $check.stdout
        $results.Add('workspace/denyRead/denyWrite/external reads+writes/environment/IPv4+IPv6 network-off')
        $readonly = Complete-Sandbox (Start-Sandbox $payload @('readonly', $workspace, $outside) (New-Policy 'ro'))
        Write-Output $readonly.stdout
        $results.Add('readonly with scratch inside readonly workspace')
    } finally {
        $ipv4.Stop()
        $ipv6.Stop()
    }

    foreach ($shellCase in @(
        @{ shell = (Join-Path $env:SystemRoot 'System32\cmd.exe'); script = 'echo output-ok & echo error-ok 1>&2 & exit /b 37' },
        @{ shell = $Pwsh; script = '[Console]::Out.WriteLine("output-ok"); [Console]::Error.WriteLine("error-ok"); exit 37' }
    )) {
        Write-Output "CHECK shell $($shellCase.shell)"
        $output = Complete-Sandbox (Start-Sandbox $shellCase.shell @('-c', $shellCase.script) (New-Policy)) 37
        Assert-True ($output.stdout.Contains('output-ok') -and $output.stderr.Contains('error-ok')) 'Shell stdout/stderr forwarding failed'
        $results.Add("generic -c argv/output/exit: $($shellCase.shell)")
    }

    $unsupported = Complete-Sandbox (Start-Sandbox $Bash @('-c', 'echo must-not-execute') (New-Policy)) 125
    Assert-True ($unsupported.stderr.Contains('MSYS/Cygwin shells')) 'Git Bash did not return an explicit compatibility refusal'
    Assert-True (-not $unsupported.stdout.Contains('must-not-execute')) 'Unsupported shell payload executed'
    $results.Add('Git Bash fails closed without global named-object permissions')

    $legacy = Join-Path $env:SystemRoot 'System32\WindowsPowerShell\v1.0\powershell.exe'
    $unsupported = Complete-Sandbox (Start-Sandbox $legacy @('-Command', 'Write-Output must-not-execute') (New-Policy)) 125
    Assert-True ($unsupported.stderr.Contains('Windows PowerShell 5.1')) 'Legacy PowerShell did not return an explicit compatibility refusal'
    Assert-True (-not $unsupported.stdout.Contains('must-not-execute')) 'Unsupported legacy shell payload executed'
    $results.Add('Windows PowerShell 5.1 fails closed instead of hanging during startup')

    Write-Output 'CHECK concurrent SID grants'
    $first = Start-Sandbox $payload @('concurrent-write', $workspace, 'first-call.txt', '2000') (New-Policy)
    $firstReady = $first.StandardOutput.ReadLineAsync().WaitAsync([TimeSpan]::FromSeconds(30)).GetAwaiter().GetResult()
    Assert-True ($firstReady -eq 'READY') 'First concurrent call did not start'
    $second = Start-Sandbox $payload @('concurrent-write', $workspace, 'second-call.txt', '4000') (New-Policy)
    $secondReady = $second.StandardOutput.ReadLineAsync().WaitAsync([TimeSpan]::FromSeconds(30)).GetAwaiter().GetResult()
    Assert-True ($secondReady -eq 'READY') 'Second concurrent call did not start'
    Assert-True (-not $first.HasExited) 'Concurrent fixtures did not overlap'
    $null = Complete-Sandbox $first
    $null = Complete-Sandbox $second
    Assert-True ((Get-Content (Join-Path $workspace 'first-call.txt') -Raw) -eq 'concurrent') 'First concurrent write failed'
    Assert-True ((Get-Content (Join-Path $workspace 'second-call.txt') -Raw) -eq 'concurrent') 'Cleanup revoked another live call'
    $results.Add('concurrent calls retain independent SID grants during cleanup')

    Write-Output 'CHECK normal descendant termination'
    $completed = Complete-Sandbox (Start-Sandbox $payload @('descendant', $workspace) (New-Policy))
    Start-Sleep -Milliseconds 2300
    Assert-True (-not (Test-Path (Join-Path $workspace 'escaped-child.txt'))) 'Grandchild survived normal shell completion'
    $results.Add('Job tree killed after normal completion')

    Write-Output 'CHECK launcher termination'
    $cancelled = Start-Sandbox $payload @('wait-descendant', $workspace) (New-Policy)
    $line = $cancelled.StandardOutput.ReadLineAsync().WaitAsync([TimeSpan]::FromSeconds(30)).GetAwaiter().GetResult()
    Assert-True ($line -match '^CHILD \d+$') 'Child did not start before cancellation'
    $cancelled.Kill()
    $cancelled.WaitForExit()
    $cleanupOutput = $cancelled.StandardError.ReadToEndAsync().WaitAsync([TimeSpan]::FromSeconds(30)).GetAwaiter().GetResult()
    Start-Sleep -Milliseconds 2300
    Assert-True (-not (Test-Path (Join-Path $workspace 'escaped-child.txt'))) 'Grandchild survived launcher termination'
    $results.Add('launcher termination triggers worker cleanup and Job kill')

    Write-Output 'CHECK partial control frame cancellation'
    $pipeName = 'opencode-security-' + [guid]::NewGuid().ToString('N')
    $token = [guid]::NewGuid().ToString('N') + [guid]::NewGuid().ToString('N')
    $pipe = [IO.Pipes.NamedPipeServerStream]::new($pipeName, [IO.Pipes.PipeDirection]::InOut, 1,
        [IO.Pipes.PipeTransmissionMode]::Byte, [IO.Pipes.PipeOptions]::Asynchronous)
    try {
        $connection = $pipe.WaitForConnectionAsync()
        $controlled = Start-Sandbox $payload @('wait-descendant', $workspace) (New-Policy) @{
            OPENCODE_WINDOWS_CONTROL_PIPE = "\\.\pipe\$pipeName"
            OPENCODE_WINDOWS_CONTROL_TOKEN = $token
        }
        $null = $connection.WaitAsync([TimeSpan]::FromSeconds(30)).GetAwaiter().GetResult()
        $reader = [IO.StreamReader]::new($pipe)
        $ready = $reader.ReadLineAsync().WaitAsync([TimeSpan]::FromSeconds(30)).GetAwaiter().GetResult() | ConvertFrom-Json
        Assert-True ($ready.type -eq 'ready' -and $ready.token -eq $token) 'Control authentication mismatch'
        $line = $controlled.StandardOutput.ReadLineAsync().WaitAsync([TimeSpan]::FromSeconds(30)).GetAwaiter().GetResult()
        Assert-True ($line -match '^CHILD \d+$') 'Controlled child did not start'
        $pipe.WriteByte([byte][char]'{') # A partial control frame must cancel immediately.
        $pipe.Flush()
        # Keep the duplex pipe drained while waiting for the sender to exit.
        $exitTask = $reader.ReadLineAsync()
        $null = Complete-Sandbox $controlled 125
        $exitFrame = $exitTask.WaitAsync([TimeSpan]::FromSeconds(30)).GetAwaiter().GetResult() | ConvertFrom-Json
        Assert-True ($exitFrame.type -eq 'exit' -and $exitFrame.token -eq $token) 'Missing authenticated exit frame'
        $results.Add('authenticated control pipe; partial frame cancels tree')
    } finally {
        $pipe.Dispose()
    }

    Write-Output 'CHECK final ACL and scratch restoration'
    Assert-True ((Get-Acl $workspace).Sddl -eq $originalAcl) 'Workspace ACL was not restored'
    $remainingSids = Get-ChildItem $workspace -Force -Recurse | ForEach-Object {
        (Get-Acl -LiteralPath $_.FullName).Access | Where-Object {
            $_.IdentityReference.Value -like 'S-1-15-2-*' -or $_.IdentityReference.Value -like 'S-1-9-*'
        }
    }
    Assert-True (@($remainingSids).Count -eq 0) 'Per-call SID ACEs remain in the fixture'
    Assert-True ((Get-Content (Join-Path $outside 'outside.txt') -Raw).Trim() -eq 'outside') 'Outside fixture data changed'
    Assert-True ((Get-ChildItem $scratch -Force).Count -eq 0) 'Private scratch was not removed'
    $results.Add('original ACL/data preservation; newly-created ACL and scratch cleanup')
    $results | ForEach-Object { Write-Output "PASS $_" }
} finally {
    if (Test-Path $root) { Remove-Item -LiteralPath $root -Recurse -Force }
}
