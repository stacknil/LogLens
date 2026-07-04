param(
    [int[]]$LineCounts = @(1000, 10000, 100000),
    [int]$Runs = 5,
    [int]$WarmupRuns = 1,
    [string]$BuildDir = "build",
    [string]$Configuration = "Release",
    [string]$OutputRoot = "build/performance-envelope",
    [switch]$SkipBuild
)

$ErrorActionPreference = "Stop"

$scriptRoot = Split-Path -Parent $MyInvocation.MyCommand.Path
$repoRoot = Split-Path -Parent $scriptRoot
$buildRoot = Join-Path $repoRoot $BuildDir
$benchmarkRoot = Join-Path $repoRoot $OutputRoot
$inputRoot = Join-Path $benchmarkRoot "inputs"
$runRoot = Join-Path $benchmarkRoot "runs"

function Resolve-LogLensExecutable {
    $candidateNames = if ($IsWindows -or $env:OS -eq "Windows_NT") {
        @("loglens.exe", "loglens")
    } else {
        @("loglens", "loglens.exe")
    }

    $candidateDirs = @(
        (Join-Path $buildRoot $Configuration),
        $buildRoot
    )

    foreach ($directory in $candidateDirs) {
        foreach ($name in $candidateNames) {
            $candidate = Join-Path $directory $name
            if (Test-Path -LiteralPath $candidate) {
                return (Resolve-Path -LiteralPath $candidate).Path
            }
        }
    }

    throw "Unable to find a LogLens executable under '$buildRoot'. Build first or pass -BuildDir/-Configuration."
}

function New-BenchmarkInput {
    param(
        [int]$LineCount,
        [string]$Path
    )

    $start = [DateTime]::new(2026, 3, 10, 0, 0, 0, [DateTimeKind]::Unspecified)
    $writer = [System.IO.StreamWriter]::new($Path, $false, [System.Text.UTF8Encoding]::new($false))

    try {
        for ($index = 0; $index -lt $LineCount; ++$index) {
            $timestamp = $start.AddSeconds($index)
            $month = $timestamp.ToString("MMM", [Globalization.CultureInfo]::InvariantCulture)
            $day = $timestamp.Day
            $time = $timestamp.ToString("HH:mm:ss", [Globalization.CultureInfo]::InvariantCulture)
            $hostname = "bench-host-{0:D2}" -f (($index % 4) + 1)
            $processIdValue = 5000 + ($index % 1000)
            $octet = 1 + ($index % 200)
            $port = 40000 + ($index % 20000)
            $user = "user{0:D3}" -f ($index % 250)

            switch ($index % 8) {
                0 {
                    $line = "{0} {1,2} {2} {3} sshd[{4}]: Failed password for {5} from 203.0.113.{6} port {7} ssh2" -f $month, $day, $time, $hostname, $processIdValue, $user, $octet, $port
                }
                1 {
                    $line = "{0} {1,2} {2} {3} sshd[{4}]: Accepted publickey for {5} from 203.0.113.{6} port {7} ssh2: ED25519 SHA256:SANITIZEDKEY" -f $month, $day, $time, $hostname, $processIdValue, $user, $octet, $port
                }
                2 {
                    $line = "{0} {1,2} {2} {3} sudo[{4}]:    {5} : TTY=pts/0 ; PWD=/home/{5} ; USER=root ; COMMAND=/usr/bin/id" -f $month, $day, $time, $hostname, $processIdValue, $user
                }
                3 {
                    $line = "{0} {1,2} {2} {3} pam_unix(sshd:auth): authentication failure; user={4} euid=0 tty=ssh rhost=203.0.113.{5}" -f $month, $day, $time, $hostname, $user, $octet
                }
                4 {
                    $line = "{0} {1,2} {2} {3} sshd[{4}]: Connection closed by authenticating user {5} 203.0.113.{6} port {7} [preauth]" -f $month, $day, $time, $hostname, $processIdValue, $user, $octet, $port
                }
                5 {
                    $line = "{0} {1,2} {2} {3} sshd[{4}]: Timeout, client not responding from 203.0.113.{5} port {6}" -f $month, $day, $time, $hostname, $processIdValue, $octet, $port
                }
                6 {
                    $line = "{0} {1,2} {2} {3} pam_unix(sudo:session): session opened for user root by {4}(uid=1000)" -f $month, $day, $time, $hostname, $user
                }
                default {
                    $line = "{0} {1,2} {2} {3} su[{4}]: FAILED SU (to root) {5} on pts/1" -f $month, $day, $time, $hostname, $processIdValue, $user
                }
            }

            $writer.WriteLine($line)
        }
    } finally {
        $writer.Dispose()
    }
}

function Get-PlatformInfo {
    $runtime = [System.Runtime.InteropServices.RuntimeInformation]
    $platform = [ordered]@{
        os = $runtime::OSDescription
        architecture = $runtime::OSArchitecture.ToString()
        shell = "PowerShell $($PSVersionTable.PSVersion)"
    }

    if (Get-Command Get-CimInstance -ErrorAction SilentlyContinue) {
        try {
            $os = Get-CimInstance Win32_OperatingSystem
            $cpu = Get-CimInstance Win32_Processor | Select-Object -First 1
            $system = Get-CimInstance Win32_ComputerSystem
            $platform.os = "$($os.Caption), version $($os.Version), build $($os.BuildNumber)"
            $platform.cpu = $cpu.Name.Trim()
            $platform.logical_processors = $cpu.NumberOfLogicalProcessors
            $platform.ram_gb = [Math]::Round($system.TotalPhysicalMemory / 1GB, 1)
        } catch {
            $platform.cim_warning = $_.Exception.Message
        }
    }

    [pscustomobject]$platform
}

function Invoke-LogLensBenchmarkRun {
    param(
        [string]$Executable,
        [int]$LineCount,
        [int]$RunNumber,
        [bool]$Warmup
    )

    $inputPath = Join-Path $inputRoot "auth_$LineCount.log"
    $runName = if ($Warmup) { "${LineCount}_warmup_${RunNumber}" } else { "${LineCount}_run_${RunNumber}" }
    $outputDirectory = Join-Path $runRoot $runName
    $stdoutPath = Join-Path $runRoot "$runName.stdout.txt"
    $stderrPath = Join-Path $runRoot "$runName.stderr.txt"

    Remove-Item -LiteralPath $outputDirectory -Recurse -Force -ErrorAction SilentlyContinue

    $processInfo = [System.Diagnostics.ProcessStartInfo]::new()
    $processInfo.FileName = $Executable
    foreach ($argument in @("--mode", "syslog", "--year", "2026", $inputPath, $outputDirectory)) {
        [void]$processInfo.ArgumentList.Add($argument)
    }
    $processInfo.WorkingDirectory = $repoRoot
    $processInfo.UseShellExecute = $false
    $processInfo.RedirectStandardOutput = $true
    $processInfo.RedirectStandardError = $true
    $processInfo.CreateNoWindow = $true

    $process = [System.Diagnostics.Process]::new()
    $process.StartInfo = $processInfo
    $timer = [System.Diagnostics.Stopwatch]::StartNew()

    [void]$process.Start()
    $maxWorkingSet = 0L
    while (-not $process.HasExited) {
        try {
            $process.Refresh()
            if ($process.WorkingSet64 -gt $maxWorkingSet) {
                $maxWorkingSet = $process.WorkingSet64
            }
        } catch {
            # The process may exit between HasExited and Refresh.
        }
        Start-Sleep -Milliseconds 1
    }

    $timer.Stop()
    $stdout = $process.StandardOutput.ReadToEnd()
    $stderr = $process.StandardError.ReadToEnd()
    Set-Content -LiteralPath $stdoutPath -Value $stdout -Encoding utf8
    Set-Content -LiteralPath $stderrPath -Value $stderr -Encoding utf8

    try {
        $process.Refresh()
        if ($process.PeakWorkingSet64 -gt $maxWorkingSet) {
            $maxWorkingSet = $process.PeakWorkingSet64
        }
    } catch {
        # PeakWorkingSet64 may not be available on every platform.
    }

    if ($process.ExitCode -ne 0) {
        throw "LogLens benchmark failed for $runName with exit code $($process.ExitCode): $stderr"
    }

    $report = Get-Content -LiteralPath (Join-Path $outputDirectory "report.json") -Raw | ConvertFrom-Json

    [pscustomobject]@{
        lines = $LineCount
        run = $RunNumber
        warmup = $Warmup
        elapsed_ms = [Math]::Round($timer.Elapsed.TotalMilliseconds, 3)
        peak_working_set_mb = [Math]::Round($maxWorkingSet / 1MB, 3)
        parsed_lines = [int]$report.parser_quality.parsed_lines
        parser_warnings = [int]$report.warning_count
        findings = [int]$report.finding_count
    }
}

function Get-Median {
    param([double[]]$Values)

    $ordered = @($Values | Sort-Object)
    if ($ordered.Count -eq 0) {
        return 0
    }

    $middle = [int]($ordered.Count / 2)
    if ($ordered.Count % 2 -eq 1) {
        return $ordered[$middle]
    }

    ($ordered[$middle - 1] + $ordered[$middle]) / 2
}

function New-Summary {
    param([object[]]$MeasuredResults)

    $summary = @()
    foreach ($group in ($MeasuredResults | Group-Object lines | Sort-Object { [int]$_.Name })) {
        $rows = @($group.Group)
        $elapsed = [double[]]@($rows.elapsed_ms)
        $peaks = [double[]]@($rows.peak_working_set_mb)
        $summary += [pscustomobject]@{
            lines = [int]$group.Name
            runs = $rows.Count
            parsed_lines = [int]$rows[0].parsed_lines
            parser_warnings = [int]$rows[0].parser_warnings
            findings = [int]$rows[0].findings
            median_elapsed_ms = [Math]::Round((Get-Median -Values $elapsed), 2)
            min_elapsed_ms = [Math]::Round((($elapsed | Measure-Object -Minimum).Minimum), 2)
            max_elapsed_ms = [Math]::Round((($elapsed | Measure-Object -Maximum).Maximum), 2)
            peak_working_set_mb = [Math]::Round((($peaks | Measure-Object -Maximum).Maximum), 2)
        }
    }

    $summary
}

if (-not $SkipBuild) {
    & cmake --build $buildRoot --config $Configuration
    if ($LASTEXITCODE -ne 0) {
        throw "CMake build failed with exit code $LASTEXITCODE"
    }
}

Remove-Item -LiteralPath $benchmarkRoot -Recurse -Force -ErrorAction SilentlyContinue
New-Item -ItemType Directory -Path $inputRoot, $runRoot | Out-Null

foreach ($lineCount in $LineCounts) {
    New-BenchmarkInput -LineCount $lineCount -Path (Join-Path $inputRoot "auth_$lineCount.log")
}

$executable = Resolve-LogLensExecutable
$allResults = @()

foreach ($lineCount in $LineCounts) {
    for ($warmup = 1; $warmup -le $WarmupRuns; ++$warmup) {
        $allResults += Invoke-LogLensBenchmarkRun -Executable $executable -LineCount $lineCount -RunNumber $warmup -Warmup $true
    }
    for ($run = 1; $run -le $Runs; ++$run) {
        $allResults += Invoke-LogLensBenchmarkRun -Executable $executable -LineCount $lineCount -RunNumber $run -Warmup $false
    }
}

$measuredResults = @($allResults | Where-Object { -not $_.warmup })
$summary = New-Summary -MeasuredResults $measuredResults
$platform = Get-PlatformInfo

$resultDocument = [pscustomobject]@{
    generated_at_utc = (Get-Date).ToUniversalTime().ToString("o")
    executable = (Resolve-Path -LiteralPath $executable).Path
    line_counts = $LineCounts
    measured_runs_per_size = $Runs
    warmup_runs_per_size = $WarmupRuns
    platform = $platform
    summary = $summary
    runs = $allResults
}

$resultDocument | ConvertTo-Json -Depth 6 | Set-Content -LiteralPath (Join-Path $benchmarkRoot "results.json") -Encoding utf8
$summary | ConvertTo-Json -Depth 4 | Set-Content -LiteralPath (Join-Path $benchmarkRoot "summary.json") -Encoding utf8

$summary | Format-Table -AutoSize
Write-Host ""
Write-Host "Wrote benchmark artifacts to $benchmarkRoot"
