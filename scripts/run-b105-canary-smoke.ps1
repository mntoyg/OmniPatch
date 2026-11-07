[CmdletBinding()]
param(
    [switch]$OfflineSelfTest,
    [ValidateSet('module-constant', 'function-local')]
    [string]$Scope = 'module-constant'
)

$ErrorActionPreference = 'Stop'
$script:ExpectedModel = 'qwen-ctx8k:latest'
$script:ExpectedDigest = '03854bfe6a89b784cda7dd3273c649fa747fd695002294cc75d8f647dfbb3cde'
$script:AuditTrialPattern = '^[A-Za-z0-9_-]{1,64}$'

function New-PreflightResult {
    param(
        [Parameter(Mandatory)][string]$Category,
        [string]$TransportCategory = 'not_applicable'
    )
    return [pscustomobject]@{
        category = $Category
        transport_category = $TransportCategory
    }
}

function Get-TransportFailureCategory {
    param([Parameter(Mandatory)][System.Exception]$Exception)

    $cursor = $Exception
    $timedOut = $false
    $transportFailure = $false
    while ($null -ne $cursor) {
        if ($cursor -is [System.TimeoutException] -or
            $cursor -is [System.Threading.Tasks.TaskCanceledException]) {
            $timedOut = $true
        }
        if ($cursor -is [System.Net.Http.HttpRequestException] -or
            $cursor -is [System.Net.WebException] -or
            $cursor -is [System.IO.IOException]) {
            $transportFailure = $true
        }
        if ($cursor -is [System.Net.Sockets.SocketException]) {
            $transportFailure = $true
            if ($cursor.SocketErrorCode -eq [System.Net.Sockets.SocketError]::ConnectionRefused) {
                return 'connection_refused'
            }
            if ($cursor.SocketErrorCode -eq [System.Net.Sockets.SocketError]::TimedOut) {
                $timedOut = $true
            }
        }
        $cursor = $cursor.InnerException
    }
    if ($timedOut) {
        return 'timeout'
    }
    if ($transportFailure) {
        return 'transport_error'
    }
    return 'other_error'
}

function Get-TagsPreflight {
    param(
        [Parameter(Mandatory)][scriptblock]$SendRequest,
        [Parameter(Mandatory)][string]$ExpectedModel,
        [Parameter(Mandatory)][string]$ExpectedDigest
    )

    try {
        $response = & $SendRequest
    } catch {
        return New-PreflightResult 'connection_error' (Get-TransportFailureCategory -Exception $_.Exception)
    }
    if ($null -eq $response -or $response.StatusCode -ne 200) {
        return New-PreflightResult 'http_status'
    }

    try {
        $document = ConvertFrom-Json -InputObject ([string]$response.Body) -AsHashtable -ErrorAction Stop
        if ($document -isnot [System.Collections.IDictionary] -or
            -not $document.Contains('models')) {
            return New-PreflightResult 'invalid_json'
        }
        $models = @($document.models)
        foreach ($item in $models) {
            if ($item -isnot [System.Collections.IDictionary] -or
                -not $item.Contains('name') -or $item.name -isnot [string]) {
                return New-PreflightResult 'invalid_json'
            }
        }
    } catch {
        return New-PreflightResult 'invalid_json'
    }

    $matches = @($models | Where-Object { $_.name -ceq $ExpectedModel })
    if ($matches.Count -eq 0) {
        return New-PreflightResult 'model_missing'
    }
    if ($matches.Count -ne 1 -or $matches[0].digest -isnot [string]) {
        return New-PreflightResult 'invalid_json'
    }
    if ($matches[0].digest -cne $ExpectedDigest) {
        return New-PreflightResult 'digest_mismatch'
    }
    return New-PreflightResult 'passed'
}

function Get-AuditSummary {
    param(
        [Parameter(Mandatory)][bool]$RecordExists,
        [Parameter(Mandatory)][AllowEmptyCollection()][string[]]$JsonLines,
        [Parameter(Mandatory)][string]$TrialId
    )

    if (-not $RecordExists -or $JsonLines.Count -eq 0) {
        return [pscustomobject]@{
            audit_category = 'no_audit_record'
            initial = 'not_observed'
            repair = 'not_observed'
            record_count = 0
        }
    }

    $rows = [System.Collections.Generic.List[object]]::new()
    try {
        foreach ($line in $JsonLines) {
            $record = ConvertFrom-Json -InputObject $line -AsHashtable -ErrorAction Stop
            if ($record -isnot [System.Collections.IDictionary]) {
                throw 'invalid_audit_record'
            }
            $keys = (@($record.Keys | Sort-Object) -join '|')
            $baseKeys = 'outcome|phase|schema_version|surface|trial_id'
            $failureKeys = 'failure_category|outcome|phase|schema_version|surface|trial_id'
            if ($keys -cnotin @($baseKeys, $failureKeys) -or
                $record.schema_version -ne 1 -or
                $record.trial_id -isnot [string] -or $record.trial_id -cne $TrialId -or
                $record.phase -isnot [string] -or
                $record.phase -cnotin @('initial', 'repair', 'not_observed') -or
                $record.surface -isnot [string] -or
                $record.surface -cne 'serialized_ollama_request_body' -or
                $record.outcome -isnot [string] -or
                $record.outcome -cnotin @('pass', 'fail')) {
                throw 'invalid_audit_record'
            }
            $failure = $null
            if ($record.Contains('failure_category')) {
                $failure = [string]$record.failure_category
                if ($failure -cnotin @('canary_match', 'phase_not_observed', 'auditor_error') -or
                    $record.outcome -cne 'fail') {
                    throw 'invalid_audit_record'
                }
            } elseif ($record.outcome -ceq 'fail') {
                throw 'invalid_audit_record'
            }
            $rows.Add([pscustomobject]@{
                phase = [string]$record.phase
                outcome = [string]$record.outcome
            })
        }
    } catch {
        return [pscustomobject]@{
            audit_category = 'audit_failed'
            initial = 'not_observed'
            repair = 'not_observed'
            record_count = $JsonLines.Count
        }
    }

    $initialRows = @($rows | Where-Object { $_.phase -ceq 'initial' })
    $repairRows = @($rows | Where-Object { $_.phase -ceq 'repair' })
    $unobservedRows = @($rows | Where-Object { $_.phase -ceq 'not_observed' })
    if ($initialRows.Count -gt 1 -or $repairRows.Count -gt 1 -or $unobservedRows.Count -gt 0) {
        return [pscustomobject]@{
            audit_category = 'audit_failed'
            initial = 'not_observed'
            repair = 'not_observed'
            record_count = $rows.Count
        }
    }

    $initial = if ($initialRows.Count -eq 1) { $initialRows[0].outcome } else { 'not_observed' }
    $repair = if ($repairRows.Count -eq 1) { $repairRows[0].outcome } else { 'not_observed' }
    if ($initial -ceq 'not_observed') {
        $category = 'initial_not_observed'
    } elseif ($initial -ceq 'fail' -or $repair -ceq 'fail') {
        $category = 'audit_failed'
    } elseif ($repair -ceq 'not_observed') {
        $category = 'audit_incomplete'
    } elseif ($initial -cne 'pass' -or $repair -cne 'pass') {
        $category = 'audit_failed'
    } else {
        $category = 'audit_pass'
    }
    return [pscustomobject]@{
        audit_category = $category
        initial = $initial
        repair = $repair
        record_count = $rows.Count
    }
}

function Invoke-LoopbackTagsRequest {
    $handler = [System.Net.Http.HttpClientHandler]::new()
    $handler.UseProxy = $false
    $handler.Proxy = $null
    $handler.AllowAutoRedirect = $false
    $client = [System.Net.Http.HttpClient]::new($handler)
    $client.Timeout = [TimeSpan]::FromSeconds(25)
    try {
        $response = $client.GetAsync('http://127.0.0.1:11434/api/tags').GetAwaiter().GetResult()
        try {
            $body = $response.Content.ReadAsStringAsync().GetAwaiter().GetResult()
            return [pscustomobject]@{
                StatusCode = [int]$response.StatusCode
                Body = $body
            }
        } finally {
            $response.Dispose()
        }
    } finally {
        $client.Dispose()
        $handler.Dispose()
    }
}

function New-SyntheticTargetDefinition {
    param(
        [Parameter(Mandatory)][ValidateSet('module-constant', 'function-local')][string]$Scope,
        [Parameter(Mandatory)][string]$CanaryValue
    )

    if ($Scope -ceq 'module-constant') {
        return [pscustomobject]@{
            Source = "import os`npassword_value = `"$CanaryValue`"`n"
            MappingKey = 'app.py::<module>'
            MappingValue = 'APP_PASSWORD'
        }
    }
    return [pscustomobject]@{
        Source = "import os`ndef configured_password():`n    password = `"$CanaryValue`"`n    public_label = `"PUBLIC_CONTEXT_CONTROL_REMAINS`"`n    return password, public_label`n"
        MappingKey = 'app.py::configured_password'
        MappingValue = 'APP_PASSWORD'
    }
}

function Test-SyntheticDefinitionHasB105 {
    param([Parameter(Mandatory)]$Definition)

    $tempRoot = [System.IO.Path]::GetFullPath($env:TEMP)
    if (-not (Test-Path -LiteralPath $tempRoot -PathType Container) -or
        -not (Test-OutsideGitRepositories -Path $tempRoot)) {
        throw 'offline_scan_temp_invalid'
    }
    $repoRoot = (Resolve-Path (Join-Path $PSScriptRoot '..')).Path
    $python = Join-Path $repoRoot '.venv\Scripts\python.exe'
    if (-not (Test-Path -LiteralPath $python -PathType Leaf)) {
        throw 'offline_scanner_unavailable'
    }
    $probeRoot = Join-Path $tempRoot ('omnipatch-b105-scope-selftest-' + [guid]::NewGuid().ToString('N'))
    $target = Join-Path $probeRoot 'target'
    New-Item -ItemType Directory -Path $target -Force -ErrorAction Stop | Out-Null
    [IO.File]::WriteAllText((Join-Path $target 'app.py'), [string]$Definition.Source, [Text.UTF8Encoding]::new($false))

    $reportLines = @(& $python -m bandit -q -r $target -f json 2>$null)
    $scannerExitCode = $LASTEXITCODE
    try {
        $report = ConvertFrom-Json -InputObject ($reportLines -join "`n") -AsHashtable -ErrorAction Stop
    } catch {
        throw 'offline_scanner_report_invalid'
    }
    $errors = @($report.errors)
    $findingFound = @($report.results | Where-Object {
        $_.test_id -ceq 'B105' -and [IO.Path]::GetFileName([string]$_.filename) -ceq 'app.py'
    }).Count -gt 0
    if ($errors.Count -ne 0 -or $scannerExitCode -ne 1 -or -not $findingFound) {
        throw 'offline_function_local_b105_missing'
    }
    return [pscustomobject]@{ finding_b105 = $true; scanner_errors_empty = $true }
}

function Protect-RunDirectory {
    param([Parameter(Mandatory)][string]$Path)

    $acl = Get-Acl -LiteralPath $Path
    $acl.SetAccessRuleProtection($true, $false)
    foreach ($rule in @($acl.Access)) {
        $acl.RemoveAccessRuleAll($rule)
    }
    $inheritance = [System.Security.AccessControl.InheritanceFlags]::ContainerInherit -bor
        [System.Security.AccessControl.InheritanceFlags]::ObjectInherit
    $rights = [System.Security.AccessControl.FileSystemRights]::FullControl
    $allow = [System.Security.AccessControl.AccessControlType]::Allow
    $currentSid = [System.Security.Principal.WindowsIdentity]::GetCurrent().User
    $systemSid = [System.Security.Principal.SecurityIdentifier]::new('S-1-5-18')
    $acl.AddAccessRule([System.Security.AccessControl.FileSystemAccessRule]::new(
        $currentSid, $rights, $inheritance,
        [System.Security.AccessControl.PropagationFlags]::None, $allow
    ))
    $acl.AddAccessRule([System.Security.AccessControl.FileSystemAccessRule]::new(
        $systemSid, $rights, $inheritance,
        [System.Security.AccessControl.PropagationFlags]::None, $allow
    ))
    Set-Acl -LiteralPath $Path -AclObject $acl
}

function Test-OutsideGitRepositories {
    param([Parameter(Mandatory)][string]$Path)

    $cursor = [System.IO.DirectoryInfo]::new([System.IO.Path]::GetFullPath($Path))
    while ($null -ne $cursor) {
        if (Test-Path -LiteralPath (Join-Path $cursor.FullName '.git')) {
            return $false
        }
        $cursor = $cursor.Parent
    }
    return $true
}

function New-RunnerStatus {
    param(
        [AllowNull()][Nullable[int]]$CliExitCode,
        [Parameter(Mandatory)][string]$PreflightCategory,
        [Parameter(Mandatory)][string]$PreflightDetail,
        [Parameter(Mandatory)][string]$AuditCategory,
        [Parameter(Mandatory)][string]$Initial,
        [Parameter(Mandatory)][string]$Repair,
        [Parameter(Mandatory)][int]$RecordCount
    )
    return [ordered]@{
        preflight_category = $PreflightCategory
        preflight_detail = $PreflightDetail
        cli_exit_code = $CliExitCode
        audit_category = $AuditCategory
        initial = $Initial
        repair = $Repair
        record_count = $RecordCount
    }
}

function Get-RunnerExitCode {
    param(
        [Parameter(Mandatory)][int]$CliExitCode,
        [Parameter(Mandatory)]$AuditSummary
    )

    if ($CliExitCode -eq 0 -and
        $AuditSummary.audit_category -ceq 'audit_pass' -and
        $AuditSummary.initial -ceq 'pass' -and
        $AuditSummary.repair -ceq 'pass') {
        return 0
    }
    return 1
}

function Invoke-OfflineSelfTest {
    $script:FakeRequestCount = 0
    $goodBody = '{"models":[{"name":"qwen-ctx8k:latest","digest":"03854bfe6a89b784cda7dd3273c649fa747fd695002294cc75d8f647dfbb3cde"}]}'
    $otherBody = '{"models":[{"name":"different-model","digest":"other"}]}'
    $wrongDigestBody = '{"models":[{"name":"qwen-ctx8k:latest","digest":"wrong"}]}'
    $preflight = [ordered]@{}
    $cases = @(
        @{ name = 'connection_error'; sender = { $script:FakeRequestCount++; throw [System.Net.Http.HttpRequestException]::new('synthetic') } },
        @{ name = 'timeout'; sender = { $script:FakeRequestCount++; throw [System.Threading.Tasks.TaskCanceledException]::new() } },
        @{ name = 'connection_refused'; sender = {
                $script:FakeRequestCount++
                $socket = [System.Net.Sockets.SocketException]::new([int][System.Net.Sockets.SocketError]::ConnectionRefused)
                throw [System.Net.Http.HttpRequestException]::new('synthetic', $socket)
            } },
        @{ name = 'transport_error'; sender = { $script:FakeRequestCount++; throw [System.Net.Http.HttpRequestException]::new('synthetic') } },
        @{ name = 'other_error'; sender = { $script:FakeRequestCount++; throw [System.InvalidOperationException]::new('synthetic') } },
        @{ name = 'http_status'; sender = { $script:FakeRequestCount++; [pscustomobject]@{ StatusCode = 503; Body = '' } } },
        @{ name = 'invalid_json'; sender = { $script:FakeRequestCount++; [pscustomobject]@{ StatusCode = 200; Body = '{' } } },
        @{ name = 'model_missing'; sender = { $script:FakeRequestCount++; [pscustomobject]@{ StatusCode = 200; Body = $otherBody } } },
        @{ name = 'digest_mismatch'; sender = { $script:FakeRequestCount++; [pscustomobject]@{ StatusCode = 200; Body = $wrongDigestBody } } },
        @{ name = 'passed'; sender = { $script:FakeRequestCount++; [pscustomobject]@{ StatusCode = 200; Body = $goodBody } } }
    )
    foreach ($case in $cases) {
        $result = Get-TagsPreflight `
            -SendRequest $case.sender `
            -ExpectedModel $script:ExpectedModel `
            -ExpectedDigest $script:ExpectedDigest
        $preflight[$case.name] = $result.category
        if ($result.category -ceq 'connection_error') {
            $preflight["$($case.name)_detail"] = $result.transport_category
        }
    }

    $offlineCanary = 'OMNIPATCH_SYNTHETIC_CANARY_' + [guid]::NewGuid().ToString('N')
    $scopeResults = [ordered]@{}
    foreach ($scopeName in @('module-constant', 'function-local')) {
        $definition = New-SyntheticTargetDefinition -Scope $scopeName -CanaryValue $offlineCanary
        $hasExpectedShape = if ($scopeName -ceq 'module-constant') {
            $definition.Source.Contains('password_value =')
        } else {
            $definition.Source.Contains('def configured_password():') -and
                $definition.Source.Contains('    password =') -and
                $definition.Source.Contains('    return password')
        }
        if (-not $hasExpectedShape -or -not $definition.Source.Contains($offlineCanary)) {
            throw 'offline_scope_definition_failed'
        }
        $scan = Test-SyntheticDefinitionHasB105 -Definition $definition
        $scopeResults[$scopeName] = [pscustomobject]@{
            mapping_key = $definition.MappingKey
            mapping_value = $definition.MappingValue
            canary_embedded = $true
            expected_shape = $true
            baseline_b105 = $scan.finding_b105
            scanner_errors_empty = $scan.scanner_errors_empty
        }
    }

    $trial = 'offline-test-trial'
    $initialPass = '{"schema_version":1,"trial_id":"offline-test-trial","phase":"initial","surface":"serialized_ollama_request_body","outcome":"pass"}'
    $repairPass = '{"schema_version":1,"trial_id":"offline-test-trial","phase":"repair","surface":"serialized_ollama_request_body","outcome":"pass"}'
    $repairOnly = Get-AuditSummary -RecordExists $true -JsonLines @($repairPass) -TrialId $trial
    $noRecord = Get-AuditSummary -RecordExists $false -JsonLines @() -TrialId $trial
    $initialOnly = Get-AuditSummary -RecordExists $true -JsonLines @($initialPass) -TrialId $trial
    $valid = Get-AuditSummary -RecordExists $true -JsonLines @($initialPass, $repairPass) -TrialId $trial
    $wrongTrial = Get-AuditSummary -RecordExists $true -JsonLines @($initialPass.Replace($trial, 'other-trial')) -TrialId $trial
    $wrongSchema = Get-AuditSummary -RecordExists $true -JsonLines @('{"schema_version":1,"trial_id":"offline-test-trial","phase":"initial","outcome":"pass"}') -TrialId $trial
    $failedInitial = '{"schema_version":1,"trial_id":"offline-test-trial","phase":"initial","surface":"serialized_ollama_request_body","outcome":"fail","failure_category":"canary_match"}'
    $failed = Get-AuditSummary -RecordExists $true -JsonLines @($failedInitial) -TrialId $trial
    $failedRepair = '{"schema_version":1,"trial_id":"offline-test-trial","phase":"repair","surface":"serialized_ollama_request_body","outcome":"fail","failure_category":"canary_match"}'
    $failedAfterInitial = Get-AuditSummary -RecordExists $true -JsonLines @($initialPass, $failedRepair) -TrialId $trial
    $runnerResults = [ordered]@{
        cli_failure_initial_only_exit = Get-RunnerExitCode -CliExitCode 1 -AuditSummary $initialOnly
        cli_failure_initial_only_category = $initialOnly.audit_category
        cli_success_no_record_exit = Get-RunnerExitCode -CliExitCode 0 -AuditSummary $noRecord
        cli_success_failed_audit_exit = Get-RunnerExitCode -CliExitCode 0 -AuditSummary $failed
        cli_success_initial_only_exit = Get-RunnerExitCode -CliExitCode 0 -AuditSummary $initialOnly
        cli_success_initial_only_category = $initialOnly.audit_category
        cli_success_failed_repair_exit = Get-RunnerExitCode -CliExitCode 0 -AuditSummary $failedAfterInitial
        cli_success_audit_pass_exit = Get-RunnerExitCode -CliExitCode 0 -AuditSummary $valid
    }
    return [ordered]@{
        preflight = $preflight
        scopes = $scopeResults
        fake_request_count = $script:FakeRequestCount
        audit = [ordered]@{
            no_record = $noRecord.audit_category
            no_record_initial = $noRecord.initial
            repair_only = $repairOnly.audit_category
            repair_only_initial = $repairOnly.initial
            repair_only_repair = $repairOnly.repair
            initial_only = $initialOnly.audit_category
            initial_only_initial = $initialOnly.initial
            initial_only_repair = $initialOnly.repair
            initial_only_record_count = $initialOnly.record_count
            valid_initial_and_repair = $valid.audit_category
            valid_initial = $valid.initial
            valid_repair = $valid.repair
            wrong_trial_id = $wrongTrial.audit_category
            wrong_schema = $wrongSchema.audit_category
            failed_record = $failed.audit_category
            failed_repair = $failedAfterInitial.audit_category
        }
        runner = $runnerResults
    }
}

if ($OfflineSelfTest) {
    Invoke-OfflineSelfTest | ConvertTo-Json -Depth 6 -Compress
    exit 0
}

$repoRoot = (Resolve-Path (Join-Path $PSScriptRoot '..')).Path
$python = Join-Path $repoRoot '.venv\Scripts\python.exe'
$status = New-RunnerStatus -CliExitCode $null -PreflightCategory 'not_run' `
    -PreflightDetail 'not_run' -AuditCategory 'not_run' -Initial 'not_observed' -Repair 'not_observed' -RecordCount 0
$status.scope = $Scope
$originalEnvironment = @{}
foreach ($entry in Get-ChildItem Env:) {
    $originalEnvironment[$entry.Name] = $entry.Value
}
$canaryValue = $null
$sourceText = $null
$cliRawOutput = $null
$cliInvoked = $false
$runnerExitCode = 2

try {
    if (-not (Test-Path -LiteralPath $python -PathType Leaf)) {
        throw 'runner_error'
    }
    $tempRoot = [System.IO.Path]::GetFullPath($env:TEMP)
    if (-not (Test-Path -LiteralPath $tempRoot -PathType Container) -or
        -not (Test-OutsideGitRepositories -Path $tempRoot)) {
        throw 'runner_error'
    }
    $runRoot = Join-Path $tempRoot ('omnipatch-b105-canary-' + [guid]::NewGuid().ToString('N'))
    New-Item -ItemType Directory -Path $runRoot -ErrorAction Stop | Out-Null
    Protect-RunDirectory -Path $runRoot
    $auditDir = Join-Path $runRoot 'audit'
    $statusDir = Join-Path $runRoot 'status'
    $workDir = Join-Path $runRoot 'work'
    New-Item -ItemType Directory -Path $auditDir, $statusDir, $workDir -ErrorAction Stop | Out-Null
    $auditPath = Join-Path $auditDir 'requests.jsonl'
    $statusPath = Join-Path $statusDir 'status.json'

    foreach ($entry in Get-ChildItem Env:) {
        if ($entry.Name -match '(?i)(OMNIPATCH_|API_KEY|TOKEN|SECRET|PASSWORD|CREDENTIAL|GITHUB|ANTHROPIC)') {
            Remove-Item -LiteralPath "Env:$($entry.Name)" -ErrorAction SilentlyContinue
        }
    }
    $env:OMNIPATCH_LLM_PROVIDER = 'ollama'
    $env:OMNIPATCH_LLM_OUTPUT = 'function'
    $env:OMNIPATCH_LLM_MODEL = $script:ExpectedModel
    $env:OMNIPATCH_OLLAMA_ENDPOINT = 'http://127.0.0.1:11434/api/chat'
    $env:PYTHONPATH = "$repoRoot;$repoRoot\src"
    $env:TEMP = $workDir
    $env:TMP = $workDir

    $preflight = Get-TagsPreflight -SendRequest { Invoke-LoopbackTagsRequest } `
        -ExpectedModel $script:ExpectedModel -ExpectedDigest $script:ExpectedDigest
    $status.preflight_category = $preflight.category
    $status.preflight_detail = $preflight.transport_category
    if ($preflight.category -cne 'passed') {
        $status.audit_category = 'not_run'
        [IO.File]::WriteAllText($statusPath, ($status | ConvertTo-Json -Compress), [Text.UTF8Encoding]::new($false))
        Write-Output "scope=$Scope preflight_category=$($preflight.category) preflight_detail=$($preflight.transport_category) cli_exit_code=not_run audit_category=not_run initial=not_observed repair=not_observed record_count=0"
        $runnerExitCode = 2
    }
    else {
        $targetDir = Join-Path $runRoot 'target'
        New-Item -ItemType Directory -Path $targetDir -ErrorAction Stop | Out-Null
        $canaryValue = 'OMNIPATCH_SYNTHETIC_CANARY_' + [guid]::NewGuid().ToString('N')
        $targetDefinition = New-SyntheticTargetDefinition -Scope $Scope -CanaryValue $canaryValue
        $sourceText = $targetDefinition.Source
        [IO.File]::WriteAllText((Join-Path $targetDir 'app.py'), $sourceText, [Text.UTF8Encoding]::new($false))
        $mapping = @{}
        $mapping[[string]$targetDefinition.MappingKey] = [string]$targetDefinition.MappingValue
        $env:OMNIPATCH_SECRET_ENVIRONMENT = $mapping | ConvertTo-Json -Compress
        $env:OP_SYNTHETIC_CANARY_AUDIT_VALUE = $canaryValue
        $env:OP_SYNTHETIC_CANARY_AUDIT_RECORD = $auditPath
        $trialId = 'b105-' + [guid]::NewGuid().ToString('N')
        $env:OP_SYNTHETIC_CANARY_AUDIT_TRIAL_ID = $trialId
        $canaryValue = $null
        $sourceText = $null
        $targetDefinition = $null

        Push-Location -LiteralPath $targetDir
        try {
            $cliInvoked = $true
            $cliRawOutput = @(& $python -m omnipatch verify --repo $targetDir --rule B105 --json 2>&1)
            $cliExitCode = $LASTEXITCODE
        } finally {
            Pop-Location
        }
        $cliRawOutput = $null

        $recordExists = Test-Path -LiteralPath $auditPath -PathType Leaf
        $jsonLines = if ($recordExists) { [IO.File]::ReadAllLines($auditPath) } else { @() }
        $summary = Get-AuditSummary -RecordExists $recordExists -JsonLines $jsonLines -TrialId $trialId
        $status = New-RunnerStatus -CliExitCode $cliExitCode -PreflightCategory 'passed' `
            -PreflightDetail 'not_applicable' -AuditCategory $summary.audit_category -Initial $summary.initial `
            -Repair $summary.repair -RecordCount $summary.record_count
        $status.scope = $Scope
        [IO.File]::WriteAllText($statusPath, ($status | ConvertTo-Json -Compress), [Text.UTF8Encoding]::new($false))
        Write-Output "scope=$Scope preflight_category=passed preflight_detail=not_applicable cli_exit_code=$cliExitCode audit_category=$($summary.audit_category) initial=$($summary.initial) repair=$($summary.repair) record_count=$($summary.record_count)"
        $runnerExitCode = Get-RunnerExitCode -CliExitCode $cliExitCode -AuditSummary $summary
    }
} catch {
    $cliRawOutput = $null
    $canaryValue = $null
    $sourceText = $null
    if ($null -ne $statusPath -and (Test-Path -LiteralPath $statusDir -PathType Container)) {
        $status.audit_category = if ($cliInvoked) { 'audit_failed' } else { 'not_run' }
        try {
            [IO.File]::WriteAllText($statusPath, ($status | ConvertTo-Json -Compress), [Text.UTF8Encoding]::new($false))
        } catch {
            # Keep filesystem diagnostics value-free.
        }
    }
    $cliStatus = if ($null -eq $status.cli_exit_code) { 'not_run' } else { [string]$status.cli_exit_code }
    $auditStatus = if ($cliInvoked) { 'audit_failed' } else { 'not_run' }
    Write-Output "scope=$Scope preflight_category=$($status.preflight_category) preflight_detail=$($status.preflight_detail) cli_exit_code=$cliStatus audit_category=$auditStatus initial=not_observed repair=not_observed record_count=0"
    $runnerExitCode = 2
} finally {
    $cliRawOutput = $null
    $canaryValue = $null
    $sourceText = $null
    foreach ($entry in Get-ChildItem Env:) {
        if (-not $originalEnvironment.ContainsKey($entry.Name)) {
            Remove-Item -LiteralPath "Env:$($entry.Name)" -ErrorAction SilentlyContinue
        }
    }
    foreach ($name in $originalEnvironment.Keys) {
        [Environment]::SetEnvironmentVariable($name, $originalEnvironment[$name], 'Process')
    }
}
exit $runnerExitCode
