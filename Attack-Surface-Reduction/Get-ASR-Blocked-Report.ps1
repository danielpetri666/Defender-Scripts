<#
.SYNOPSIS
    Retrieves ASR blocked events and exports them to an Excel file.
.DESCRIPTION
    Runs Microsoft Defender Advanced Hunting queries via Microsoft Graph for all ASR rules.
    Creates a Summary sheet with totals per rule and a separate detail
    sheet per rule in the same Excel file.
    Control the number of days with QueryDays (default 30) and optionally
    filter by one or more Machine Groups with MachineGroupFilter.
    Multiple groups can be specified using comma or semicolon as separator.
.AUTHOR
    Daniel Petri
.PARAMETER TenantId
    Optional. Azure AD tenant ID. If omitted, connects to the home tenant.
.PARAMETER QueryDays
    Number of days back to include in the report. Default is 30.
.PARAMETER MachineGroupFilter
    Optional filter for one or more Machine Groups.
    Specify multiple values separated by comma or semicolon.
    Example: "Group1,Group2" or "Group1;Group2".
.PARAMETER ExportPath
    Output directory for the Excel report. Defaults to $env:TEMP.
.EXAMPLE
    .\Get-ASR-Blocked-Report.ps1
    Connects interactively and runs the report for the last 30 days across all Machine Groups.
.EXAMPLE
    .\Get-ASR-Blocked-Report.ps1 -QueryDays 7
    Runs the report for the last 7 days across all Machine Groups.
.EXAMPLE
    .\Get-ASR-Blocked-Report.ps1 -QueryDays 14 -MachineGroupFilter "Group1;Group2"
    Runs the report for the last 14 days, filtered to the specified Machine Groups.
.NOTES
    Requires: Microsoft.Graph.Authentication, ImportExcel
    Version: 2.0.0
    Permissions required (delegated): ThreatHunting.Read.All
#>
#Requires -Module Microsoft.Graph.Authentication
#Requires -Module ImportExcel

param(
    [string]$TenantId,

    [ValidateRange(1, 3650)]
    [int]$QueryDays = 30,

    [string]$MachineGroupFilter = "",

    [string]$ExportPath = $env:TEMP
)

#region Variables
$MachineGroupFilter = $MachineGroupFilter.Trim()
$QueryTime = "${QueryDays}d"
$DetailBatchSize = 10000
$DetailChunkDays = 2
$ApiMinDelayMs = 300
$ApiRetryMax = 6
$ApiRetryBaseDelaySec = 2
$PageRetryRounds = 6
$PageRetrySleepSec = 10
$RequireCompleteData = $true
$LogPageProgress = $false
$MinAdaptiveChunkMinutes = 60
$ExportFile = Join-Path $ExportPath "$(Get-Date -Format 'yyyy-MM-dd HHmm') - ASR Blocked Report.xlsx"

$MachineGroupFilterClause = ""
$MachineGroupFilters = @()
if (-not [string]::IsNullOrWhiteSpace($MachineGroupFilter)) {
    $MachineGroupFilters = @(
        $MachineGroupFilter -split '[,;]' |
        ForEach-Object { $_.Trim() } |
        Where-Object { -not [string]::IsNullOrWhiteSpace($_) } |
        Select-Object -Unique
    )
}

if ($MachineGroupFilters.Count -gt 0) {
    $escapedMachineGroupFilters = @(
        $MachineGroupFilters |
        ForEach-Object { '"' + ($_.Replace('"', '\\"')) + '"' }
    )
    $MachineGroupFilterClause = "| where tostring(MachineGroup) in~ (" + ($escapedMachineGroupFilters -join ', ') + ")"
}
#endregion

#region Connect to Microsoft Graph
$connectParams = @{
    Scopes = @('ThreatHunting.Read.All')
}
if (-not [string]::IsNullOrWhiteSpace($TenantId)) {
    $connectParams['TenantId'] = $TenantId
}
Connect-MgGraph @connectParams -ErrorAction Stop | Out-Null
#endregion

#region ASR rules
$AsrRules = @(
    [PSCustomObject]@{ RuleName = "Block abuse of exploited vulnerable signed drivers"; RuleId = "56a863a9-875e-4185-98a7-b882c64b5ce5" }
    [PSCustomObject]@{ RuleName = "Block Adobe Reader from creating child processes"; RuleId = "7674ba52-37eb-4a4f-a9a1-f0f9a1619a2c" }
    [PSCustomObject]@{ RuleName = "Block all Office applications from creating child processes"; RuleId = "d4f940ab-401b-4efc-aadc-ad5f3c50688a" }
    [PSCustomObject]@{ RuleName = "Block credential stealing from the Windows local security authority subsystem (lsass.exe)"; RuleId = "9e6c4e1f-7d60-472f-ba1a-a39ef669e4b2" }
    [PSCustomObject]@{ RuleName = "Block executable content from email client and webmail"; RuleId = "be9ba2d9-53ea-4cdc-84e5-9b1eeee46550" }
    [PSCustomObject]@{ RuleName = "Block executable files from running unless they meet a prevalence, age, or trusted list criterion"; RuleId = "01443614-cd74-433a-b99e-2ecdc07bfc25" }
    [PSCustomObject]@{ RuleName = "Block execution of potentially obfuscated scripts"; RuleId = "5beb7efe-fd9a-4556-801d-275e5ffc04cc" }
    [PSCustomObject]@{ RuleName = "Block JavaScript or VBScript from launching downloaded executable content"; RuleId = "d3e037e1-3eb8-44c8-a917-57927947596d" }
    [PSCustomObject]@{ RuleName = "Block Office applications from creating executable content"; RuleId = "3b576869-a4ec-4529-8536-b80a7769e899" }
    [PSCustomObject]@{ RuleName = "Block Office applications from injecting code into other processes"; RuleId = "75668c1f-73b5-4cf0-bb93-3ecf5cb7cc84" }
    [PSCustomObject]@{ RuleName = "Block Office communication application from creating child processes"; RuleId = "26190899-1602-49e8-8b27-eb1d0a1ce869" }
    [PSCustomObject]@{ RuleName = "Block persistence through WMI event subscription"; RuleId = "e6db77e5-3df2-4cf1-b95a-636979351e5b" }
    [PSCustomObject]@{ RuleName = "Block process creations originating from PSExec and WMI commands"; RuleId = "d1e49aac-8f56-4280-b9ba-993a6d77406c" }
    [PSCustomObject]@{ RuleName = "Block rebooting machine in Safe Mode"; RuleId = "33ddedf1-c6e0-47cb-833e-de6133960387" }
    [PSCustomObject]@{ RuleName = "Block untrusted and unsigned processes that run from USB"; RuleId = "b2b3f03d-6a65-4f7b-a9c7-1c7ef74a9ba4" }
    [PSCustomObject]@{ RuleName = "Block use of copied or impersonated system tools"; RuleId = "c0033c00-d16d-4114-a5a0-dc9b3a7d2ceb" }
    [PSCustomObject]@{ RuleName = "Block Webshell creation for Servers"; RuleId = "a8f5898e-1dc8-49a9-9878-85004b8a61e6" }
    [PSCustomObject]@{ RuleName = "Block Win32 API calls from Office macros"; RuleId = "92e97fa1-2edf-4476-bdd6-9dd0b4dddc7b" }
    [PSCustomObject]@{ RuleName = "Use advanced protection against ransomware"; RuleId = "c1db55ab-c21a-4637-bb3f-a12568109d35" }
)
#endregion

#region Helpers
function Get-SafeWorksheetName {
    param([string]$Name)

    $safeName = ($Name -replace '[:\\/\?\*\[\]]', ' ') -replace '\s+', ' '
    $safeName = $safeName.Trim()
    if ([string]::IsNullOrWhiteSpace($safeName)) { $safeName = "Rule" }
    if ($safeName.Length -gt 31) { $safeName = $safeName.Substring(0, 31) }
    return $safeName
}

function Get-UniqueWorksheetName {
    param(
        [string]$BaseName,
        [hashtable]$UsedNames
    )

    $candidate = $BaseName
    $suffixIndex = 1
    while ($UsedNames.ContainsKey($candidate)) {
        $suffix = " $suffixIndex"
        $maxLength = 31 - $suffix.Length
        if ($maxLength -lt 1) { $maxLength = 1 }
        $trimmedBase = if ($BaseName.Length -gt $maxLength) { $BaseName.Substring(0, $maxLength) } else { $BaseName }
        $candidate = "$trimmedBase$suffix"
        $suffixIndex++
    }

    $UsedNames[$candidate] = $true
    return $candidate
}

function Write-Log {
    param(
        [ValidateSet('INFO', 'OK', 'WARN', 'ERROR')]
        [string]$Level,
        [string]$Message,
        [int]$Indent = 0
    )

    $timestamp = Get-Date -Format 'HH:mm:ss'
    $levelLabel = switch ($Level) {
        'INFO' { 'INFO ' }
        'OK' { 'OK   ' }
        'WARN' { 'WARN ' }
        'ERROR' { 'ERROR' }
    }

    $color = switch ($Level) {
        'INFO' { 'Cyan' }
        'OK' { 'Green' }
        'WARN' { 'Yellow' }
        'ERROR' { 'Red' }
    }

    if ($Indent -lt 0) { $Indent = 0 }
    $indentText = "`t" * $Indent
    Write-Host ("[{0}]`t[{1}]`t{2}{3}" -f $timestamp, $levelLabel, $indentText, $Message) -ForegroundColor $color
}

function Test-HasNonEmptyData {
    param(
        [Parameter(ValueFromPipeline = $true)]
        $InputObject
    )

    if ($null -eq $InputObject) {
        return $false
    }

    $properties = @($InputObject.PSObject.Properties)
    if ($properties.Count -eq 0) {
        return $false
    }

    foreach ($prop in $properties) {
        if ($prop.Name -eq 'RowNum') {
            continue
        }

        $value = $prop.Value
        if ($null -eq $value) {
            continue
        }

        if ($value -is [string]) {
            if (-not [string]::IsNullOrWhiteSpace($value)) {
                return $true
            }
        }
        else {
            return $true
        }
    }

    return $false
}

function Invoke-HuntingQuery {
    param([string]$QueryText)
    $response = Invoke-MgGraphRequest -Method POST -Uri 'https://graph.microsoft.com/v1.0/security/runHuntingQuery' -Body @{ Query = $QueryText } -ErrorAction Stop
    return [PSCustomObject]@{
        value = [PSCustomObject]@{
            Results = @($response.results)
        }
    }
}

function Invoke-DefenderAdvancedQuerySafe {
    param(
        [string]$Query,
        [string]$RuleName,
        [string]$RuleId,
        [string]$QueryType,
        [string]$FallbackQuery,
        [switch]$SuppressFailureLogs
    )

    function Invoke-QueryWithRetry {
        param([string]$QueryText)

        $attempt = 0
        while ($attempt -lt $ApiRetryMax) {
            $attempt++
            try {
                if ($ApiMinDelayMs -gt 0) {
                    Start-Sleep -Milliseconds $ApiMinDelayMs
                }

                $response = Invoke-HuntingQuery -QueryText $QueryText
                if ($null -eq $response -or $null -eq $response.value) {
                    throw "Empty response from Defender API"
                }

                $rawResults = @()

                $responseValue = $response.value

                if ($responseValue.PSObject.Properties.Name -contains 'Results') {
                    $rawResults += @($responseValue.Results)
                }
                elseif ($responseValue -is [System.Collections.IEnumerable] -and -not ($responseValue -is [string])) {
                    foreach ($entry in @($responseValue)) {
                        if ($null -eq $entry) {
                            continue
                        }

                        if ($entry.PSObject.Properties.Name -contains 'Results') {
                            $rawResults += @($entry.Results)
                        }
                        else {
                            $rawResults += @($entry)
                        }
                    }
                }
                else {
                    $rawResults += @($responseValue)
                }

                $rawResults = @($rawResults | Where-Object { $null -ne $_ })

                return [PSCustomObject]@{
                    Succeeded = $true
                    Results   = $rawResults
                }
            }
            catch {
                $message = $_.Exception.Message
                $is429 = $message -match '429|Too Many Requests'

                if ($is429 -and $attempt -lt $ApiRetryMax) {
                    $delay = [Math]::Min(60, [Math]::Pow(2, $attempt - 1) * $ApiRetryBaseDelaySec + (Get-Random -Minimum 0 -Maximum 2))
                    if (-not $SuppressFailureLogs) {
                        Write-Log -Level WARN -Message "[$QueryType] Throttled (429) for '$RuleName' ($RuleId). Retry $attempt/$ApiRetryMax in $delay s." -Indent 2
                    }
                    Start-Sleep -Seconds $delay
                    continue
                }

                return [PSCustomObject]@{
                    Succeeded = $false
                    Results   = @()
                    Error     = $_
                }
            }
        }

        return [PSCustomObject]@{
            Succeeded = $false
            Results   = @()
            Error     = "Retry limit reached"
        }
    }

    try {
        $previousWarningPreference = $WarningPreference
        $WarningPreference = 'SilentlyContinue'
        $primaryResult = Invoke-QueryWithRetry -QueryText $Query
        if ($primaryResult.Succeeded) { return $primaryResult }
        throw $primaryResult.Error
    }
    catch {
        $errorMessage = $_.Exception.Message
        $errorDetails = $null

        try {
            if ($_.Exception.Response -and $_.Exception.Response.Content) {
                $errorDetails = $_.Exception.Response.Content.ReadAsStringAsync().GetAwaiter().GetResult()
            }
        }
        catch {
            $errorDetails = $null
        }

        if (-not $SuppressFailureLogs) {
            if ([string]::IsNullOrWhiteSpace($errorDetails)) {
                Write-Log -Level WARN -Message "[$QueryType] Rule '$RuleName' ($RuleId) failed: $errorMessage" -Indent 1
            }
            else {
                Write-Log -Level WARN -Message "[$QueryType] Rule '$RuleName' ($RuleId) failed: $errorMessage | Details: $errorDetails" -Indent 1
            }
        }

        if (-not [string]::IsNullOrWhiteSpace($FallbackQuery)) {
            try {
                if (-not $SuppressFailureLogs) {
                    Write-Log -Level WARN -Message "[$QueryType] Retrying rule '$RuleName' ($RuleId) with fallback query." -Indent 2
                }
                $fallbackResult = Invoke-QueryWithRetry -QueryText $FallbackQuery
                if ($fallbackResult.Succeeded) { return $fallbackResult }
                throw $fallbackResult.Error
            }
            catch {
                if (-not $SuppressFailureLogs) {
                    Write-Log -Level WARN -Message "[$QueryType] Fallback for rule '$RuleName' ($RuleId) also failed: $($_.Exception.Message)" -Indent 2
                }
            }
        }

        return [PSCustomObject]@{
            Succeeded = $false
            Results   = @()
        }
    }
    finally {
        if ($null -ne $previousWarningPreference) {
            $WarningPreference = $previousWarningPreference
        }
    }
}

function Get-QueryTimeDays {
    param([string]$QueryTime)

    if ($QueryTime -match '^(\d+)d$') {
        return [int]$Matches[1]
    }

    return 30
}

function Get-AsrRuleDetailsBatched {
    param(
        [string]$RuleName,
        [string]$RuleId,
        [string]$QueryTime,
        [int]$BatchSize,
        [int]$ChunkDays,
        [int]$RetryRounds,
        [int]$RetrySleepSec
    )

    $allResults = @()
    $allSucceeded = $true
    $totalRequests = 0
    $failedRequests = 0
    $days = Get-QueryTimeDays -QueryTime $QueryTime
    $rangeEnd = Get-Date
    $rangeStart = $rangeEnd.AddDays(-$days)
    $chunkStart = $rangeStart
    $totalChunks = [Math]::Ceiling($days / [double]$ChunkDays)
    $chunkIndex = 0

    function Get-WindowDetails {
        param(
            [datetime]$WindowStart,
            [datetime]$WindowEnd,
            [int]$WindowIndent
        )

        $windowResults = @()
        $windowSucceeded = $true
        $windowRequests = 0
        $windowFailedRequests = 0
        $fromIso = $WindowStart.ToUniversalTime().ToString("yyyy-MM-ddTHH:mm:ssZ")
        $toIso = $WindowEnd.ToUniversalTime().ToString("yyyy-MM-ddTHH:mm:ssZ")
        $offset = 0
        $maxPagesPerChunk = 200

        for ($page = 1; $page -le $maxPagesPerChunk; $page++) {
            $upper = $offset + $BatchSize
            if ($LogPageProgress) {
                Write-Log -Level INFO -Message "Page $page (rows $($offset + 1)-$upper)." -Indent ($WindowIndent + 1)
            }

            $queryDetails = @"
let ruleId = "$RuleId";
let fromTime = datetime($fromIso);
let toTime = datetime($toIso);
DeviceEvents
| where Timestamp >= fromTime and Timestamp < toTime
| where ActionType startswith "ASR"
| where ActionType contains "Blocked"
| extend AF = todynamic(AdditionalFields)
| where tostring(AF["RuleId"]) == ruleId
| join kind=leftouter (
DeviceInfo
| summarize arg_max(Timestamp, MachineGroup) by DeviceId
) on DeviceId
$MachineGroupFilterClause
| order by Timestamp desc
| serialize RowNum = row_number()
| where RowNum > $offset and RowNum <= $upper
"@

            $queryDetailsFallback = @"
let ruleId = "$RuleId";
let fromTime = datetime($fromIso);
let toTime = datetime($toIso);
DeviceEvents
| where Timestamp >= fromTime and Timestamp < toTime
| where ActionType startswith "ASR"
| where ActionType contains "Blocked"
| extend AF = todynamic(AdditionalFields)
| where tostring(AF["RuleId"]) == ruleId
| order by Timestamp desc
| serialize RowNum = row_number()
| where RowNum > $offset and RowNum <= $upper
"@

            $result = $null
            for ($round = 1; $round -le $RetryRounds; $round++) {
                $suppress = ($round -lt $RetryRounds)
                $result = Invoke-DefenderAdvancedQuerySafe -Query $queryDetails -FallbackQuery $queryDetailsFallback -RuleName $RuleName -RuleId $RuleId -QueryType "Details" -SuppressFailureLogs:$suppress
                $windowRequests++
                if ($result.Succeeded) {
                    break
                }

                if ($round -lt $RetryRounds) {
                    Write-Log -Level WARN -Message "Page retry $round/$RetryRounds (page $page). Waiting $RetrySleepSec s." -Indent ($WindowIndent + 1)
                    Start-Sleep -Seconds $RetrySleepSec
                }
            }

            if (-not $result.Succeeded) {
                $windowMinutes = [int][Math]::Floor(($WindowEnd - $WindowStart).TotalMinutes)
                if ($windowMinutes -gt $MinAdaptiveChunkMinutes) {
                    $midpoint = $WindowStart.AddMinutes([Math]::Floor(($WindowEnd - $WindowStart).TotalMinutes / 2))
                    Write-Log -Level WARN -Message "Window failed, splitting range ($windowMinutes min): $($WindowStart.ToString('yyyy-MM-dd HH:mm')) -> $($WindowEnd.ToString('yyyy-MM-dd HH:mm'))." -Indent $WindowIndent

                    $left = Get-WindowDetails -WindowStart $WindowStart -WindowEnd $midpoint -WindowIndent ($WindowIndent + 1)
                    $right = Get-WindowDetails -WindowStart $midpoint -WindowEnd $WindowEnd -WindowIndent ($WindowIndent + 1)

                    return [PSCustomObject]@{
                        Succeeded      = ($left.Succeeded -and $right.Succeeded)
                        Results        = @($left.Results + $right.Results)
                        TotalRequests  = ($windowRequests + $left.TotalRequests + $right.TotalRequests)
                        FailedRequests = ($windowFailedRequests + $left.FailedRequests + $right.FailedRequests)
                    }
                }

                $windowSucceeded = $false
                $windowFailedRequests++
                break
            }

            $rows = @($result.Results | Where-Object { Test-HasNonEmptyData -InputObject $_ })
            if ($rows.Count -eq 0) {
                break
            }

            $windowResults += $rows

            if ($rows.Count -lt $BatchSize) {
                break
            }

            $offset += $BatchSize
        }

        return [PSCustomObject]@{
            Succeeded      = $windowSucceeded
            Results        = $windowResults
            TotalRequests  = $windowRequests
            FailedRequests = $windowFailedRequests
        }
    }

    while ($chunkStart -lt $rangeEnd) {
        $chunkIndex++
        $chunkEnd = $chunkStart.AddDays($ChunkDays)
        if ($chunkEnd -gt $rangeEnd) {
            $chunkEnd = $rangeEnd
        }

        Write-Log -Level INFO -Message "Chunk $chunkIndex/$totalChunks ($($chunkStart.ToString('yyyy-MM-dd')) -> $($chunkEnd.ToString('yyyy-MM-dd')))." -Indent 1

        $chunkResult = Get-WindowDetails -WindowStart $chunkStart -WindowEnd $chunkEnd -WindowIndent 2
        $allResults += @($chunkResult.Results)
        $totalRequests += $chunkResult.TotalRequests
        $failedRequests += $chunkResult.FailedRequests
        if (-not $chunkResult.Succeeded) {
            $allSucceeded = $false
        }

        $chunkStart = $chunkEnd
    }

    $status = if ($allSucceeded) {
        "OK"
    }
    elseif ($allResults.Count -gt 0) {
        "Partial"
    }
    else {
        "Failed"
    }

    return [PSCustomObject]@{
        Succeeded      = $allSucceeded
        Status         = $status
        Results        = $allResults
        TotalRequests  = $totalRequests
        FailedRequests = $failedRequests
    }
}
#endregion

#region Collect summary and details for all ASR rules
$Summary = @()
$RuleDetailsByRuleId = @{}
$RuleSheetNameByRuleId = @{}
$UsedSheetNames = @{ Summary = $true }
$totalRules = $AsrRules.Count
$ruleIndex = 0

Write-Host ""
Write-Host "========== ASR BLOCKED REPORT ==========" -ForegroundColor Magenta
$machineGroupScope = if ($MachineGroupFilters.Count -eq 0) { "All machine groups" } else { "MachineGroups='" + ($MachineGroupFilters -join ', ') + "'" }
Write-Log -Level INFO -Message "Start. Rules: $totalRules, QueryTime: $QueryTime, BatchSize: $DetailBatchSize, ChunkDays: $DetailChunkDays, Scope: $machineGroupScope"

foreach ($Rule in $AsrRules) {
    $ruleIndex++
    $RuleId = $Rule.RuleId
    $RuleName = $Rule.RuleName
    Write-Log -Level INFO -Message "[$ruleIndex/$totalRules] $RuleName" -Indent 0
    Write-Log -Level INFO -Message "RuleId: $RuleId" -Indent 1

    $safeSheetBase = Get-SafeWorksheetName -Name $RuleName
    $RuleSheetNameByRuleId[$RuleId] = Get-UniqueWorksheetName -BaseName $safeSheetBase -UsedNames $UsedSheetNames

    $DetailQueryResult = Get-AsrRuleDetailsBatched -RuleName $RuleName -RuleId $RuleId -QueryTime $QueryTime -BatchSize $DetailBatchSize -ChunkDays $DetailChunkDays -RetryRounds $PageRetryRounds -RetrySleepSec $PageRetrySleepSec
    $DetailResults = @($DetailQueryResult.Results | Where-Object { Test-HasNonEmptyData -InputObject $_ })

    if ($RequireCompleteData -and -not $DetailQueryResult.Succeeded) {
        throw "Incomplete data for ASR rule '$RuleName' ($RuleId). Stopping to avoid incorrect report."
    }

    $RuleDetails = @()
    foreach ($DR in $DetailResults) {
        $RuleDetails += [PSCustomObject]@{
            RuleName                                    = $RuleName
            RuleId                                      = $RuleId
            MachineGroup                                = if ([string]::IsNullOrWhiteSpace($DR.MachineGroup)) { "(Unknown)" } else { $DR.MachineGroup }
            DeviceName                                  = $DR.DeviceName
            DeviceId                                    = $DR.DeviceId
            Timestamp                                   = $DR.Timestamp
            ActionType                                  = $DR.ActionType
            FileName                                    = $DR.FileName
            FolderPath                                  = $DR.FolderPath
            InitiatingProcessFileName                   = $DR.InitiatingProcessFileName
            InitiatingProcessFolderPath                 = $DR.InitiatingProcessFolderPath
            InitiatingProcessCommandLine                = $DR.InitiatingProcessCommandLine
            InitiatingProcessAccountDomain              = $DR.InitiatingProcessAccountDomain
            InitiatingProcessAccountName                = $DR.InitiatingProcessAccountName
            InitiatingProcessAccountSid                 = $DR.InitiatingProcessAccountSid
            InitiatingProcessVersionInfoFileDescription = $DR.InitiatingProcessVersionInfoFileDescription
            InitiatingProcessParentFileName             = $DR.InitiatingProcessParentFileName
            IsBlocked                                   = ($DR.ActionType -like "*Blocked*")
        }
    }

    $totalBlocked = $RuleDetails.Count
    $uniqueDeviceCount = @(
        $RuleDetails |
        Where-Object { -not [string]::IsNullOrWhiteSpace($_.DeviceId) } |
        Select-Object -ExpandProperty DeviceId -Unique
    ).Count
    $machineGroupCount = @(
        $RuleDetails |
        Where-Object { -not [string]::IsNullOrWhiteSpace($_.MachineGroup) } |
        Select-Object -ExpandProperty MachineGroup -Unique
    ).Count

    $Summary += [PSCustomObject]@{
        RuleName              = $RuleName
        RuleId                = $RuleId
        Total_Blocked_Count   = $totalBlocked
        Devices               = $uniqueDeviceCount
        MachineGroups         = $machineGroupCount
        ZeroBlockedLastPeriod = ($totalBlocked -eq 0)
        FailedRequests        = $DetailQueryResult.FailedRequests
        TotalRequests         = $DetailQueryResult.TotalRequests
        QueryStatus           = $DetailQueryResult.Status
    }

    Write-Log -Level OK -Message "Done. Blocked: $totalBlocked | Devices: $uniqueDeviceCount | Status: $($DetailQueryResult.Status) | Requests: $($DetailQueryResult.TotalRequests) | Failed: $($DetailQueryResult.FailedRequests)" -Indent 1

    $RuleDetailsByRuleId[$RuleId] = $RuleDetails
}
Write-Log -Level INFO -Message "Data collection complete. Exporting to '$ExportFile'..."
#endregion

#region Export results to multisheet excel file
$Summary |
Sort-Object -Property @{ Expression = 'Total_Blocked_Count'; Descending = $true }, RuleName |
Export-Excel -Path $ExportFile -WorkSheetname "Summary" -AutoSize -AutoFilter -TableStyle Medium2

foreach ($Rule in $AsrRules) {
    $RuleId = $Rule.RuleId
    $RuleName = $Rule.RuleName
    $WorksheetName = $RuleSheetNameByRuleId[$RuleId]
    $RuleDetails = $RuleDetailsByRuleId[$RuleId]

    if ($RuleDetails.Count -gt 0) {
        $RuleDetails | Export-Excel -Path $ExportFile -WorkSheetname $WorksheetName -AutoSize -AutoFilter -TableStyle Medium2 -Append
    }
    else {
        [PSCustomObject]@{
            RuleName = $RuleName
            RuleId   = $RuleId
            Message  = "No ASR blocked events found"
        } | Export-Excel -Path $ExportFile -WorkSheetname $WorksheetName -AutoSize -AutoFilter -TableStyle Medium2 -Append
    }
}
Write-Log -Level OK -Message "Export complete: $ExportFile"
Write-Host "======================================" -ForegroundColor Magenta
Write-Host ""
#endregion
