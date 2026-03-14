#Requires -Version 5.1
#Requires -Module Az.Accounts
<#
.SYNOPSIS
    Adds or removes Defender for Endpoint machine tags from a CSV or a single device.
.DESCRIPTION
    Adds or removes a machine tag on devices in Microsoft Defender for Endpoint.
    Accepts either a CSV file with a DeviceName column (bulk) or a single -DeviceName
    parameter. If the CSV contains a Tag column, the per-row tag value is used;
    otherwise the -MachineTag parameter value is applied.

    Authenticates interactively via Connect-AzAccount -- no app registration, secrets,
    or certificates needed. The signed-in user must have a Defender RBAC role with
    machine write access.

    Supports -WhatIf for dry runs without making any changes.
.AUTHOR
    Daniel Petri
.PARAMETER CSVPath
    Path to a CSV file with a DeviceName column (and optional Tag column).
    Cannot be used together with -DeviceName.
.PARAMETER DeviceName
    A single device name to tag. Cannot be used together with -CSVPath.
.PARAMETER MachineTag
    The machine tag to add or remove. Defaults to "Offboarded".
    Overridden per row if the CSV has a Tag column.
.PARAMETER Action
    Whether to Add or Remove the tag. Defaults to Add.
.PARAMETER TenantId
    Entra ID tenant ID. Optional.
.PARAMETER ApiBaseUrl
    Defender for Endpoint API base URL. Defaults to the global instance.
    Use https://api-eu.securitycenter.microsoft.com for EU tenants.
    Use https://api-gcc.securitycenter.microsoft.us for GCC High.
.EXAMPLE
    .\Set-DefenderMachineTag.ps1 -CSVPath "C:\Data\Devices.csv"
    Adds the default "Offboarded" tag to all devices in the CSV.
.EXAMPLE
    .\Set-DefenderMachineTag.ps1 -DeviceName "DESKTOP-ABC123" -MachineTag "VIP"
    Adds the "VIP" tag to a single device.
.EXAMPLE
    .\Set-DefenderMachineTag.ps1 -CSVPath "C:\Data\Devices.csv" -Action Remove -WhatIf
    Shows which devices would have the "Offboarded" tag removed without making changes.
.EXAMPLE
    .\Set-DefenderMachineTag.ps1 -DeviceName "SERVER-01" -Action Remove -MachineTag "Deprecated"
    Removes the "Deprecated" tag from a single device.
.EXAMPLE
    .\Set-DefenderMachineTag.ps1 -CSVPath "C:\Data\Devices.csv" -ApiBaseUrl "https://api-eu.securitycenter.microsoft.com"
    Targets the EU regional Defender API instance.
.NOTES
    Requires: Az.Accounts module, Defender RBAC role with machine write access.
    Version: 2.0.0
#>

[CmdletBinding(SupportsShouldProcess)]
param(
    [Parameter(Mandatory, ParameterSetName = 'CSV')]
    [string]$CSVPath,

    [Parameter(Mandatory, ParameterSetName = 'Single')]
    [string]$DeviceName,

    [string]$MachineTag = 'Offboarded',

    [ValidateSet('Add', 'Remove')]
    [string]$Action = 'Add',

    [string]$TenantId,

    [string]$ApiBaseUrl = 'https://api.securitycenter.windows.com'
)

#region Connect and acquire Defender token
$connectParams = @{}
if ($TenantId) { $connectParams['TenantId'] = $TenantId }
Connect-AzAccount @connectParams -ErrorAction Stop | Out-Null

$tokenResponse = Get-AzAccessToken -ResourceUrl $ApiBaseUrl -ErrorAction Stop
$accessToken = if ($tokenResponse.Token -is [securestring]) {
    [System.Net.NetworkCredential]::new('', $tokenResponse.Token).Password
} else {
    $tokenResponse.Token
}
$DefH = @{ Authorization = "Bearer $accessToken" }
Write-Host 'Authenticated to Defender API.' -ForegroundColor Green
#endregion

#region API helper with retry
function Invoke-DefenderCall {
    [CmdletBinding()]
    param(
        [ValidateSet('Get', 'Post')]
        [string]$Method = 'Get',

        [Parameter(Mandatory)]
        [hashtable]$Headers,

        [Parameter(Mandatory)]
        [string]$Uri,

        [hashtable]$Body
    )

    $params = @{
        Method      = $Method
        Headers     = $Headers
        Uri         = $Uri
        ContentType = 'application/json'
    }
    if ($Body) { $params.Body = $Body | ConvertTo-Json -Depth 20 }

    for ($attempt = 1; $attempt -le 5; $attempt++) {
        try {
            $response = Invoke-RestMethod @params

            if ($Method -eq 'Get') {
                $next = $response.'@odata.nextLink'
                while ($null -ne $next) {
                    $page = Invoke-RestMethod -Method Get -Uri $next -Headers $Headers
                    $next = $page.'@odata.nextLink'
                    $response.value += $page.value
                }
            }

            return $response
        }
        catch {
            $statusCode = $null
            if ($_.Exception.Response) { $statusCode = [int]$_.Exception.Response.StatusCode }

            if ($statusCode -eq 429) {
                $retryHeader = try { $_.Exception.Response.Headers['Retry-After'] } catch { $null }
                $wait = if ($retryHeader) { [int]$retryHeader } else { [Math]::Min(5 * [Math]::Pow(2, $attempt - 1), 60) }
                Write-Host "  Throttled (attempt $attempt/5), waiting ${wait}s..." -ForegroundColor DarkYellow
                Start-Sleep -Seconds $wait
                continue
            }

            throw
        }
    }

    throw "Failed after 5 retries: $Uri"
}
#endregion

#region Build device list
if ($PSCmdlet.ParameterSetName -eq 'CSV') {
    if (-not (Test-Path $CSVPath)) { throw "CSV not found: $CSVPath" }
    $CSV = Import-Csv -Path $CSVPath
    if (-not $CSV -or -not $CSV.DeviceName) { throw "CSV must contain a 'DeviceName' column with values." }
    $PerRowTag = ($CSV | Get-Member -Name Tag -MemberType NoteProperty) -ne $null
    $deviceRows = $CSV
    Write-Host "CSV rows: $($CSV.Count) | Per-row tags: $PerRowTag" -ForegroundColor Cyan
}
else {
    $PerRowTag = $false
    $deviceRows = @([PSCustomObject]@{ DeviceName = $DeviceName })
    Write-Host "Single device: $DeviceName" -ForegroundColor Cyan
}
#endregion

#region Fetch Defender machines
Write-Host 'Fetching machines from Defender...' -ForegroundColor Cyan
$resp = Invoke-DefenderCall -Headers $DefH -Uri "$ApiBaseUrl/api/machines"
$AllDef = @($resp.value)
if (-not $AllDef -or $AllDef.Count -eq 0) { throw "No machines returned from Defender API." }
Write-Host "  Machines in tenant: $($AllDef.Count)"
#endregion

#region Process
$stats = [ordered]@{
    Total         = 0
    NotFound      = 0
    Ambiguous     = 0
    AlreadyTagged = 0
    Added         = 0
    Removed       = 0
    NotPresent    = 0
    Skipped       = 0
    Errors        = 0
}

foreach ($row in $deviceRows) {
    $stats.Total++

    $name = [string]$row.DeviceName
    if ([string]::IsNullOrWhiteSpace($name)) { $stats.Skipped++; Write-Warning "Empty DeviceName in row $($stats.Total)"; continue }

    $candidates = $AllDef | Where-Object { $_.computerDnsName -like "$name*" }
    if (-not $candidates -or $candidates.Count -eq 0) {
        Write-Warning "Device not found in Defender: $name"
        $stats.NotFound++
        continue
    }

    $target = $candidates | Where-Object { $_.computerDnsName -ieq $name } | Select-Object -First 1
    $amb = $false
    if (-not $target) { $target = $candidates | Select-Object -First 1; $amb = $true }
    if ($amb -and $candidates.Count -gt 1) {
        $stats.Ambiguous++
        Write-Warning ("Ambiguous match for '{0}' -> taking '{1}' (found {2} candidates)" -f $name, $target.computerDnsName, $candidates.Count)
    }

    $id = $target.id
    $dns = $target.computerDnsName
    $tags = @($target.machineTags)

    $tag = if ($PerRowTag -and $row.Tag) { [string]$row.Tag } else { $MachineTag }

    if ($Action -eq 'Add') {
        if ($tags -contains $tag) {
            $stats.AlreadyTagged++
            Write-Host "Already tagged: $dns -> '$tag'" -ForegroundColor Yellow
            continue
        }

        if ($PSCmdlet.ShouldProcess($dns, "Add tag '$tag'")) {
            try {
                $body = @{ Value = $tag; Action = 'Add' }
                Invoke-DefenderCall -Headers $DefH -Uri "$ApiBaseUrl/api/machines/$id/tags" -Method Post -Body $body | Out-Null
                Write-Host "Added tag '$tag' -> $dns" -ForegroundColor Green
                $stats.Added++
            }
            catch {
                Write-Error "Failed to add tag '$tag' -> $dns ($id): $($_.Exception.Message)"
                $stats.Errors++
            }
        }
    }
    else {
        if ($tags -notcontains $tag) {
            $stats.NotPresent++
            Write-Host "Tag not present: $dns -> '$tag'" -ForegroundColor DarkYellow
            continue
        }

        if ($PSCmdlet.ShouldProcess($dns, "Remove tag '$tag'")) {
            try {
                $body = @{ Value = $tag; Action = 'Remove' }
                Invoke-DefenderCall -Headers $DefH -Uri "$ApiBaseUrl/api/machines/$id/tags" -Method Post -Body $body | Out-Null
                Write-Host "Removed tag '$tag' <- $dns" -ForegroundColor Green
                $stats.Removed++
            }
            catch {
                Write-Error "Failed to remove tag '$tag' <- $dns ($id): $($_.Exception.Message)"
                $stats.Errors++
            }
        }
    }
}
#endregion

#region Summary
Write-Host "`n=== Summary ===" -ForegroundColor Cyan
$stats.GetEnumerator() | ForEach-Object { "{0,-15} {1}" -f $_.Key, $_.Value } | Write-Host
#endregion
