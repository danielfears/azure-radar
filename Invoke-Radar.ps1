<#
.SYNOPSIS
    RADAR - Restricted Action Detector for Azure Roles.

.DESCRIPTION
    Compares a list of restricted Azure RBAC actions (provided via CSV) against
    Azure built-in role definitions, and optionally custom roles authored at a
    specified management group scope. Reports which roles grant any of the
    restricted actions, honoring wildcard permissions and NotActions exclusions.

.PARAMETER InputCsv
    Path to a CSV containing the restricted actions. Must include an "Action" column.

.PARAMETER OutputCsv
    Path to write the CSV report. The output directory will be created if needed.

.PARAMETER OutputHtml
    Optional. Path to write a styled HTML report. The output directory will be created if needed.

.PARAMETER ManagementGroup
    Optional. Name (ID) of a management group. When supplied, RADAR additionally
    scans custom roles whose AssignableScopes is exactly that management group
    (i.e. roles authored at that MG, not inherited from above). Built-in roles
    are always scanned.

.PARAMETER DynamicRestrictedActions
    When set, RADAR derives the restricted-action list at runtime from the
    NotActions of "grant-all then claw-back" custom roles (those whose Actions
    is '*') found at the -ManagementGroup scope, instead of (or together with)
    -InputCsv. This always reflects the live role definitions. Requires
    -ManagementGroup.

.PARAMETER RestrictedFromRoleNames
    Optional. One or more role-name patterns (wildcards supported) that narrow
    which wildcard roles -DynamicRestrictedActions derives from. When omitted,
    every wildcard custom role at the scope is used.

.EXAMPLE
    # Default: scan only built-in roles.
    ./Invoke-Radar.ps1 -InputCsv ./restricted-actions.csv -OutputCsv ./output/radar-report.csv -OutputHtml ./output/radar-report.html

.EXAMPLE
    # Scan built-ins plus custom roles authored at a management group.
    ./Invoke-Radar.ps1 -InputCsv ./restricted-actions.csv -OutputCsv ./output/radar-report.csv -OutputHtml ./output/radar-report.html -ManagementGroup <your-management-group>

.EXAMPLE
    # Derive the restricted actions live from the wildcard claw-back roles at a management group.
    ./Invoke-Radar.ps1 -DynamicRestrictedActions -ManagementGroup <your-management-group> -OutputCsv ./output/radar-report.csv -OutputHtml ./output/radar-report.html -DeniedRolesCsv ./denied-roles.csv
#>

[CmdletBinding()]
param(
    [string]$InputCsv,

    [string]$OutputCsv,

    [string]$OutputHtml,

    [string]$DeniedRolesCsv,

    [string]$ManagementGroup,

    [switch]$NoMenu,

    [switch]$DynamicRestrictedActions,

    [string[]]$RestrictedFromRoleNames
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

# Suppress noisy "Upcoming breaking changes" warnings emitted by Az.Resources cmdlets.
$env:SuppressAzurePowerShellBreakingChangeWarnings = 'true'

# Interactive menu when launched with no scoping parameters.
$invokedWithArgs = $InputCsv -or $OutputCsv -or $OutputHtml -or $ManagementGroup -or $DynamicRestrictedActions
if (-not $invokedWithArgs -and -not $NoMenu) {
    $scriptDir = Split-Path -Parent $PSCommandPath
    $defaultIn     = Join-Path $scriptDir 'restricted-actions.csv'
    $defaultCsv    = Join-Path $scriptDir 'output/radar-report.csv'
    $defaultHtml   = Join-Path $scriptDir 'output/radar-report.html'
    $defaultDenied = Join-Path $scriptDir 'denied-roles.csv'

    Write-Host ''
    Write-Host '========================================' -ForegroundColor Cyan
    Write-Host ' RADAR - Restricted Action Detector' -ForegroundColor Cyan
    Write-Host '========================================' -ForegroundColor Cyan
    Write-Host ''
    Write-Host 'Choose a scan mode:'
    Write-Host '  1) Built-in roles only (default)'
    Write-Host '  2) Built-in roles + custom roles authored at a management group (you will be prompted)'
    Write-Host '  Q) Quit'
    Write-Host ''

    $choice = Read-Host 'Selection [1]'
    if ([string]::IsNullOrWhiteSpace($choice)) { $choice = '1' }

    switch ($choice.ToUpperInvariant()) {
        '1' { }
        '2' {
            $entered = Read-Host 'Management group name'
            if ([string]::IsNullOrWhiteSpace($entered)) {
                throw 'No management group provided.'
            }
            $ManagementGroup = $entered.Trim()
        }
        'Q' { Write-Host 'Cancelled.'; return }
        default { throw "Unknown selection: $choice" }
    }

    if ($ManagementGroup) {
        $dynAns = Read-Host 'Pull restricted actions dynamically from that MG''s wildcard-role NotActions instead of the CSV? [Y/n]'
        if ([string]::IsNullOrWhiteSpace($dynAns) -or $dynAns.Trim().ToUpperInvariant() -eq 'Y') {
            $DynamicRestrictedActions = $true
        }
    }

    if (-not $InputCsv -and -not $DynamicRestrictedActions) { $InputCsv = $defaultIn }
    if (-not $OutputCsv)      { $OutputCsv      = $defaultCsv }
    if (-not $OutputHtml)     { $OutputHtml     = $defaultHtml }
    if (-not $DeniedRolesCsv -and (Test-Path -LiteralPath $defaultDenied)) { $DeniedRolesCsv = $defaultDenied }

    Write-Host ''
    Write-Host 'Running with:'
    if ($DynamicRestrictedActions) {
        Write-Host '  Restricted from: dynamic (NotActions of wildcard roles at the MG)'
        if ($InputCsv) { Write-Host "  + InputCsv:      $InputCsv" }
    } else {
        Write-Host "  InputCsv:        $InputCsv"
    }
    Write-Host "  OutputCsv:       $OutputCsv"
    Write-Host "  OutputHtml:      $OutputHtml"
    if ($DeniedRolesCsv) {
        Write-Host "  DeniedRolesCsv:  $DeniedRolesCsv"
    }
    if ($ManagementGroup) {
        Write-Host "  ManagementGroup: $ManagementGroup"
    } else {
        Write-Host '  ManagementGroup: (none - built-in roles only)'
    }
    Write-Host ''
}

if (-not $OutputCsv) { throw 'OutputCsv is required.' }
if (-not $InputCsv -and -not $DynamicRestrictedActions) {
    throw 'Provide -InputCsv, -DynamicRestrictedActions, or both as the source of restricted actions.'
}
if ($DynamicRestrictedActions -and -not $ManagementGroup) {
    throw '-DynamicRestrictedActions requires -ManagementGroup (the scope where the wildcard claw-back roles are authored).'
}

$IncludeCustomRoles = [bool]$ManagementGroup

function Connect-RadarAzAccount {
    <#
    Ensures the Az.Resources module is loaded and an Azure context exists.
    If a session is already active, the existing context is reused.
    Otherwise, Connect-AzAccount is invoked interactively.
    #>
    if (-not (Get-Module -ListAvailable -Name Az.Accounts)) {
        throw "The Az.Accounts module is required. Install with: Install-Module Az.Accounts"
    }
    if (-not (Get-Module -ListAvailable -Name Az.Resources)) {
        throw "The Az.Resources module is required. Install with: Install-Module Az.Resources"
    }
    Import-Module Az.Accounts -ErrorAction Stop | Out-Null
    Import-Module Az.Resources -ErrorAction Stop | Out-Null

    $ctx = Get-AzContext -ErrorAction SilentlyContinue
    if ($ctx -and $ctx.Account) {
        Write-Host "Using existing Azure session: $($ctx.Account.Id) (tenant $($ctx.Tenant.Id))"
        return
    }

    Write-Host "No active Azure session found. Launching Connect-AzAccount..."
    Connect-AzAccount -ErrorAction Stop | Out-Null

    $ctx = Get-AzContext -ErrorAction SilentlyContinue
    if (-not $ctx -or -not $ctx.Account) {
        throw "Connect-AzAccount completed but no Azure context is available."
    }
    Write-Host "Connected as $($ctx.Account.Id) (tenant $($ctx.Tenant.Id))"
}

function Test-PermissionMatch {
    <#
    Returns $true if the role's permission pattern and the restricted action
    overlap, that is, there exists at least one concrete action that satisfies
    both. Wildcards ('*') are honored on either side.

    Examples that return $true:
      Pattern='Microsoft.Network/*'                  Action='Microsoft.Network/virtualNetworks/write'
      Pattern='Microsoft.Network/virtualNetworks/write' Action='Microsoft.Network/*'
      Pattern='Microsoft.ContainerService/managedClusters/read'
        Action='Microsoft.ContainerService/managedClusters/*'
    #>
    param(
        [string]$Pattern,
        [string]$Action
    )

    if ([string]::IsNullOrWhiteSpace($Pattern) -or [string]::IsNullOrWhiteSpace($Action)) {
        return $false
    }

    $opts  = [System.Text.RegularExpressions.RegexOptions]::IgnoreCase
    $rxPat = '^' + [Regex]::Escape($Pattern).Replace('\*', '.*') + '$'
    $rxAct = '^' + [Regex]::Escape($Action).Replace('\*',  '.*') + '$'

    # Either side's regex matching the literal text of the other implies overlap,
    # because a literal '*' in the other string is consumed by '.*' in the regex.
    return ([Regex]::IsMatch($Action,  $rxPat, $opts) -or
            [Regex]::IsMatch($Pattern, $rxAct, $opts))
}

function ConvertTo-HtmlSafe {
    param([string]$Text)
    if ($null -eq $Text) { return '' }
    return $Text.Replace('&', '&amp;').Replace('<', '&lt;').Replace('>', '&gt;').Replace('"', '&quot;').Replace("'", '&#39;')
}

function ConvertTo-RadarHtmlReport {
    <#
    Renders the RADAR results into a self-contained, styled HTML report.
    #>
    param(
        [Parameter(Mandatory = $true)]
        [System.Collections.IEnumerable]$Results,

        [Parameter(Mandatory = $true)]
        [string[]]$RestrictedActions,

        [Parameter(Mandatory = $true)]
        [int]$RolesScanned,

        [int]$BuiltInScanned = 0,

        [int]$CustomScanned = 0,

        [Parameter(Mandatory = $true)]
        [bool]$IncludeCustomRoles,

        [string]$CustomScope,

        [bool]$DeniedListProvided = $false,

        [string[]]$SourceRoleNames = @()
    )

    $generated = (Get-Date).ToString('u')
    $resultArray = @($Results)
    $totalMatches = $resultArray.Count
    $rolesAffected = ($resultArray | Select-Object -ExpandProperty RoleName -Unique | Measure-Object).Count
    $actionsTriggered = ($resultArray | Select-Object -ExpandProperty RestrictedAction -Unique | Measure-Object).Count

    # Group by role for a collapsible per-role section.
    $grouped = $resultArray | Group-Object -Property RoleName | Sort-Object Name

    $sb = [System.Text.StringBuilder]::new()
    [void]$sb.AppendLine('<!DOCTYPE html>')
    [void]$sb.AppendLine('<html lang="en"><head><meta charset="utf-8"/>')
    [void]$sb.AppendLine('<meta name="viewport" content="width=device-width,initial-scale=1"/>')
    [void]$sb.AppendLine('<title>RADAR Report</title>')
    [void]$sb.AppendLine(@'
<style>
  :root {
    --bg: #0b1020;
    --panel: #131a33;
    --panel-2: #1a2245;
    --text: #e6ebff;
    --muted: #9aa3c7;
    --accent: #6ea8ff;
    --danger: #ff5c7a;
    --warn: #ffb86b;
    --ok: #5be3b1;
    --border: #2a335c;
  }
  * { box-sizing: border-box; }
  body {
    margin: 0; font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, Helvetica, Arial, sans-serif;
    background: linear-gradient(180deg, #0b1020 0%, #0d1530 100%);
    color: var(--text);
    min-height: 100vh;
  }
  header {
    padding: 28px 36px; border-bottom: 1px solid var(--border);
    display: flex; align-items: center; justify-content: center; gap: 16px; text-align: center;
    background: rgba(255,255,255,0.02);
  }
  header .logo {
    width: 44px; height: 44px; border-radius: 10px;
    background: radial-gradient(circle at 30% 30%, var(--accent), #2b3a8c 70%);
    box-shadow: 0 0 24px rgba(110,168,255,0.45);
  }
  header h1 { margin: 0; font-size: 22px; letter-spacing: 0.5px; }
  header .sub { color: var(--muted); font-size: 13px; margin-top: 2px; }
  main { padding: 28px 36px 60px; max-width: 1400px; margin: 0 auto; }
  .grid { display: grid; grid-template-columns: repeat(auto-fit, minmax(200px, 1fr)); gap: 16px; margin-bottom: 28px; }
  .card {
    background: var(--panel); border: 1px solid var(--border);
    border-radius: 12px; padding: 18px 20px;
  }
  .card .label { color: var(--muted); font-size: 12px; text-transform: uppercase; letter-spacing: 1px; }
  .card .value { font-size: 28px; font-weight: 600; margin-top: 6px; }
  .value.danger { color: var(--danger); }
  .value.warn { color: var(--warn); }
  .value.ok { color: var(--ok); }
  .value.accent { color: var(--accent); }

  .toolbar {
    display: flex; gap: 12px; align-items: center; margin: 12px 0 18px; flex-wrap: wrap;
  }
  .toolbar input[type="search"] {
    flex: 1; min-width: 240px;
    background: var(--panel); color: var(--text);
    border: 1px solid var(--border); border-radius: 8px;
    padding: 10px 12px; font-size: 14px;
  }
  .toolbar input[type="search"]:focus { outline: none; border-color: var(--accent); }
  .toolbar button {
    flex: 0 0 auto; cursor: pointer;
    background: var(--panel-2); color: var(--text);
    border: 1px solid var(--border); border-radius: 8px;
    padding: 10px 16px; font-size: 13px; white-space: nowrap;
  }
  .toolbar button:hover { border-color: var(--accent); color: var(--accent); }

  .role {
    background: var(--panel); border: 1px solid var(--border); border-radius: 12px;
    margin-bottom: 14px; overflow: hidden;
  }
  .role summary {
    list-style: none; cursor: pointer; padding: 14px 18px;
    display: flex; align-items: center; gap: 12px;
    background: var(--panel-2);
    flex-wrap: wrap;
  }
  .role summary::-webkit-details-marker { display: none; }
  .role summary .chev { transition: transform .15s ease; color: var(--muted); flex: 0 0 auto; }
  .role[open] summary .chev { transform: rotate(90deg); }
  .role .name { font-weight: 600; flex: 0 1 auto; min-width: 0; word-break: break-word; }
  .role .role-id {
    flex: 1 1 auto; min-width: 0;
    color: var(--muted); font-size: 11px;
    font-family: ui-monospace, SFMono-Regular, Menlo, Consolas, monospace;
    white-space: nowrap; overflow: hidden; text-overflow: ellipsis;
  }
  .role .count {
    margin-left: auto;
    background: rgba(255,92,122,0.15); color: var(--danger);
    border: 1px solid rgba(255,92,122,0.4);
    padding: 2px 10px; border-radius: 999px; font-size: 12px;
    flex: 0 0 auto;
  }
  .role .badge {
    background: rgba(110,168,255,0.12); color: var(--accent);
    border: 1px solid rgba(110,168,255,0.35);
    padding: 2px 8px; border-radius: 6px; font-size: 11px; text-transform: uppercase; letter-spacing: 0.5px;
    flex: 0 0 auto;
  }
  .role .badge.custom {
    background: rgba(255,184,107,0.12); color: var(--warn);
    border-color: rgba(255,184,107,0.45);
  }
  .role.is-denied { border-left: 3px solid var(--ok); }
  .role.is-undenied { border-left: 3px solid var(--danger); }
  .role.is-custom.is-undenied { border-left: 3px solid var(--danger); }
  .role .badge.denied {
    background: rgba(91,227,177,0.12); color: var(--ok);
    border-color: rgba(91,227,177,0.4);
  }
  .role .badge.undenied {
    background: rgba(255,92,122,0.15); color: var(--danger);
    border-color: rgba(255,92,122,0.45);
  }

  table { width: 100%; border-collapse: collapse; table-layout: auto; }
  th, td {
    padding: 10px 14px; text-align: left; font-size: 13px;
    border-bottom: 1px solid var(--border);
    vertical-align: middle;
    white-space: nowrap;
  }
  .role .table-wrap { overflow-x: auto; }
  th { color: var(--muted); font-weight: 500; text-transform: uppercase; letter-spacing: 0.6px; font-size: 11px; }
  tr:last-child td { border-bottom: none; }
  td.code, .code { font-family: ui-monospace, SFMono-Regular, Menlo, Consolas, monospace; font-size: 12.5px; color: #d6deff; }

  details.actions-list {
    background: var(--panel); border: 1px solid var(--border); border-radius: 12px;
    padding: 14px 18px; margin-bottom: 28px;
  }
  details.actions-list summary { cursor: pointer; color: var(--muted); }
  details.actions-list ul { columns: 2; column-gap: 32px; margin: 12px 0 0; padding-left: 20px; }
  details.actions-list li { font-family: ui-monospace, SFMono-Regular, Menlo, Consolas, monospace; font-size: 12.5px; padding: 2px 0; }
  details.actions-list.exposed { border-color: rgba(255,92,122,0.45); }
  details.actions-list.exposed summary { color: var(--danger); }
  details.actions-list .note { color: var(--muted); font-size: 12px; margin: 10px 0 0; max-width: 760px; }
  details.actions-list li .via { color: var(--muted); font-size: 11px; font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", sans-serif; }

  footer { color: var(--muted); font-size: 12px; text-align: center; padding: 20px; }
  .empty {
    background: var(--panel); border: 1px dashed var(--border); border-radius: 12px;
    padding: 40px; text-align: center; color: var(--muted);
  }

  .compliance {
    display: flex; align-items: center; gap: 28px; flex-wrap: wrap;
    background: var(--panel); border: 1px solid var(--border);
    border-radius: 12px; padding: 22px 26px; margin-bottom: 22px;
  }
  .donut { flex: 0 0 auto; }
  .donut .track { stroke: rgba(255,92,122,0.22); }
  .donut .arc { stroke: var(--ok); }
  .donut .pct { font-size: 28px; font-weight: 700; fill: var(--text); }
  .donut .pct-sub { font-size: 10px; fill: var(--muted); text-transform: uppercase; letter-spacing: 1.5px; }
  .compliance-info { flex: 1 1 240px; }
  .compliance-info h2 { margin: 0 0 4px; font-size: 16px; }
  .compliance-info p { margin: 0; color: var(--muted); font-size: 13px; max-width: 540px; }
  .compliance-info .nums { margin-top: 14px; display: flex; gap: 26px; flex-wrap: wrap; }
  .compliance-info .num { font-size: 12px; color: var(--muted); text-transform: uppercase; letter-spacing: 0.5px; }
  .compliance-info .num b { font-size: 22px; display: block; color: var(--text); letter-spacing: 0; }
  .compliance-info .num.ok b { color: var(--ok); }
  .compliance-info .num.gap b { color: var(--danger); }
</style>
'@)
    [void]$sb.AppendLine('</head><body>')

    [void]$sb.AppendLine('<header><div class="logo"></div><div>')
    [void]$sb.AppendLine('<h1>RADAR - Restricted Action Detector for Azure Roles</h1>')
    $scope = if ($IncludeCustomRoles) { 'built-in &amp; custom roles' } else { 'built-in roles' }
    $scopeNote = if ($IncludeCustomRoles -and $CustomScope) {
        ' &middot; ' + (ConvertTo-HtmlSafe $CustomScope)
    } else { '' }
    [void]$sb.AppendLine("<div class=`"sub`">Generated $generated &middot; Scope: $scope$scopeNote</div>")
    [void]$sb.AppendLine('</div></header>')

    [void]$sb.AppendLine('<main>')

    $customMatches  = @(@($Results) | Where-Object { $_.IsCustom }).Count
    $builtInMatches = $totalMatches - $customMatches

    # Compute denied / not-denied across affected roles (per unique role).
    $affectedRoles = @($Results) | Group-Object -Property RoleName
    $rolesAlreadyDenied = 0
    $rolesNotYetDenied  = 0
    foreach ($g in $affectedRoles) {
        $first = $g.Group | Select-Object -First 1
        if ($first.PSObject.Properties['IsAlreadyDenied'] -and $first.IsAlreadyDenied) {
            $rolesAlreadyDenied++
        } else {
            $rolesNotYetDenied++
        }
    }

    # Deny-policy coverage donut (compliance %).
    if ($DeniedListProvided -and $rolesAffected -gt 0) {
        $coveragePct = [math]::Round((($rolesAlreadyDenied / $rolesAffected) * 100), 0)
        $radius = 52
        $circ   = 2 * [math]::PI * $radius
        $arc    = [math]::Round((($coveragePct / 100) * $circ), 2)
        $rest   = [math]::Round(($circ - $arc), 2)
        [void]$sb.AppendLine('<section class="compliance">')
        [void]$sb.AppendLine('<svg class="donut" viewBox="0 0 120 120" width="150" height="150" role="img" aria-label="Deny-policy coverage ' + $coveragePct + ' percent">')
        [void]$sb.AppendLine('  <circle class="track" cx="60" cy="60" r="' + $radius + '" fill="none" stroke-width="14"/>')
        [void]$sb.AppendLine('  <circle class="arc" cx="60" cy="60" r="' + $radius + '" fill="none" stroke-width="14" stroke-linecap="round" transform="rotate(-90 60 60)" stroke-dasharray="' + $arc + ' ' + $rest + '"/>')
        [void]$sb.AppendLine('  <text class="pct" x="60" y="60" text-anchor="middle" dominant-baseline="central">' + $coveragePct + '%</text>')
        [void]$sb.AppendLine('  <text class="pct-sub" x="60" y="80" text-anchor="middle">covered</text>')
        [void]$sb.AppendLine('</svg>')
        [void]$sb.AppendLine('<div class="compliance-info">')
        [void]$sb.AppendLine('  <h2>Deny-policy coverage</h2>')
        [void]$sb.AppendLine('  <p>Share of roles that grant a restricted action and are already blocked by the deny policy.<br />The remainder are the roles still to add.</p>')
        [void]$sb.AppendLine('  <div class="nums">')
        [void]$sb.AppendLine('    <div class="num"><b>' + $rolesAffected + '</b>roles affected</div>')
        [void]$sb.AppendLine('    <div class="num ok"><b>' + $rolesAlreadyDenied + '</b>already denied</div>')
        [void]$sb.AppendLine('    <div class="num gap"><b>' + $rolesNotYetDenied + '</b>still to deny</div>')
        [void]$sb.AppendLine('  </div>')
        [void]$sb.AppendLine('</div>')
        [void]$sb.AppendLine('</section>')
    }

    # Summary cards.
    [void]$sb.AppendLine('<section class="grid">')
    [void]$sb.AppendLine("<div class=`"card`"><div class=`"label`">Built-in Scanned</div><div class=`"value accent`">$BuiltInScanned</div></div>")
    if ($IncludeCustomRoles) {
        [void]$sb.AppendLine("<div class=`"card`"><div class=`"label`">Custom Scanned</div><div class=`"value accent`">$CustomScanned</div></div>")
    }
    [void]$sb.AppendLine("<div class=`"card`"><div class=`"label`">Restricted Actions</div><div class=`"value`">$($RestrictedActions.Count)</div></div>")
    if ($SourceRoleNames -and $SourceRoleNames.Count -gt 0) {
        $srcTitle = ConvertTo-HtmlSafe ($SourceRoleNames -join ', ')
        [void]$sb.AppendLine("<div class=`"card`" title=`"$srcTitle`"><div class=`"label`">Source Roles</div><div class=`"value accent`">$($SourceRoleNames.Count)</div></div>")
    }
    [void]$sb.AppendLine('</section>')

    # Restricted actions input list.
    [void]$sb.AppendLine('<details class="actions-list"><summary>Restricted actions evaluated (' + $RestrictedActions.Count + ')</summary><ul>')
    foreach ($a in $RestrictedActions) {
        [void]$sb.AppendLine('<li>' + (ConvertTo-HtmlSafe $a) + '</li>')
    }
    [void]$sb.AppendLine('</ul></details>')

    # Currently obtainable restricted actions: still granted by at least one role
    # not on the deny list, so a user who can assign roles could regain them.
    if ($DeniedListProvided) {
        $obtainable = [ordered]@{}
        foreach ($item in $resultArray) {
            $isDen = $item.PSObject.Properties['IsAlreadyDenied'] -and $item.IsAlreadyDenied
            if (-not $isDen) {
                $act = [string]$item.RestrictedAction
                if (-not $obtainable.Contains($act)) { $obtainable[$act] = New-Object System.Collections.Generic.List[string] }
                $rn = [string]$item.RoleName
                if (-not $obtainable[$act].Contains($rn)) { [void]$obtainable[$act].Add($rn) }
            }
        }
        $obtainableActions = @($obtainable.Keys | Sort-Object)
        $obtainClass = if ($obtainableActions.Count -gt 0) { 'actions-list exposed' } else { 'actions-list' }
        [void]$sb.AppendLine('<details class="' + $obtainClass + '"><summary>Currently obtainable restricted actions (' + $obtainableActions.Count + ' of ' + $RestrictedActions.Count + ')</summary>')
        [void]$sb.AppendLine('<p class="note">Restricted actions still granted by at least one role that is not on the deny list. A user who can assign roles could regain these by self-assigning an un-denied role. Hover an action to see which roles grant it.</p>')
        if ($obtainableActions.Count -eq 0) {
            [void]$sb.AppendLine('<p class="note">None - every restricted action is granted only by roles already on the deny list.</p>')
        }
        else {
            [void]$sb.AppendLine('<ul>')
            foreach ($act in $obtainableActions) {
                $roles = $obtainable[$act]
                $titleSafe = ConvertTo-HtmlSafe ((@($roles) | Sort-Object) -join ', ')
                $plural = if ($roles.Count -ne 1) { 's' } else { '' }
                [void]$sb.AppendLine('<li title="' + $titleSafe + '">' + (ConvertTo-HtmlSafe $act) + ' <span class="via">(' + $roles.Count + ' role' + $plural + ')</span></li>')
            }
            [void]$sb.AppendLine('</ul>')
        }
        [void]$sb.AppendLine('</details>')
    }

    # Toolbar / filter.
    [void]$sb.AppendLine('<div class="toolbar"><input id="filter" type="search" placeholder="Filter by role name, action, or matched pattern..." /><button id="toggle-all" type="button">Expand all</button></div>')

    if ($grouped.Count -eq 0) {
        [void]$sb.AppendLine('<div class="empty">No matches found. None of the scanned roles grant the restricted actions.</div>')
    }
    else {
        foreach ($g in $grouped) {
            $roleName = $g.Name
            $items = $g.Group | Sort-Object RestrictedAction
            $first = $items | Select-Object -First 1
            $isCustom = $first.IsCustom
            $roleId = $first.RoleId
            $isAlreadyDenied = $first.PSObject.Properties['IsAlreadyDenied'] -and $first.IsAlreadyDenied

            $badge = if ($isCustom) { '<span class="badge custom">Custom</span>' } else { '<span class="badge">Built-in</span>' }

            $denyBadge = ''
            if ($DeniedListProvided) {
                $denyBadge = if ($isAlreadyDenied) {
                    ' <span class="badge denied">Denied</span>'
                } else {
                    ' <span class="badge undenied">Not Denied</span>'
                }
            }

            $roleClasses = @('role')
            if ($isCustom) { $roleClasses += 'is-custom' }
            if ($DeniedListProvided -and -not $isAlreadyDenied) { $roleClasses += 'is-undenied' }
            if ($DeniedListProvided -and $isAlreadyDenied) { $roleClasses += 'is-denied' }
            $roleClass = $roleClasses -join ' '

            $matchWord = if ($items.Count -eq 1) { 'match' } else { 'matches' }
            [void]$sb.AppendLine('<details class="' + $roleClass + '">')
            [void]$sb.AppendLine('<summary><span class="chev">&#9656;</span><span class="name">' + (ConvertTo-HtmlSafe $roleName) + '</span> ' + $badge + $denyBadge + ' <span class="role-id" title="' + (ConvertTo-HtmlSafe $roleId) + '">' + (ConvertTo-HtmlSafe $roleId) + '</span><span class="count">' + $items.Count + ' ' + $matchWord + '</span></summary>')
            [void]$sb.AppendLine('<div class="table-wrap"><table><thead><tr><th>Restricted Action</th><th>Matched Pattern</th></tr></thead><tbody>')

            foreach ($item in $items) {
                [void]$sb.AppendLine('<tr>')
                [void]$sb.AppendLine('<td class="code">' + (ConvertTo-HtmlSafe $item.RestrictedAction) + '</td>')
                [void]$sb.AppendLine('<td class="code">' + (ConvertTo-HtmlSafe $item.MatchedPattern) + '</td>')
                [void]$sb.AppendLine('</tr>')
            }

            [void]$sb.AppendLine('</tbody></table></div></details>')
        }
    }

    [void]$sb.AppendLine('</main>')
    [void]$sb.AppendLine('<footer>RADAR report &middot; ' + $generated + '</footer>')

    # Client-side filter.
    [void]$sb.AppendLine(@'
<script>
  const input = document.getElementById('filter');
  if (input) {
    input.addEventListener('input', () => {
      const q = input.value.toLowerCase().trim();
      document.querySelectorAll('details.role').forEach(role => {
        const summaryText = role.querySelector('summary').innerText.toLowerCase();
        let any = false;
        role.querySelectorAll('tbody tr').forEach(tr => {
          const match = tr.innerText.toLowerCase().includes(q);
          tr.style.display = match ? '' : 'none';
          if (match) any = true;
        });
        const summaryMatch = summaryText.includes(q);
        role.style.display = (any || summaryMatch || q === '') ? '' : 'none';
        if (q !== '' && (any || summaryMatch)) role.open = true;
      });
    });
  }

  const toggleBtn = document.getElementById('toggle-all');
  if (toggleBtn) {
    toggleBtn.addEventListener('click', () => {
      const roles = document.querySelectorAll('details.role');
      const expand = Array.from(roles).some(r => !r.open);
      roles.forEach(r => { r.open = expand; });
      toggleBtn.textContent = expand ? 'Collapse all' : 'Expand all';
    });
  }
</script>
'@)
    [void]$sb.AppendLine('</body></html>')

    return $sb.ToString()
}

function Get-RoleProperty {
    <#
    Safely reads an array-typed property from a role definition, handling
    strict mode and roles that may not expose every collection.
    #>
    param(
        [object]$Role,
        [string]$Name
    )
    $member = $Role.PSObject.Properties[$Name]
    if (-not $member) { return @() }
    $value = $member.Value
    if ($null -eq $value) { return @() }
    return @($value)
}

function Get-ActionMatch {
    <#
    Determines whether a role grants the given action via its Actions while not
    being excluded via NotActions. Returns the matching pattern, or $null if no
    effective match exists.
    #>
    param(
        [object]$Role,
        [string]$Action
    )

    $actions    = @(Get-RoleProperty -Role $Role -Name 'Actions')
    $notActions = @(Get-RoleProperty -Role $Role -Name 'NotActions')

    $matchedAction = $actions | Where-Object { Test-PermissionMatch -Pattern $_ -Action $Action } | Select-Object -First 1
    if ($matchedAction) {
        $excluded = $notActions | Where-Object { Test-PermissionMatch -Pattern $_ -Action $Action } | Select-Object -First 1
        if (-not $excluded) {
            return [pscustomobject]@{
                MatchedPattern = $matchedAction
            }
        }
    }

    return $null
}

# --- Main ---------------------------------------------------------------

Connect-RadarAzAccount

$csvActions = @()
if ($InputCsv) {
    if (-not (Test-Path -LiteralPath $InputCsv)) {
        throw "Input CSV not found: $InputCsv"
    }

    $restricted = Import-Csv -LiteralPath $InputCsv
    if (-not ($restricted | Get-Member -Name 'Action' -MemberType NoteProperty)) {
        throw "Input CSV must contain an 'Action' column."
    }

    $csvActions = @($restricted.Action |
        Where-Object { -not [string]::IsNullOrWhiteSpace($_) } |
        ForEach-Object { $_.Trim() })

    Write-Host "Loaded $(@($csvActions | Sort-Object -Unique).Count) restricted action(s) from $InputCsv"
}

# Optional: load list of role names already denied (e.g. via Azure Policy / blocklist).
$deniedRoleSet = New-Object System.Collections.Generic.HashSet[string] ([StringComparer]::OrdinalIgnoreCase)
if ($DeniedRolesCsv) {
    if (-not (Test-Path -LiteralPath $DeniedRolesCsv)) {
        throw "Denied roles CSV not found: $DeniedRolesCsv"
    }
    $deniedRows = Import-Csv -LiteralPath $DeniedRolesCsv
    if (-not ($deniedRows | Get-Member -Name 'RoleName' -MemberType NoteProperty)) {
        throw "Denied roles CSV must contain a 'RoleName' column."
    }
    foreach ($row in $deniedRows) {
        $name = $row.RoleName
        if (-not [string]::IsNullOrWhiteSpace($name)) {
            [void]$deniedRoleSet.Add($name.Trim())
        }
    }
    Write-Host "Loaded $($deniedRoleSet.Count) denied role name(s) from $DeniedRolesCsv"
}

Write-Host "Fetching Azure role definitions..."

$builtInRoles = @(Get-AzRoleDefinition -WarningAction SilentlyContinue | Where-Object { -not $_.IsCustom })
Write-Host "  Built-in roles found: $($builtInRoles.Count)"

$customRoles = @()
$rawCustom   = @()
$scopeLabel  = $null

if ($ManagementGroup) {
    $mgScope = "/providers/Microsoft.Management/managementGroups/$ManagementGroup"
    try {
        $rawCustom = @(Get-AzRoleDefinition -Custom -Scope $mgScope -WarningAction SilentlyContinue -ErrorAction Stop)
    }
    catch {
        Write-Warning "Failed to enumerate custom roles at $mgScope`: $($_.Exception.Message)"
        $rawCustom = @()
    }

    # Keep only roles whose AssignableScopes is exactly the supplied MG.
    $customRoles = @($rawCustom | Where-Object {
        $_.PSObject.Properties['AssignableScopes'] -and
        $_.AssignableScopes -and
        ($_.AssignableScopes | Where-Object { $_ -ieq $mgScope })
    })

    $scopeLabel = "MG '$ManagementGroup'"
    Write-Host "  Custom roles found:   $($customRoles.Count) (authored at $scopeLabel; $($rawCustom.Count - $customRoles.Count) inherited from above were excluded)"
}

# Derive restricted actions dynamically from the NotActions of wildcard
# "grant-all then claw-back" roles (Actions = '*') found at the MG scope.
$dynamicActions = @()
$dynamicSourceRoleNames = @()
if ($DynamicRestrictedActions) {
    $sourceRoles = @($rawCustom | Where-Object { @(Get-RoleProperty -Role $_ -Name 'Actions') -contains '*' })
    if ($RestrictedFromRoleNames) {
        $sourceRoles = @($sourceRoles | Where-Object {
            $rn = $_.Name
            @($RestrictedFromRoleNames | Where-Object { $rn -like $_ }).Count -gt 0
        })
    }
    $dynamicSourceRoleNames = @($sourceRoles | ForEach-Object { $_.Name })

    $naSet = New-Object System.Collections.Generic.HashSet[string] ([StringComparer]::OrdinalIgnoreCase)
    foreach ($sr in $sourceRoles) {
        foreach ($na in @(Get-RoleProperty -Role $sr -Name 'NotActions')) {
            if (-not [string]::IsNullOrWhiteSpace($na)) { [void]$naSet.Add($na.Trim()) }
        }
    }
    $dynamicActions = @($naSet)

    if ($sourceRoles.Count -eq 0) {
        Write-Warning "Dynamic mode: no wildcard (Actions = '*') roles found at $scopeLabel to derive NotActions from."
    }
    else {
        Write-Host "  Derived $($dynamicActions.Count) restricted action(s) from $($sourceRoles.Count) wildcard role(s): $(@($sourceRoles | ForEach-Object { $_.Name }) -join ', ')"
    }
}

# Final restricted-action set: CSV actions and/or dynamically derived NotActions.
$restrictedActions = @(@($csvActions) + @($dynamicActions) |
    Where-Object { -not [string]::IsNullOrWhiteSpace($_) } |
    ForEach-Object { $_.Trim() } |
    Sort-Object -Unique)

if ($restrictedActions.Count -eq 0) {
    throw "No restricted actions to evaluate. Provide -InputCsv with entries and/or -DynamicRestrictedActions with wildcard roles present at the scope."
}

Write-Host "Total restricted actions to evaluate: $($restrictedActions.Count)"

$roles = @()
$roles += $builtInRoles
$roles += $customRoles

if ($roles.Count -eq 0) {
    throw "No role definitions to evaluate. Check your Azure context."
}

Write-Host "Evaluating $($roles.Count) role(s)..."

$results = New-Object System.Collections.Generic.List[object]

foreach ($role in $roles) {
    foreach ($action in $restrictedActions) {
        $match = Get-ActionMatch -Role $role -Action $action
        if ($null -ne $match) {
            $results.Add([pscustomobject]@{
                RoleName         = $role.Name
                RoleId           = $role.Id
                IsCustom         = $role.IsCustom
                RestrictedAction = $action
                MatchedPattern   = $match.MatchedPattern
                IsAlreadyDenied  = $deniedRoleSet.Contains([string]$role.Name)
            }) | Out-Null
        }
    }
}

$outputDir = Split-Path -Parent $OutputCsv
if ($outputDir -and -not (Test-Path -LiteralPath $outputDir)) {
    New-Item -ItemType Directory -Path $outputDir -Force | Out-Null
}

$results | Sort-Object RoleName, RestrictedAction | Export-Csv -LiteralPath $OutputCsv -NoTypeInformation

if ($OutputHtml) {

    $htmlDir = Split-Path -Parent $OutputHtml
    if ($htmlDir -and -not (Test-Path -LiteralPath $htmlDir)) {
        New-Item -ItemType Directory -Path $htmlDir -Force | Out-Null
    }

    $effectiveScope = if ($ManagementGroup) {
        "Management group: $ManagementGroup"
    } else { $null }

    $html = ConvertTo-RadarHtmlReport `
        -Results ($results | Sort-Object RoleName, RestrictedAction) `
        -RestrictedActions $restrictedActions `
        -RolesScanned $roles.Count `
        -BuiltInScanned $builtInRoles.Count `
        -CustomScanned $customRoles.Count `
        -IncludeCustomRoles ([bool]$IncludeCustomRoles) `
        -CustomScope $effectiveScope `
        -DeniedListProvided ([bool]$DeniedRolesCsv) `
        -SourceRoleNames $dynamicSourceRoleNames

    Set-Content -LiteralPath $OutputHtml -Value $html -Encoding UTF8
}

$customMatches = @($results | Where-Object { $_.IsCustom }).Count
$builtInMatches = $results.Count - $customMatches

Write-Host ""
Write-Host "RADAR scan complete."
Write-Host "  Roles scanned:        $($roles.Count) (built-in: $($builtInRoles.Count), custom: $($customRoles.Count))"
Write-Host "  Matches found:        $($results.Count) (built-in: $builtInMatches, custom: $customMatches)"
Write-Host "  Roles affected:       $((($results | Select-Object -ExpandProperty RoleName -Unique) | Measure-Object).Count)"
if ($DeniedRolesCsv) {
    $uniqueAffected   = @($results | Select-Object -ExpandProperty RoleName -Unique)
    $alreadyDenied    = @($uniqueAffected | Where-Object { $deniedRoleSet.Contains($_) })
    $notYetDenied     = @($uniqueAffected | Where-Object { -not $deniedRoleSet.Contains($_) })
    Write-Host "  Roles already denied: $($alreadyDenied.Count)"
    Write-Host "  Roles to deny:        $($notYetDenied.Count)"
    if ($notYetDenied.Count -gt 0) {
        foreach ($n in ($notYetDenied | Sort-Object)) {
            Write-Host "    - $n"
        }
    }
}
Write-Host "  CSV report:           $OutputCsv"
if ($OutputHtml) {
    Write-Host "  HTML report:          $OutputHtml"
}
