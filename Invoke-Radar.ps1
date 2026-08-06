<#
.SYNOPSIS
    RADAR - Restricted Action Detector for Azure Roles.

.DESCRIPTION
    Compares restricted Azure RBAC actions against built-in and custom role
    definitions across the accessible Azure estate. It discovers Azure Policy
    assignments that deny role assignments and reports the restricted actions
    that remain potentially obtainable through roles not denied at every
    scanned scope.

.PARAMETER InputCsv
    Path to a CSV containing the restricted actions. Must include an "Action" column.

.PARAMETER OutputCsv
    Path to write the CSV report. The output directory will be created if needed.

.PARAMETER OutputHtml
    Optional. Path to write a styled HTML report. The output directory will be created if needed.

.PARAMETER DeniedRolesCsv
    Optional supplement containing role names known to be denied everywhere.
    Live Azure Policy discovery remains enabled unless -NoPolicyDiscovery is set.

.PARAMETER Scope
    Optional Azure resource scope IDs to scan. Accepts management group,
    subscription, resource group, or resource IDs. When omitted, RADAR discovers
    accessible management groups and subscriptions in the current tenant.

.PARAMETER ManagementGroup
    Backwards-compatible shortcut for scanning one management group. Use -Scope
    for multiple or non-management-group scopes.

.PARAMETER CurrentSubscriptionOnly
    Limits discovery to the current Azure subscription.

.PARAMETER BuiltInOnly
    Skips custom-role discovery. Policy coverage is still evaluated across the
    selected scopes.

.PARAMETER DynamicRestrictedActions
    When set, RADAR derives the restricted-action list at runtime from the
    NotActions of matching "grant-all then claw-back" custom roles found across
    the selected estate, instead of (or together with) -InputCsv.

.PARAMETER BaselineRolePattern
    Optional role-name wildcard patterns used by -DynamicRestrictedActions.
    When omitted, RADAR selects custom wildcard roles with Owner, Contributor,
    or Baseline in the name. Supply patterns to override auto-detection.

.PARAMETER NoPolicyDiscovery
    Disables live discovery of Azure Policy assignments that deny roles.

.PARAMETER TargetPrincipalType
    Principal type used when evaluating role-assignment policy conditions.
    Defaults to User.

.PARAMETER TargetPrincipalId
    Optional object ID of the principal receiving the role. When omitted,
    RADAR models an ordinary principal that is not explicitly exempted.

.PARAMETER NoAssignmentDiscovery
    Disables live correlation of direct baseline-role assignments. Findings
    remain capability-only and assignment exposure is reported as unknown.

.PARAMETER NoPrincipalCorrelation
    Disables principal-level net-new escalation correlation. The secondary
    capability and scope-posture reports are still produced.

.EXAMPLE
    # Scan the accessible estate and derive deny coverage from Azure Policy.
    ./Invoke-Radar.ps1 -InputCsv ./restricted-actions.csv -OutputCsv ./output/radar-report.csv -OutputHtml ./output/radar-report.html

.EXAMPLE
    # Limit the scan to one management group.
    ./Invoke-Radar.ps1 -InputCsv ./restricted-actions.csv -OutputCsv ./output/radar-report.csv -ManagementGroup <your-management-group>

.EXAMPLE
    # Derive restricted actions from customer-specific baseline roles.
    ./Invoke-Radar.ps1 -DynamicRestrictedActions -BaselineRolePattern '*-Owner-*','*-Contributor-*' -OutputCsv ./output/radar-report.csv
#>

[CmdletBinding()]
param(
    [string]$InputCsv,

    [string]$OutputCsv,

    [string]$OutputHtml,

    [string]$DeniedRolesCsv,

    [string[]]$Scope,

    [string]$ManagementGroup,

    [switch]$CurrentSubscriptionOnly,

    [switch]$BuiltInOnly,

    [switch]$NoMenu,

    [switch]$DynamicRestrictedActions,

    [string[]]$BaselineRolePattern = @(),

    [ValidateSet('User', 'Group', 'ServicePrincipal')]
    [string]$TargetPrincipalType = 'User',

    [string]$TargetPrincipalId,

    [switch]$NoAssignmentDiscovery,

    [switch]$NoPrincipalCorrelation,

    [switch]$NoPolicyDiscovery
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

# Suppress noisy "Upcoming breaking changes" warnings emitted by Az.Resources cmdlets.
$env:SuppressAzurePowerShellBreakingChangeWarnings = 'true'
$scriptDir = Split-Path -Parent $PSCommandPath
$defaultInputCsv = Join-Path $scriptDir 'restricted-actions.csv'
$effectiveTargetPrincipalId = if (
    [string]::IsNullOrWhiteSpace($TargetPrincipalId)
) {
    '__RADAR_NON_EXEMPT_PRINCIPAL__'
}
else {
    $TargetPrincipalId
}
$targetPrincipalScenario = if (
    [string]::IsNullOrWhiteSpace($TargetPrincipalId)
) {
    "Non-exempt $TargetPrincipalType"
}
else {
    "$TargetPrincipalType with supplied principal ID"
}

# Interactive menu when launched with no scoping parameters.
$invokedWithArgs =
    $InputCsv -or
    $OutputCsv -or
    $OutputHtml -or
    $Scope -or
    $ManagementGroup -or
    $CurrentSubscriptionOnly -or
    $BuiltInOnly -or
    $DynamicRestrictedActions -or
    $NoAssignmentDiscovery -or
    $NoPrincipalCorrelation -or
    $PSBoundParameters.ContainsKey('TargetPrincipalType') -or
    $PSBoundParameters.ContainsKey('TargetPrincipalId')
if (-not $invokedWithArgs -and -not $NoMenu) {
    $defaultIn     = $defaultInputCsv
    $defaultCsv    = Join-Path $scriptDir 'output/radar-report.csv'
    $defaultHtml   = Join-Path $scriptDir 'output/radar-report.html'

    Write-Host ''
    Write-Host '========================================' -ForegroundColor Cyan
    Write-Host ' RADAR - Restricted Action Detector' -ForegroundColor Cyan
    Write-Host '========================================' -ForegroundColor Cyan
    Write-Host ''
    Write-Host 'Choose a scan mode:'
    Write-Host '  1) Accessible estate: management groups + subscriptions (default)'
    Write-Host '  2) Current subscription only'
    Write-Host '  3) One management group (you will be prompted)'
    Write-Host '  4) Built-in roles only across the accessible estate'
    Write-Host '  Q) Quit'
    Write-Host ''

    $choice = Read-Host 'Selection [1]'
    if ([string]::IsNullOrWhiteSpace($choice)) { $choice = '1' }

    switch ($choice.ToUpperInvariant()) {
        '1' { }
        '2' { $CurrentSubscriptionOnly = $true }
        '3' {
            $entered = Read-Host 'Management group name'
            if ([string]::IsNullOrWhiteSpace($entered)) {
                throw 'No management group provided.'
            }
            $ManagementGroup = $entered.Trim()
        }
        '4' { $BuiltInOnly = $true }
        'Q' { Write-Host 'Cancelled.'; return }
        default { throw "Unknown selection: $choice" }
    }

    if (-not $BuiltInOnly) {
        $dynAns = Read-Host 'Also derive restricted actions from baseline wildcard-role NotActions? [y/N]'
        if ($dynAns.Trim().ToUpperInvariant() -eq 'Y') {
            $DynamicRestrictedActions = $true
        }
    }

    if (-not $InputCsv) { $InputCsv = $defaultIn }
    if (-not $OutputCsv)      { $OutputCsv      = $defaultCsv }
    if (-not $OutputHtml)     { $OutputHtml     = $defaultHtml }

    Write-Host ''
    Write-Host 'Running with:'
    if ($DynamicRestrictedActions) {
        Write-Host '  Restricted from: CSV + dynamic baseline-role NotActions'
        if ($BaselineRolePattern.Count -gt 0) {
            Write-Host "  Baseline patterns: $($BaselineRolePattern -join ', ')"
        }
        else {
            Write-Host '  Baseline roles:    automatic (Owner/Contributor/Baseline wildcard roles)'
        }
        Write-Host "  InputCsv:          $InputCsv"
    } else {
        Write-Host "  InputCsv:        $InputCsv"
    }
    Write-Host "  OutputCsv:       $OutputCsv"
    Write-Host "  OutputHtml:      $OutputHtml"
    if ($DeniedRolesCsv) {
        Write-Host "  Denied supplement: $DeniedRolesCsv"
    }
    Write-Host "  Policy discovery:  $(-not $NoPolicyDiscovery)"
    if ($ManagementGroup) {
        Write-Host "  Scope:             management group '$ManagementGroup'"
    } elseif ($CurrentSubscriptionOnly) {
        Write-Host '  Scope:             current subscription'
    } elseif ($BuiltInOnly) {
        Write-Host '  Scope:             accessible estate (built-in roles only)'
    } else {
        Write-Host '  Scope:             accessible estate'
    }
    Write-Host ''
}

if (-not $OutputCsv) { throw 'OutputCsv is required.' }
if (-not $InputCsv -and -not $DynamicRestrictedActions) {
    throw 'Provide -InputCsv, -DynamicRestrictedActions, or both as the source of restricted actions.'
}
if ($Scope -and $ManagementGroup) {
    throw 'Use either -Scope or -ManagementGroup, not both.'
}
if (($Scope -or $ManagementGroup) -and $CurrentSubscriptionOnly) {
    throw '-CurrentSubscriptionOnly cannot be combined with -Scope or -ManagementGroup.'
}
if ($DynamicRestrictedActions -and $BuiltInOnly) {
    throw '-DynamicRestrictedActions requires custom-role discovery; remove -BuiltInOnly.'
}

$IncludeCustomRoles = -not $BuiltInOnly

if ($DynamicRestrictedActions) {
    if ($BaselineRolePattern.Count -gt 0) {
        Write-Host "Dynamic derivation scoped to baseline role pattern(s): $($BaselineRolePattern -join ', ')"
    }
    else {
        Write-Host 'Dynamic derivation will auto-detect Owner/Contributor/Baseline wildcard roles.'
    }
}

function Test-RadarAzSession {
    $context = Get-AzContext -ErrorAction SilentlyContinue
    if (-not $context -or -not $context.Account) { return $false }
    try {
        $accessToken = Get-AzAccessToken `
            -ErrorAction Stop `
            -WarningAction SilentlyContinue
        $expiresOnProperty =
            $accessToken.PSObject.Properties['ExpiresOn']
        if ($expiresOnProperty -and $expiresOnProperty.Value) {
            try {
                $expiresOn =
                    [DateTimeOffset]$expiresOnProperty.Value
            }
            catch {
                return $false
            }
            if (
                $expiresOn -le
                [DateTimeOffset]::UtcNow.AddMinutes(2)
            ) {
                return $false
            }
        }
        return $true
    }
    catch {
        return $false
    }
}

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

    if (Test-RadarAzSession) {
        $ctx = Get-AzContext
        Write-Host "Using existing Azure session: $($ctx.Account.Id) (tenant $($ctx.Tenant.Id))"
        return
    }

    Write-Host "No active Azure session found. Launching Connect-AzAccount..."
    Connect-AzAccount -ErrorAction Stop | Out-Null

    if (-not (Test-RadarAzSession)) {
        throw 'Connect-AzAccount completed but no usable Azure context is available.'
    }
    $ctx = Get-AzContext
    Write-Host "Connected as $($ctx.Account.Id) (tenant $($ctx.Tenant.Id))"
}

function New-RadarScope {
    param(
        [string]$Id,
        [string]$Name,
        [string]$DisplayName
    )

    if ([string]::IsNullOrWhiteSpace($Id)) { return $null }
    $normalisedId = $Id.Trim()
    if ($normalisedId.Length -gt 1) {
        $normalisedId = $normalisedId.TrimEnd('/')
    }

    $type = if (
        $normalisedId -like
        '/providers/Microsoft.Management/managementGroups/*'
    ) {
        'ManagementGroup'
    }
    elseif (
        $normalisedId -match
        '(?i)^/subscriptions/[^/]+$'
    ) {
        'Subscription'
    }
    elseif (
        $normalisedId -match
        '(?i)^/subscriptions/[^/]+/resourceGroups/[^/]+$'
    ) {
        'ResourceGroup'
    }
    else {
        'Resource'
    }

    $resolvedName = if ([string]::IsNullOrWhiteSpace($Name)) {
        ($normalisedId -split '/')[-1]
    }
    else {
        $Name
    }

    [pscustomobject]@{
        Id = $normalisedId
        Name = $resolvedName
        DisplayName = if ([string]::IsNullOrWhiteSpace($DisplayName)) {
            $resolvedName
        }
        else {
            $DisplayName
        }
        Type = $type
    }
}

function Get-RadarScanScope {
    <#
    Resolves explicit scope controls or discovers the management groups and
    enabled subscriptions visible to the current tenant identity.
    #>
    param(
        [string[]]$ExplicitScope,
        [string]$ManagementGroup,
        [switch]$CurrentSubscriptionOnly
    )

    $scopeById = @{}
    $warnings = New-Object System.Collections.Generic.List[string]
    $isComplete = $true
    $discoveryMode = 'Estate'

    $addScope = {
        param($ScopeObject)
        if ($null -eq $ScopeObject) { return }
        $scopeById[$ScopeObject.Id.ToLowerInvariant()] = $ScopeObject
    }

    $context = Get-AzContext -ErrorAction Stop

    if ($ExplicitScope) {
        $discoveryMode = 'Explicit'
        foreach ($scopeId in $ExplicitScope) {
            if ([string]::IsNullOrWhiteSpace($scopeId)) { continue }
            $resolvedScope = New-RadarScope -Id $scopeId
            & $addScope $resolvedScope
            if ($resolvedScope.Type -eq 'ManagementGroup') {
                $isComplete = $false
                [void]$warnings.Add(
                    "Explicit scope '$($resolvedScope.Id)' is a management group whose descendant exemptions are not fully enumerated. Full deny coverage cannot be proven."
                )
            }
        }
    }
    elseif ($ManagementGroup) {
        $discoveryMode = 'ManagementGroup'
        $managementGroupScope = if ($ManagementGroup.StartsWith('/')) {
            $ManagementGroup
        }
        else {
            "/providers/Microsoft.Management/managementGroups/$ManagementGroup"
        }
        & $addScope (
            New-RadarScope -Id $managementGroupScope -Name $ManagementGroup
        )
        $isComplete = $false
        [void]$warnings.Add(
            'An explicit management-group scan does not enumerate every descendant exemption. Full deny coverage cannot be proven; use the default estate scan or pass descendant scopes explicitly.'
        )
    }
    elseif ($CurrentSubscriptionOnly) {
        $discoveryMode = 'CurrentSubscription'
        $subscriptionId = Get-RadarPropertyValue `
            -InputObject $context.Subscription `
            -Name 'Id'
        if ([string]::IsNullOrWhiteSpace([string]$subscriptionId)) {
            throw 'The current Azure context has no subscription.'
        }
        & $addScope (
            New-RadarScope `
                -Id "/subscriptions/$subscriptionId" `
                -Name $subscriptionId `
                -DisplayName (
                    Get-RadarPropertyValue `
                        -InputObject $context.Subscription `
                        -Name 'Name'
                )
        )
    }
    else {
        $tenantId = [string](
            Get-RadarPropertyValue `
                -InputObject $context.Tenant `
                -Name 'Id'
        )
        try {
            foreach ($group in @(Get-AzManagementGroup -ErrorAction Stop)) {
                $groupId = Get-RadarPropertyValue `
                    -InputObject $group `
                    -Name 'Id'
                $groupName = Get-RadarPropertyValue `
                    -InputObject $group `
                    -Name 'Name'
                if (
                    -not [string]::IsNullOrWhiteSpace($tenantId) -and
                    (
                        [string]::Equals(
                            [string]$groupName,
                            $tenantId,
                            [System.StringComparison]::OrdinalIgnoreCase
                        ) -or
                        [string]::Equals(
                            ([string]$groupId).TrimEnd('/'),
                            "/providers/Microsoft.Management/managementGroups/$tenantId",
                            [System.StringComparison]::OrdinalIgnoreCase
                        )
                    )
                ) {
                    continue
                }
                if ([string]::IsNullOrWhiteSpace([string]$groupId)) {
                    $groupId =
                        "/providers/Microsoft.Management/managementGroups/$groupName"
                }
                & $addScope (
                    New-RadarScope `
                        -Id $groupId `
                        -Name $groupName `
                        -DisplayName (
                            Get-RadarPropertyValue `
                                -InputObject $group `
                                -Name 'DisplayName'
                        )
                )
            }
        }
        catch {
            $isComplete = $false
            [void]$warnings.Add(
                "Management-group discovery failed: $($_.Exception.Message)"
            )
        }

        try {
            foreach (
                $subscription in @(
                    Get-AzSubscription -TenantId $tenantId -ErrorAction Stop
                )
            ) {
                $state = Get-RadarPropertyValue `
                    -InputObject $subscription `
                    -Name 'State'
                if ($state -and $state -ine 'Enabled') { continue }

                $subscriptionId = Get-RadarPropertyValue `
                    -InputObject $subscription `
                    -Name 'Id'
                if ([string]::IsNullOrWhiteSpace([string]$subscriptionId)) {
                    $subscriptionId = Get-RadarPropertyValue `
                        -InputObject $subscription `
                        -Name 'SubscriptionId'
                }
                & $addScope (
                    New-RadarScope `
                        -Id "/subscriptions/$subscriptionId" `
                        -Name $subscriptionId `
                        -DisplayName (
                            Get-RadarPropertyValue `
                                -InputObject $subscription `
                                -Name 'Name'
                        )
                )
            }
        }
        catch {
            $isComplete = $false
            [void]$warnings.Add(
                "Subscription discovery failed: $($_.Exception.Message)"
            )
        }
    }

    if ($scopeById.Count -eq 0) {
        throw 'No Azure scopes were discovered. Check the current context and read access.'
    }

    [pscustomobject]@{
        Scopes = @($scopeById.Values | Sort-Object Type, Id)
        IsComplete = $isComplete
        Warnings = $warnings.ToArray()
        DiscoveryMode = $discoveryMode
    }
}

function Add-RadarHierarchyNode {
    param(
        [object]$Node,
        [string[]]$AncestorIds,
        [hashtable]$AncestorsByScope,
        [hashtable]$ScopeById
    )

    $id = [string](
        Get-RadarPropertyValue -InputObject $Node -Name 'Id'
    )
    if ([string]::IsNullOrWhiteSpace($id)) { return }
    $normalisedId = $id.TrimEnd('/')
    $key = $normalisedId.ToLowerInvariant()
    $AncestorsByScope[$key] = @($AncestorIds)
    $ScopeById[$key] = New-RadarScope `
        -Id $normalisedId `
        -Name (
            Get-RadarPropertyValue -InputObject $Node -Name 'Name'
        ) `
        -DisplayName (
            Get-RadarPropertyValue `
                -InputObject $Node `
                -Name 'DisplayName'
        )

    $nextAncestors = @($AncestorIds + $normalisedId)
    foreach (
        $child in @(
            Get-RadarPropertyValue -InputObject $Node -Name 'Children' |
                Where-Object { $null -ne $_ }
        )
    ) {
        Add-RadarHierarchyNode `
            -Node $child `
            -AncestorIds $nextAncestors `
            -AncestorsByScope $AncestorsByScope `
            -ScopeById $ScopeById
    }
}

function Get-RadarScopeHierarchy {
    <#
    Builds management-group and subscription ancestry once. Resource-group and
    resource scopes inherit their subscription's management-group ancestors.
    #>
    param(
        [object[]]$KnownScopes = @(),
        [object[]]$RequiredScopes = @()
    )

    $ancestorsByScope = @{}
    $scopeById = @{}
    $warnings = New-Object System.Collections.Generic.List[string]
    $isComplete = $true
    $fallbackParentByRoot = @{}
    $unresolvedAncestorRoots =
        New-Object System.Collections.Generic.HashSet[string] (
            [StringComparer]::OrdinalIgnoreCase
        )

    $requiresManagementGroupHierarchy = @(
        $KnownScopes |
            Where-Object {
                $_.Type -eq 'ManagementGroup' -or
                $_.Id -like
                    '/providers/Microsoft.Management/managementGroups/*'
            }
    ).Count -gt 0
    if ($requiresManagementGroupHierarchy) {
        $hierarchyErrors =
            New-Object System.Collections.Generic.List[string]
        try {
            $context = Get-AzContext -ErrorAction Stop
            $tenantId = [string](
                Get-RadarPropertyValue `
                    -InputObject $context.Tenant `
                    -Name 'Id'
            )
            if ([string]::IsNullOrWhiteSpace($tenantId)) {
                throw 'The current Azure context has no tenant ID.'
            }
            $root = Get-AzManagementGroup `
                -GroupName $tenantId `
                -Expand `
                -Recurse `
                -ErrorAction Stop `
                -WarningAction SilentlyContinue
            Add-RadarHierarchyNode `
                -Node $root `
                -AncestorIds @() `
                -AncestorsByScope $ancestorsByScope `
                -ScopeById $scopeById
        }
        catch {
            [void]$hierarchyErrors.Add(
                "Tenant-root hierarchy was not readable: $($_.Exception.Message)"
            )
        }

        # Reader is commonly granted at a customer root below the Tenant Root
        # Group. Recurse from every still-uncovered visible MG so that deployment
        # remains useful without tenant-root permissions.
        foreach (
            $knownManagementGroup in @(
                $KnownScopes |
                    Where-Object {
                        $_.Type -eq 'ManagementGroup'
                    } |
                    Sort-Object Name
            )
        ) {
            $knownKey =
                $knownManagementGroup.Id.TrimEnd('/').ToLowerInvariant()
            if ($scopeById.ContainsKey($knownKey)) { continue }
            try {
                $accessibleRoot = Get-AzManagementGroup `
                    -GroupName $knownManagementGroup.Name `
                    -Expand `
                    -Recurse `
                    -ErrorAction Stop `
                    -WarningAction SilentlyContinue
                $accessibleRootId = [string](
                    Get-RadarPropertyValue `
                        -InputObject $accessibleRoot `
                        -Name 'Id'
                )
                $accessibleParentId = [string](
                    Get-RadarPropertyValue `
                        -InputObject $accessibleRoot `
                        -Name 'ParentId'
                )
                if ($accessibleRootId -and $accessibleParentId) {
                    $fallbackParentByRoot[
                        $accessibleRootId.TrimEnd('/').ToLowerInvariant()
                    ] = $accessibleParentId.TrimEnd('/')
                }
                Add-RadarHierarchyNode `
                    -Node $accessibleRoot `
                    -AncestorIds @() `
                    -AncestorsByScope $ancestorsByScope `
                    -ScopeById $scopeById
            }
            catch {
                [void]$hierarchyErrors.Add(
                    "Hierarchy below management group '$($knownManagementGroup.Name)' was not readable: $($_.Exception.Message)"
                )
            }
        }

        foreach ($fallbackRootKey in $fallbackParentByRoot.Keys) {
            $parentKey =
                $fallbackParentByRoot[$fallbackRootKey].ToLowerInvariant()
            if (-not $scopeById.ContainsKey($parentKey)) {
                [void]$unresolvedAncestorRoots.Add($fallbackRootKey)
            }
        }

        $requiredHierarchyScopes = if (
            @($RequiredScopes).Count -gt 0
        ) {
            @($RequiredScopes)
        }
        else {
            @($KnownScopes)
        }
        $missingRequiredSubscriptions = @(
            $requiredHierarchyScopes |
                Where-Object {
                    $scopeId = $_.Id.TrimEnd('/').ToLowerInvariant()
                    $_.Type -eq 'Subscription' -and
                    -not $ancestorsByScope.ContainsKey($scopeId)
                }
        )
        if (
            $missingRequiredSubscriptions.Count -gt 0 -and
            (Get-Command Search-AzGraph -ErrorAction SilentlyContinue)
        ) {
            try {
                $subscriptionIds = @(
                    $missingRequiredSubscriptions |
                        ForEach-Object { ($_.Id -split '/')[2] } |
                        Sort-Object -Unique
                )
                $quotedSubscriptionIds = @(
                    $subscriptionIds |
                        ForEach-Object { "'$_'" }
                ) -join ', '
                $query = @"
resourcecontainers
| where type =~ 'microsoft.resources/subscriptions'
| where subscriptionId in~ ($quotedSubscriptionIds)
| project
    subscriptionId,
    managementGroupAncestorsChain =
        properties.managementGroupAncestorsChain
"@
                $pageSize = 1000
                $skip = 0
                $skipToken = $null
                do {
                    $parameters = @{
                        Query = $query
                        First = $pageSize
                        UseTenantScope = $true
                        ErrorAction = 'Stop'
                    }
                    if ($skipToken) {
                        $parameters.SkipToken = $skipToken
                    }
                    elseif ($skip -gt 0) {
                        $parameters.Skip = $skip
                    }
                    $response = Search-AzGraph @parameters
                    $wrapped = Test-RadarHasProperty `
                        -InputObject $response `
                        -Name 'Data'
                    if ($wrapped) {
                        $rows = @(
                            Get-RadarPropertyValue `
                                -InputObject $response `
                                -Name 'Data' |
                                Where-Object { $null -ne $_ }
                        )
                        $skipToken = [string](
                            Get-RadarPropertyValue `
                                -InputObject $response `
                                -Name 'SkipToken'
                        )
                    }
                    else {
                        $rows = @(
                            $response |
                                Where-Object { $null -ne $_ }
                        )
                        $skip += $rows.Count
                        $skipToken = $null
                    }

                    foreach ($row in $rows) {
                        $subscriptionId = [string](
                            Get-RadarPropertyValue `
                                -InputObject $row `
                                -Name 'SubscriptionId'
                        )
                        if (
                            [string]::IsNullOrWhiteSpace(
                                $subscriptionId
                            )
                        ) {
                            continue
                        }
                        $chain = Get-RadarPropertyValue `
                            -InputObject $row `
                            -Name 'ManagementGroupAncestorsChain'
                        if ($chain -is [string]) {
                            $chain = $chain | ConvertFrom-Json
                        }
                        $ancestorIds = @(
                            foreach ($ancestor in @($chain)) {
                                $ancestorName = [string](
                                    Get-RadarPropertyValue `
                                        -InputObject $ancestor `
                                        -Name 'Name'
                                )
                                if (
                                    -not [string]::IsNullOrWhiteSpace(
                                        $ancestorName
                                    )
                                ) {
                                    "/providers/Microsoft.Management/managementGroups/$ancestorName"
                                }
                            }
                        )
                        # Resource Graph returns immediate parent first; the
                        # live hierarchy walker stores root first.
                        [array]::Reverse($ancestorIds)
                        $subscriptionScope =
                            "/subscriptions/$subscriptionId"
                        $subscriptionKey =
                            $subscriptionScope.ToLowerInvariant()
                        $ancestorsByScope[$subscriptionKey] =
                            $ancestorIds
                        if (-not $scopeById.ContainsKey($subscriptionKey)) {
                            $knownSubscription = @(
                                $missingRequiredSubscriptions |
                                    Where-Object {
                                        $_.Id -ieq $subscriptionScope
                                    }
                            ) | Select-Object -First 1
                            $scopeById[$subscriptionKey] = if (
                                $knownSubscription
                            ) {
                                $knownSubscription
                            }
                            else {
                                New-RadarScope `
                                    -Id $subscriptionScope `
                                    -Name $subscriptionId
                            }
                        }
                    }
                } while (
                    $skipToken -or
                    (-not $wrapped -and $rows.Count -eq $pageSize)
                )
            }
            catch {
                [void]$hierarchyErrors.Add(
                    "Subscription hierarchy discovery through Azure Resource Graph failed: $($_.Exception.Message)"
                )
            }
        }

        $unresolvedHierarchyScopes = @(
            $requiredHierarchyScopes |
                Where-Object {
                    $scopeId = $_.Id.TrimEnd('/').ToLowerInvariant()
                    (
                        $_.Type -eq 'ManagementGroup' -or
                        $_.Type -eq 'Subscription'
                    ) -and
                    -not $scopeById.ContainsKey($scopeId)
                }
        )
        if ($unresolvedHierarchyScopes.Count -gt 0) {
            $isComplete = $false
            [void]$warnings.Add(
                "Hierarchy discovery could not place $($unresolvedHierarchyScopes.Count) visible management-group or subscription scope(s)."
            )
            foreach ($hierarchyError in $hierarchyErrors) {
                [void]$warnings.Add($hierarchyError)
            }
        }
    }

    foreach ($scope in $KnownScopes) {
        if ($null -eq $scope) { continue }
        $scopeId = [string](
            Get-RadarPropertyValue -InputObject $scope -Name 'Id'
        )
        if ([string]::IsNullOrWhiteSpace($scopeId)) { continue }
        $normalisedId = $scopeId.TrimEnd('/')
        $key = $normalisedId.ToLowerInvariant()
        if (-not $scopeById.ContainsKey($key)) {
            $scopeById[$key] = if ($scope.PSObject.Properties['Type']) {
                $scope
            }
            else {
                New-RadarScope -Id $normalisedId
            }
        }

        if ($ancestorsByScope.ContainsKey($key)) { continue }
        $subscriptionMatch = [regex]::Match(
            $normalisedId,
            '(?i)^(/subscriptions/[^/]+)'
        )
        if ($subscriptionMatch.Success) {
            $subscriptionKey =
                $subscriptionMatch.Groups[1].Value.ToLowerInvariant()
            if ($ancestorsByScope.ContainsKey($subscriptionKey)) {
                $ancestorsByScope[$key] = @(
                    $ancestorsByScope[$subscriptionKey] +
                    $subscriptionMatch.Groups[1].Value
                )
            }
        }
    }

    [pscustomobject]@{
        AncestorsByScope = $ancestorsByScope
        ScopeById = $scopeById
        Scopes = @($scopeById.Values | Sort-Object Type, Id)
        IsComplete = $isComplete
        UnresolvedAncestorRoots = @(
            $unresolvedAncestorRoots |
                Sort-Object
        )
        Warnings = $warnings.ToArray()
    }
}

function Test-RadarScopeDescendsFrom {
    param(
        [string]$Scope,
        [string]$RootScope,
        [object]$Hierarchy
    )

    $normalisedScope = $Scope.TrimEnd('/')
    $normalisedRoot = $RootScope.TrimEnd('/')
    if ([string]::IsNullOrWhiteSpace($normalisedRoot)) {
        $normalisedRoot = '/'
    }

    if ($normalisedRoot -eq '/') {
        return [pscustomobject]@{
            State = 'True'
            Reason = $null
        }
    }
    if ($normalisedScope -ieq $normalisedRoot) {
        return [pscustomobject]@{
            State = 'True'
            Reason = $null
        }
    }

    if (
        $normalisedRoot -notlike
        '/providers/Microsoft.Management/managementGroups/*'
    ) {
        return [pscustomobject]@{
            State = if (
                $normalisedScope.StartsWith(
                    "$normalisedRoot/",
                    [System.StringComparison]::OrdinalIgnoreCase
                )
            ) {
                'True'
            }
            else {
                'False'
            }
            Reason = $null
        }
    }

    $scopeKey = $normalisedScope.ToLowerInvariant()
    if (-not $Hierarchy.AncestorsByScope.ContainsKey($scopeKey)) {
        $subscriptionMatch = [regex]::Match(
            $normalisedScope,
            '(?i)^(/subscriptions/[^/]+)'
        )
        if ($subscriptionMatch.Success) {
            $scopeKey =
                $subscriptionMatch.Groups[1].Value.ToLowerInvariant()
        }
    }

    if ($Hierarchy.AncestorsByScope.ContainsKey($scopeKey)) {
        $scopeAncestors = @($Hierarchy.AncestorsByScope[$scopeKey])
        $isDescendant = @(
            $scopeAncestors |
                Where-Object {
                    [string]::Equals(
                        [string]$_,
                        $normalisedRoot,
                        [System.StringComparison]::OrdinalIgnoreCase
                    )
                }
        ).Count -gt 0
        if (-not $isDescendant) {
            $rootKey = $normalisedRoot.ToLowerInvariant()
            if ($Hierarchy.AncestorsByScope.ContainsKey($rootKey)) {
                return [pscustomobject]@{
                    State = 'False'
                    Reason = $null
                }
            }
            $scopeOrAncestors = @($scopeKey) + @(
                $scopeAncestors |
                    ForEach-Object {
                        ([string]$_).ToLowerInvariant()
                    }
            )
            if (
                @(
                    Get-RadarPropertyValue `
                        -InputObject $Hierarchy `
                        -Name 'UnresolvedAncestorRoots' |
                        Where-Object {
                            $scopeOrAncestors -contains
                                ([string]$_).ToLowerInvariant()
                        }
                ).Count -gt 0
            ) {
                return [pscustomobject]@{
                    State = 'Unknown'
                    Reason = "The ancestry of '$Scope' above an accessible management-group root is unresolved."
                }
            }
        }
        return [pscustomobject]@{
            State = if ($isDescendant) { 'True' } else { 'False' }
            Reason = $null
        }
    }

    return [pscustomobject]@{
        State = 'Unknown'
        Reason = "Could not resolve whether '$Scope' is below management group '$RootScope'."
    }
}

function Get-RadarSubtreeScope {
    param(
        [string]$RootScope,
        [object[]]$Scopes,
        [object]$Hierarchy,
        [switch]$IncludeRootIfMissing
    )

    $scopeById = @{}
    $warnings = New-Object System.Collections.Generic.List[string]
    $isComplete = $true
    foreach ($scope in $Scopes) {
        $scopeId = [string](
            Get-RadarPropertyValue -InputObject $scope -Name 'Id'
        )
        if ([string]::IsNullOrWhiteSpace($scopeId)) { continue }
        $relationship = Test-RadarScopeDescendsFrom `
            -Scope $scopeId `
            -RootScope $RootScope `
            -Hierarchy $Hierarchy
        if ($relationship.State -eq 'True') {
            $scopeById[$scopeId.TrimEnd('/').ToLowerInvariant()] = $scope
        }
        elseif ($relationship.State -eq 'Unknown') {
            # Fail open so an unresolved branch cannot hide a potential role.
            $scopeById[$scopeId.TrimEnd('/').ToLowerInvariant()] = $scope
            $isComplete = $false
            [void]$warnings.Add($relationship.Reason)
        }
    }

    $normalisedRoot = $RootScope.TrimEnd('/')
    if ([string]::IsNullOrWhiteSpace($normalisedRoot)) {
        $normalisedRoot = '/'
    }
    $rootKey = $normalisedRoot.ToLowerInvariant()
    if (
        $IncludeRootIfMissing -and
        -not $scopeById.ContainsKey($rootKey)
    ) {
        $scopeById[$rootKey] = New-RadarScope -Id $normalisedRoot
    }

    [pscustomobject]@{
        Scopes = @($scopeById.Values | Sort-Object Type, Id)
        IsComplete = $isComplete
        Warnings = @($warnings | Sort-Object -Unique)
    }
}

function Get-RadarRoleKey {
    param([object]$Role)

    $id = [string](
        Get-RadarPropertyValue -InputObject $Role -Name 'Id'
    )
    if (-not [string]::IsNullOrWhiteSpace($id)) {
        $guidMatch = [regex]::Match(
            $id,
            '(?i)[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}(?=/?$)'
        )
        if ($guidMatch.Success) {
            return $guidMatch.Value.ToLowerInvariant()
        }
        return $id.TrimEnd('/').ToLowerInvariant()
    }

    $name = [string](
        Get-RadarPropertyValue -InputObject $Role -Name 'Name'
    )
    return "name:$($name.ToLowerInvariant())"
}

function ConvertTo-RadarGraphRole {
    param([object]$GraphRole)

    $permissions = Get-RadarPropertyValue `
        -InputObject $GraphRole `
        -Name 'Permissions'
    if ($permissions -is [string]) {
        $permissions = $permissions | ConvertFrom-Json
    }

    $normalisedPermissions = @(
        foreach (
            $permission in @(
                $permissions |
                    Where-Object { $null -ne $_ }
            )
        ) {
            [pscustomobject]@{
                Actions = @(
                    Get-RadarPropertyValue `
                        -InputObject $permission `
                        -Name 'Actions'
                )
                NotActions = @(
                    Get-RadarPropertyValue `
                        -InputObject $permission `
                        -Name 'NotActions'
                )
                DataActions = @(
                    Get-RadarPropertyValue `
                        -InputObject $permission `
                        -Name 'DataActions'
                )
                NotDataActions = @(
                    Get-RadarPropertyValue `
                        -InputObject $permission `
                        -Name 'NotDataActions'
                )
                Condition = Get-RadarPropertyValue `
                    -InputObject $permission `
                    -Name 'Condition'
                ConditionVersion = Get-RadarPropertyValue `
                    -InputObject $permission `
                    -Name 'ConditionVersion'
            }
        }
    )

    [pscustomobject]@{
        Name = Get-RadarPropertyValue `
            -InputObject $GraphRole `
            -Name 'RoleName'
        Id = Get-RadarPropertyValue -InputObject $GraphRole -Name 'Id'
        IsCustom = $true
        Description = Get-RadarPropertyValue `
            -InputObject $GraphRole `
            -Name 'Description'
        AssignableScopes = @(
            Get-RadarPropertyValue `
                -InputObject $GraphRole `
                -Name 'AssignableScopes' |
                Where-Object { $null -ne $_ }
        )
        Permissions = $normalisedPermissions
    }
}

function Get-RadarRoleInventory {
    <#
    Gets built-in roles once, then discovers custom roles through Azure Resource
    Graph at tenant or explicit scope, with Az.Resources queries as a fallback.
    #>
    param(
        [Parameter(Mandatory = $true)]
        [object[]]$Scopes,

        [switch]$BuiltInOnly,

        [switch]$UseTenantDiscovery
    )

    $roleByKey = @{}
    $scopeSetByRole = @{}
    $warnings = New-Object System.Collections.Generic.List[string]
    $isComplete = $true

    $addRole = {
        param(
            [object]$Role,
            [string[]]$AvailableScopes
        )

        if ($null -eq $Role) { return }
        $key = Get-RadarRoleKey -Role $Role
        if (-not $roleByKey.ContainsKey($key)) {
            $roleByKey[$key] = $Role
            $scopeSetByRole[$key] =
                New-Object System.Collections.Generic.HashSet[string] (
                    [StringComparer]::OrdinalIgnoreCase
                )
        }
        foreach ($availableScope in @($AvailableScopes)) {
            if (-not [string]::IsNullOrWhiteSpace($availableScope)) {
                [void]$scopeSetByRole[$key].Add($availableScope.TrimEnd('/'))
            }
        }
    }

    $builtInRoles = @(
        Get-AzRoleDefinition -WarningAction SilentlyContinue -ErrorAction Stop |
            Where-Object {
                -not [bool](
                    Get-RadarPropertyValue `
                        -InputObject $_ `
                        -Name 'IsCustom'
                )
            }
    )
    $allScopeIds = @($Scopes | ForEach-Object { $_.Id })
    foreach ($role in $builtInRoles) {
        & $addRole $role $allScopeIds
    }

    $customSource = 'Disabled'
    if (-not $BuiltInOnly) {
        $resourceGraphSucceeded = $false
        if (Get-Command Search-AzGraph -ErrorAction SilentlyContinue) {
            try {
                $query = @'
authorizationresources
| where type =~ 'microsoft.authorization/roledefinitions'
| where properties.type =~ 'CustomRole'
| project
    id,
    RoleName = properties.roleName,
    Description = properties.description,
    Permissions = properties.permissions,
    AssignableScopes = properties.assignableScopes
'@
                $pageSize = 1000
                $skip = 0
                $skipToken = $null
                do {
                    $graphParameters = @{
                        Query = $query
                        First = $pageSize
                        ErrorAction = 'Stop'
                    }
                    $subscriptionIds = @(
                        $Scopes |
                            ForEach-Object {
                                $match = [regex]::Match(
                                    $_.Id,
                                    '(?i)^/subscriptions/([^/]+)'
                                )
                                if ($match.Success) {
                                    $match.Groups[1].Value
                                }
                            } |
                            Sort-Object -Unique
                    )
                    $managementGroupNames = @(
                        $Scopes |
                            Where-Object {
                                $_.Type -eq 'ManagementGroup'
                            } |
                            ForEach-Object { $_.Name } |
                            Sort-Object -Unique
                    )
                    if ($UseTenantDiscovery) {
                        $graphParameters.UseTenantScope = $true
                    }
                    elseif (
                        $managementGroupNames.Count -gt 0 -and
                        $subscriptionIds.Count -eq 0
                    ) {
                        $graphParameters.ManagementGroup =
                            $managementGroupNames
                    }
                    elseif (
                        $subscriptionIds.Count -gt 0 -and
                        $managementGroupNames.Count -eq 0
                    ) {
                        $graphParameters.Subscription = $subscriptionIds
                    }
                    else {
                        # Mixed MG and standalone subscription roots cannot be
                        # represented in one scoped ARG parameter set. Query
                        # the tenant and apply the requested-root hierarchy
                        # filter after discovery.
                        $graphParameters.UseTenantScope = $true
                    }
                    if ($skipToken) {
                        $graphParameters.SkipToken = $skipToken
                    }
                    elseif ($skip -gt 0) {
                        $graphParameters.Skip = $skip
                    }
                    $response = Search-AzGraph @graphParameters
                    $wrappedResponse = (
                        Test-RadarHasProperty `
                            -InputObject $response `
                            -Name 'Data'
                    )
                    if ($wrappedResponse) {
                        $page = @(
                            Get-RadarPropertyValue `
                                -InputObject $response `
                                -Name 'Data' |
                                Where-Object { $null -ne $_ }
                        )
                        $skipToken = [string](
                            Get-RadarPropertyValue `
                                -InputObject $response `
                                -Name 'SkipToken'
                        )
                    }
                    else {
                        $page = @(
                            $response |
                                Where-Object { $null -ne $_ }
                        )
                        $skip += $page.Count
                        $skipToken = $null
                    }
                    foreach ($graphRole in $page) {
                        $role = ConvertTo-RadarGraphRole -GraphRole $graphRole
                        $assignableScopes = @(
                            Get-RadarPropertyValue `
                                -InputObject $role `
                                -Name 'AssignableScopes'
                        )
                        $hasManagementGroupScope = @(
                            $assignableScopes |
                                Where-Object {
                                    $_ -like
                                    '/providers/Microsoft.Management/managementGroups/*'
                                }
                        ).Count -gt 0
                        $availableScopes = if (
                            $assignableScopes -contains '/' -or
                            $hasManagementGroupScope
                        ) {
                            # Management-group IDs do not encode hierarchy.
                            # Treat the role as available at every discovered
                            # estate scope so a child exemption or exclusion
                            # can never be hidden by a parent-only result.
                            $allScopeIds
                        }
                        elseif (
                            $managementGroupNames.Count -gt 0
                        ) {
                            # A management-group-scoped Graph query includes
                            # descendant subscription/RG role definitions. Keep
                            # their declared scopes; hierarchy intersection is
                            # performed after the full estate graph is built.
                            $assignableScopes
                        }
                        else {
                            $roleScopeSet =
                                New-Object System.Collections.Generic.HashSet[string] (
                                    [StringComparer]::OrdinalIgnoreCase
                                )
                            foreach ($assignableScope in $assignableScopes) {
                                $normalisedAssignable =
                                    ([string]$assignableScope).TrimEnd('/')
                                foreach ($scanScope in $Scopes) {
                                    $normalisedScan =
                                        $scanScope.Id.TrimEnd('/')
                                    if (
                                        $normalisedScan -ieq
                                            $normalisedAssignable -or
                                        $normalisedScan.StartsWith(
                                            "$normalisedAssignable/",
                                            [System.StringComparison]::OrdinalIgnoreCase
                                        )
                                    ) {
                                        [void]$roleScopeSet.Add(
                                            $normalisedScan
                                        )
                                    }
                                    elseif (
                                        $normalisedAssignable.StartsWith(
                                            "$normalisedScan/",
                                            [System.StringComparison]::OrdinalIgnoreCase
                                        )
                                    ) {
                                        [void]$roleScopeSet.Add(
                                            $normalisedAssignable
                                        )
                                    }
                                }
                            }
                            @($roleScopeSet)
                        }
                        if (@($availableScopes).Count -gt 0) {
                            & $addRole $role $availableScopes
                        }
                    }
                } while (
                    $skipToken -or
                    (-not $wrappedResponse -and $page.Count -eq $pageSize)
                )

                $resourceGraphSucceeded = $true
                $customSource = 'Azure Resource Graph'

                # Scoped Resource Graph queries primarily enumerate roles at or
                # below the query scope. Merge live ARM results so custom roles
                # defined at ancestor management groups remain available.
                if (-not $UseTenantDiscovery) {
                    $roleDefinitionCommand =
                        Get-Command Get-AzRoleDefinition
                    foreach ($scanScope in $Scopes) {
                        try {
                            $armParameters = @{
                                Custom = $true
                                Scope = $scanScope.Id
                                WarningAction = 'SilentlyContinue'
                                ErrorAction = 'Stop'
                            }
                            if (
                                $roleDefinitionCommand.Parameters.ContainsKey(
                                    'SkipClientSideScopeValidation'
                                )
                            ) {
                                $armParameters.SkipClientSideScopeValidation =
                                    $true
                            }
                            foreach (
                                $role in @(
                                    Get-AzRoleDefinition @armParameters
                                )
                            ) {
                                & $addRole $role @($scanScope.Id)
                            }
                        }
                        catch {
                            $isComplete = $false
                            [void]$warnings.Add(
                                "Ancestor custom-role discovery failed at $($scanScope.Id): $($_.Exception.Message)"
                            )
                        }
                    }
                    $customSource =
                        'Azure Resource Graph + scoped ARM ancestors'
                }
            }
            catch {
                [void]$warnings.Add(
                    "Azure Resource Graph role discovery failed: $($_.Exception.Message). Falling back to Az.Resources scope queries."
                )
            }
        }

        if (-not $resourceGraphSucceeded) {
            $customSource = 'Az.Resources scope queries'
            $isComplete = $false
            [void]$warnings.Add(
                'Azure Resource Graph was unavailable. Scoped Az.Resources queries can miss custom roles assignable only at descendant resource groups or resources.'
            )
            $roleDefinitionCommand = Get-Command Get-AzRoleDefinition
            foreach ($scanScope in $Scopes) {
                try {
                    $parameters = @{
                        Custom = $true
                        Scope = $scanScope.Id
                        WarningAction = 'SilentlyContinue'
                        ErrorAction = 'Stop'
                    }
                    if (
                        $roleDefinitionCommand.Parameters.ContainsKey(
                            'SkipClientSideScopeValidation'
                        )
                    ) {
                        $parameters.SkipClientSideScopeValidation = $true
                    }

                    foreach (
                        $role in @(Get-AzRoleDefinition @parameters)
                    ) {
                        & $addRole $role @($scanScope.Id)
                    }
                }
                catch {
                    $isComplete = $false
                    [void]$warnings.Add(
                        "Custom-role discovery failed at $($scanScope.Id): $($_.Exception.Message)"
                    )
                }
            }
        }
    }

    $roleScopes = @{}
    foreach ($key in $scopeSetByRole.Keys) {
        $roleScopes[$key] = @($scopeSetByRole[$key] | Sort-Object)
    }

    $roles = @($roleByKey.Values | Sort-Object Name)
    [pscustomobject]@{
        Roles = $roles
        BuiltInRoles = @(
            $roles |
                Where-Object {
                    -not [bool](
                        Get-RadarPropertyValue `
                            -InputObject $_ `
                            -Name 'IsCustom'
                    )
                }
        )
        CustomRoles = @(
            $roles |
                Where-Object {
                    [bool](
                        Get-RadarPropertyValue `
                            -InputObject $_ `
                            -Name 'IsCustom'
                    )
                }
        )
        RoleScopes = $roleScopes
        IsComplete = $isComplete
        Warnings = $warnings.ToArray()
        CustomRoleSource = $customSource
    }
}

function Get-RadarBaselineRoleAssignmentInventory {
    <#
    Retrieves direct assignments of the selected baseline roles in one filtered
    Azure Resource Graph query. This avoids one ARM request per scope and keeps
    correlation cost proportional to relevant assignments rather than estate
    size. PIM schedule instances are not exposed by Resource Graph and remain
    outside this direct-assignment inventory.
    #>
    param(
        [object[]]$BaselineContexts,
        [switch]$NoAssignmentDiscovery
    )

    $warnings = New-Object System.Collections.Generic.List[string]
    $roleGuids = @(
        $BaselineContexts |
            ForEach-Object {
                Get-RadarRoleDefinitionGuid `
                    -RoleOrId $_.BaselineRoleId
            } |
            Where-Object {
                $_ -match
                    '^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$'
            } |
            ForEach-Object { $_.ToLowerInvariant() } |
            Sort-Object -Unique
    )
    if ($roleGuids.Count -eq 0) {
        return [pscustomobject]@{
            IsEvaluated = $true
            IsComplete = $true
            Assignments = @()
            AssignmentCount = 0
            Warnings = @()
            Source = 'Not required'
        }
    }
    if ($NoAssignmentDiscovery) {
        return [pscustomobject]@{
            IsEvaluated = $false
            IsComplete = $false
            Assignments = @()
            AssignmentCount = 0
            Warnings = @(
                'Live baseline-role assignment discovery was disabled.'
            )
            Source = 'Disabled'
        }
    }
    if (-not (Get-Command Search-AzGraph -ErrorAction SilentlyContinue)) {
        return [pscustomobject]@{
            IsEvaluated = $false
            IsComplete = $false
            Assignments = @()
            AssignmentCount = 0
            Warnings = @(
                'Azure Resource Graph is required to correlate direct baseline-role assignments without per-scope ARM calls.'
            )
            Source = 'Unavailable'
        }
    }

    $roleFilter = @(
        $roleGuids |
            ForEach-Object { "'$_'" }
    ) -join ', '
    $query = @"
authorizationresources
| where type =~ 'microsoft.authorization/roleassignments'
| extend
    RoleDefinitionId = tostring(properties.roleDefinitionId),
    AssignmentScope = tostring(properties.scope),
    PrincipalId = tostring(properties.principalId),
    PrincipalType = tostring(properties.principalType),
    Condition = tostring(properties.condition),
    ConditionVersion = tostring(properties.conditionVersion)
| extend RoleDefinitionGuid = tolower(
    extract('([^/]+)$', 1, RoleDefinitionId)
)
| where RoleDefinitionGuid in~ ($roleFilter)
| project
    id,
    AssignmentId = id,
    AssignmentScope,
    PrincipalId,
    PrincipalType,
    Condition,
    ConditionVersion,
    RoleDefinitionId,
    RoleDefinitionGuid
"@

    $graphParameters = @{
        Query = $query
        First = 1000
        ErrorAction = 'Stop'
        # Tenant scope is intentional: authorization-resource queries scoped to
        # a subscription or MG omit assignments inherited from ancestors.
        UseTenantScope = $true
    }

    $assignments = New-Object System.Collections.Generic.List[object]
    $assignmentIds =
        New-Object System.Collections.Generic.HashSet[string] (
            [StringComparer]::OrdinalIgnoreCase
        )
    $skip = 0
    $skipToken = $null
    try {
        do {
            if ($skipToken) {
                $graphParameters.SkipToken = $skipToken
                [void]$graphParameters.Remove('Skip')
            }
            elseif ($skip -gt 0) {
                $graphParameters.Skip = $skip
                [void]$graphParameters.Remove('SkipToken')
            }
            $response = Search-AzGraph @graphParameters
            $wrappedResponse = Test-RadarHasProperty `
                -InputObject $response `
                -Name 'Data'
            if ($wrappedResponse) {
                $page = @(
                    Get-RadarPropertyValue `
                        -InputObject $response `
                        -Name 'Data' |
                        Where-Object { $null -ne $_ }
                )
                $skipToken = [string](
                    Get-RadarPropertyValue `
                        -InputObject $response `
                        -Name 'SkipToken'
                )
            }
            else {
                $page = @(
                    $response |
                        Where-Object { $null -ne $_ }
                )
                $skip += $page.Count
                $skipToken = $null
            }
            foreach ($row in $page) {
                $assignmentId = [string](
                    Get-RadarPropertyValue `
                        -InputObject $row `
                        -Name 'AssignmentId'
                )
                if (
                    [string]::IsNullOrWhiteSpace($assignmentId) -or
                    -not $assignmentIds.Add($assignmentId)
                ) {
                    continue
                }
                $assignmentScope = [string](
                    Get-RadarPropertyValue `
                        -InputObject $row `
                        -Name 'AssignmentScope'
                )
                if ([string]::IsNullOrWhiteSpace($assignmentScope)) {
                    $marker =
                        '/providers/Microsoft.Authorization/roleAssignments/'
                    $markerIndex = $assignmentId.IndexOf(
                        $marker,
                        [System.StringComparison]::OrdinalIgnoreCase
                    )
                    if ($markerIndex -gt 0) {
                        $assignmentScope =
                            $assignmentId.Substring(0, $markerIndex)
                    }
                }
                if ([string]::IsNullOrWhiteSpace($assignmentScope)) {
                    [void]$warnings.Add(
                        "Role assignment '$assignmentId' has no readable scope."
                    )
                    continue
                }
                $roleDefinitionGuid = [string](
                    Get-RadarPropertyValue `
                        -InputObject $row `
                        -Name 'RoleDefinitionGuid'
                )
                if ([string]::IsNullOrWhiteSpace($roleDefinitionGuid)) {
                    $roleDefinitionGuid =
                        Get-RadarRoleDefinitionGuid `
                            -RoleOrId (
                                Get-RadarPropertyValue `
                                    -InputObject $row `
                                    -Name 'RoleDefinitionId'
                            )
                }
                [void]$assignments.Add([pscustomobject]@{
                    AssignmentId = $assignmentId
                    AssignmentScope = $assignmentScope.TrimEnd('/')
                    RoleDefinitionGuid =
                        $roleDefinitionGuid.ToLowerInvariant()
                    PrincipalId = [string](
                        Get-RadarPropertyValue `
                            -InputObject $row `
                            -Name 'PrincipalId'
                    )
                    PrincipalType = [string](
                        Get-RadarPropertyValue `
                            -InputObject $row `
                            -Name 'PrincipalType'
                    )
                    Condition = [string](
                        Get-RadarPropertyValue `
                            -InputObject $row `
                            -Name 'Condition'
                    )
                    ConditionVersion = [string](
                        Get-RadarPropertyValue `
                            -InputObject $row `
                            -Name 'ConditionVersion'
                    )
                })
            }
            if (
                ($wrappedResponse -and -not $skipToken) -or
                (-not $wrappedResponse -and $page.Count -lt 1000)
            ) {
                break
            }
        } while ($true)
    }
    catch {
        return [pscustomobject]@{
            IsEvaluated = $true
            IsComplete = $false
            Assignments = $assignments.ToArray()
            AssignmentCount = $assignments.Count
            Warnings = @(
                @($warnings) +
                "Direct baseline-role assignment discovery failed: $($_.Exception.Message)"
            )
            Source = 'Azure Resource Graph'
        }
    }

    [pscustomobject]@{
        IsEvaluated = $true
        IsComplete = ($warnings.Count -eq 0)
        Assignments = $assignments.ToArray()
        AssignmentCount = $assignments.Count
        Warnings = $warnings.ToArray()
        Source = 'Azure Resource Graph'
    }
}

function Get-RadarBaselineAssignmentEvidenceKey {
    param(
        [string]$BaselineRoleId,
        [string]$BaselineScope,
        [string]$EvaluationScope
    )

    return @(
        $BaselineRoleId.TrimEnd('/').ToLowerInvariant(),
        $BaselineScope.TrimEnd('/').ToLowerInvariant(),
        $EvaluationScope.TrimEnd('/').ToLowerInvariant()
    ) -join [char]31
}

function Get-RadarBaselineAssignmentEvidenceMap {
    param(
        [object[]]$BaselineContexts,
        [object]$AssignmentInventory,
        [object]$Hierarchy
    )

    $evidenceByKey = @{}
    $assignmentsByRoleAndScope = @{}
    foreach ($assignment in @($AssignmentInventory.Assignments)) {
        $roleGuid = [string](
            Get-RadarPropertyValue `
                -InputObject $assignment `
                -Name 'RoleDefinitionGuid'
        )
        if ([string]::IsNullOrWhiteSpace($roleGuid)) {
            continue
        }
        $roleKey = $roleGuid.ToLowerInvariant()
        if (-not $assignmentsByRoleAndScope.ContainsKey($roleKey)) {
            $assignmentsByRoleAndScope[$roleKey] = @{}
        }
        $assignmentScope = [string](
            Get-RadarPropertyValue `
                -InputObject $assignment `
                -Name 'AssignmentScope'
        )
        if ([string]::IsNullOrWhiteSpace($assignmentScope)) {
            continue
        }
        $scopeKey = $assignmentScope.TrimEnd('/').ToLowerInvariant()
        if ([string]::IsNullOrWhiteSpace($scopeKey)) {
            $scopeKey = '/'
        }
        if (
            -not $assignmentsByRoleAndScope[$roleKey].
                ContainsKey($scopeKey)
        ) {
            $assignmentsByRoleAndScope[$roleKey][$scopeKey] =
                New-Object System.Collections.Generic.List[object]
        }
        [void]$assignmentsByRoleAndScope[$roleKey][
            $scopeKey
        ].Add($assignment)
    }

    foreach ($context in $BaselineContexts) {
        $roleGuid = (
            Get-RadarRoleDefinitionGuid `
                -RoleOrId $context.BaselineRoleId
        ).ToLowerInvariant()
        $assignmentsByScope = if (
            $assignmentsByRoleAndScope.ContainsKey($roleGuid)
        ) {
            $assignmentsByRoleAndScope[$roleGuid]
        }
        else {
            @{}
        }
        foreach ($evaluationScope in $context.EvaluationScopes) {
            if (
                $evaluationScope.Type -notin @(
                    'ManagementGroup',
                    'Subscription'
                )
            ) {
                continue
            }
            $effectiveAssignments =
                New-Object System.Collections.Generic.List[object]
            $effectiveAssignmentIds =
                New-Object System.Collections.Generic.HashSet[string] (
                    [StringComparer]::OrdinalIgnoreCase
                )
            $evaluationKey =
                $evaluationScope.Id.TrimEnd('/').ToLowerInvariant()
            $candidateScopeKeys =
                New-Object System.Collections.Generic.HashSet[string] (
                    [StringComparer]::OrdinalIgnoreCase
                )
            [void]$candidateScopeKeys.Add($evaluationKey)
            [void]$candidateScopeKeys.Add('/')
            if ($Hierarchy.AncestorsByScope.ContainsKey($evaluationKey)) {
                foreach (
                    $ancestor in @(
                        $Hierarchy.AncestorsByScope[$evaluationKey]
                    )
                ) {
                    $ancestorKey =
                        ([string]$ancestor).TrimEnd('/').
                            ToLowerInvariant()
                    if ([string]::IsNullOrWhiteSpace($ancestorKey)) {
                        $ancestorKey = '/'
                    }
                    [void]$candidateScopeKeys.Add($ancestorKey)
                }
            }
            foreach ($candidateScopeKey in $candidateScopeKeys) {
                if (
                    -not $assignmentsByScope.ContainsKey(
                        $candidateScopeKey
                    )
                ) {
                    continue
                }
                foreach (
                    $assignment in @(
                        $assignmentsByScope[
                            $candidateScopeKey
                        ].ToArray()
                    )
                ) {
                    if (
                        $effectiveAssignmentIds.Add(
                            $assignment.AssignmentId
                        )
                    ) {
                        [void]$effectiveAssignments.Add(
                            $assignment
                        )
                    }
                }
            }
            $hierarchyComplete = [bool](
                Get-RadarPropertyValue `
                    -InputObject $Hierarchy `
                    -Name 'IsComplete'
            )
            $unresolvedAncestorKeys = @(
                Get-RadarPropertyValue `
                    -InputObject $Hierarchy `
                    -Name 'UnresolvedAncestorRoots' |
                    ForEach-Object {
                        ([string]$_).TrimEnd('/').
                            ToLowerInvariant()
                    }
            )
            $hasUnresolvedAncestry = @(
                $candidateScopeKeys |
                    Where-Object {
                        $unresolvedAncestorKeys -contains
                            ([string]$_).ToLowerInvariant()
                    }
            ).Count -gt 0
            $relationshipUnknown = $false
            if (-not $hierarchyComplete -or $hasUnresolvedAncestry) {
                foreach (
                    $unplacedScopeKey in @(
                        $assignmentsByScope.Keys |
                            Where-Object {
                                -not $candidateScopeKeys.Contains(
                                    [string]$_
                                )
                            }
                    )
                ) {
                    $relationship = Test-RadarScopeDescendsFrom `
                        -Scope $evaluationScope.Id `
                        -RootScope $unplacedScopeKey `
                        -Hierarchy $Hierarchy
                    if ($relationship.State -eq 'Unknown') {
                        $relationshipUnknown = $true
                    }
                    elseif ($relationship.State -eq 'True') {
                        foreach (
                            $assignment in @(
                                $assignmentsByScope[
                                    $unplacedScopeKey
                                ].ToArray()
                            )
                        ) {
                            if (
                                $effectiveAssignmentIds.Add(
                                    $assignment.AssignmentId
                                )
                            ) {
                                [void]$effectiveAssignments.Add(
                                    $assignment
                                )
                            }
                        }
                    }
                }
            }
            $unconditionedAssignments = @(
                $effectiveAssignments |
                    Where-Object {
                        [string]::IsNullOrWhiteSpace(
                            [string](
                                Get-RadarPropertyValue `
                                    -InputObject $_ `
                                    -Name 'Condition'
                            )
                        )
                    }
            )
            $conditionedAssignmentCount =
                $effectiveAssignments.Count -
                $unconditionedAssignments.Count
            $state = if ($unconditionedAssignments.Count -gt 0) {
                'DirectAssignmentObserved'
            }
            elseif ($conditionedAssignmentCount -gt 0) {
                'AssignmentUnknown'
            }
            elseif (
                -not $AssignmentInventory.IsComplete -or
                $relationshipUnknown
            ) {
                'AssignmentUnknown'
            }
            else {
                'NoDirectAssignment'
            }
            $evidenceKey = Get-RadarBaselineAssignmentEvidenceKey `
                -BaselineRoleId $context.BaselineRoleId `
                -BaselineScope $context.BaselineScope `
                -EvaluationScope $evaluationScope.Id
            $evidenceByKey[$evidenceKey] = [pscustomobject]@{
                State = $state
                EffectiveDirectAssignmentCount =
                    $effectiveAssignments.Count
                AssignmentIds = @(
                    $effectiveAssignments |
                        ForEach-Object { $_.AssignmentId } |
                        Sort-Object -Unique
                )
                PrincipalTypes = @(
                    $effectiveAssignments |
                        ForEach-Object { $_.PrincipalType } |
                        Where-Object {
                            -not [string]::IsNullOrWhiteSpace($_)
                        } |
                        Sort-Object -Unique
                )
                AssignmentScopes = @(
                    $effectiveAssignments |
                        ForEach-Object { $_.AssignmentScope } |
                        Sort-Object -Unique
                )
                Warnings = @(
                    @($AssignmentInventory.Warnings) +
                    $(if ($conditionedAssignmentCount -gt 0) {
                        "$conditionedAssignmentCount effective direct baseline-role assignment(s) have Azure RBAC conditions that RADAR does not evaluate."
                    }) +
                    $(if ($relationshipUnknown) {
                        'At least one baseline-role assignment could not be placed safely in the visible hierarchy.'
                    }) |
                        Where-Object {
                            -not [string]::IsNullOrWhiteSpace($_)
                        } |
                        Sort-Object -Unique
                )
            }
        }
    }
    return $evidenceByKey
}

function Get-RadarRelevantBaselineAssignmentCount {
    param([hashtable]$EvidenceByKey = @{})

    return @(
        $EvidenceByKey.Values |
            ForEach-Object {
                Get-RadarPropertyValue `
                    -InputObject $_ `
                    -Name 'AssignmentIds'
            } |
            Where-Object {
                -not [string]::IsNullOrWhiteSpace($_)
            } |
            Sort-Object -Unique
    ).Count
}

function Get-RadarPolicyBoundaryScope {
    <#
    Discovers exact scopes that can change a parent policy result: policy
    assignment notScopes and policy exemption resource scopes. These scopes are
    added to baseline subtrees and evaluated independently.
    #>
    param(
        [object[]]$Scopes,
        [switch]$UseTenantDiscovery,
        [switch]$NoPolicyDiscovery
    )

    $scopeById = @{}
    $warnings = New-Object System.Collections.Generic.List[string]
    $uncertainRootScopes =
        New-Object System.Collections.Generic.HashSet[string] (
            [StringComparer]::OrdinalIgnoreCase
        )
    $tenantRootScopeKey = $null
    if ($UseTenantDiscovery) {
        $context = Get-AzContext -ErrorAction Stop
        $tenantId = [string](
            Get-RadarPropertyValue `
                -InputObject $context.Tenant `
                -Name 'Id'
        )
        if (-not [string]::IsNullOrWhiteSpace($tenantId)) {
            $tenantRootScopeKey = (
                "/providers/Microsoft.Management/managementGroups/$tenantId"
            ).ToLowerInvariant()
        }
    }
    $addBoundary = {
        param([string]$ScopeId)
        if ([string]::IsNullOrWhiteSpace($ScopeId)) { return }
        $normalised = $ScopeId.TrimEnd('/')
        if ([string]::IsNullOrWhiteSpace($normalised)) { return }
        $scopeKey = $normalised.ToLowerInvariant()
        if (
            $tenantRootScopeKey -and
            $scopeKey -eq $tenantRootScopeKey
        ) {
            return
        }
        $scopeById[$scopeKey] =
            New-RadarScope -Id $normalised
    }
    $addAssignmentBoundaries = {
        param([object]$Assignment)
        & $addBoundary (
            [string](
                Get-RadarPolicyProperty `
                    -InputObject $Assignment `
                    -Name 'Scope'
            )
        )
        foreach (
            $notScope in @(
                Get-RadarPolicyProperty `
                    -InputObject $Assignment `
                    -Name 'NotScope' |
                    Where-Object {
                        -not [string]::IsNullOrWhiteSpace($_)
                    }
            )
        ) {
            & $addBoundary ([string]$notScope)
        }
    }
    $addExemptionBoundary = {
        param([object]$Exemption)
        $resourceId = [string](
            Get-RadarPolicyProperty `
                -InputObject $Exemption `
                -Name 'Id'
        )
        $resourceScope = $resourceId -replace (
            '(?i)/providers/Microsoft\.Authorization/' +
            'policyExemptions/[^/]+$'
        ), ''
        if ($resourceScope -ne $resourceId) {
            & $addBoundary $resourceScope
        }
    }
    if ($NoPolicyDiscovery) {
        return [pscustomobject]@{
            Scopes = @()
            IsComplete = $true
            UncertainRootScopes = @()
            Warnings = @()
        }
    }
    if (-not (Get-Command Search-AzGraph -ErrorAction SilentlyContinue)) {
        [void]$warnings.Add(
            'Azure Resource Graph is unavailable; policy boundary discovery is using live subscription queries only.'
        )
    }
    else {
        try {
        $query = @'
authorizationresources
| where type in~ (
    'microsoft.authorization/policyassignments',
    'microsoft.authorization/policyexemptions'
)
| project
    id,
    type,
    Scope = tostring(properties.scope),
    NotScopes = properties.notScopes
'@
        $pageSize = 1000
        $skipToken = $null
        $skip = 0
        do {
            $parameters = @{
                Query = $query
                First = $pageSize
                ErrorAction = 'Stop'
            }
            $subscriptionIds = @(
                $Scopes |
                    ForEach-Object {
                        $match = [regex]::Match(
                            $_.Id,
                            '(?i)^/subscriptions/([^/]+)'
                        )
                        if ($match.Success) {
                            $match.Groups[1].Value
                        }
                    } |
                    Sort-Object -Unique
            )
            $managementGroupNames = @(
                $Scopes |
                    Where-Object {
                        $_.Type -eq 'ManagementGroup'
                    } |
                    ForEach-Object { $_.Name } |
                    Sort-Object -Unique
            )
            if ($UseTenantDiscovery) {
                $parameters.UseTenantScope = $true
            }
            elseif (
                $subscriptionIds.Count -gt 0 -and
                $managementGroupNames.Count -eq 0
            ) {
                $parameters.Subscription = $subscriptionIds
            }
            elseif (
                $managementGroupNames.Count -gt 0 -and
                $subscriptionIds.Count -eq 0
            ) {
                $parameters.ManagementGroup = $managementGroupNames
            }
            else {
                $parameters.UseTenantScope = $true
            }
            if ($skipToken) {
                $parameters.SkipToken = $skipToken
            }
            elseif ($skip -gt 0) {
                $parameters.Skip = $skip
            }

            $response = Search-AzGraph @parameters
            $wrapped = Test-RadarHasProperty `
                -InputObject $response `
                -Name 'Data'
            if ($wrapped) {
                $rows = @(
                    Get-RadarPropertyValue `
                        -InputObject $response `
                        -Name 'Data' |
                        Where-Object { $null -ne $_ }
                )
                $skipToken = [string](
                    Get-RadarPropertyValue `
                        -InputObject $response `
                        -Name 'SkipToken'
                )
            }
            else {
                $rows = @($response | Where-Object { $null -ne $_ })
                $skip += $rows.Count
                $skipToken = $null
            }

            foreach ($row in $rows) {
                $candidateScopes = New-Object System.Collections.Generic.List[string]
                $propertyScope = [string](
                    Get-RadarPropertyValue `
                        -InputObject $row `
                        -Name 'Scope'
                )
                if ($propertyScope) {
                    [void]$candidateScopes.Add($propertyScope)
                }

                $resourceId = [string](
                    Get-RadarPropertyValue `
                        -InputObject $row `
                        -Name 'Id'
                )
                $resourceScope = $resourceId -replace (
                    '(?i)/providers/Microsoft\.Authorization/' +
                    '(policyAssignments|policyExemptions)/[^/]+$'
                ), ''
                if (
                    $resourceScope -and
                    $resourceScope -ne $resourceId
                ) {
                    [void]$candidateScopes.Add($resourceScope)
                }

                foreach (
                    $notScope in @(
                        Get-RadarPropertyValue `
                            -InputObject $row `
                            -Name 'NotScopes' |
                            Where-Object {
                                -not [string]::IsNullOrWhiteSpace($_)
                            }
                    )
                ) {
                    [void]$candidateScopes.Add([string]$notScope)
                }

                foreach ($candidateScope in $candidateScopes) {
                    & $addBoundary ([string]$candidateScope)
                }
            }
        } while (
            $skipToken -or
            (-not $wrapped -and $rows.Count -eq $pageSize)
        )
        }
        catch {
            [void]$warnings.Add(
                "Azure Resource Graph policy boundary discovery failed: $($_.Exception.Message)"
            )
        }
    }

    # Resource Graph is eventually consistent. Confirm descendant policy and
    # exemption boundaries through live ARM queries for every visible
    # subscription. These results are used only to discover exact scopes; each
    # scope is evaluated later without IncludeDescendent.
    foreach (
        $subscriptionScope in @(
            $Scopes |
                Where-Object {
                    $_.Type -ne 'ManagementGroup'
                } |
                Sort-Object Id -Unique
        )
    ) {
        try {
            foreach (
                $assignment in @(
                    Get-AzPolicyAssignment `
                        -Scope $subscriptionScope.Id `
                        -IncludeDescendent `
                        -ErrorAction Stop `
                        -WarningAction SilentlyContinue
                )
            ) {
                & $addAssignmentBoundaries $assignment
            }
        }
        catch {
            [void]$uncertainRootScopes.Add($subscriptionScope.Id)
            [void]$warnings.Add(
                "Live descendant policy-assignment boundary discovery failed at $($subscriptionScope.Id): $($_.Exception.Message)"
            )
        }

        try {
            foreach (
                $exemption in @(
                    Get-AzPolicyExemption `
                        -Scope $subscriptionScope.Id `
                        -IncludeDescendent `
                        -ErrorAction Stop `
                        -WarningAction SilentlyContinue
                )
            ) {
                & $addExemptionBoundary $exemption
            }
        }
        catch {
            [void]$uncertainRootScopes.Add($subscriptionScope.Id)
            [void]$warnings.Add(
                "Live descendant policy-exemption boundary discovery failed at $($subscriptionScope.Id): $($_.Exception.Message)"
            )
        }
    }

    [pscustomobject]@{
        Scopes = @($scopeById.Values | Sort-Object Type, Id)
        IsComplete = $uncertainRootScopes.Count -eq 0
        UncertainRootScopes = @(
            $uncertainRootScopes |
                Sort-Object
        )
        Warnings = $warnings.ToArray()
    }
}

function Test-GlobIntersect {
    <#
    Returns $true when two wildcard patterns can match at least one common
    concrete action. Azure RBAC '*' can consume any run of characters,
    including '/'.
    #>
    param(
        [string]$A,
        [string]$B
    )

    $n = $A.Length
    $m = $B.Length
    $width = $m + 1
    $matches = New-Object 'bool[]' (($n + 1) * $width)

    $matches[$n * $width + $m] = $true
    for ($j = $m - 1; $j -ge 0; $j--) {
        $matches[$n * $width + $j] =
            ($B[$j] -eq '*') -and $matches[$n * $width + $j + 1]
    }
    for ($i = $n - 1; $i -ge 0; $i--) {
        $matches[$i * $width + $m] =
            ($A[$i] -eq '*') -and $matches[($i + 1) * $width + $m]
    }

    for ($i = $n - 1; $i -ge 0; $i--) {
        for ($j = $m - 1; $j -ge 0; $j--) {
            if ($A[$i] -eq '*' -or $B[$j] -eq '*') {
                $matches[$i * $width + $j] =
                    $matches[($i + 1) * $width + $j] -or
                    $matches[$i * $width + $j + 1]
            }
            elseif (
                [char]::ToLowerInvariant($A[$i]) -eq
                [char]::ToLowerInvariant($B[$j])
            ) {
                $matches[$i * $width + $j] =
                    $matches[($i + 1) * $width + $j + 1]
            }
        }
    }

    return $matches[0]
}

function Test-PermissionMatch {
    <#
    Returns $true if the role's permission pattern and the restricted action
    overlap, that is, there exists at least one concrete action that satisfies
    both. Wildcards ('*') are honoured on either side.

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

    $patternHasWildcard = $Pattern.Contains('*')
    $actionHasWildcard = $Action.Contains('*')

    if (-not $patternHasWildcard -and -not $actionHasWildcard) {
        return [string]::Equals(
            $Pattern,
            $Action,
            [System.StringComparison]::OrdinalIgnoreCase
        )
    }

    $options = [System.Text.RegularExpressions.RegexOptions]::IgnoreCase
    if ($patternHasWildcard -and -not $actionHasWildcard) {
        $regex = '^' + [Regex]::Escape($Pattern).Replace('\*', '.*') + '$'
        return [Regex]::IsMatch($Action, $regex, $options)
    }
    if ($actionHasWildcard -and -not $patternHasWildcard) {
        $regex = '^' + [Regex]::Escape($Action).Replace('\*', '.*') + '$'
        return [Regex]::IsMatch($Pattern, $regex, $options)
    }

    return (Test-GlobIntersect -A $Pattern -B $Action)
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
        [AllowEmptyCollection()]
        [object[]]$Results,

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

        [string[]]$SourceRoleNames = @(),

        [int]$ScopeCount = 0,

        [int]$BaselineContextCount = 0,

        [int]$BaselineAssignmentCount = 0,

        [object[]]$BaselineSummaries = @(),

        [object[]]$ControlGapMap = @(),

        [object[]]$PrincipalGaps = @(),

        [int]$PolicyAssignmentCount = 0,

        [int]$RoleDenyRuleCount = 0,

        [int]$PolicyExemptionCount = 0,

        [bool]$DiscoveryComplete = $true,

        [string[]]$DiscoveryWarnings = @(),

        [string]$PrincipalScenario = 'Non-exempt User',

        [switch]$MapOnly
    )

    $generated = (Get-Date).ToString('u')
    $resultArray = @($Results)
    $discoveryWarningArray = @($DiscoveryWarnings)
    $sourceRoleNameArray = @($SourceRoleNames)
    $controlGapMapArray = @($ControlGapMap)
    $principalGapArray = @($PrincipalGaps)
    $netNewGapRows = @(
        $principalGapArray |
            Where-Object {
                $_.NetNewGapStatus -eq 'NetNewGap'
            }
    )
    $netNewGapActionCount = @(
        $netNewGapRows |
            Select-Object -ExpandProperty RestrictedAction -Unique
    ).Count
    $netNewGapPrincipalCount = @(
        $netNewGapRows |
            Select-Object -ExpandProperty PrincipalId -Unique
    ).Count
    $totalMatches = $resultArray.Count
    $uniqueRolesAffected = (
        $resultArray |
            Select-Object -ExpandProperty RoleId -Unique |
            Measure-Object
    ).Count
    $actionsTriggered = ($resultArray | Select-Object -ExpandProperty RestrictedAction -Unique | Measure-Object).Count

    # Group by baseline context and granting role so distinct customer
    # restriction models are never collapsed into a global role result.
    $grouped = @(
        $resultArray |
            Group-Object {
                "$($_.AnalysisMode)$([char]31)$($_.BaselineRoleId)$([char]31)$($_.BaselineScope)$([char]31)$($_.RoleId)"
            } |
            Sort-Object {
                "$($_.Group[0].BaselineRoleName)$([char]31)$($_.Group[0].BaselineScope)$([char]31)$($_.Group[0].RoleName)"
            }
    )
    $rolesAffected = $grouped.Count

    $sb = [System.Text.StringBuilder]::new()
    [void]$sb.AppendLine('<!DOCTYPE html>')
    [void]$sb.AppendLine('<html lang="en"><head><meta charset="utf-8"/>')
    [void]$sb.AppendLine('<meta name="viewport" content="width=device-width,initial-scale=1"/>')
    $documentTitle = if ($MapOnly) {
        'RADAR Scope Control-Gap Map'
    }
    else {
        'RADAR Report'
    }
    [void]$sb.AppendLine(
        '<title>' + $documentTitle + '</title>'
    )
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
  .value.gap { color: var(--danger); }

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
  .role.is-partial, .role.is-unknown { border-left: 3px solid var(--warn); }
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
  .role .badge.partial, .role .badge.unknown {
    background: rgba(255,184,107,0.12); color: var(--warn);
    border-color: rgba(255,184,107,0.45);
  }

  table { width: 100%; border-collapse: collapse; table-layout: auto; }
  th, td {
    padding: 10px 14px; text-align: left; font-size: 13px;
    border-bottom: 1px solid var(--border);
    vertical-align: middle;
    white-space: nowrap;
  }
  .role .table-wrap { overflow-x: auto; }
  .role .coverage-note {
    padding: 10px 18px; color: var(--muted); font-size: 12px;
    border-bottom: 1px solid var(--border);
  }
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
  .warning {
    background: rgba(255,184,107,0.1);
    border: 1px solid rgba(255,184,107,0.45);
    border-radius: 12px; padding: 14px 18px; margin-bottom: 22px;
    color: var(--warn); font-size: 13px;
  }
  .warning ul { margin: 8px 0 0; padding-left: 20px; }
  .warning li { padding: 2px 0; }
  .model-note {
    display: grid; grid-template-columns: repeat(auto-fit, minmax(320px, 1fr));
    gap: 12px;
    background: rgba(110,168,255,0.08);
    border: 1px solid rgba(110,168,255,0.35);
    border-radius: 12px; padding: 14px 18px; margin-bottom: 22px;
    color: var(--accent); font-size: 13px;
  }
  .equation {
    padding: 10px 12px; background: rgba(0,0,0,.12);
    border: 1px solid rgba(110,168,255,.2); border-radius: 8px;
  }
  .equation strong {
    display: block; margin-bottom: 4px; color: var(--text);
  }
  .equation span { color: var(--muted); }
  .map-toolbar {
    display: flex; gap: 10px; align-items: center; flex-wrap: wrap;
    margin: 14px 0 18px; padding: 12px;
    background: var(--panel); border: 1px solid var(--border);
    border-radius: 10px;
  }
  .map-tabs { display: flex; gap: 6px; flex-wrap: wrap; }
  .map-tab {
    cursor: pointer; padding: 8px 12px; border-radius: 8px;
    border: 1px solid var(--border); color: var(--muted);
    background: var(--panel-2); font-size: 12px;
  }
  .map-tab[aria-selected="true"] {
    color: var(--text); border-color: var(--accent);
    box-shadow: 0 0 0 1px rgba(110,168,255,.2);
  }
  .map-tab[data-map-mode="actionable"][aria-selected="true"] {
    color: var(--danger); border-color: var(--danger);
  }
  .map-tab[data-map-mode="blast"][aria-selected="true"] {
    color: var(--danger); border-color: var(--danger);
  }
  .map-search {
    flex: 1 1 240px; min-width: 180px; padding: 8px 10px;
    color: var(--text); background: var(--panel-2);
    border: 1px solid var(--border); border-radius: 8px;
  }
  .map-scope-type {
    padding: 8px 10px; color: var(--text);
    background: var(--panel-2); border: 1px solid var(--border);
    border-radius: 8px;
  }
  .map-visible-count { color: var(--muted); font-size: 12px; }
  .map-empty {
    margin: 12px 0 18px; padding: 24px; text-align: center;
    color: var(--muted); background: var(--panel);
    border: 1px dashed var(--border); border-radius: 10px;
  }
  .map-empty[hidden] { display: none; }
  .scope-tree[data-mode="actionable"]
    .map-metric:not(.map-actionable),
  .scope-tree[data-mode="blast"]
    .map-metric:not(.map-blast),
  .scope-tree[data-mode="review"]
    .map-metric:not(.map-review) { display: none; }
  .scope-tree[data-mode="actionable"]
    .baseline-summary:not([data-has-net-new="true"]),
  .scope-tree[data-mode="blast"]
    .baseline-summary:not([data-has-blast-radius="true"]),
  .scope-tree[data-mode="review"]
    .baseline-summary:not([data-has-principal-unknown="true"]) {
    display: none;
  }
  .scope-tree[data-mode="actionable"]
    .map-status:not(.map-status-actionable),
  .scope-tree[data-mode="blast"]
    .map-status:not(.map-status-blast),
  .scope-tree[data-mode="review"]
    .map-status:not(.map-status-review) { display: none; }
  .scope-tree[data-mode="all"]
    .map-status-review-secondary,
  .scope-tree[data-mode="all"]
    .map-status-blast { display: none; }
  .scope-node .ancestor-context { display: none; }
  .scope-node.map-ancestor-only .scope-count { display: none; }
  .scope-node.map-ancestor-only .ancestor-context {
    display: inline-block;
  }
  .scope-map-wrap { overflow-x: auto; margin-top: 12px; }
  .scope-map-table td {
    white-space: normal; vertical-align: top; min-width: 110px;
  }
  .scope-map-table { table-layout: fixed; }
  .scope-map-table td.scope-id {
    min-width: 260px; overflow-wrap: anywhere;
  }
  .scope-map-table details summary {
    cursor: pointer; color: var(--accent); white-space: nowrap;
  }
  .scope-map-table .list {
    margin-top: 6px; max-width: 520px;
    overflow-wrap: anywhere; line-height: 1.45;
  }
  .scope-tree { margin-top: 16px; }
  .scope-node {
    position: relative;
    margin: 10px 0 10px var(--scope-indent, 0);
    width: calc(100% - var(--scope-indent, 0));
  }
  .scope-node::before {
    content: ""; position: absolute; top: 20px; left: -12px;
    width: 10px; border-top: 1px solid var(--border);
  }
  .scope-node[data-depth="0"]::before { display: none; }
  .scope-card {
    background: var(--panel-2); border: 1px solid var(--border);
    border-radius: 10px; padding: 10px 12px;
  }
  .scope-card summary {
    cursor: pointer; display: flex; gap: 8px;
    align-items: center; flex-wrap: wrap;
  }
  .scope-card .scope-title { font-weight: 600; }
  .scope-card .scope-type {
    color: var(--accent); font-size: 11px; text-transform: uppercase;
  }
  .scope-card .scope-count {
    border-radius: 999px; padding: 1px 8px; font-size: 11px;
  }
  .scope-card .scope-count.gap {
    color: var(--danger); border: 1px solid rgba(255,92,122,.45);
  }
  .scope-card .scope-count.current {
    color: var(--accent); border: 1px solid rgba(110,168,255,.45);
  }
  .scope-card .scope-count.external {
    color: #f59e0b; border: 1px solid rgba(245,158,11,.45);
  }
  .scope-card .scope-count.unknown {
    color: var(--warn); border: 1px solid rgba(255,184,107,.45);
  }
  .scope-card .scope-count.covered {
    color: var(--ok); border: 1px solid rgba(91,227,177,.4);
  }
  .scope-node-content { margin-top: 10px; }
  .baseline-summary {
    margin-top: 12px; padding: 12px;
    background: rgba(255,255,255,.025);
    border: 1px solid var(--border); border-radius: 8px;
  }
  .baseline-summary:first-child { margin-top: 10px; }
  .baseline-heading {
    font-weight: 600; margin-bottom: 10px; overflow-wrap: anywhere;
  }
  .baseline-scope {
    display: block; margin-top: 3px; color: var(--muted);
    font-size: 11px; font-weight: 400;
  }
  .baseline-metrics {
    display: grid;
    grid-template-columns: repeat(auto-fit, minmax(190px, 1fr));
    gap: 10px;
  }
  .map-metric {
    min-width: 0; padding: 10px 12px;
    background: var(--panel); border: 1px solid var(--border);
    border-radius: 8px;
  }
  .map-metric-trigger {
    display: block; width: 100%; padding: 0; cursor: pointer;
    color: var(--muted); background: transparent; border: 0;
    text-align: left; font: inherit; font-size: 12px; line-height: 1.4;
  }
  .map-metric-trigger:hover { color: var(--accent); }
  .map-metric-trigger:focus-visible {
    outline: 2px solid var(--accent); outline-offset: 4px;
  }
  .map-metric-trigger strong {
    display: inline-block; margin-right: 5px;
    color: var(--text); font-size: 15px;
  }
  .map-metric-open {
    float: right; color: var(--accent); font-size: 10px;
    text-transform: uppercase; letter-spacing: .5px;
  }
  .map-metric.gap { border-color: rgba(255,92,122,.35); }
  .map-metric.current { border-color: rgba(110,168,255,.4); }
  .map-metric.external { border-color: rgba(245,158,11,.35); }
  .map-metric.unknown { border-color: rgba(255,184,107,.35); }
  .map-metric.covered { border-color: rgba(91,227,177,.3); }
  .map-metric .list {
    margin-top: 8px; max-height: 220px; overflow: auto;
    white-space: normal; overflow-wrap: anywhere;
  }
  .metric-list {
    columns: 1 !important; column-gap: 0 !important;
    list-style: none; margin: 8px 0 0; padding: 0 8px 0 0;
    white-space: normal; overflow-wrap: anywhere;
  }
  .metric-list li {
    padding: 7px 0; border-bottom: 1px solid var(--border);
    line-height: 1.35; color: var(--text);
  }
  .metric-list li:last-child { border-bottom: none; }
  .metric-list small {
    display: block; margin-top: 2px; color: var(--muted);
    font-size: 10.5px; font-weight: 400; overflow-wrap: anywhere;
  }
  .metric-dialog {
    width: min(860px, calc(100vw - 32px));
    max-height: min(82vh, 900px); padding: 0;
    color: var(--text); background: var(--panel);
    border: 1px solid var(--border); border-radius: 12px;
    box-shadow: 0 24px 80px rgba(0,0,0,.55);
  }
  .metric-dialog::backdrop { background: rgba(3,7,18,.78); }
  .metric-dialog-header {
    position: sticky; top: 0; z-index: 1;
    display: flex; align-items: center; gap: 16px;
    padding: 16px 18px; background: var(--panel-2);
    border-bottom: 1px solid var(--border);
  }
  .metric-dialog-title { flex: 1; margin: 0; font-size: 16px; }
  .metric-dialog-close {
    cursor: pointer; padding: 6px 10px; border-radius: 8px;
    color: var(--text); background: transparent;
    border: 1px solid var(--border); font-size: 18px;
  }
  .metric-dialog-search {
    width: calc(100% - 36px); margin: 16px 18px 4px;
    padding: 10px 12px; color: var(--text);
    background: var(--panel-2); border: 1px solid var(--border);
    border-radius: 8px;
  }
  .metric-dialog-body {
    max-height: calc(82vh - 132px); padding: 6px 18px 20px;
    overflow: auto;
  }
  .metric-dialog-body .metric-list {
    max-height: none; overflow: visible; padding-right: 0;
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
    [void]$sb.AppendLine(
        '<h1>' +
        $documentTitle +
        '</h1>'
    )
    if ($MapOnly) {
        $mappedScopeCount = @(
            $controlGapMapArray |
                ForEach-Object {
                    Get-RadarPropertyValue `
                        -InputObject $_ `
                        -Name 'EvaluationScope'
                } |
                Sort-Object -Unique
        ).Count
        $mappedScopeLabel = if ($mappedScopeCount -eq 1) {
            'mapped scope'
        }
        else {
            'mapped scopes'
        }
        $sourceRoleCount = @(
            $controlGapMapArray |
                ForEach-Object {
                    Get-RadarPropertyValue `
                        -InputObject $_ `
                        -Name 'BaselineRoleId'
                } |
                Where-Object {
                    -not [string]::IsNullOrWhiteSpace($_)
                } |
                Sort-Object -Unique
        ).Count
        $sourceRoleLabel = if ($sourceRoleCount -eq 1) {
            'source role'
        }
        else {
            'source roles'
        }
        [void]$sb.AppendLine(
            '<div class="sub">Generated ' +
            $generated +
            ' &middot; ' +
            $mappedScopeCount +
            ' ' +
            $mappedScopeLabel +
            ' &middot; ' +
            $sourceRoleCount +
            ' ' +
            $sourceRoleLabel +
            '</div>'
        )
    }
    else {
        $scope = if ($IncludeCustomRoles) {
            'built-in &amp; custom roles'
        }
        else {
            'built-in roles'
        }
        $scopeNote = if ($IncludeCustomRoles -and $CustomScope) {
            ' &middot; ' + (ConvertTo-HtmlSafe $CustomScope)
        }
        else {
            ''
        }
        [void]$sb.AppendLine(
            '<div class="sub">Generated ' +
            $generated +
            ' &middot; Scope: ' +
            $scope +
            $scopeNote +
            ' &middot; Assignment subject: ' +
            (ConvertTo-HtmlSafe $PrincipalScenario) +
            '</div>'
        )
    }
    [void]$sb.AppendLine('</div></header>')

    [void]$sb.AppendLine('<main>')

    if (-not $DiscoveryComplete -or $discoveryWarningArray.Count -gt 0) {
        [void]$sb.AppendLine('<section class="warning"><strong>Discovery warning:</strong> deny coverage may be incomplete. Any role not marked Fully Denied is treated as potentially assignable, not as proven current exposure.')
        if ($discoveryWarningArray.Count -gt 0) {
            [void]$sb.AppendLine('<ul>')
            foreach ($warningMessage in $discoveryWarningArray) {
                [void]$sb.AppendLine(
                    '<li>' + (ConvertTo-HtmlSafe $warningMessage) + '</li>'
                )
            }
            [void]$sb.AppendLine('</ul>')
        }
        [void]$sb.AppendLine('</section>')
    }
    if ($BaselineContextCount -gt 0 -or $controlGapMapArray.Count -gt 0) {
        [void]$sb.AppendLine(
            '<section class="model-note">' +
            '<div class="equation"><strong>Control gap</strong>' +
            '<span>= restricted action + granting role &minus; deny-control ' +
            'coverage</span></div>' +
            '<div class="equation"><strong>Proven exposure</strong>' +
            '<span>= restricted action + granting role + actual holder + ' +
            'self-assignment &minus; existing access &minus; effective ' +
            'policy block</span></div></section>'
        )
    }

    if (-not $MapOnly) {
    $customMatches  = @(@($Results) | Where-Object { $_.IsCustom }).Count
    $builtInMatches = $totalMatches - $customMatches

    # Compute scope-aware deny coverage across baseline/granting-role pairs.
    $affectedRoles = $grouped
    $rolesAlreadyDenied = 0
    $rolesPartiallyDenied = 0
    $rolesUnknown = 0
    $rolesNotYetDenied  = 0
    foreach ($g in $affectedRoles) {
        $first = $g.Group | Select-Object -First 1
        switch ([string]$first.DenyCoverage) {
            'Full' { $rolesAlreadyDenied++ }
            'Partial' { $rolesPartiallyDenied++ }
            { $_ -in @('Unknown', 'NotEvaluated') } { $rolesUnknown++ }
            default { $rolesNotYetDenied++ }
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
        [void]$sb.AppendLine('  <h2>Secondary role-capability deny coverage</h2>')
        [void]$sb.AppendLine('  <p>Share of baseline/granting-role pairs represented in the control posture. Proven principal paths are reported separately and do not replace this control-gap evidence.</p>')
        [void]$sb.AppendLine('  <div class="nums">')
        [void]$sb.AppendLine('    <div class="num"><b>' + $rolesAffected + '</b>baseline/role pairs</div>')
        [void]$sb.AppendLine('    <div class="num ok"><b>' + $rolesAlreadyDenied + '</b>fully denied</div>')
        [void]$sb.AppendLine('    <div class="num"><b>' + $rolesPartiallyDenied + '</b>partially denied</div>')
        [void]$sb.AppendLine('    <div class="num"><b>' + $rolesUnknown + '</b>coverage unknown</div>')
        [void]$sb.AppendLine('    <div class="num gap"><b>' + $rolesNotYetDenied + '</b>not denied</div>')
        [void]$sb.AppendLine('  </div>')
        [void]$sb.AppendLine('</div>')
        [void]$sb.AppendLine('</section>')
    }

    # Summary cards.
    [void]$sb.AppendLine('<section class="grid">')
    if ($BaselineContextCount -gt 0) {
        [void]$sb.AppendLine(
            "<div class=`"card`"><div class=`"label`">Net-New Gap Actions</div><div class=`"value gap`">$netNewGapActionCount</div></div>"
        )
        [void]$sb.AppendLine(
            "<div class=`"card`"><div class=`"label`">Net-New Gap Principals</div><div class=`"value gap`">$netNewGapPrincipalCount</div></div>"
        )
    }
    [void]$sb.AppendLine("<div class=`"card`"><div class=`"label`">Built-in Scanned</div><div class=`"value accent`">$BuiltInScanned</div></div>")
    if ($IncludeCustomRoles) {
        [void]$sb.AppendLine("<div class=`"card`"><div class=`"label`">Custom Scanned</div><div class=`"value accent`">$CustomScanned</div></div>")
    }
    if ($ScopeCount -gt 0) {
        [void]$sb.AppendLine("<div class=`"card`"><div class=`"label`">Scopes Evaluated</div><div class=`"value accent`">$ScopeCount</div></div>")
    }
    if ($BaselineContextCount -gt 0) {
        [void]$sb.AppendLine("<div class=`"card`"><div class=`"label`">Baseline Contexts</div><div class=`"value accent`">$BaselineContextCount</div></div>")
    }
    if ($BaselineContextCount -gt 0) {
        [void]$sb.AppendLine(
            "<div class=`"card`"><div class=`"label`">Direct Baseline Assignments</div><div class=`"value accent`">$BaselineAssignmentCount</div></div>"
        )
    }
    if ($DeniedListProvided) {
        [void]$sb.AppendLine("<div class=`"card`"><div class=`"label`">Policy Assignments</div><div class=`"value`">$PolicyAssignmentCount</div></div>")
        [void]$sb.AppendLine("<div class=`"card`"><div class=`"label`">Role-Deny Rules</div><div class=`"value`">$RoleDenyRuleCount</div></div>")
        [void]$sb.AppendLine("<div class=`"card`"><div class=`"label`">Active Exemptions</div><div class=`"value`">$PolicyExemptionCount</div></div>")
    }
    [void]$sb.AppendLine("<div class=`"card`"><div class=`"label`">Restricted Actions</div><div class=`"value`">$($RestrictedActions.Count)</div></div>")
    [void]$sb.AppendLine("<div class=`"card`"><div class=`"label`">Granting Roles</div><div class=`"value`">$uniqueRolesAffected</div></div>")
    if ($sourceRoleNameArray.Count -gt 0) {
        $srcTitle = ConvertTo-HtmlSafe ($sourceRoleNameArray -join ', ')
        [void]$sb.AppendLine("<div class=`"card`" title=`"$srcTitle`"><div class=`"label`">Source Roles</div><div class=`"value accent`">$($sourceRoleNameArray.Count)</div></div>")
    }
    [void]$sb.AppendLine('</section>')

    # Restricted actions input list.
    [void]$sb.AppendLine('<details class="actions-list"><summary>Restricted actions evaluated (' + $RestrictedActions.Count + ')</summary><ul>')
    foreach ($a in $RestrictedActions) {
        [void]$sb.AppendLine('<li>' + (ConvertTo-HtmlSafe $a) + '</li>')
    }
    [void]$sb.AppendLine('</ul></details>')

    # Potentially obtainable restricted actions: still granted by at least one
    # role not on the deny list. This does not prove a current principal can
    # perform the assignment.
    if ($DeniedListProvided) {
        $obtainable = [ordered]@{}
        foreach ($item in $resultArray) {
            $isDen = $item.PSObject.Properties['IsAlreadyDenied'] -and $item.IsAlreadyDenied
            if (-not $isDen) {
                $act = [string]$item.RestrictedAction
                if (-not $obtainable.Contains($act)) { $obtainable[$act] = New-Object System.Collections.Generic.List[string] }
                $via = "$($item.RoleName) via $($item.BaselineRoleName) @ $($item.BaselineScope)"
                if (-not $obtainable[$act].Contains($via)) { [void]$obtainable[$act].Add($via) }
            }
        }
        $obtainableActions = @($obtainable.Keys | Sort-Object)
        $obtainClass = if ($obtainableActions.Count -gt 0) { 'actions-list exposed' } else { 'actions-list' }
        [void]$sb.AppendLine('<details class="' + $obtainClass + '"><summary>Secondary estate-wide candidate-action union (' + $obtainableActions.Count + ' of ' + $RestrictedActions.Count + ')</summary>')
        [void]$sb.AppendLine('<p class="note">Union across every baseline context and the optional CSV audit. Use the per-baseline section below to distinguish a covered production baseline from a gap in another scope.</p>')
        if ($obtainableActions.Count -eq 0) {
            [void]$sb.AppendLine('<p class="note">None - every restricted action is granted only by roles already on the deny list.</p>')
        }
        else {
            [void]$sb.AppendLine('<ul>')
            foreach ($act in $obtainableActions) {
                $paths = $obtainable[$act]
                $titleSafe = ConvertTo-HtmlSafe ((@($paths) | Sort-Object) -join ', ')
                $plural = if ($paths.Count -ne 1) { 's' } else { '' }
                [void]$sb.AppendLine('<li title="' + $titleSafe + '">' + (ConvertTo-HtmlSafe $act) + ' <span class="via">(' + $paths.Count + ' path' + $plural + ')</span></li>')
            }
            [void]$sb.AppendLine('</ul>')
        }
        [void]$sb.AppendLine('</details>')
    }

    if (@($BaselineSummaries).Count -gt 0) {
        [void]$sb.AppendLine('<details class="actions-list"><summary>Secondary candidate actions by baseline context (' + @($BaselineSummaries).Count + ')</summary>')
        [void]$sb.AppendLine('<p class="note">Each baseline role and exact AssignableScope is evaluated independently for control coverage. Actual holders, existing access and principal-specific policy are correlated separately in the proven user-path results.</p>')
        [void]$sb.AppendLine('<ul>')
        foreach (
            $baselineSummary in @(
                $BaselineSummaries |
                    Sort-Object BaselineRoleName, BaselineScope
            )
        ) {
            $summaryTitle = ConvertTo-HtmlSafe (
                @($baselineSummary.ObtainableActions) -join ', '
            )
            $contextLabel = "$($baselineSummary.BaselineRoleName) @ $($baselineSummary.BaselineScope)"
            [void]$sb.AppendLine(
                '<li title="' + $summaryTitle + '">' +
                (ConvertTo-HtmlSafe $contextLabel) +
                ' <span class="via">(' +
                $baselineSummary.ObtainableActionCount +
                ' of ' +
                $baselineSummary.RestrictedActionCount +
                ' potentially obtainable via ' +
                $baselineSummary.GapRoleCount +
                ' role(s))</span></li>'
            )
        }
        [void]$sb.AppendLine('</ul></details>')
    }
    }

    if ($controlGapMapArray.Count -gt 0) {
        $collectDelimitedValues = {
            param(
                [object[]]$Rows,
                [string]$Property
            )
            @(
                $Rows |
                    ForEach-Object {
                        [string](
                            Get-RadarPropertyValue `
                                -InputObject $_ `
                                -Name $Property
                        ) -split '; '
                    } |
                    Where-Object {
                        -not [string]::IsNullOrWhiteSpace($_)
                    } |
                    Sort-Object -Unique
            )
        }
        $getMapBaselineAccessStatus = {
            param([object]$Row)

            $status = [string](
            Get-RadarPropertyValue `
                -InputObject $Row `
                -Name 'BaselineAccessStatus'
            )
            if (
            $status -in @(
                'DirectAssignmentObserved',
                'BaselineCapable',
                'AssignmentUnknown',
                'ExternalOnly',
                'Unknown',
                'Covered'
            )
            ) {
            return $status
            }
            if ($status -eq 'Obtainable') {
            return 'BaselineCapable'
            }
            if (
            -not [string]::IsNullOrWhiteSpace(
                [string](
                    Get-RadarPropertyValue `
                        -InputObject $Row `
                        -Name 'BaselineAssignableRoles'
                )
            )
            ) {
            return 'BaselineCapable'
            }
            if (
            [string](
                Get-RadarPropertyValue `
                    -InputObject $Row `
                    -Name 'GapStatus'
            ) -eq 'Unknown' -or
            -not [string]::IsNullOrWhiteSpace(
                [string](
                    Get-RadarPropertyValue `
                        -InputObject $Row `
                        -Name 'UnknownBaselineAssignableRoles'
                    )
            ) -or
            -not [string]::IsNullOrWhiteSpace(
                [string](
                    Get-RadarPropertyValue `
                        -InputObject $Row `
                        -Name 'CoverageWarnings'
                )
            )
            ) {
            return 'Unknown'
            }
            if (
            -not [string]::IsNullOrWhiteSpace(
                [string](
                    Get-RadarPropertyValue `
                        -InputObject $Row `
                        -Name 'ExternalAssignmentRoles'
                )
            )
            ) {
            return 'ExternalOnly'
            }
            return 'Covered'
        }
        $scopeMapSummaries = @(
            $controlGapMapArray |
            Group-Object {
                @(
                    $_.EvaluationScope,
                    $_.BaselineRoleId,
                    (
                        Get-RadarPropertyValue `
                            -InputObject $_ `
                            -Name 'BaselineScope'
                    )
                ) -join [char]31
            } |
            ForEach-Object {
                $rows = @($_.Group)
                $first = $rows[0]
                $subtreeGapRows = @(
                    $rows |
                        Where-Object {
                            [string](
                                Get-RadarPropertyValue `
                                    -InputObject $_ `
                                    -Name 'SubtreeControlStatus'
                            ) -eq 'Gap'
                        }
                )
                $subtreeCoveredRows = @(
                    $rows |
                        Where-Object {
                            [string](
                                Get-RadarPropertyValue `
                                    -InputObject $_ `
                                    -Name 'SubtreeControlStatus'
                            ) -eq 'Covered'
                        }
                )
                $currentDirectRows = @(
                    $rows |
                        Where-Object {
                            (& $getMapBaselineAccessStatus $_) -eq
                                'DirectAssignmentObserved'
                        }
                )
                $baselineObtainableRows = @(
                    $rows |
                        Where-Object {
                            (& $getMapBaselineAccessStatus $_) -eq
                                'BaselineCapable'
                        }
                )
                $assignmentUnknownRows = @(
                    $rows |
                        Where-Object {
                            (& $getMapBaselineAccessStatus $_) -eq
                                'AssignmentUnknown'
                        }
                )
                $externalGapRows = @(
                    $rows |
                        Where-Object {
                            (& $getMapBaselineAccessStatus $_) -eq
                                'ExternalOnly'
                        }
                )
                $unknownRows = @(
                    $rows |
                        Where-Object {
                            (& $getMapBaselineAccessStatus $_) -eq
                                'Unknown'
                        }
                )
                $coveredRows = @(
                    $rows |
                        Where-Object {
                            (& $getMapBaselineAccessStatus $_) -eq
                                'Covered'
                        }
                )
                [pscustomobject]@{
                        PostureEvidenceOnly = $false
                        EvaluationScopeType =
                            $first.EvaluationScopeType
                        EvaluationScopeName =
                            $first.EvaluationScopeName
                        EvaluationScope =
                            $first.EvaluationScope
                        ParentScopeName = [string](
                            Get-RadarPropertyValue `
                                -InputObject $first `
                                -Name 'ParentScopeName'
                        )
                        ParentScope = [string](
                            Get-RadarPropertyValue `
                                -InputObject $first `
                                -Name 'ParentScope'
                        )
                        AncestorScopes = [string](
                            Get-RadarPropertyValue `
                                -InputObject $first `
                                -Name 'AncestorScopes'
                        )
                        BaselineRoleName =
                            $first.BaselineRoleName
                        BaselineScope =
                            Get-RadarPropertyValue `
                                -InputObject $first `
                                -Name 'BaselineScope'
                        NetNewGapActions = @(
                            $rows |
                                Where-Object {
                                    [string](
                                        Get-RadarPropertyValue `
                                            -InputObject $_ `
                                            -Name 'PrincipalGapStatus'
                                    ) -eq 'NetNewGap'
                                } |
                                ForEach-Object {
                                    Get-RadarPropertyValue `
                                        -InputObject $_ `
                                        -Name 'RestrictedAction'
                                } |
                                Sort-Object -Unique
                        )
                        NetNewGapRoles = @(
                            & $collectDelimitedValues `
                                $rows `
                                'NetNewGapRoles'
                        )
                        NetNewGapPolicies = @(
                            & $collectDelimitedValues `
                                $rows `
                                'NetNewGapPolicies'
                        )
                        NetNewGapPaths = @(
                            $rows |
                                ForEach-Object {
                                    [string](
                                        Get-RadarPropertyValue `
                                            -InputObject $_ `
                                            -Name 'NetNewGapPaths'
                                    ) -split ' \|\| '
                                } |
                                Where-Object {
                                    -not [string]::IsNullOrWhiteSpace(
                                        $_
                                    )
                                } |
                                Sort-Object -Unique
                        )
                        NetNewGapPrincipals = @(
                            & $collectDelimitedValues `
                                $rows `
                                'NetNewGapPrincipals'
                        )
                        PrincipalUnknownActions = @(
                            $rows |
                                Where-Object {
                                    [int](
                                        Get-RadarPropertyValue `
                                            -InputObject $_ `
                                            -Name 'UnknownPrincipalRowCount'
                                    ) -gt 0 -or
                                    [int](
                                        Get-RadarPropertyValue `
                                            -InputObject $_ `
                                            -Name 'UnknownPrincipalCount'
                                    ) -gt 0 -or
                                    -not [string]::IsNullOrWhiteSpace(
                                        [string](
                                            Get-RadarPropertyValue `
                                                -InputObject $_ `
                                                -Name 'UnknownPrincipals'
                                        )
                                    ) -or
                                    [string](
                                        Get-RadarPropertyValue `
                                            -InputObject $_ `
                                            -Name 'PrincipalGapStatus'
                                    ) -eq 'Unknown'
                                } |
                                ForEach-Object {
                                    Get-RadarPropertyValue `
                                        -InputObject $_ `
                                        -Name 'RestrictedAction'
                                } |
                                Sort-Object -Unique
                        )
                        PrincipalUnknownPrincipals = @(
                            & $collectDelimitedValues `
                                $rows `
                                'UnknownPrincipals'
                        )
                        PrincipalReviewWarnings = @(
                            & $collectDelimitedValues `
                                $rows `
                                'PrincipalGapWarnings'
                        )
                        RemediationGapActions = @(
                            $subtreeGapRows |
                                ForEach-Object {
                                    Get-RadarPropertyValue `
                                        -InputObject $_ `
                                        -Name 'RestrictedAction'
                                } |
                                Sort-Object -Unique
                        )
                        RemediationGapRoles = @(
                            & $collectDelimitedValues `
                                $subtreeGapRows `
                                'SubtreeGapRoles'
                        )
                        SubtreeControlledActions = @(
                            $subtreeCoveredRows |
                                ForEach-Object {
                                    Get-RadarPropertyValue `
                                        -InputObject $_ `
                                        -Name 'RestrictedAction'
                                } |
                                Sort-Object -Unique
                        )
                        GapSubtreeControlledRoles = @(
                            & $collectDelimitedValues `
                                $subtreeGapRows `
                                'SubtreeControlledRoles'
                        )
                        SubtreeControlledRoles = @(
                            & $collectDelimitedValues `
                                $rows `
                                'SubtreeControlledRoles'
                        )
                        DirectAssignedActions = @(
                            $currentDirectRows |
                                ForEach-Object {
                                    Get-RadarPropertyValue `
                                        -InputObject $_ `
                                        -Name 'RestrictedAction'
                                } |
                                Sort-Object -Unique
                        )
                        BaselineObtainableActions = @(
                            $baselineObtainableRows |
                                ForEach-Object {
                                    Get-RadarPropertyValue `
                                        -InputObject $_ `
                                        -Name 'RestrictedAction'
                                } |
                                Sort-Object -Unique
                        )
                        ExternalGapActions = @(
                            $externalGapRows |
                                ForEach-Object {
                                    Get-RadarPropertyValue `
                                        -InputObject $_ `
                                        -Name 'RestrictedAction'
                                } |
                                Sort-Object -Unique
                        )
                        BaselineAssignableRoles = @(
                            & $collectDelimitedValues `
                                @(
                                    $currentDirectRows +
                                    $baselineObtainableRows +
                                    $assignmentUnknownRows
                                ) `
                                'BaselineAssignableRoles'
                        )
                        AssignmentUnknownActions = @(
                            $assignmentUnknownRows |
                                ForEach-Object {
                                    Get-RadarPropertyValue `
                                        -InputObject $_ `
                                        -Name 'RestrictedAction'
                                } |
                                Sort-Object -Unique
                        )
                        EffectiveDirectAssignmentCount = [int](
                            Get-RadarPropertyValue `
                                -InputObject $first `
                                -Name 'EffectiveDirectAssignmentCount'
                        )
                        BaselinePrincipalTypes = @(
                            & $collectDelimitedValues `
                                $rows `
                                'BaselinePrincipalTypes'
                        )
                        BaselineAssignmentScopes = @(
                            & $collectDelimitedValues `
                                $rows `
                                'BaselineAssignmentScopes'
                        )
                        AssignmentWarnings = @(
                            & $collectDelimitedValues `
                                $rows `
                                'AssignmentWarnings'
                        )
                        ExternalAssignmentRoles = @(
                            & $collectDelimitedValues `
                                $externalGapRows `
                                'ExternalAssignmentRoles'
                        )
                        UnknownActions = @(
                            $unknownRows |
                                ForEach-Object {
                                    Get-RadarPropertyValue `
                                        -InputObject $_ `
                                        -Name 'RestrictedAction'
                                } |
                                Sort-Object -Unique
                        )
                        CoveredActions = @(
                            $coveredRows |
                                ForEach-Object {
                                    Get-RadarPropertyValue `
                                        -InputObject $_ `
                                        -Name 'RestrictedAction'
                                } |
                                Sort-Object -Unique
                        )
                        BlockingPolicies = @(
                            & $collectDelimitedValues `
                                $rows `
                                'BlockingPolicies'
                        )
                    }
                } |
                Sort-Object `
                    EvaluationScopeType,
                    EvaluationScopeName,
                    BaselineRoleName,
                    BaselineScope
        )
        $scopeCountInMap = @(
            $controlGapMapArray |
                ForEach-Object {
                    Get-RadarPropertyValue `
                        -InputObject $_ `
                        -Name 'EvaluationScope'
                } |
                Sort-Object -Unique
        ).Count
        $actionableScopeCount = @(
            $controlGapMapArray |
                Where-Object {
                    [string](
                        Get-RadarPropertyValue `
                            -InputObject $_ `
                            -Name 'PrincipalGapStatus'
                    ) -eq 'NetNewGap'
                } |
                Select-Object -ExpandProperty EvaluationScope -Unique
        ).Count
        $reviewScopeCount = @(
            $controlGapMapArray |
                Where-Object {
                    [int](
                        Get-RadarPropertyValue `
                            -InputObject $_ `
                            -Name 'UnknownPrincipalRowCount'
                    ) -gt 0 -or
                    [int](
                        Get-RadarPropertyValue `
                            -InputObject $_ `
                            -Name 'UnknownPrincipalCount'
                    ) -gt 0 -or
                    -not [string]::IsNullOrWhiteSpace(
                        [string](
                            Get-RadarPropertyValue `
                                -InputObject $_ `
                                -Name 'UnknownPrincipals'
                        )
                    ) -or
                    [string](
                        Get-RadarPropertyValue `
                            -InputObject $_ `
                            -Name 'PrincipalGapStatus'
                    ) -eq 'Unknown'
                } |
                Select-Object -ExpandProperty EvaluationScope -Unique
        ).Count
        $blastRadiusScopeCount = @(
            $controlGapMapArray |
                Where-Object {
                    [string](
                        Get-RadarPropertyValue `
                            -InputObject $_ `
                            -Name 'SubtreeControlStatus'
                    ) -eq 'Gap'
                } |
                Select-Object -ExpandProperty EvaluationScope -Unique
        ).Count
        $defaultMapMode = 'actionable'
        $metricState = [pscustomobject]@{
            NextId = 0
            Payloads = [ordered]@{}
        }
        $renderMapMetric = {
            param(
                [object[]]$Values,
                [string]$Label,
                [string]$ClassName = ''
            )
            $items = @($Values)
            if ($items.Count -eq 0) {
                return ''
            }
            $classAttribute = if ($ClassName) {
                " $ClassName"
            }
            else {
                ''
            }
            $metricState.NextId++
            $metricKey = "metric-$($metricState.NextId)"
            $metricState.Payloads[$metricKey] = [ordered]@{
                title = $Label
                items = @($items | ForEach-Object { [string]$_ })
            }
            return (
                '<div class="map-metric' +
                $classAttribute +
                '"><button type="button" class="map-metric-trigger" ' +
                'aria-haspopup="dialog" data-metric-title="' +
                (ConvertTo-HtmlSafe $Label) +
                '" data-metric-key="' +
                $metricKey +
                '"><strong>' +
                $items.Count +
                '</strong>' +
                (ConvertTo-HtmlSafe $Label) +
                '<span class="map-metric-open">Open</span></button></div>'
            )
        }
        $renderScopeCount = {
            param(
                [int]$Count,
                [string]$Label,
                [string]$ClassName
            )
            if ($Count -le 0) { return '' }
            return (
                '<span class="scope-count ' +
                (ConvertTo-HtmlSafe $ClassName) +
                '">' +
                $Count +
                ' ' +
                (ConvertTo-HtmlSafe $Label) +
                '</span>'
            )
        }

        [void]$sb.AppendLine(
            '<details class="actions-list" open><summary>' +
            'Security gap map (' +
            $scopeCountInMap +
            $(if ($scopeCountInMap -eq 1) {
                ' scope'
            }
            else {
                ' scopes'
            }) +
            ')</summary>'
        )
        [void]$sb.AppendLine(
            '<p class="note"><strong>Proven user paths</strong> shows current ' +
            'principal-to-action exposure; <strong>Control coverage gaps</strong> ' +
            'shows the broader role/action blast radius.</p>'
        )
        [void]$sb.AppendLine(
            '<div class="map-toolbar">' +
            '<div class="map-tabs" role="tablist" ' +
            'aria-label="Scope-map view">' +
            '<button type="button" class="map-tab" ' +
            'data-map-mode="actionable" role="tab">' +
            'Proven user paths (' +
            $actionableScopeCount +
            ')</button>' +
            '<button type="button" class="map-tab" ' +
            'data-map-mode="blast" role="tab">' +
            'Control coverage gaps (' +
            $blastRadiusScopeCount +
            ')</button>' +
            '<button type="button" class="map-tab" ' +
            'data-map-mode="review" role="tab">' +
            'Review scopes (' +
            $reviewScopeCount +
            ')</button>' +
            '<button type="button" class="map-tab" ' +
            'data-map-mode="all" role="tab">All scopes (' +
            $scopeCountInMap +
            ')</button></div>' +
            '<input id="map-search" class="map-search" type="search" ' +
            'placeholder="Find a management group or subscription..." ' +
            'aria-label="Find a scope" />' +
            '<select id="map-scope-type" class="map-scope-type" ' +
            'aria-label="Filter scope type">' +
            '<option value="all">All scope types</option>' +
            '<option value="ManagementGroup">Management groups</option>' +
            '<option value="Subscription">Subscriptions</option>' +
            '</select>' +
            '<span id="map-visible-count" class="map-visible-count"></span>' +
            '</div>'
        )
        [void]$sb.AppendLine(
            '<div id="map-empty" class="map-empty" hidden></div>'
        )
        [void]$sb.AppendLine(
            '<dialog id="metric-dialog" class="metric-dialog" ' +
            'aria-labelledby="metric-dialog-title">' +
            '<div class="metric-dialog-header">' +
            '<h2 id="metric-dialog-title" class="metric-dialog-title"></h2>' +
            '<button type="button" class="metric-dialog-close" ' +
            'aria-label="Close details">&times;</button></div>' +
            '<input id="metric-dialog-search" ' +
            'class="metric-dialog-search" type="search" ' +
            'placeholder="Filter this list..." ' +
            'aria-label="Filter this list" />' +
            '<div id="metric-dialog-body" class="metric-dialog-body" ' +
            'tabindex="0" role="region" ' +
            'aria-label="Metric details"></div>' +
            '</dialog>'
        )

        $rootNodeKey = '__RADAR_ROOT__'
        $scopeNodeById = @{}
        foreach ($summary in $scopeMapSummaries) {
            $nodeKey =
                $summary.EvaluationScope.TrimEnd('/').
                    ToLowerInvariant()
            if (-not $scopeNodeById.ContainsKey($nodeKey)) {
                $scopeNodeById[$nodeKey] = [pscustomobject]@{
                    Id = $summary.EvaluationScope
                    Name = $summary.EvaluationScopeName
                    Type = $summary.EvaluationScopeType
                    ParentScope = $summary.ParentScope
                    AncestorScopes = $summary.AncestorScopes
                    EffectiveParentScope = ''
                    Summaries =
                        New-Object System.Collections.Generic.List[object]
                }
            }
            [void]$scopeNodeById[$nodeKey].Summaries.Add(
                $summary
            )
        }
        $childrenByParent = @{}
        foreach ($nodeKey in $scopeNodeById.Keys) {
            $node = $scopeNodeById[$nodeKey]
            $ancestorIds = @(
                [string]$node.AncestorScopes -split '; ' |
                    Where-Object {
                        -not [string]::IsNullOrWhiteSpace($_)
                    }
            )
            if (
                $ancestorIds.Count -eq 0 -and
                -not [string]::IsNullOrWhiteSpace(
                    $node.ParentScope
                )
            ) {
                $ancestorIds = @($node.ParentScope)
            }
            $parentKey = $rootNodeKey
            for (
                $ancestorIndex = $ancestorIds.Count - 1;
                $ancestorIndex -ge 0;
                $ancestorIndex--
            ) {
                $candidateParentKey =
                    $ancestorIds[$ancestorIndex].
                        TrimEnd('/').
                        ToLowerInvariant()
                if (
                    $candidateParentKey -ne $nodeKey -and
                    $scopeNodeById.ContainsKey(
                        $candidateParentKey
                    )
                ) {
                    $parentKey = $candidateParentKey
                    break
                }
            }
            if ($parentKey -ne $rootNodeKey) {
                $node.EffectiveParentScope =
                    $scopeNodeById[$parentKey].Id
            }
            if (-not $childrenByParent.ContainsKey($parentKey)) {
                $childrenByParent[$parentKey] =
                    New-Object System.Collections.Generic.List[string]
            }
            [void]$childrenByParent[$parentKey].Add($nodeKey)
        }

        $renderScopeNode = {
            param(
                [string]$NodeKey,
                [int]$Depth
            )
            $node = $scopeNodeById[$NodeKey]
            $nodeSummaries = @($node.Summaries.ToArray())
            $nodeNetNewGapActions = @(
                $nodeSummaries |
                    ForEach-Object {
                        Get-RadarPropertyValue `
                            -InputObject $_ `
                            -Name 'NetNewGapActions'
                    } |
                    Sort-Object -Unique
            )
            $nodePrincipalUnknownActions = @(
                $nodeSummaries |
                    ForEach-Object {
                        Get-RadarPropertyValue `
                            -InputObject $_ `
                            -Name 'PrincipalUnknownActions'
                    } |
                    Sort-Object -Unique
            )
            $nodeRemediationGapActions = @(
                $nodeSummaries |
                    ForEach-Object {
                        Get-RadarPropertyValue `
                            -InputObject $_ `
                            -Name 'RemediationGapActions'
                    } |
                    Sort-Object -Unique
            )
            $nodeSubtreeControlledActions = @(
                $nodeSummaries |
                    ForEach-Object {
                        Get-RadarPropertyValue `
                            -InputObject $_ `
                            -Name 'SubtreeControlledActions'
                    } |
                    Sort-Object -Unique
            )
            $nodeDirectAssignedActions = @(
                $nodeSummaries |
                    ForEach-Object {
                        Get-RadarPropertyValue `
                            -InputObject $_ `
                            -Name 'DirectAssignedActions'
                    } |
                    Sort-Object -Unique
            )
            $nodeBaselineObtainableActions = @(
                $nodeSummaries |
                    ForEach-Object {
                        Get-RadarPropertyValue `
                            -InputObject $_ `
                            -Name 'BaselineObtainableActions'
                    } |
                    Sort-Object -Unique
            )
            $nodeAssignmentUnknownActions = @(
                $nodeSummaries |
                    ForEach-Object {
                        Get-RadarPropertyValue `
                            -InputObject $_ `
                            -Name 'AssignmentUnknownActions'
                    } |
                    Sort-Object -Unique
            )
            $nodeExternalGapActions = @(
                $nodeSummaries |
                    ForEach-Object {
                        Get-RadarPropertyValue `
                            -InputObject $_ `
                            -Name 'ExternalGapActions'
                    } |
                    Sort-Object -Unique
            )
            $nodeUnknownActions = @(
                $nodeSummaries |
                    ForEach-Object {
                        Get-RadarPropertyValue `
                            -InputObject $_ `
                            -Name 'UnknownActions'
                    } |
                    Sort-Object -Unique
            )
            $nodeCoveredActions = @(
                $nodeSummaries |
                    ForEach-Object {
                        Get-RadarPropertyValue `
                            -InputObject $_ `
                            -Name 'CoveredActions'
                    } |
                    Sort-Object -Unique
            )
            $openAttribute = if ($Depth -eq 0) {
                ' open'
            }
            else {
                ''
            }
            $indent = [math]::Min($Depth * 22, 132)
            $combinedUnknownCount = @(
                $nodeAssignmentUnknownActions +
                $nodeUnknownActions |
                    Sort-Object -Unique
            ).Count
            $actionableStatusBadge = if (
                $nodeNetNewGapActions.Count -gt 0
            ) {
                & $renderScopeCount `
                    $nodeNetNewGapActions.Count `
                    'net-new gaps' `
                    'gap map-status map-status-actionable'
            }
            else {
                ''
            }
            $reviewStatusBadge = if (
                $nodePrincipalUnknownActions.Count -gt 0
            ) {
                $reviewStatusClass = if (
                    $nodeNetNewGapActions.Count -gt 0
                ) {
                    'unknown map-status map-status-review ' +
                    'map-status-review-secondary'
                }
                else {
                    'unknown map-status map-status-review'
                }
                & $renderScopeCount `
                    $nodePrincipalUnknownActions.Count `
                    'principal unknown' `
                    $reviewStatusClass
            }
            else {
                ''
            }
            $blastRadiusStatusBadge = if (
                $nodeRemediationGapActions.Count -gt 0
            ) {
                & $renderScopeCount `
                    $nodeRemediationGapActions.Count `
                    'control-gap actions' `
                    'gap map-status map-status-blast'
            }
            else {
                ''
            }
            $cleanStatusBadge = if (
                $nodeNetNewGapActions.Count -eq 0 -and
                $nodePrincipalUnknownActions.Count -eq 0
            ) {
                '<span class="scope-count covered map-status ' +
                'map-status-clean">' +
                'No proven user path</span>'
            }
            else {
                ''
            }
            $primaryStatusBadges =
                $actionableStatusBadge +
                $reviewStatusBadge +
                $blastRadiusStatusBadge +
                $cleanStatusBadge
            $secondaryStatusBadges = @(
                (& $renderScopeCount `
                    $nodeRemediationGapActions.Count `
                    'remediation gaps (latent/posture)' `
                    'gap map-status map-status-diagnostic'),
                (& $renderScopeCount `
                    $nodeSubtreeControlledActions.Count `
                    'subtree-controlled' `
                    'covered map-status map-status-diagnostic'),
                (& $renderScopeCount `
                    $nodeDirectAssignedActions.Count `
                    'direct-assigned' `
                    'current map-status map-status-diagnostic'),
                (& $renderScopeCount `
                    $nodeBaselineObtainableActions.Count `
                    'latent-capable' `
                    'external map-status map-status-diagnostic'),
                (& $renderScopeCount `
                    $nodeExternalGapActions.Count `
                    'external-route' `
                    'external map-status map-status-diagnostic'),
                (& $renderScopeCount `
                    $combinedUnknownCount `
                    'unknown' `
                    'unknown map-status map-status-diagnostic'),
                (& $renderScopeCount `
                    $nodeCoveredActions.Count `
                    'covered' `
                    'covered map-status map-status-diagnostic')
            ) -join ''
            [void]$sb.AppendLine(
                '<div class="scope-node" data-depth="' +
                $Depth +
                '" data-has-net-new="' +
                ($nodeNetNewGapActions.Count -gt 0).ToString().
                    ToLowerInvariant() +
                '" data-has-principal-unknown="' +
                ($nodePrincipalUnknownActions.Count -gt 0).ToString().
                    ToLowerInvariant() +
                '" data-has-blast-radius="' +
                ($nodeRemediationGapActions.Count -gt 0).ToString().
                    ToLowerInvariant() +
                '" data-scope-type="' +
                (ConvertTo-HtmlSafe $node.Type) +
                '" style="--scope-indent:' +
                $indent +
                'px" data-scope-id="' +
                (ConvertTo-HtmlSafe $node.Id) +
                '" data-parent-scope="' +
                (ConvertTo-HtmlSafe $node.EffectiveParentScope) +
                '">'
            )
            [void]$sb.AppendLine(
                '<details class="scope-card"' +
                $openAttribute +
                '><summary><span class="scope-title">' +
                (ConvertTo-HtmlSafe $node.Name) +
                '</span><span class="scope-type">' +
                (ConvertTo-HtmlSafe $node.Type) +
                '</span>' +
                $primaryStatusBadges +
                $secondaryStatusBadges +
                '<span class="scope-count current ancestor-context">' +
                'Ancestor path</span>' +
                '</summary>'
            )
            [void]$sb.AppendLine(
                '<div class="scope-node-content"><div class="code">' +
                (ConvertTo-HtmlSafe $node.Id) +
                '</div>'
            )
            foreach (
                $summary in @(
                    $nodeSummaries |
                        Sort-Object BaselineRoleName, BaselineScope
                )
            ) {
                $baselineScopeMarkup = if (
                    -not [string]::IsNullOrWhiteSpace(
                        [string]$summary.BaselineScope
                    )
                ) {
                    '<span class="baseline-scope">@ ' +
                    (ConvertTo-HtmlSafe $summary.BaselineScope) +
                    '</span>'
                }
                else {
                    ''
                }
                $principalTypeLabel = @(
                    $summary.BaselinePrincipalTypes
                ) -join ', '
                $directAssignmentScopeLabels = @(
                    $summary.BaselineAssignmentScopes |
                        ForEach-Object {
                            if ($principalTypeLabel) {
                                "$_ [$principalTypeLabel]"
                            }
                            else {
                                [string]$_
                            }
                        }
                )
                $summaryHasNetNew = (
                    @($summary.NetNewGapActions).Count -gt 0
                ).ToString().ToLowerInvariant()
                $summaryHasPrincipalUnknown = (
                    @($summary.PrincipalUnknownActions).Count -gt 0
                ).ToString().ToLowerInvariant()
                $summaryHasBlastRadius = (
                    @($summary.RemediationGapActions).Count -gt 0
                ).ToString().ToLowerInvariant()
                [void]$sb.AppendLine(
                    '<section class="baseline-summary" ' +
                    'data-has-net-new="' +
                    $summaryHasNetNew +
                    '" data-has-principal-unknown="' +
                    $summaryHasPrincipalUnknown +
                    '" data-has-blast-radius="' +
                    $summaryHasBlastRadius +
                    '">' +
                    '<div class="baseline-heading">' +
                    (ConvertTo-HtmlSafe $summary.BaselineRoleName) +
                    $baselineScopeMarkup +
                    '</div><div class="baseline-metrics">' +
                    (& $renderMapMetric `
                        $summary.NetNewGapActions `
                        'net-new principal gap actions' `
                        'gap map-actionable') +
                    (& $renderMapMetric `
                        $summary.NetNewGapPaths `
                        'proven principal -> action -> role -> policy paths' `
                        'gap map-actionable') +
                    (& $renderMapMetric `
                        $summary.NetNewGapRoles `
                        'net-new granting roles' `
                        'gap map-diagnostic') +
                    (& $renderMapMetric `
                        $summary.NetNewGapPrincipals `
                        'net-new principals (ID and type)' `
                        'current map-diagnostic') +
                    (& $renderMapMetric `
                        $summary.NetNewGapPolicies `
                        'policy intent evaluated at this scope' `
                        'current map-diagnostic') +
                    (& $renderMapMetric `
                        $summary.PrincipalUnknownActions `
                        'principal correlation unknown' `
                        'unknown map-review') +
                    (& $renderMapMetric `
                        $summary.PrincipalUnknownPrincipals `
                        'principals requiring review (ID and type)' `
                        'unknown map-review') +
                    (& $renderMapMetric `
                        $summary.PrincipalReviewWarnings `
                        'why principal evidence is unknown' `
                        'unknown map-review') +
                    (& $renderMapMetric `
                        $summary.RemediationGapActions `
                        'control-gap actions' `
                        'gap map-blast map-diagnostic') +
                    (& $renderMapMetric `
                        $summary.RemediationGapRoles `
                        'granting roles missing from deny controls' `
                        'gap map-blast map-diagnostic') +
                    (& $renderMapMetric `
                        $summary.GapSubtreeControlledRoles `
                        'control-gap roles represented elsewhere in subtree controls' `
                        'covered map-blast') +
                    (& $renderMapMetric `
                        $summary.SubtreeControlledRoles `
                        'all roles represented in subtree controls' `
                        'covered map-diagnostic') +
                    (& $renderMapMetric `
                        $summary.DirectAssignedActions `
                        'actions with a direct baseline assignment' `
                        'current map-diagnostic') +
                    (& $renderMapMetric `
                        $directAssignmentScopeLabels `
                        'direct baseline assignment scopes' `
                        'current map-diagnostic') +
                    (& $renderMapMetric `
                        $summary.BaselineObtainableActions `
                        'latent actions if baseline is assigned' `
                        'gap map-diagnostic') +
                    (& $renderMapMetric `
                        $summary.BaselineAssignableRoles `
                        'roles this baseline can assign' `
                        'gap map-diagnostic') +
                    (& $renderMapMetric `
                        $summary.AssignmentUnknownActions `
                        'assignment exposure unknown' `
                        'unknown map-diagnostic') +
                    (& $renderMapMetric `
                        $summary.AssignmentWarnings `
                        'assignment discovery warnings' `
                        'unknown map-diagnostic') +
                    (& $renderMapMetric `
                        $summary.ExternalGapActions `
                        'external-process gap actions' `
                        'external map-diagnostic') +
                    (& $renderMapMetric `
                        $summary.ExternalAssignmentRoles `
                        'roles requiring another process' `
                        'external map-diagnostic') +
                    (& $renderMapMetric `
                        $summary.UnknownActions `
                        'unknown actions' `
                        'unknown map-diagnostic') +
                    (& $renderMapMetric `
                        $summary.CoveredActions `
                        'covered actions' `
                        'covered map-diagnostic') +
                    (& $renderMapMetric `
                        $summary.BlockingPolicies `
                        'blocking policies' `
                        'covered map-diagnostic') +
                    '</div></section>'
                )
            }
            [void]$sb.AppendLine(
                '</div></details></div>'
            )
            if ($childrenByParent.ContainsKey($NodeKey)) {
                foreach (
                    $childKey in @(
                        $childrenByParent[$NodeKey] |
                            Sort-Object {
                                @(
                                    $scopeNodeById[$_].Type,
                                    $scopeNodeById[$_].Name
                                ) -join [char]31
                            }
                    )
                ) {
                    & $renderScopeNode $childKey ($Depth + 1)
                }
            }
        }

        [void]$sb.AppendLine(
            '<div class="scope-tree" data-mode="' +
            $defaultMapMode +
            '">'
        )
        foreach (
            $rootChildKey in @(
                $childrenByParent[$rootNodeKey] |
                    Sort-Object {
                        @(
                            $scopeNodeById[$_].Type,
                            $scopeNodeById[$_].Name
                        ) -join [char]31
                    }
            )
        ) {
            & $renderScopeNode $rootChildKey 0
        }
        [void]$sb.AppendLine('</div>')
        $metricJson = (
            $metricState.Payloads |
                ConvertTo-Json -Depth 5 -Compress
        ).Replace('<', '\u003c')
        [void]$sb.AppendLine(
            '<script id="metric-data" type="application/json">' +
            $metricJson +
            '</script>'
        )
        [void]$sb.AppendLine('</details>')
    }

    if (-not $MapOnly) {
    # Toolbar / filter.
    [void]$sb.AppendLine('<div class="toolbar"><input id="filter" type="search" placeholder="Filter by role name, action, or matched pattern..." /><button id="toggle-all" type="button">Expand all</button></div>')

    if ($grouped.Count -eq 0) {
        [void]$sb.AppendLine('<div class="empty">No matches found. None of the scanned roles grant the restricted actions.</div>')
    }
    else {
        foreach ($g in $grouped) {
            $items = $g.Group | Sort-Object RestrictedAction
            $first = $items | Select-Object -First 1
            $roleName = $first.RoleName
            $isCustom = $first.IsCustom
            $roleId = $first.RoleId
            $baselineRoleName = $first.BaselineRoleName
            $baselineScope = $first.BaselineScope
            $isAlreadyDenied = $first.PSObject.Properties['IsAlreadyDenied'] -and $first.IsAlreadyDenied
            $denyCoverage = if ($first.PSObject.Properties['DenyCoverage']) {
                [string]$first.DenyCoverage
            }
            elseif ($isAlreadyDenied) {
                'Full'
            }
            else {
                'None'
            }

            $badge = if ($isCustom) { '<span class="badge custom">Custom</span>' } else { '<span class="badge">Built-in</span>' }
            $baselineBadge = ' <span class="badge">' +
                (ConvertTo-HtmlSafe $baselineRoleName) +
                '</span>'

            $denyBadge = ''
            if ($DeniedListProvided) {
                $denyBadge = switch ($denyCoverage) {
                    'Full' {
                        ' <span class="badge denied">Fully Denied</span>'
                    }
                    'Partial' {
                        ' <span class="badge partial">Partially Denied</span>'
                    }
                    { $_ -in @('Unknown', 'NotEvaluated') } {
                        ' <span class="badge unknown">Coverage Unknown</span>'
                    }
                    default {
                        ' <span class="badge undenied">Not Denied</span>'
                    }
                }
            }

            $roleClasses = @('role')
            if ($isCustom) { $roleClasses += 'is-custom' }
            if ($DeniedListProvided) {
                switch ($denyCoverage) {
                    'Full' { $roleClasses += 'is-denied' }
                    'Partial' { $roleClasses += 'is-partial' }
                    { $_ -in @('Unknown', 'NotEvaluated') } {
                        $roleClasses += 'is-unknown'
                    }
                    default { $roleClasses += 'is-undenied' }
                }
            }
            $roleClass = $roleClasses -join ' '

            $matchWord = if ($items.Count -eq 1) { 'match' } else { 'matches' }
            [void]$sb.AppendLine('<details class="' + $roleClass + '">')
            [void]$sb.AppendLine('<summary><span class="chev">&#9656;</span><span class="name">' + (ConvertTo-HtmlSafe $roleName) + '</span> ' + $badge + $baselineBadge + $denyBadge + ' <span class="role-id" title="' + (ConvertTo-HtmlSafe $roleId) + '">' + (ConvertTo-HtmlSafe $roleId) + '</span><span class="count">' + $items.Count + ' ' + $matchWord + '</span></summary>')
            [void]$sb.AppendLine(
                '<div class="coverage-note">Baseline scope: ' +
                (ConvertTo-HtmlSafe $baselineScope) +
                ' &middot; Restriction source: ' +
                (ConvertTo-HtmlSafe $first.RestrictionSource) +
                ' &middot; Assignment path: ' +
                (ConvertTo-HtmlSafe $first.AssignmentPath) +
                '</div>'
            )
            if ($DeniedListProvided) {
                $scopeCoverage = "$($first.DeniedScopeCount) of $($first.EvaluatedScopeCount) relevant evaluation scopes denied"
                $policyText = if ($first.BlockingPolicies) {
                    ' &middot; Policies: ' +
                        (ConvertTo-HtmlSafe $first.BlockingPolicies)
                }
                else {
                    ''
                }
                [void]$sb.AppendLine(
                    '<div class="coverage-note">' +
                    (ConvertTo-HtmlSafe $scopeCoverage) +
                    $policyText +
                    '</div>'
                )
                if ($first.UnblockedAssignmentPaths) {
                    [void]$sb.AppendLine(
                        '<div class="coverage-note">Unblocked assignment paths: ' +
                        (ConvertTo-HtmlSafe $first.UnblockedAssignmentPaths) +
                        '</div>'
                    )
                }
            }
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
    }

    [void]$sb.AppendLine('</main>')
    [void]$sb.AppendLine(
        '<footer>' +
        $documentTitle +
        ' &middot; ' +
        $generated +
        '</footer>'
    )

    # Client-side filter.
    [void]$sb.AppendLine(@'
<script>
  const metricDialog = document.getElementById('metric-dialog');
  const metricDialogTitle =
    document.getElementById('metric-dialog-title');
  const metricDialogBody =
    document.getElementById('metric-dialog-body');
  const metricDialogSearch =
    document.getElementById('metric-dialog-search');
  let metricData = {};
  try {
    metricData = JSON.parse(
      document.getElementById('metric-data')?.textContent || '{}'
    );
  } catch {
    metricData = {};
  }
  if (metricDialog && metricDialogBody) {
    document.querySelectorAll('.map-metric-trigger').forEach(trigger => {
      trigger.addEventListener('click', () => {
        const payload = metricData[trigger.dataset.metricKey] || {
          title: trigger.dataset.metricTitle || 'details',
          items: []
        };
        metricDialogBody.replaceChildren();
        const list = document.createElement('ul');
        list.className = 'list code metric-list';
        (payload.items || []).forEach(value => {
          const item = document.createElement('li');
          const text = String(value);
          const roleMatch = text.match(/^(.*?) \[([^\]]+)\]$/);
          if (roleMatch) {
            item.append(document.createTextNode(roleMatch[1]));
            const id = document.createElement('small');
            id.textContent = roleMatch[2];
            item.appendChild(id);
          } else {
            item.textContent = text;
          }
          list.appendChild(item);
        });
        metricDialogBody.appendChild(list);
        if (metricDialogTitle) {
          const count = (payload.items || []).length;
          metricDialogTitle.textContent =
            `${count} ${payload.title || 'details'}`;
        }
        if (metricDialogSearch) {
          metricDialogSearch.value = '';
        }
        metricDialog.showModal();
        metricDialogSearch?.focus();
      });
    });
    document.querySelector('.metric-dialog-close')?.addEventListener(
      'click',
      () => metricDialog.close()
    );
    metricDialog.addEventListener('click', event => {
      if (event.target !== metricDialog) return;
      const bounds = metricDialog.getBoundingClientRect();
      const outside =
        event.clientX < bounds.left ||
        event.clientX > bounds.right ||
        event.clientY < bounds.top ||
        event.clientY > bounds.bottom;
      if (outside) metricDialog.close();
    });
    metricDialog.addEventListener('close', () => {
      metricDialogBody.replaceChildren();
    });
    metricDialogSearch?.addEventListener('input', () => {
      const query = metricDialogSearch.value.toLowerCase().trim();
      metricDialogBody.querySelectorAll('li').forEach(item => {
        item.style.display =
          query === '' ||
          item.innerText.toLowerCase().includes(query)
            ? ''
            : 'none';
      });
    });
  }

  const scopeTree = document.querySelector('.scope-tree');
  if (scopeTree) {
    const scopeNodes = Array.from(
      scopeTree.querySelectorAll('.scope-node')
    );
    const nodeById = new Map(
      scopeNodes.map(node => [
        (node.dataset.scopeId || '').toLowerCase(),
        node
      ])
    );
    const mapTabs = Array.from(
      document.querySelectorAll('.map-tab')
    );
    const mapSearch = document.getElementById('map-search');
    const mapScopeType = document.getElementById('map-scope-type');
    const mapVisibleCount =
      document.getElementById('map-visible-count');
    const mapEmpty = document.getElementById('map-empty');
    let mapMode = scopeTree.dataset.mode || 'all';

    const applyMapFilters = () => {
      const query = (mapSearch?.value || '').toLowerCase().trim();
      const scopeType = mapScopeType?.value || 'all';
      const directMatches = new Set();
      const searchMatches = new Set();
      if (query !== '') {
        scopeNodes.forEach(node => {
          const summary = node.querySelector('.scope-card > summary');
          const searchText = (
            (node.dataset.scopeId || '') +
            ' ' +
            (summary?.innerText || '')
          ).toLowerCase();
          if (searchText.includes(query)) {
            searchMatches.add(node);
          }
        });
      }
      const scopeOrAncestorMatchesSearch = node => {
        if (query === '') return true;
        let current = node;
        const visited = new Set();
        while (current) {
          if (searchMatches.has(current)) return true;
          const parentId = (
            current.dataset.parentScope || ''
          ).toLowerCase();
          if (!parentId || visited.has(parentId)) break;
          visited.add(parentId);
          current = nodeById.get(parentId);
        }
        return false;
      };
      scopeNodes.forEach(node => {
        const modeMatch =
          mapMode === 'all' ||
          (
            mapMode === 'actionable' &&
            node.dataset.hasNetNew === 'true'
          ) ||
          (
            mapMode === 'blast' &&
            node.dataset.hasBlastRadius === 'true'
          ) ||
          (
            mapMode === 'review' &&
            node.dataset.hasPrincipalUnknown === 'true'
          );
        const typeMatch =
          scopeType === 'all' ||
          node.dataset.scopeType === scopeType;
        if (
          modeMatch &&
          typeMatch &&
          scopeOrAncestorMatchesSearch(node)
        ) {
          directMatches.add(node);
        }
      });

      const visible = new Set(directMatches);
      if (scopeType === 'all') {
        directMatches.forEach(node => {
          let parentId = (
            node.dataset.parentScope || ''
          ).toLowerCase();
          const visited = new Set();
          while (parentId && !visited.has(parentId)) {
            visited.add(parentId);
            const parent = nodeById.get(parentId);
            if (!parent) break;
            visible.add(parent);
            parentId = (
              parent.dataset.parentScope || ''
            ).toLowerCase();
          }
        });
      }

      scopeNodes.forEach(node => {
        node.style.display = visible.has(node) ? '' : 'none';
        node.classList.toggle(
          'map-ancestor-only',
          visible.has(node) && !directMatches.has(node)
        );
        const details = node.querySelector('.scope-card');
        if (
          details &&
          (
            mapMode !== 'all' ||
            query !== ''
          )
        ) {
          details.open = directMatches.has(node);
        }
      });
      scopeTree.dataset.mode = mapMode;
      mapTabs.forEach(tab => {
        tab.setAttribute(
          'aria-selected',
          String(tab.dataset.mapMode === mapMode)
        );
      });
      if (mapVisibleCount) {
        const ancestorCount =
          visible.size - directMatches.size;
        mapVisibleCount.textContent =
          `${directMatches.size} matching scope` +
          `${directMatches.size === 1 ? '' : 's'}` +
          `${ancestorCount > 0 ? ` + ${ancestorCount} ancestor${ancestorCount === 1 ? '' : 's'}` : ''}`;
      }
      if (mapEmpty) {
        mapEmpty.hidden = directMatches.size > 0;
        if (!mapEmpty.hidden) {
          mapEmpty.textContent =
            mapMode === 'actionable'
              ? 'No proven user self-escalation paths match these filters.'
              : mapMode === 'review'
                ? 'No scopes requiring principal-evidence review match these filters.'
                : mapMode === 'blast'
                  ? 'No control-coverage gaps match these filters.'
                  : 'No scopes match these filters.';
        }
      }
    };

    mapTabs.forEach(tab => {
      tab.addEventListener('click', () => {
        mapMode = tab.dataset.mapMode || 'all';
        applyMapFilters();
      });
    });
    mapSearch?.addEventListener('input', applyMapFilters);
    mapScopeType?.addEventListener('change', applyMapFilters);
    applyMapFilters();
  }

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

function Get-RadarPropertyValue {
    param(
        [object]$InputObject,
        [string]$Name
    )

    if ($null -eq $InputObject) { return $null }

    if ($InputObject -is [System.Collections.IDictionary]) {
        foreach ($key in $InputObject.Keys) {
            if ([string]::Equals(
                [string]$key,
                $Name,
                [System.StringComparison]::OrdinalIgnoreCase
            )) {
                return $InputObject[$key]
            }
        }
        return $null
    }

    $property = $InputObject.PSObject.Properties |
        Where-Object { $_.Name -ieq $Name } |
        Select-Object -First 1
    if (-not $property) { return $null }
    return $property.Value
}

function Get-RolePermissionBlock {
    <#
    Normalises role definitions from Az.Resources 9 and earlier (flattened
    Actions/NotActions) and Az.Resources 10+ (Permissions[]).
    #>
    param([object]$Role)

    $permissions = @(Get-RadarPropertyValue -InputObject $Role -Name 'Permissions')
    $permissions = @($permissions | Where-Object { $null -ne $_ })
    if ($permissions.Count -gt 0) {
        foreach ($permission in $permissions) {
            [pscustomobject]@{
                Actions = @(
                    Get-RadarPropertyValue -InputObject $permission -Name 'Actions'
                )
                NotActions = @(
                    Get-RadarPropertyValue -InputObject $permission -Name 'NotActions'
                )
            }
        }
        return
    }

    [pscustomobject]@{
        Actions = @(
            Get-RadarPropertyValue -InputObject $Role -Name 'Actions'
        )
        NotActions = @(
            Get-RadarPropertyValue -InputObject $Role -Name 'NotActions'
        )
    }
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
    return @(
        Get-RolePermissionBlock -Role $Role |
            ForEach-Object {
                Get-RadarPropertyValue -InputObject $_ -Name $Name
            } |
            Where-Object { $null -ne $_ }
    )
}

function Get-RadarGlobEpsilonClosure {
    param(
        [string]$Pattern,
        [int[]]$States
    )

    $seen = New-Object System.Collections.Generic.HashSet[int]
    $pending = New-Object System.Collections.Generic.Queue[int]
    foreach ($state in $States) {
        if ($seen.Add($state)) {
            $pending.Enqueue($state)
        }
    }

    while ($pending.Count -gt 0) {
        $state = $pending.Dequeue()
        if (
            $state -lt $Pattern.Length -and
            $Pattern[$state] -eq '*'
        ) {
            $nextState = $state + 1
            if ($seen.Add($nextState)) {
                $pending.Enqueue($nextState)
            }
        }
    }

    return @($seen | Sort-Object)
}

function Get-RadarGlobTransition {
    param(
        [string]$Pattern,
        [int[]]$States,
        [string]$Symbol,
        [switch]$OtherSymbol
    )

    $nextStates = New-Object System.Collections.Generic.HashSet[int]
    foreach ($state in $States) {
        if ($state -ge $Pattern.Length) { continue }
        $character = $Pattern[$state]
        if ($character -eq '*') {
            [void]$nextStates.Add($state)
        }
        elseif (
            -not $OtherSymbol -and
            [string]$character -eq $Symbol
        ) {
            [void]$nextStates.Add($state + 1)
        }
    }

    if ($nextStates.Count -eq 0) { return @() }
    return @(
        Get-RadarGlobEpsilonClosure `
            -Pattern $Pattern `
            -States @($nextStates)
    )
}

function Get-RadarGlobProductKey {
    param([object[]]$StateSets)

    return (
        $StateSets |
            ForEach-Object { @($_) -join ',' }
    ) -join '|'
}

function Test-RadarGlobProductAccepting {
    param(
        [string[]]$Patterns,
        [object[]]$StateSets,
        [int]$IncludeCount
    )

    for ($index = 0; $index -lt $IncludeCount; $index++) {
        if (
            @($StateSets[$index]) -notcontains
            $Patterns[$index].Length
        ) {
            return $false
        }
    }
    for (
        $index = $IncludeCount;
        $index -lt $Patterns.Count;
        $index++
    ) {
        if (
            @($StateSets[$index]) -contains
            $Patterns[$index].Length
        ) {
            return $false
        }
    }
    return $true
}

function Test-RadarGlobDifferenceExists {
    <#
    Decides whether at least one non-empty concrete action matches every include
    glob while matching none of the exclude globs. This is the exact language
    difference needed for (Actions intersect Restricted) minus NotActions.
    #>
    param(
        [string[]]$IncludePatterns,
        [string[]]$ExcludePatterns = @()
    )

    $includes = @(
        $IncludePatterns |
            Where-Object { -not [string]::IsNullOrWhiteSpace($_) } |
            ForEach-Object { $_.ToLowerInvariant() }
    )
    if ($includes.Count -eq 0) { return $false }
    $excludes = @(
        $ExcludePatterns |
            Where-Object { -not [string]::IsNullOrWhiteSpace($_) } |
            ForEach-Object { $_.ToLowerInvariant() } |
            Sort-Object -Unique
    )
    $patterns = @($includes + $excludes)

    $cacheVariable = Get-Variable `
        -Name RadarGlobDifferenceCache `
        -Scope Script `
        -ErrorAction SilentlyContinue
    if (-not $cacheVariable) {
        Set-Variable `
            -Name RadarGlobDifferenceCache `
            -Scope Script `
            -Value @{}
        $cacheVariable = Get-Variable `
            -Name RadarGlobDifferenceCache `
            -Scope Script
    }
    $cache = $cacheVariable.Value
    $cacheKey = "$($includes -join [char]30)$([char]29)$($excludes -join [char]30)"
    if ($cache.ContainsKey($cacheKey)) {
        return [bool]$cache[$cacheKey]
    }

    $concretePattern = $includes |
        Where-Object { -not $_.Contains('*') } |
        Select-Object -First 1
    if ($concretePattern) {
        $included = @(
            $includes |
                Where-Object {
                    -not (
                        Test-PermissionMatch `
                            -Pattern $_ `
                            -Action $concretePattern
                    )
                }
        ).Count -eq 0
        $excluded = @(
            $excludes |
                Where-Object {
                    Test-PermissionMatch `
                        -Pattern $_ `
                        -Action $concretePattern
                }
        ).Count -gt 0
        $cache[$cacheKey] = ($included -and -not $excluded)
        return [bool]$cache[$cacheKey]
    }

    if (
        $includes.Count -eq 2 -and
        -not (
            Test-GlobIntersect `
                -A $includes[0] `
                -B $includes[1]
        )
    ) {
        $cache[$cacheKey] = $false
        return $false
    }

    if ($excludes.Count -eq 0) {
        $cache[$cacheKey] = $true
        return $true
    }

    foreach ($exclude in $excludes) {
        if (
            @(
                $includes |
                    Where-Object {
                        [string]::Equals(
                            $_,
                            $exclude,
                            [System.StringComparison]::OrdinalIgnoreCase
                        )
                    }
            ).Count -gt 0
        ) {
            $cache[$cacheKey] = $false
            return $false
        }
    }

    $excludes = @(
        $excludes |
            Where-Object {
                $exclude = $_
                @(
                    $includes |
                        Where-Object {
                            Test-GlobIntersect -A $_ -B $exclude
                        }
                ).Count -eq $includes.Count
            }
    )
    if ($excludes.Count -eq 0) {
        $cache[$cacheKey] = $true
        return $true
    }
    $patterns = @($includes + $excludes)

    $literalSet = New-Object System.Collections.Generic.HashSet[string]
    foreach ($pattern in $patterns) {
        foreach ($character in $pattern.ToCharArray()) {
            if ($character -ne '*') {
                [void]$literalSet.Add([string]$character)
            }
        }
    }
    $symbols = New-Object System.Collections.Generic.List[object]
    foreach ($literal in ($literalSet | Sort-Object)) {
        [void]$symbols.Add([pscustomobject]@{
            Value = $literal
            IsOther = $false
        })
    }
    [void]$symbols.Add([pscustomobject]@{
        Value = ''
        IsOther = $true
    })

    $initialSets = New-Object System.Collections.Generic.List[object]
    foreach ($pattern in $patterns) {
        [void]$initialSets.Add(
            [int[]]@(
                Get-RadarGlobEpsilonClosure `
                    -Pattern $pattern `
                    -States @(0)
            )
        )
    }

    $pending = New-Object System.Collections.Generic.Queue[object]
    $pending.Enqueue($initialSets.ToArray())
    $visited = New-Object System.Collections.Generic.HashSet[string]
    $initialKey = Get-RadarGlobProductKey `
        -StateSets $initialSets.ToArray()
    [void]$visited.Add($initialKey)

    while ($pending.Count -gt 0) {
        $stateSets = [object[]]$pending.Dequeue()
        foreach ($symbol in $symbols) {
            $nextSets = New-Object System.Collections.Generic.List[object]
            $includeStillPossible = $true
            for (
                $index = 0;
                $index -lt $patterns.Count;
                $index++
            ) {
                $next = @(
                    Get-RadarGlobTransition `
                        -Pattern $patterns[$index] `
                        -States ([int[]]@($stateSets[$index])) `
                        -Symbol $symbol.Value `
                        -OtherSymbol:$symbol.IsOther
                )
                if (
                    $index -lt $includes.Count -and
                    $next.Count -eq 0
                ) {
                    $includeStillPossible = $false
                    break
                }
                [void]$nextSets.Add([int[]]$next)
            }
            if (-not $includeStillPossible) { continue }

            $nextStateSets = $nextSets.ToArray()
            if (
                Test-RadarGlobProductAccepting `
                    -Patterns $patterns `
                    -StateSets $nextStateSets `
                    -IncludeCount $includes.Count
            ) {
                $cache[$cacheKey] = $true
                return $true
            }

            $stateKey = Get-RadarGlobProductKey `
                -StateSets $nextStateSets
            if ($visited.Add($stateKey)) {
                if ($visited.Count -gt 20000) {
                    # Fail open: an unproven exclusion remains a potential path.
                    $cache[$cacheKey] = $true
                    return $true
                }
                $pending.Enqueue($nextStateSets)
            }
        }
    }

    $cache[$cacheKey] = $false
    return $false
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

    $actionIsConcrete =
        -not [string]::IsNullOrWhiteSpace($Action) -and
        -not $Action.Contains('*')
    foreach ($permission in @(Get-RolePermissionBlock -Role $Role)) {
        $notActions = @($permission.NotActions)
        foreach ($matchedAction in @($permission.Actions)) {
            if (
                -not (
                    Test-PermissionMatch `
                        -Pattern $matchedAction `
                        -Action $Action
                )
            ) {
                continue
            }

            if ($actionIsConcrete) {
                $isExcluded = $false
                foreach ($notAction in $notActions) {
                    if (
                        Test-PermissionMatch `
                            -Pattern $notAction `
                            -Action $Action
                    ) {
                        $isExcluded = $true
                        break
                    }
                }
                if (-not $isExcluded) {
                    return [pscustomobject]@{
                        MatchedPattern = $matchedAction
                    }
                }
                continue
            }

            if (
                Test-RadarGlobDifferenceExists `
                    -IncludePatterns @($matchedAction, $Action) `
                    -ExcludePatterns $notActions
            ) {
                return [pscustomobject]@{
                    MatchedPattern = $matchedAction
                }
            }
        }
    }

    return $null
}

function Get-RadarBaselineRole {
    <#
    Selects dynamic restricted-action source roles. Explicit patterns are
    authoritative. Auto-detection retains every wildcard Owner, Contributor,
    or Baseline role with non-empty NotActions. Each role is analysed separately
    later, so their distinct restriction sets are never unioned.
    #>
    param(
        [object[]]$Roles,
        [string[]]$Pattern = @()
    )

    $patterns = @(
        $Pattern |
            Where-Object { -not [string]::IsNullOrWhiteSpace($_) }
    )
    $candidates = @(
        foreach ($role in $Roles) {
            $actions = @(
                Get-RoleProperty -Role $role -Name 'Actions'
            )
            $notActions = @(
                Get-RoleProperty -Role $role -Name 'NotActions' |
                    Where-Object {
                        -not [string]::IsNullOrWhiteSpace($_)
                    } |
                    Sort-Object -Unique
            )
            if (
                $actions -contains '*' -and
                $notActions.Count -gt 0
            ) {
                [pscustomobject]@{
                    Role = $role
                    Name = [string](
                        Get-RadarPropertyValue `
                            -InputObject $role `
                            -Name 'Name'
                    )
                    NotActionCount = $notActions.Count
                }
            }
        }
    )

    $selected = New-Object System.Collections.Generic.List[object]
    $selectedKeys =
        New-Object System.Collections.Generic.HashSet[string] (
            [StringComparer]::OrdinalIgnoreCase
        )
    $addSelection = {
        param([object]$Candidate)
        $key = Get-RadarRoleKey -Role $Candidate.Role
        if ($selectedKeys.Add($key)) {
            [void]$selected.Add($Candidate.Role)
        }
    }

    if ($patterns.Count -gt 0) {
        foreach ($candidate in $candidates) {
            if (
                @(
                    $patterns |
                        Where-Object {
                            $candidate.Name -like $_
                        }
                ).Count -gt 0
            ) {
                & $addSelection $candidate
            }
        }
        $mode = 'ExplicitPattern'
    }
    else {
        foreach (
            $candidate in @(
                $candidates |
                    Where-Object {
                        $_.NotActionCount -gt 0 -and
                        $_.Name -match
                            '(?i)(^|[^a-z0-9])(owner|contributor|baseline)([^a-z0-9]|$)'
                    } |
                    Sort-Object Name
            )
        ) {
                & $addSelection $candidate
        }
        $mode = 'Automatic'
    }

    [pscustomobject]@{
        Roles = $selected.ToArray()
        Candidates = $candidates
        SelectionMode = $mode
    }
}

function Get-RadarBaselineContext {
    param(
        [object[]]$BaselineRoles,
        [object[]]$KnownScopes,
        [object]$Hierarchy
    )

    $contexts = New-Object System.Collections.Generic.List[object]
    $warnings = New-Object System.Collections.Generic.List[string]
    foreach ($role in $BaselineRoles) {
        $roleName = [string](
            Get-RadarPropertyValue -InputObject $role -Name 'Name'
        )
        $roleId = [string](
            Get-RadarPropertyValue -InputObject $role -Name 'Id'
        )
        $assignableScopes = @(
            Get-RadarPropertyValue `
                -InputObject $role `
                -Name 'AssignableScopes' |
                Where-Object {
                    -not [string]::IsNullOrWhiteSpace($_)
                } |
                ForEach-Object { ([string]$_).TrimEnd('/') } |
                Sort-Object -Unique
        )
        if ($assignableScopes.Count -eq 0) {
            [void]$warnings.Add(
                "Baseline role '$roleName' has no readable AssignableScopes."
            )
            continue
        }

        $declaredNotActions = @(
            Get-RoleProperty -Role $role -Name 'NotActions' |
                Where-Object {
                    -not [string]::IsNullOrWhiteSpace($_)
                } |
                ForEach-Object { $_.Trim() } |
                Sort-Object -Unique
        )
        $restrictionWarnings =
            New-Object System.Collections.Generic.List[string]
        $restrictedActions = New-Object System.Collections.Generic.List[string]
        $restrictionComplete = $true
        foreach ($declaredNotAction in $declaredNotActions) {
            $regranted = Get-ActionMatch `
                -Role $role `
                -Action $declaredNotAction
            if ($null -eq $regranted) {
                [void]$restrictedActions.Add($declaredNotAction)
                continue
            }

            if (-not $declaredNotAction.Contains('*')) {
                [void]$restrictionWarnings.Add(
                    "NotAction '$declaredNotAction' is re-granted by permission pattern '$($regranted.MatchedPattern)' and was excluded from the baseline restriction set."
                )
                continue
            }

            # Some of a wildcard NotAction may still be restricted, but its
            # exact residual language cannot be represented as one Azure action
            # string. Retain it conservatively and prevent a Full conclusion.
            [void]$restrictedActions.Add($declaredNotAction)
            $restrictionComplete = $false
            [void]$restrictionWarnings.Add(
                "Wildcard NotAction '$declaredNotAction' overlaps re-granted permission '$($regranted.MatchedPattern)'; findings for this action are conservative."
            )
        }
        if ($restrictedActions.Count -eq 0) { continue }

        $assignmentPaths = New-Object System.Collections.Generic.List[object]
        $directSelfAssignment = $null -ne (
            Get-ActionMatch `
                -Role $role `
                -Action 'Microsoft.Authorization/roleAssignments/write'
        )
        [void]$assignmentPaths.Add([pscustomobject]@{
            Name = 'Direct role assignment'
            ResourceType =
                'Microsoft.Authorization/roleAssignments'
            Reachability = if ($directSelfAssignment) {
                'Baseline role can create direct role assignments'
            }
            else {
                'Requires another principal or assignment process'
            }
        })

        foreach (
            $pimPath in @(
                [pscustomobject]@{
                    Name = 'PIM active assignment request'
                    ResourceType =
                        'Microsoft.Authorization/roleAssignmentScheduleRequests'
                    Action =
                        'Microsoft.Authorization/roleAssignmentScheduleRequests/write'
                },
                [pscustomobject]@{
                    Name = 'PIM eligible assignment request'
                    ResourceType =
                        'Microsoft.Authorization/roleEligibilityScheduleRequests'
                    Action =
                        'Microsoft.Authorization/roleEligibilityScheduleRequests/write'
                }
            )
        ) {
            if (
                $null -ne (
                    Get-ActionMatch `
                        -Role $role `
                        -Action $pimPath.Action
                )
            ) {
                [void]$assignmentPaths.Add([pscustomobject]@{
                    Name = $pimPath.Name
                    ResourceType = $pimPath.ResourceType
                    Reachability =
                        'Baseline role can create this PIM request'
                })
            }
        }

        foreach ($assignableScope in $assignableScopes) {
            $rootScope = if ($assignableScope) {
                $assignableScope
            }
            else {
                '/'
            }
            $subtree = Get-RadarSubtreeScope `
                -RootScope $rootScope `
                -Scopes $KnownScopes `
                -Hierarchy $Hierarchy
            if (@($subtree.Scopes).Count -eq 0) {
                continue
            }
            foreach ($warning in $subtree.Warnings) {
                [void]$warnings.Add(
                    "$roleName at ${rootScope}: $warning"
                )
            }
            foreach ($warning in $restrictionWarnings) {
                [void]$warnings.Add(
                    "${roleName}: $warning"
                )
            }

            [void]$contexts.Add([pscustomobject]@{
                BaselineRole = $role
                BaselineRoleName = $roleName
                BaselineRoleId = $roleId
                BaselineScope = $rootScope
                RestrictedActions = $restrictedActions.ToArray()
                EvaluationScopes = @($subtree.Scopes)
                IsComplete = (
                    $subtree.IsComplete -and
                    $restrictionComplete
                )
                RestrictionWarnings =
                    $restrictionWarnings.ToArray()
                AssignmentPaths = $assignmentPaths.ToArray()
                AssignmentPath = @(
                    $assignmentPaths |
                        ForEach-Object {
                            "$($_.Name): $($_.Reachability)"
                        }
                ) -join '; '
            })
        }
    }

    [pscustomobject]@{
        Contexts = $contexts.ToArray()
        IsComplete = @(
            $contexts |
                Where-Object { -not $_.IsComplete }
        ).Count -eq 0
        Warnings = @($warnings | Sort-Object -Unique)
    }
}

function Get-RadarRoleScopesInContext {
    param(
        [object]$Role,
        [object[]]$ContextScopes,
        [object]$Hierarchy
    )

    $isCustom = [bool](
        Get-RadarPropertyValue -InputObject $Role -Name 'IsCustom'
    )
    if (-not $isCustom) {
        return [pscustomobject]@{
            Scopes = @($ContextScopes)
            IsComplete = $true
            Warnings = @()
        }
    }

    $assignableScopes = @(
        Get-RadarPropertyValue `
            -InputObject $Role `
            -Name 'AssignableScopes' |
            Where-Object {
                -not [string]::IsNullOrWhiteSpace($_)
            }
    )
    $availableScopeById = @{}
    $warnings = New-Object System.Collections.Generic.List[string]
    $isComplete = $true
    foreach ($contextScope in $ContextScopes) {
        $scopeId = [string](
            Get-RadarPropertyValue `
                -InputObject $contextScope `
                -Name 'Id'
        )
        foreach ($assignableScope in $assignableScopes) {
            $relationship = Test-RadarScopeDescendsFrom `
                -Scope $scopeId `
                -RootScope ([string]$assignableScope) `
                -Hierarchy $Hierarchy
            if ($relationship.State -eq 'True') {
                $availableScopeById[
                    $scopeId.TrimEnd('/').ToLowerInvariant()
                ] = $contextScope
                break
            }
            if ($relationship.State -eq 'Unknown') {
                # Include uncertain availability so it cannot hide a gap.
                $availableScopeById[
                    $scopeId.TrimEnd('/').ToLowerInvariant()
                ] = $contextScope
                $isComplete = $false
                [void]$warnings.Add($relationship.Reason)
                break
            }
        }
    }

    [pscustomobject]@{
        Scopes = @($availableScopeById.Values | Sort-Object Type, Id)
        IsComplete = $isComplete
        Warnings = @($warnings | Sort-Object -Unique)
    }
}

function Import-RadarRestrictedActionCsv {
    param(
        [Parameter(Mandatory = $true)]
        [string]$Path
    )

    if (-not (Test-Path -LiteralPath $Path)) {
        throw "Input CSV not found: $Path"
    }

    $rows = @(Import-Csv -LiteralPath $Path)
    if ($rows.Count -gt 0) {
        if (
            -not (
                $rows[0].PSObject.Properties |
                    Where-Object { $_.Name -ieq 'Action' }
            )
        ) {
            throw "Input CSV must contain an 'Action' column."
        }
    }
    else {
        $header = Get-Content -LiteralPath $Path -TotalCount 1
        if (
            $header -notmatch
            '(?i)(^|,)\s*"?Action"?\s*(,|$)'
        ) {
            throw "Input CSV must contain an 'Action' column."
        }
    }

    return @(
        $rows |
            ForEach-Object {
                Get-RadarPropertyValue `
                    -InputObject $_ `
                    -Name 'Action'
            } |
            Where-Object {
                -not [string]::IsNullOrWhiteSpace($_)
            } |
            ForEach-Object { $_.Trim() }
    )
}

function Test-RadarHasProperty {
    param(
        [object]$InputObject,
        [string]$Name
    )

    if ($null -eq $InputObject) { return $false }
    if ($InputObject -is [System.Collections.IDictionary]) {
        foreach ($key in $InputObject.Keys) {
            if ([string]::Equals(
                [string]$key,
                $Name,
                [System.StringComparison]::OrdinalIgnoreCase
            )) {
                return $true
            }
        }
        return $false
    }

    return $null -ne (
        $InputObject.PSObject.Properties |
            Where-Object { $_.Name -ieq $Name } |
            Select-Object -First 1
    )
}

function Get-RadarPolicyProperty {
    param(
        [object]$InputObject,
        [string]$Name
    )

    if (Test-RadarHasProperty -InputObject $InputObject -Name $Name) {
        return Get-RadarPropertyValue -InputObject $InputObject -Name $Name
    }

    $properties = Get-RadarPropertyValue `
        -InputObject $InputObject `
        -Name 'Properties'
    return Get-RadarPropertyValue -InputObject $properties -Name $Name
}

function Get-RadarObjectEntry {
    param([object]$InputObject)

    if ($null -eq $InputObject) { return }
    if ($InputObject -is [System.Collections.IDictionary]) {
        foreach ($key in $InputObject.Keys) {
            [pscustomobject]@{
                Name = [string]$key
                Value = $InputObject[$key]
            }
        }
        return
    }

    foreach ($property in $InputObject.PSObject.Properties) {
        [pscustomobject]@{
            Name = $property.Name
            Value = $property.Value
        }
    }
}

function ConvertFrom-RadarJsonObject {
    param([object]$InputObject)

    if ($InputObject -is [string] -and $InputObject.TrimStart().StartsWith('{')) {
        return $InputObject | ConvertFrom-Json
    }
    return $InputObject
}

function New-RadarUnresolvedValue {
    param([string]$Reason)

    [pscustomobject]@{
        RadarUnresolved = $true
        Reason = $Reason
    }
}

function Resolve-RadarPolicyValue {
    param(
        [object]$Value,
        [hashtable]$Parameters = @{}
    )

    if (
        $null -ne $Value -and
        (Test-RadarHasProperty -InputObject $Value -Name 'RadarUnresolved')
    ) {
        return [pscustomobject]@{
            IsResolved = $false
            Value = $null
            Reason = Get-RadarPropertyValue `
                -InputObject $Value `
                -Name 'Reason'
        }
    }

    if ($Value -isnot [string] -or -not $Value.StartsWith('[')) {
        return [pscustomobject]@{
            IsResolved = $true
            Value = $Value
            Reason = $null
        }
    }

    $parameterMatch = [regex]::Match(
        $Value,
        "^\[\s*parameters\(\s*['`"]([^'`"]+)['`"]\s*\)\s*\]$",
        [System.Text.RegularExpressions.RegexOptions]::IgnoreCase
    )
    if ($parameterMatch.Success) {
        $parameterName = $parameterMatch.Groups[1].Value
        if ($Parameters.ContainsKey($parameterName)) {
            return [pscustomobject]@{
                IsResolved = $true
                Value = $Parameters[$parameterName]
                Reason = $null
            }
        }
        return [pscustomobject]@{
            IsResolved = $false
            Value = $null
            Reason = "Parameter '$parameterName' has no assigned or default value."
        }
    }

    return [pscustomobject]@{
        IsResolved = $false
        Value = $null
        Reason = "Unsupported Azure Policy expression: $Value"
    }
}

function Get-RadarPolicyParameterMap {
    param(
        [object]$DefinitionParameters,
        [object]$AssignedParameters,
        [hashtable]$ParentParameters
    )

    $values = @{}
    foreach ($entry in @(Get-RadarObjectEntry -InputObject $DefinitionParameters)) {
        if (
            Test-RadarHasProperty `
                -InputObject $entry.Value `
                -Name 'DefaultValue'
        ) {
            $values[$entry.Name] = Get-RadarPropertyValue `
                -InputObject $entry.Value `
                -Name 'DefaultValue'
        }
    }

    foreach ($entry in @(Get-RadarObjectEntry -InputObject $AssignedParameters)) {
        $rawValue = if (
            Test-RadarHasProperty -InputObject $entry.Value -Name 'Value'
        ) {
            Get-RadarPropertyValue -InputObject $entry.Value -Name 'Value'
        }
        else {
            $entry.Value
        }

        if ($null -ne $ParentParameters) {
            $resolved = Resolve-RadarPolicyValue `
                -Value $rawValue `
                -Parameters $ParentParameters
            if ($resolved.IsResolved) {
                $values[$entry.Name] = $resolved.Value
            }
            else {
                $values[$entry.Name] = New-RadarUnresolvedValue `
                    -Reason $resolved.Reason
            }
        }
        else {
            $values[$entry.Name] = $rawValue
        }
    }

    return $values
}

function Get-RadarRoleDefinitionGuid {
    param([object]$RoleOrId)

    $id = if ($RoleOrId -is [string]) {
        $RoleOrId
    }
    else {
        [string](
            Get-RadarPropertyValue -InputObject $RoleOrId -Name 'Id'
        )
    }
    $match = [regex]::Match(
        [string]$id,
        '(?i)[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}(?=/?$)'
    )
    if ($match.Success) {
        return $match.Value.ToLowerInvariant()
    }
    return ([string]$id).TrimEnd('/').ToLowerInvariant()
}

function New-RadarPolicyEvaluation {
    param(
        [ValidateSet('True', 'False', 'Unknown')]
        [string]$State,
        [string]$Reason
    )

    [pscustomobject]@{
        State = $State
        Reason = $Reason
    }
}

function Compare-RadarPolicyValue {
    param(
        [object]$Actual,
        [object]$Expected,
        [string]$Operator,
        [switch]$RoleDefinitionId
    )

    $normalise = {
        param($InputValue)
        if ($RoleDefinitionId) {
            $guid = Get-RadarRoleDefinitionGuid -RoleOrId ([string]$InputValue)
            if (-not [string]::IsNullOrWhiteSpace($guid)) { return $guid }
        }
        if ($InputValue -is [string]) {
            return $InputValue.ToLowerInvariant()
        }
        return $InputValue
    }

    $actualValue = & $normalise $Actual
    $expectedValues = @($Expected | ForEach-Object { & $normalise $_ })
    $operatorName = $Operator.ToLowerInvariant()

    $equals = {
        param($Left, $Right)
        if ($Left -is [string] -or $Right -is [string]) {
            return [string]::Equals(
                [string]$Left,
                [string]$Right,
                [System.StringComparison]::OrdinalIgnoreCase
            )
        }
        return $Left -eq $Right
    }

    switch ($operatorName) {
        'equals' {
            return (& $equals $actualValue $expectedValues[0])
        }
        'notequals' {
            return (-not (& $equals $actualValue $expectedValues[0]))
        }
        'in' {
            return @(
                $expectedValues |
                    Where-Object { & $equals $actualValue $_ }
            ).Count -gt 0
        }
        'notin' {
            return @(
                $expectedValues |
                    Where-Object { & $equals $actualValue $_ }
            ).Count -eq 0
        }
        'like' {
            return [string]$actualValue -like [string]$expectedValues[0]
        }
        'notlike' {
            return [string]$actualValue -notlike [string]$expectedValues[0]
        }
        'contains' {
            if ($Actual -is [string]) {
                return $Actual.IndexOf(
                    [string]$Expected,
                    [System.StringComparison]::OrdinalIgnoreCase
                ) -ge 0
            }
            return @(
                @($Actual) |
                    Where-Object {
                        & $equals (& $normalise $_) $expectedValues[0]
                    }
            ).Count -gt 0
        }
        'notcontains' {
            return -not (
                Compare-RadarPolicyValue `
                    -Actual $Actual `
                    -Expected $Expected `
                    -Operator 'contains' `
                    -RoleDefinitionId:$RoleDefinitionId
            )
        }
        'exists' {
            $shouldExist = [System.Convert]::ToBoolean($Expected)
            return ($null -ne $Actual) -eq $shouldExist
        }
        default {
            throw "Unsupported Azure Policy comparison operator '$Operator'."
        }
    }
}

function Resolve-RadarPolicyAliasValue {
    param(
        [string]$Field,
        [object]$Role,
        [string]$AssignmentResourceType,
        [string]$AssignmentScope,
        [string]$TargetPrincipalType,
        [string]$TargetPrincipalId,
        [switch]$StringValue
    )

    $supportedResourceTypes = @(
        'Microsoft.Authorization/roleAssignments',
        'Microsoft.Authorization/roleAssignmentScheduleRequests',
        'Microsoft.Authorization/roleEligibilityScheduleRequests'
    )
    $aliasResourceType = @(
        $supportedResourceTypes |
            Where-Object {
                $Field.StartsWith(
                    "$_/",
                    [System.StringComparison]::OrdinalIgnoreCase
                )
            }
    ) | Select-Object -First 1

    if (-not $aliasResourceType) {
        if ($Field -match '^[^/]+/[^/]+/') {
            return [pscustomobject]@{
                IsResolved = $true
                Value = if ($StringValue) { '' } else { $null }
                IsRoleDefinitionId = $false
                Reason = $null
            }
        }
        return [pscustomobject]@{
            IsResolved = $false
            Value = $null
            IsRoleDefinitionId = $false
            Reason = "Unsupported policy field '$Field'."
        }
    }

    if (
        -not [string]::Equals(
            $aliasResourceType,
            $AssignmentResourceType,
            [System.StringComparison]::OrdinalIgnoreCase
        )
    ) {
        return [pscustomobject]@{
            IsResolved = $true
            Value = if ($StringValue) { '' } else { $null }
            IsRoleDefinitionId = $false
            Reason = $null
        }
    }

    $propertyName = $Field.Substring($aliasResourceType.Length + 1)
    if ($propertyName -ieq 'roleDefinitionId') {
        return [pscustomobject]@{
            IsResolved = $true
            Value = Get-RadarPropertyValue -InputObject $Role -Name 'Id'
            IsRoleDefinitionId = $true
            Reason = $null
        }
    }
    if (
        $propertyName -ieq 'principalType' -and
        -not [string]::IsNullOrWhiteSpace($TargetPrincipalType)
    ) {
        return [pscustomobject]@{
            IsResolved = $true
            Value = $TargetPrincipalType
            IsRoleDefinitionId = $false
            Reason = $null
        }
    }
    if (
        $propertyName -ieq 'principalId' -and
        -not [string]::IsNullOrWhiteSpace($TargetPrincipalId)
    ) {
        return [pscustomobject]@{
            IsResolved = $true
            Value = $TargetPrincipalId
            IsRoleDefinitionId = $false
            Reason = $null
        }
    }
    if (
        $propertyName -ieq 'scope' -and
        -not [string]::IsNullOrWhiteSpace($AssignmentScope)
    ) {
        return [pscustomobject]@{
            IsResolved = $true
            Value = $AssignmentScope
            IsRoleDefinitionId = $false
            Reason = $null
        }
    }

    return [pscustomobject]@{
        IsResolved = $false
        Value = $null
        IsRoleDefinitionId = $false
        Reason = "Policy field '$Field' depends on assignment request data that RADAR does not know."
    }
}

function Test-RadarPolicyCondition {
    param(
        [object]$Condition,
        [object]$Role,
        [hashtable]$Parameters = @{},
        [string]$AssignmentResourceType =
            'Microsoft.Authorization/roleAssignments',
        [string]$AssignmentScope,
        [string]$TargetPrincipalType,
        [string]$TargetPrincipalId
    )

    $Condition = ConvertFrom-RadarJsonObject -InputObject $Condition

    if (Test-RadarHasProperty -InputObject $Condition -Name 'AllOf') {
        $sawUnknown = $false
        $unknownReasons = New-Object System.Collections.Generic.List[string]
        foreach (
            $child in @(
                Get-RadarPropertyValue -InputObject $Condition -Name 'AllOf'
            )
        ) {
            $result = Test-RadarPolicyCondition `
                -Condition $child `
                -Role $Role `
                -Parameters $Parameters `
                -AssignmentResourceType $AssignmentResourceType `
                -AssignmentScope $AssignmentScope `
                -TargetPrincipalType $TargetPrincipalType `
                -TargetPrincipalId $TargetPrincipalId
            if ($result.State -eq 'False') { return $result }
            if ($result.State -eq 'Unknown') {
                $sawUnknown = $true
                [void]$unknownReasons.Add($result.Reason)
            }
        }
        if ($sawUnknown) {
            return New-RadarPolicyEvaluation `
                -State 'Unknown' `
                -Reason ($unknownReasons -join '; ')
        }
        return New-RadarPolicyEvaluation -State 'True'
    }

    if (Test-RadarHasProperty -InputObject $Condition -Name 'AnyOf') {
        $sawUnknown = $false
        $unknownReasons = New-Object System.Collections.Generic.List[string]
        foreach (
            $child in @(
                Get-RadarPropertyValue -InputObject $Condition -Name 'AnyOf'
            )
        ) {
            $result = Test-RadarPolicyCondition `
                -Condition $child `
                -Role $Role `
                -Parameters $Parameters `
                -AssignmentResourceType $AssignmentResourceType `
                -AssignmentScope $AssignmentScope `
                -TargetPrincipalType $TargetPrincipalType `
                -TargetPrincipalId $TargetPrincipalId
            if ($result.State -eq 'True') { return $result }
            if ($result.State -eq 'Unknown') {
                $sawUnknown = $true
                [void]$unknownReasons.Add($result.Reason)
            }
        }
        if ($sawUnknown) {
            return New-RadarPolicyEvaluation `
                -State 'Unknown' `
                -Reason ($unknownReasons -join '; ')
        }
        return New-RadarPolicyEvaluation -State 'False'
    }

    if (Test-RadarHasProperty -InputObject $Condition -Name 'Not') {
        $innerResult = Test-RadarPolicyCondition `
            -Condition (
                Get-RadarPropertyValue -InputObject $Condition -Name 'Not'
            ) `
            -Role $Role `
            -Parameters $Parameters `
            -AssignmentResourceType $AssignmentResourceType `
            -AssignmentScope $AssignmentScope `
            -TargetPrincipalType $TargetPrincipalType `
            -TargetPrincipalId $TargetPrincipalId
        if ($innerResult.State -eq 'Unknown') { return $innerResult }
        return New-RadarPolicyEvaluation `
            -State $(if ($innerResult.State -eq 'True') { 'False' } else { 'True' })
    }

    $isRoleDefinitionField = $false
    if (Test-RadarHasProperty -InputObject $Condition -Name 'Field') {
        $field = [string](
            Get-RadarPropertyValue -InputObject $Condition -Name 'Field'
        )
        if ($field -ieq 'type') {
            $actual = $AssignmentResourceType
        }
        elseif ($field -ieq 'name' -or $field -ieq 'fullName') {
            $actual = '00000000-0000-0000-0000-000000000000'
        }
        elseif (
            $field -ieq 'id' -and
            -not [string]::IsNullOrWhiteSpace($AssignmentScope)
        ) {
            $actual = (
                $AssignmentScope.TrimEnd('/') +
                '/providers/' +
                $AssignmentResourceType +
                '/00000000-0000-0000-0000-000000000000'
            )
        }
        else {
            $aliasValue = Resolve-RadarPolicyAliasValue `
                -Field $field `
                -Role $Role `
                -AssignmentResourceType $AssignmentResourceType `
                -AssignmentScope $AssignmentScope `
                -TargetPrincipalType $TargetPrincipalType `
                -TargetPrincipalId $TargetPrincipalId
            if (-not $aliasValue.IsResolved) {
                return New-RadarPolicyEvaluation `
                    -State 'Unknown' `
                    -Reason $aliasValue.Reason
            }
            $actual = $aliasValue.Value
            $isRoleDefinitionField =
                $aliasValue.IsRoleDefinitionId
        }
    }
    elseif (Test-RadarHasProperty -InputObject $Condition -Name 'Value') {
        $valueExpression = Get-RadarPropertyValue `
            -InputObject $Condition `
            -Name 'Value'
        if (
            $valueExpression -is [string] -and
            $valueExpression -match '(?i)roleDefinitionId' -and
            $valueExpression -match '(?i)last\s*\(\s*split\s*\('
        ) {
            $fieldMatch = [regex]::Match(
                $valueExpression,
                "(?i)field\(\s*['`"](?<field>[^'`"]+/roleDefinitionId)['`"]\s*\)"
            )
            if ($fieldMatch.Success) {
                $aliasResourceType =
                    $fieldMatch.Groups['field'].Value -replace (
                        '(?i)/roleDefinitionId$'
                    ), ''
                if (
                    -not [string]::Equals(
                        $aliasResourceType,
                        $AssignmentResourceType,
                        [System.StringComparison]::OrdinalIgnoreCase
                    )
                ) {
                    return New-RadarPolicyEvaluation `
                        -State 'False' `
                        -Reason "Value-expression alias '$($fieldMatch.Groups['field'].Value)' does not apply to assignment resource type '$AssignmentResourceType'."
                }
            }
            else {
                return New-RadarPolicyEvaluation `
                    -State 'Unknown' `
                    -Reason 'The roleDefinitionId value-expression alias could not be resolved.'
            }
            $actual = Get-RadarRoleDefinitionGuid -RoleOrId $Role
            $isRoleDefinitionField = $true
        }
        else {
            $stringFieldMatch = [regex]::Match(
                [string]$valueExpression,
                "^\[\s*string\(\s*field\(\s*['`"](?<field>[^'`"]+)['`"]\s*\)\s*\)\s*\]$",
                [System.Text.RegularExpressions.RegexOptions]::IgnoreCase
            )
            $fieldValueMatch = [regex]::Match(
                [string]$valueExpression,
                "^\[\s*field\(\s*['`"](?<field>[^'`"]+)['`"]\s*\)\s*\]$",
                [System.Text.RegularExpressions.RegexOptions]::IgnoreCase
            )
            if ($stringFieldMatch.Success -or $fieldValueMatch.Success) {
                $matchedField = if ($stringFieldMatch.Success) {
                    $stringFieldMatch.Groups['field'].Value
                }
                else {
                    $fieldValueMatch.Groups['field'].Value
                }
                $aliasValue = Resolve-RadarPolicyAliasValue `
                    -Field $matchedField `
                    -Role $Role `
                    -AssignmentResourceType $AssignmentResourceType `
                    -AssignmentScope $AssignmentScope `
                    -TargetPrincipalType $TargetPrincipalType `
                    -TargetPrincipalId $TargetPrincipalId `
                    -StringValue:$stringFieldMatch.Success
                if (-not $aliasValue.IsResolved) {
                    return New-RadarPolicyEvaluation `
                        -State 'Unknown' `
                        -Reason $aliasValue.Reason
                }
                $actual = $aliasValue.Value
                $isRoleDefinitionField =
                    $aliasValue.IsRoleDefinitionId
            }
            else {
                $leftResolution = Resolve-RadarPolicyValue `
                    -Value $valueExpression `
                    -Parameters $Parameters
                if (-not $leftResolution.IsResolved) {
                    return New-RadarPolicyEvaluation `
                        -State 'Unknown' `
                        -Reason $leftResolution.Reason
                }
                $actual = $leftResolution.Value
            }
        }
    }
    else {
        return New-RadarPolicyEvaluation `
            -State 'Unknown' `
            -Reason 'Policy condition has no supported field or value operand.'
    }

    $comparisonOperator = $null
    $comparisonValue = $null
    foreach (
        $operatorName in @(
            'Equals',
            'NotEquals',
            'In',
            'NotIn',
            'Like',
            'NotLike',
            'Contains',
            'NotContains',
            'Exists'
        )
    ) {
        if (
            Test-RadarHasProperty `
                -InputObject $Condition `
                -Name $operatorName
        ) {
            $comparisonOperator = $operatorName
            $comparisonValue = Get-RadarPropertyValue `
                -InputObject $Condition `
                -Name $operatorName
            break
        }
    }
    if (-not $comparisonOperator) {
        return New-RadarPolicyEvaluation `
            -State 'Unknown' `
            -Reason 'Policy condition uses an unsupported comparison operator.'
    }

    $rightResolution = Resolve-RadarPolicyValue `
        -Value $comparisonValue `
        -Parameters $Parameters
    if (-not $rightResolution.IsResolved) {
        return New-RadarPolicyEvaluation `
            -State 'Unknown' `
            -Reason $rightResolution.Reason
    }

    try {
        $matches = Compare-RadarPolicyValue `
            -Actual $actual `
            -Expected $rightResolution.Value `
            -Operator $comparisonOperator `
            -RoleDefinitionId:$isRoleDefinitionField
        return New-RadarPolicyEvaluation `
            -State $(if ($matches) { 'True' } else { 'False' })
    }
    catch {
        return New-RadarPolicyEvaluation `
            -State 'Unknown' `
            -Reason $_.Exception.Message
    }
}

function Get-RadarPolicyTypePossibility {
    param(
        [object]$Condition,
        [hashtable]$Parameters,
        [string]$ResourceType
    )

    $Condition = ConvertFrom-RadarJsonObject -InputObject $Condition
    if (Test-RadarHasProperty -InputObject $Condition -Name 'AllOf') {
        $children = @(
            foreach (
                $child in @(
                    Get-RadarPropertyValue `
                        -InputObject $Condition `
                        -Name 'AllOf'
                )
            ) {
                Get-RadarPolicyTypePossibility `
                    -Condition $child `
                    -Parameters $Parameters `
                    -ResourceType $ResourceType
            }
        )
        return [pscustomobject]@{
            CanBeTrue = @(
                $children |
                    Where-Object { -not $_.CanBeTrue }
            ).Count -eq 0
            CanBeFalse = @(
                $children |
                    Where-Object { $_.CanBeFalse }
            ).Count -gt 0
        }
    }

    if (Test-RadarHasProperty -InputObject $Condition -Name 'AnyOf') {
        $children = @(
            foreach (
                $child in @(
                    Get-RadarPropertyValue `
                        -InputObject $Condition `
                        -Name 'AnyOf'
                )
            ) {
                Get-RadarPolicyTypePossibility `
                    -Condition $child `
                    -Parameters $Parameters `
                    -ResourceType $ResourceType
            }
        )
        return [pscustomobject]@{
            CanBeTrue = @(
                $children |
                    Where-Object { $_.CanBeTrue }
            ).Count -gt 0
            CanBeFalse = @(
                $children |
                    Where-Object { -not $_.CanBeFalse }
            ).Count -eq 0
        }
    }

    if (Test-RadarHasProperty -InputObject $Condition -Name 'Not') {
        $inner = Get-RadarPolicyTypePossibility `
            -Condition (
                Get-RadarPropertyValue `
                    -InputObject $Condition `
                    -Name 'Not'
            ) `
            -Parameters $Parameters `
            -ResourceType $ResourceType
        return [pscustomobject]@{
            CanBeTrue = $inner.CanBeFalse
            CanBeFalse = $inner.CanBeTrue
        }
    }

    if (-not (Test-RadarHasProperty -InputObject $Condition -Name 'Field')) {
        return [pscustomobject]@{
            CanBeTrue = $true
            CanBeFalse = $true
        }
    }
    $field = [string](
        Get-RadarPropertyValue -InputObject $Condition -Name 'Field'
    )
    if ($field -ine 'type') {
        return [pscustomobject]@{
            CanBeTrue = $true
            CanBeFalse = $true
        }
    }

    $operator = $null
    $expected = $null
    foreach (
        $operatorName in @(
            'Equals',
            'NotEquals',
            'In',
            'NotIn',
            'Like',
            'NotLike',
            'Contains',
            'NotContains'
        )
    ) {
        if (
            Test-RadarHasProperty `
                -InputObject $Condition `
                -Name $operatorName
        ) {
            $operator = $operatorName
            $expected = Get-RadarPropertyValue `
                -InputObject $Condition `
                -Name $operatorName
            break
        }
    }
    if (-not $operator) {
        return [pscustomobject]@{
            CanBeTrue = $true
            CanBeFalse = $true
        }
    }

    $resolution = Resolve-RadarPolicyValue `
        -Value $expected `
        -Parameters $Parameters
    if (-not $resolution.IsResolved) {
        return [pscustomobject]@{
            CanBeTrue = $true
            CanBeFalse = $true
        }
    }

    try {
        $matches = Compare-RadarPolicyValue `
            -Actual $ResourceType `
            -Expected $resolution.Value `
            -Operator $operator
        return [pscustomobject]@{
            CanBeTrue = $matches
            CanBeFalse = -not $matches
        }
    }
    catch {
        return [pscustomobject]@{
            CanBeTrue = $true
            CanBeFalse = $true
        }
    }
}

function Test-RadarPolicyTypeApplicability {
    <#
    Returns False only when the policy condition cannot be true for any
    supported assignment resource type. Non-type conditions remain variables.
    #>
    param(
        [object]$Condition,
        [hashtable]$Parameters = @{},
        [string[]]$ResourceTypes
    )

    foreach ($resourceType in $ResourceTypes) {
        $possibility = Get-RadarPolicyTypePossibility `
            -Condition $Condition `
            -Parameters $Parameters `
            -ResourceType $resourceType
        if ($possibility.CanBeTrue) { return 'True' }
    }
    return 'False'
}

function Test-RadarPolicyRuleForRole {
    param(
        [object]$PolicyRule,
        [object]$Role,
        [hashtable]$Parameters = @{},
        [string]$AssignmentResourceType =
            'Microsoft.Authorization/roleAssignments',
        [string]$AssignmentScope,
        [string]$TargetPrincipalType,
        [string]$TargetPrincipalId
    )

    $PolicyRule = ConvertFrom-RadarJsonObject -InputObject $PolicyRule
    if ($null -eq $PolicyRule) {
        return [pscustomobject]@{
            State = 'Unknown'
            Reason = 'Policy definition has no policy rule.'
        }
    }

    $thenBlock = Get-RadarPropertyValue `
        -InputObject $PolicyRule `
        -Name 'Then'
    $effectValue = Get-RadarPropertyValue `
        -InputObject $thenBlock `
        -Name 'Effect'
    $effectResolution = Resolve-RadarPolicyValue `
        -Value $effectValue `
        -Parameters $Parameters
    if (-not $effectResolution.IsResolved) {
        return [pscustomobject]@{
            State = 'Unknown'
            Reason = $effectResolution.Reason
        }
    }
    if ([string]$effectResolution.Value -ine 'Deny') {
        return [pscustomobject]@{
            State = 'NotBlocked'
            Reason = "Effective policy effect is '$($effectResolution.Value)'."
        }
    }

    $conditionResult = Test-RadarPolicyCondition `
        -Condition (
            Get-RadarPropertyValue -InputObject $PolicyRule -Name 'If'
        ) `
        -Role $Role `
        -Parameters $Parameters `
        -AssignmentResourceType $AssignmentResourceType `
        -AssignmentScope $AssignmentScope `
        -TargetPrincipalType $TargetPrincipalType `
        -TargetPrincipalId $TargetPrincipalId
    switch ($conditionResult.State) {
        'True' {
            return [pscustomobject]@{
                State = 'Blocked'
                Reason = 'The deny policy condition matches this role.'
            }
        }
        'False' {
            return [pscustomobject]@{
                State = 'NotBlocked'
                Reason = 'The deny policy condition does not match this role.'
            }
        }
        default {
            return [pscustomobject]@{
                State = 'Unknown'
                Reason = $conditionResult.Reason
            }
        }
    }
}

function Get-RadarPolicyAssignmentKey {
    param([object]$Assignment)

    $id = [string](
        Get-RadarPolicyProperty -InputObject $Assignment -Name 'Id'
    )
    if (-not [string]::IsNullOrWhiteSpace($id)) {
        return $id.ToLowerInvariant()
    }

    $scope = [string](
        Get-RadarPolicyProperty -InputObject $Assignment -Name 'Scope'
    )
    $name = [string](
        Get-RadarPolicyProperty -InputObject $Assignment -Name 'Name'
    )
    return "$($scope.ToLowerInvariant())::$($name.ToLowerInvariant())"
}

function Get-RadarPolicyDefinitionCached {
    param(
        [Parameter(Mandatory = $true)]
        [string]$Id,

        [Parameter(Mandatory = $true)]
        [hashtable]$DefinitionCache,

        [Parameter(Mandatory = $true)]
        [hashtable]$PolicySetCache,

        [string]$Version
    )

    $versionKey = if ($Version) {
        $Version.ToLowerInvariant()
    }
    else {
        ''
    }
    $key = "$($Id.ToLowerInvariant())::$versionKey"
    if ($Id -match '(?i)/policySetDefinitions/') {
        if (-not $PolicySetCache.ContainsKey($key)) {
            $parameters = @{
                Id = $Id
                ErrorAction = 'Stop'
            }
            $command = Get-Command Get-AzPolicySetDefinition
            if ($Version) {
                if (-not $command.Parameters.ContainsKey('Version')) {
                    throw 'The installed Az.Resources version cannot retrieve pinned policy set definition versions.'
                }
                $parameters.Version = $Version
            }
            if ($command.Parameters.ContainsKey('Expand')) {
                $parameters.Expand = 'EffectiveDefinitionVersion'
            }
            try {
                $policySet = Get-AzPolicySetDefinition @parameters
                $members = @(
                    Get-RadarPolicyProperty `
                        -InputObject $policySet `
                        -Name 'PolicyDefinition' |
                        Where-Object { $null -ne $_ }
                )
                if ($members.Count -eq 0) {
                    throw 'The versioned policy set response contained no member definitions.'
                }
                $unresolvedMemberVersions = @(
                    foreach ($member in $members) {
                        $memberVersion =
                            Get-RadarDefinitionVersion `
                                -InputObject $member
                        if ($memberVersion.Warning) {
                            $member
                        }
                    }
                )
                if ($unresolvedMemberVersions.Count -gt 0) {
                    throw 'The versioned policy set response did not resolve every member definition version.'
                }
                $PolicySetCache[$key] = $policySet
            }
            catch {
                $PolicySetCache[$key] =
                    Get-RadarPolicyDefinitionVersionViaRest `
                        -Id $Id `
                        -Version $Version `
                        -PolicySet
            }
        }
        return $PolicySetCache[$key]
    }

    if (-not $DefinitionCache.ContainsKey($key)) {
        $parameters = @{
            Id = $Id
            ErrorAction = 'Stop'
        }
        $command = Get-Command Get-AzPolicyDefinition
        if ($Version) {
            if (-not $command.Parameters.ContainsKey('Version')) {
                throw 'The installed Az.Resources version cannot retrieve pinned policy definition versions.'
            }
            $parameters.Version = $Version
        }
        try {
            $definition = Get-AzPolicyDefinition @parameters
            $policyRule = Get-RadarPolicyProperty `
                -InputObject $definition `
                -Name 'PolicyRule'
            if ($null -eq $policyRule) {
                throw 'The versioned policy definition response contained no policy rule.'
            }
            $DefinitionCache[$key] = $definition
        }
        catch {
            $DefinitionCache[$key] =
                Get-RadarPolicyDefinitionVersionViaRest `
                    -Id $Id `
                    -Version $Version
        }
    }
    return $DefinitionCache[$key]
}

function ConvertTo-RadarPolicyDefinitionObject {
    param(
        [Parameter(Mandatory = $true)]
        [object]$InputObject,

        [Parameter(Mandatory = $true)]
        [string]$Id,

        [string]$Version,

        [switch]$PolicySet
    )

    $properties = Get-RadarPropertyValue `
        -InputObject $InputObject `
        -Name 'Properties'
    if ($null -eq $properties) {
        throw 'The policy definition response contained no properties.'
    }

    [pscustomobject]@{
        Id = $Id
        Name = Get-RadarPropertyValue `
            -InputObject $InputObject `
            -Name 'Name'
        DisplayName = Get-RadarPropertyValue `
            -InputObject $properties `
            -Name 'DisplayName'
        Description = Get-RadarPropertyValue `
            -InputObject $properties `
            -Name 'Description'
        PolicyType = Get-RadarPropertyValue `
            -InputObject $properties `
            -Name 'PolicyType'
        Mode = Get-RadarPropertyValue `
            -InputObject $properties `
            -Name 'Mode'
        Metadata = Get-RadarPropertyValue `
            -InputObject $properties `
            -Name 'Metadata'
        Parameter = Get-RadarPropertyValue `
            -InputObject $properties `
            -Name 'Parameters'
        PolicyRule = Get-RadarPropertyValue `
            -InputObject $properties `
            -Name 'PolicyRule'
        PolicyDefinition = if ($PolicySet) {
            @(
                Get-RadarPropertyValue `
                    -InputObject $properties `
                    -Name 'PolicyDefinitions'
            )
        }
        else {
            @()
        }
        Version = $Version
    }
}

function Get-RadarPolicyDefinitionVersionViaRest {
    param(
        [Parameter(Mandatory = $true)]
        [string]$Id,

        [string]$Version,

        [switch]$PolicySet
    )

    if (-not (Get-Command Invoke-AzRestMethod -ErrorAction SilentlyContinue)) {
        throw 'Invoke-AzRestMethod is required to retrieve this policy definition version.'
    }
    $path = $Id.TrimEnd('/')
    if ($Version) {
        $path += "/versions/${Version}"
    }
    $path += '?api-version=2023-04-01'
    if ($PolicySet) {
        $path += '&$expand=EffectiveDefinitionVersion'
    }
    $raw = (
        Invoke-AzRestMethod `
            -Path $path `
            -Method GET `
            -ErrorAction Stop
    ).Content | ConvertFrom-Json
    $converted = ConvertTo-RadarPolicyDefinitionObject `
        -InputObject $raw `
        -Id $Id `
        -Version $Version `
        -PolicySet:$PolicySet
    if ($PolicySet) {
        $unresolved = @(
            foreach ($member in @($converted.PolicyDefinition)) {
                $memberVersion =
                    Get-RadarDefinitionVersion -InputObject $member
                if ($memberVersion.Warning) {
                    $member
                }
            }
        )
        if ($unresolved.Count -gt 0) {
            throw 'ARM did not return effective versions for every initiative member.'
        }
    }
    return $converted
}

function Get-RadarDefinitionVersion {
    param([object]$InputObject)

    $effectiveVersion = [string](
        Get-RadarPolicyProperty `
            -InputObject $InputObject `
            -Name 'EffectiveDefinitionVersion'
    )
    if ($effectiveVersion) {
        return [pscustomobject]@{
            Version = $effectiveVersion
            Warning = $null
        }
    }

    $requestedVersion = [string](
        Get-RadarPolicyProperty `
            -InputObject $InputObject `
            -Name 'DefinitionVersion'
    )
    if (-not $requestedVersion) {
        return [pscustomobject]@{
            Version = $null
            Warning = $null
        }
    }
    if ($requestedVersion -match '^\d+\.\d+\.\d+$') {
        return [pscustomobject]@{
            Version = $requestedVersion
            Warning = $null
        }
    }

    return [pscustomobject]@{
        Version = $null
        Warning = "Definition version '$requestedVersion' is a range, but Azure did not return its effective version."
    }
}

function Import-RadarPolicyDefinitionGraphCache {
    param(
        [object[]]$Assignments,

        [Parameter(Mandatory = $true)]
        [hashtable]$DefinitionCache,

        [Parameter(Mandatory = $true)]
        [hashtable]$PolicySetCache
    )

    if (-not (Get-Command Search-AzGraph -ErrorAction SilentlyContinue)) {
        return
    }

    $newTargetMap = {
        [System.Collections.Generic.Dictionary[string, object]]::new(
            [StringComparer]::OrdinalIgnoreCase
        )
    }
    $addTarget = {
        param(
            [System.Collections.Generic.Dictionary[string, object]]$TargetMap,
            [string]$Id,
            [string]$Version,
            [bool]$PolicySet
        )

        if ([string]::IsNullOrWhiteSpace($Id)) { return }
        $baseId = $Id.TrimEnd('/')
        $fullId = if ($Version) {
            "$baseId/versions/$Version"
        }
        else {
            $baseId
        }
        if (-not $TargetMap.ContainsKey($fullId)) {
            $TargetMap[$fullId] = [pscustomobject]@{
                BaseId = $baseId
                FullId = $fullId
                Version = $Version
                PolicySet = $PolicySet
            }
        }
    }
    $loadTargets = {
        param(
            [System.Collections.Generic.Dictionary[string, object]]$TargetMap
        )

        $targets = @($TargetMap.Values)
        $batchSize = 50
        for (
            $offset = 0;
            $offset -lt $targets.Count;
            $offset += $batchSize
        ) {
            $batch = @(
                $targets |
                    Select-Object `
                        -Skip $offset `
                        -First $batchSize
            )
            $quotedIds = @(
                $batch |
                    ForEach-Object {
                        "'" +
                        $_.FullId.Replace("'", "''") +
                        "'"
                    }
            ) -join ', '
            $query = @"
policyresources
| where id in~ ($quotedIds)
| project id, name, type, properties
"@
            try {
                $response = Search-AzGraph `
                    -Query $query `
                    -First $batch.Count `
                    -UseTenantScope `
                    -ErrorAction Stop
                $rows = if (
                    Test-RadarHasProperty `
                        -InputObject $response `
                        -Name 'Data'
                ) {
                    @(
                        Get-RadarPropertyValue `
                            -InputObject $response `
                            -Name 'Data' |
                            Where-Object { $null -ne $_ }
                    )
                }
                else {
                    @(
                        $response |
                            Where-Object { $null -ne $_ }
                    )
                }

                foreach ($row in $rows) {
                    $rowId = [string](
                        Get-RadarPropertyValue `
                            -InputObject $row `
                            -Name 'Id'
                    )
                    if (
                        [string]::IsNullOrWhiteSpace($rowId) -or
                        -not $TargetMap.ContainsKey($rowId)
                    ) {
                        continue
                    }
                    $target = $TargetMap[$rowId]
                    $converted =
                        ConvertTo-RadarPolicyDefinitionObject `
                            -InputObject $row `
                            -Id $target.BaseId `
                            -Version $target.Version `
                            -PolicySet:$target.PolicySet
                    if ($target.PolicySet) {
                        $unresolved = @(
                            foreach (
                                $member in @(
                                    $converted.PolicyDefinition
                                )
                            ) {
                                $memberVersion =
                                    Get-RadarDefinitionVersion `
                                        -InputObject $member
                                if ($memberVersion.Warning) {
                                    $member
                                }
                            }
                        )
                        if ($unresolved.Count -gt 0) {
                            continue
                        }
                    }
                    $versionKey = if ($target.Version) {
                        $target.Version.ToLowerInvariant()
                    }
                    else {
                        ''
                    }
                    $cacheKey = (
                        $target.BaseId.ToLowerInvariant() +
                        '::' +
                        $versionKey
                    )
                    if ($target.PolicySet) {
                        $PolicySetCache[$cacheKey] = $converted
                    }
                    else {
                        $DefinitionCache[$cacheKey] = $converted
                    }
                }
            }
            catch {
                Write-Verbose (
                    'Azure Resource Graph policy-definition preload failed ' +
                    "for one batch: $($_.Exception.Message)"
                )
            }
        }
    }

    $assignedTargets = & $newTargetMap
    foreach ($assignment in @($Assignments)) {
        $definitionId = [string](
            Get-RadarPolicyProperty `
                -InputObject $assignment `
                -Name 'PolicyDefinitionId'
        )
        $definitionVersion =
            Get-RadarDefinitionVersion `
                -InputObject $assignment
        if ($definitionVersion.Warning) { continue }
        & $addTarget `
            $assignedTargets `
            $definitionId `
            $definitionVersion.Version `
            ($definitionId -match '(?i)/policySetDefinitions/')
    }
    & $loadTargets $assignedTargets

    $memberTargets = & $newTargetMap
    foreach (
        $target in @(
            $assignedTargets.Values |
                Where-Object { $_.PolicySet }
        )
    ) {
        $versionKey = if ($target.Version) {
            $target.Version.ToLowerInvariant()
        }
        else {
            ''
        }
        $cacheKey = (
            $target.BaseId.ToLowerInvariant() +
            '::' +
            $versionKey
        )
        if (-not $PolicySetCache.ContainsKey($cacheKey)) {
            continue
        }
        foreach (
            $member in @(
                $PolicySetCache[$cacheKey].PolicyDefinition
            )
        ) {
            $memberId = [string](
                Get-RadarPropertyValue `
                    -InputObject $member `
                    -Name 'PolicyDefinitionId'
            )
            $memberVersion =
                Get-RadarDefinitionVersion `
                    -InputObject $member
            if ($memberVersion.Warning) { continue }
            & $addTarget `
                $memberTargets `
                $memberId `
                $memberVersion.Version `
                $false
        }
    }
    & $loadTargets $memberTargets
}

function Resolve-RadarPolicyAssignmentVersion {
    <#
    Populates EffectiveDefinitionVersion on assignment objects. Az.Resources
    10 can expand this natively; older modules use the same ARM REST API.
    #>
    param(
        [Parameter(Mandatory = $true)]
        [object]$Assignment
    )

    $version = Get-RadarDefinitionVersion -InputObject $Assignment
    if (-not $version.Warning) { return $Assignment }

    $assignmentId = [string](
        Get-RadarPolicyProperty `
            -InputObject $Assignment `
            -Name 'Id'
    )
    if ([string]::IsNullOrWhiteSpace($assignmentId)) {
        throw 'The policy assignment has no resource ID for version expansion.'
    }

    $assignmentCommand = Get-Command Get-AzPolicyAssignment
    if ($assignmentCommand.Parameters.ContainsKey('Expand')) {
        try {
            $expandedAssignment = Get-AzPolicyAssignment `
                -Id $assignmentId `
                -Expand 'EffectiveDefinitionVersion' `
                -ErrorAction Stop `
                -WarningAction SilentlyContinue
            $expandedVersion =
                Get-RadarDefinitionVersion `
                    -InputObject $expandedAssignment
            if (-not $expandedVersion.Warning) {
                return $expandedAssignment
            }
        }
        catch {
            # Fall through to the direct ARM request below.
        }
    }

    if (-not (Get-Command Invoke-AzRestMethod -ErrorAction SilentlyContinue)) {
        throw 'Neither Get-AzPolicyAssignment -Expand nor Invoke-AzRestMethod is available.'
    }

    $path = (
        $assignmentId +
        '?api-version=2025-03-01&$expand=EffectiveDefinitionVersion'
    )
    $response = Invoke-AzRestMethod `
        -Path $path `
        -Method GET `
        -ErrorAction Stop
    $expanded = $response.Content | ConvertFrom-Json
    $effectiveVersion = [string](
        Get-RadarPropertyValue `
            -InputObject $expanded.properties `
            -Name 'EffectiveDefinitionVersion'
    )
    if ([string]::IsNullOrWhiteSpace($effectiveVersion)) {
        throw 'Azure did not return effectiveDefinitionVersion.'
    }

    $Assignment |
        Add-Member `
            -MemberType NoteProperty `
            -Name 'EffectiveDefinitionVersion' `
            -Value $effectiveVersion `
            -Force
    return $Assignment
}

function Resolve-RadarPolicyAssignment {
    <#
    Resolves a direct policy or initiative assignment into role-assignment deny
    rules with effective parameter values. Unrelated policies are omitted.
    #>
    param(
        [Parameter(Mandatory = $true)]
        [object]$Assignment,

        [Parameter(Mandatory = $true)]
        [hashtable]$DefinitionCache,

        [Parameter(Mandatory = $true)]
        [hashtable]$PolicySetCache
    )

    $warnings = New-Object System.Collections.Generic.List[string]
    $rules = New-Object System.Collections.Generic.List[object]
    $assignmentResourceTypes = @(
        'Microsoft.Authorization/roleAssignments',
        'Microsoft.Authorization/roleAssignmentScheduleRequests',
        'Microsoft.Authorization/roleEligibilityScheduleRequests'
    )

    $enforcementMode = [string](
        Get-RadarPolicyProperty `
            -InputObject $Assignment `
            -Name 'EnforcementMode'
    )
    if ($enforcementMode -ieq 'DoNotEnforce') {
        return [pscustomobject]@{
            Rules = @()
            Warnings = @()
        }
    }

    $assignmentId = [string](
        Get-RadarPolicyProperty -InputObject $Assignment -Name 'Id'
    )
    $assignmentName = [string](
        Get-RadarPolicyProperty `
            -InputObject $Assignment `
            -Name 'DisplayName'
    )
    if ([string]::IsNullOrWhiteSpace($assignmentName)) {
        $assignmentName = [string](
            Get-RadarPolicyProperty `
                -InputObject $Assignment `
                -Name 'Name'
        )
    }
    $assignmentScope = [string](
        Get-RadarPolicyProperty -InputObject $Assignment -Name 'Scope'
    )
    $notScopes = @(
        Get-RadarPolicyProperty `
            -InputObject $Assignment `
            -Name 'NotScope' |
            Where-Object { $null -ne $_ }
    )
    if ($notScopes.Count -eq 0) {
        $notScopes = @(
            Get-RadarPolicyProperty `
                -InputObject $Assignment `
                -Name 'NotScopes' |
                Where-Object { $null -ne $_ }
        )
    }

    $overrides = @(
        Get-RadarPolicyProperty `
            -InputObject $Assignment `
            -Name 'Override' |
            Where-Object { $null -ne $_ }
    )
    if ($overrides.Count -eq 0) {
        $overrides = @(
            Get-RadarPolicyProperty `
                -InputObject $Assignment `
                -Name 'Overrides' |
                Where-Object { $null -ne $_ }
        )
    }
    $overrideWarning = if ($overrides.Count -gt 0) {
        'Policy assignment overrides are present and are not statically evaluated.'
    }
    else {
        $null
    }

    $resourceSelectors = @(
        Get-RadarPolicyProperty `
            -InputObject $Assignment `
            -Name 'ResourceSelector' |
            Where-Object { $null -ne $_ }
    )
    if ($resourceSelectors.Count -eq 0) {
        $resourceSelectors = @(
            Get-RadarPolicyProperty `
                -InputObject $Assignment `
                -Name 'ResourceSelectors' |
                Where-Object { $null -ne $_ }
        )
    }
    $selectorWarning = if ($resourceSelectors.Count -gt 0) {
        'Policy assignment resource selectors are present and are not statically evaluated.'
    }
    else {
        $null
    }

    $definitionId = [string](
        Get-RadarPolicyProperty `
            -InputObject $Assignment `
            -Name 'PolicyDefinitionId'
    )
    if ([string]::IsNullOrWhiteSpace($definitionId)) {
        [void]$warnings.Add(
            "Policy assignment '$assignmentName' has no policyDefinitionId."
        )
        return [pscustomobject]@{
            Rules = @()
            Warnings = $warnings.ToArray()
        }
    }

    $assignedVersion = Get-RadarDefinitionVersion -InputObject $Assignment
    try {
        $assignedDefinition = Get-RadarPolicyDefinitionCached `
            -Id $definitionId `
            -DefinitionCache $DefinitionCache `
            -PolicySetCache $PolicySetCache `
            -Version $assignedVersion.Version
    }
    catch {
        [void]$warnings.Add(
            "Could not resolve policy definition '$definitionId' for assignment '$assignmentName': $($_.Exception.Message)"
        )
        return [pscustomobject]@{
            Rules = @()
            Warnings = $warnings.ToArray()
        }
    }

    $assignmentParameters = Get-RadarPolicyProperty `
        -InputObject $Assignment `
        -Name 'Parameter'
    if ($null -eq $assignmentParameters) {
        $assignmentParameters = Get-RadarPolicyProperty `
            -InputObject $Assignment `
            -Name 'Parameters'
    }

    $addRule = {
        param(
            [object]$Definition,
            [hashtable]$Parameters,
            [string]$ReferenceId,
            [string]$VersionWarning
        )

        $policyRule = Get-RadarPolicyProperty `
            -InputObject $Definition `
            -Name 'PolicyRule'
        $policyRule = ConvertFrom-RadarJsonObject -InputObject $policyRule
        if ($null -eq $policyRule) { return }

        $policyMode = [string](
            Get-RadarPolicyProperty `
                -InputObject $Definition `
                -Name 'Mode'
        )
        if ($policyMode -and $policyMode -ine 'All') {
            return
        }
        $modeWarning = if (-not $policyMode) {
            'Policy definition mode is unavailable, so role-assignment applicability cannot be proven.'
        }
        else {
            $null
        }

        $typeApplicability = Test-RadarPolicyTypeApplicability `
            -Condition (
                Get-RadarPropertyValue `
                    -InputObject $policyRule `
                    -Name 'If'
            ) `
            -Parameters $Parameters `
            -ResourceTypes $assignmentResourceTypes
        if ($typeApplicability -eq 'False') {
            return
        }

        $targetEvidence = [pscustomobject]@{
            Rule = $policyRule
            Parameters = $Parameters
        } | ConvertTo-Json -Depth 100 -Compress
        $scopeSensitive = $targetEvidence -match (
            '(?i)Microsoft\.Authorization/' +
            '(roleAssignments|roleAssignmentScheduleRequests|' +
            'roleEligibilityScheduleRequests)/scope'
        ) -or $targetEvidence -match '(?i)"field"\s*:\s*"id"' -or
            $targetEvidence -match (
                "(?i)field\(\s*['`"]id['`"]\s*\)"
            )
        $classificationWarning = $null
        if ($typeApplicability -eq 'Unknown') {
            $classificationWarning =
                'Policy resource-type targeting could not be resolved safely.'
        }
        if (
            $targetEvidence -notmatch
            '(?i)Microsoft\.Authorization/(roleAssignments|roleAssignmentScheduleRequests|roleEligibilityScheduleRequests)(?:/|["''])'
        ) {
            $probeRole = [pscustomobject]@{
                Id = '/providers/Microsoft.Authorization/roleDefinitions/00000000-0000-0000-0000-000000000000'
            }
            $probeResults = @(
                foreach ($assignmentResourceType in $assignmentResourceTypes) {
                    Test-RadarPolicyRuleForRole `
                        -PolicyRule $policyRule `
                        -Role $probeRole `
                        -Parameters $Parameters `
                        -AssignmentResourceType $assignmentResourceType
                }
            )
            $nonNotBlockedProbeCount = @(
                $probeResults |
                    Where-Object {
                        $_.State -ne 'NotBlocked'
                    }
            ).Count
            if ($nonNotBlockedProbeCount -eq 0) {
                return
            }
            if (
                @(
                    $probeResults |
                        Where-Object {
                            $_.State -eq 'Unknown'
                        }
                ).Count -gt 0
            ) {
                $classificationWarning =
                    'Policy targeting could not be ruled out safely for every supported role-assignment path.'
            }
        }

        $definitionName = [string](
            Get-RadarPolicyProperty `
                -InputObject $Definition `
                -Name 'DisplayName'
        )
        if ([string]::IsNullOrWhiteSpace($definitionName)) {
            $definitionName = [string](
                Get-RadarPolicyProperty `
                    -InputObject $Definition `
                    -Name 'Name'
            )
        }

        $unsupportedReasons = @(
            $overrideWarning,
            $selectorWarning,
            $VersionWarning,
            $modeWarning,
            $classificationWarning
        ) | Where-Object { -not [string]::IsNullOrWhiteSpace($_) }

        [void]$rules.Add([pscustomobject]@{
            AssignmentId = $assignmentId
            AssignmentName = $assignmentName
            AssignmentScope = $assignmentScope
            NotScopes = @($notScopes)
            DefinitionName = $definitionName
            ReferenceId = $ReferenceId
            PolicyRule = $policyRule
            Parameters = $Parameters
            ScopeSensitive = $scopeSensitive
            UnsupportedReason = $unsupportedReasons -join ' '
        })
    }

    if ($definitionId -match '(?i)/policySetDefinitions/') {
        $initiativeParameters = Get-RadarPolicyParameterMap `
            -DefinitionParameters (
                Get-RadarPolicyProperty `
                    -InputObject $assignedDefinition `
                    -Name 'Parameter'
            ) `
            -AssignedParameters $assignmentParameters

        $members = @(
            Get-RadarPolicyProperty `
                -InputObject $assignedDefinition `
                -Name 'PolicyDefinition' |
                Where-Object { $null -ne $_ }
        )
        if ($members.Count -eq 0) {
            $members = @(
                Get-RadarPolicyProperty `
                    -InputObject $assignedDefinition `
                    -Name 'PolicyDefinitions' |
                    Where-Object { $null -ne $_ }
            )
        }

        foreach ($member in $members) {
            $memberDefinitionId = [string](
                Get-RadarPropertyValue `
                    -InputObject $member `
                    -Name 'PolicyDefinitionId'
            )
            $memberVersion = Get-RadarDefinitionVersion `
                -InputObject $member
            if ($memberVersion.Warning) {
                [void]$warnings.Add(
                    "Initiative member '$memberDefinitionId' has no resolved effective definition version."
                )
                continue
            }
            $versionWarning = @(
                $assignedVersion.Warning,
                $memberVersion.Warning
            ) | Where-Object {
                -not [string]::IsNullOrWhiteSpace($_)
            }
            try {
                $memberDefinition = Get-RadarPolicyDefinitionCached `
                    -Id $memberDefinitionId `
                    -DefinitionCache $DefinitionCache `
                    -PolicySetCache $PolicySetCache `
                    -Version $memberVersion.Version
            }
            catch {
                [void]$warnings.Add(
                    "Could not resolve initiative member '$memberDefinitionId' for assignment '$assignmentName': $($_.Exception.Message)"
                )
                continue
            }

            $memberParameters = Get-RadarPropertyValue `
                -InputObject $member `
                -Name 'Parameters'
            if ($null -eq $memberParameters) {
                $memberParameters = Get-RadarPropertyValue `
                    -InputObject $member `
                    -Name 'Parameter'
            }
            $effectiveParameters = Get-RadarPolicyParameterMap `
                -DefinitionParameters (
                    Get-RadarPolicyProperty `
                        -InputObject $memberDefinition `
                        -Name 'Parameter'
                ) `
                -AssignedParameters $memberParameters `
                -ParentParameters $initiativeParameters

            & $addRule `
                $memberDefinition `
                $effectiveParameters `
                ([string](
                    Get-RadarPropertyValue `
                        -InputObject $member `
                        -Name 'PolicyDefinitionReferenceId'
                )) `
                ($versionWarning -join ' ')
        }
    }
    else {
        $effectiveParameters = Get-RadarPolicyParameterMap `
            -DefinitionParameters (
                Get-RadarPolicyProperty `
                    -InputObject $assignedDefinition `
                    -Name 'Parameter'
            ) `
            -AssignedParameters $assignmentParameters
        & $addRule `
            $assignedDefinition `
            $effectiveParameters `
            $null `
            $assignedVersion.Warning
    }

    [pscustomobject]@{
        Rules = $rules.ToArray()
        Warnings = $warnings.ToArray()
    }
}

function Get-RadarPolicyAssignmentAtScope {
    <#
    Lists effective assignments at one scope with effective definition versions
    expanded in the same request. This avoids one REST call per assignment on
    Az.Resources versions whose cmdlet cannot expand list results.
    #>
    param(
        [Parameter(Mandatory = $true)]
        [string]$Scope
    )

    if (Get-Command Invoke-AzRestMethod -ErrorAction SilentlyContinue) {
        try {
            $normalisedScope = $Scope.TrimEnd('/')
            if ([string]::IsNullOrWhiteSpace($normalisedScope)) {
                $normalisedScope = ''
            }
            $requestTarget = (
                $normalisedScope +
                '/providers/Microsoft.Authorization/policyAssignments' +
                '?api-version=2025-03-01' +
                '&$filter=atScope()' +
                '&$expand=EffectiveDefinitionVersion'
            )
            $results = New-Object System.Collections.Generic.List[object]
            while ($requestTarget) {
                $invokeParameters = @{
                    Method = 'GET'
                    ErrorAction = 'Stop'
                }
                if ($requestTarget -match '^https?://') {
                    $invokeParameters.Uri = $requestTarget
                }
                else {
                    $invokeParameters.Path = $requestTarget
                }
                $content = (
                    Invoke-AzRestMethod @invokeParameters
                ).Content | ConvertFrom-Json
                foreach ($assignment in @($content.value)) {
                    [void]$results.Add($assignment)
                }
                $requestTarget = [string](
                    Get-RadarPropertyValue `
                        -InputObject $content `
                        -Name 'NextLink'
                )
            }
            return $results.ToArray()
        }
        catch {
            Write-Verbose (
                "Expanded REST policy assignment list failed at ${Scope}: " +
                $_.Exception.Message +
                '. Falling back to Get-AzPolicyAssignment.'
            )
        }
    }

    return @(
        Get-AzPolicyAssignment `
            -Scope $Scope `
            -ErrorAction Stop `
            -WarningAction SilentlyContinue
    )
}

function Get-RadarPolicyInventory {
    param(
        [Parameter(Mandatory = $true)]
        [object[]]$Scopes,

        [switch]$NoPolicyDiscovery
    )

    $rulesByScope = @{}
    $exemptionsByScope = @{}
    foreach ($scope in $Scopes) {
        $rulesByScope[$scope.Id.ToLowerInvariant()] = @()
        $exemptionsByScope[$scope.Id.ToLowerInvariant()] = @()
    }

    if ($NoPolicyDiscovery) {
        return [pscustomobject]@{
            RulesByScope = $rulesByScope
            ExemptionsByScope = $exemptionsByScope
            AssignmentCount = 0
            RelevantRuleCount = 0
            ExemptionCount = 0
            IsEvaluated = $false
            IsComplete = $true
            UncertainScopes = @()
            Warnings = @()
        }
    }

    $definitionCache = @{}
    $policySetCache = @{}
    $resolvedAssignmentCache = @{}
    $assignmentByKey = @{}
    $assignmentKeysByScope = @{}
    $assignmentIds = New-Object System.Collections.Generic.HashSet[string] (
        [StringComparer]::OrdinalIgnoreCase
    )
    $exemptionIds = New-Object System.Collections.Generic.HashSet[string] (
        [StringComparer]::OrdinalIgnoreCase
    )
    $warnings = New-Object System.Collections.Generic.List[string]
    $uncertainScopes =
        New-Object System.Collections.Generic.HashSet[string] (
            [StringComparer]::OrdinalIgnoreCase
        )

    $scopeIndex = 0
    $nextProgress = 5
    $scopeTotal = @($Scopes).Count
    foreach ($scope in $Scopes) {
        $scopeIndex++
        if ($scopeTotal -gt 0) {
            $progressPercent = [math]::Floor(
                ($scopeIndex / $scopeTotal) * 100
            )
            Write-Progress `
                -Activity 'RADAR policy and exemption discovery' `
                -Status "$progressPercent% - $($scope.Id)" `
                -PercentComplete $progressPercent
            if ($progressPercent -ge $nextProgress) {
                Write-Host (
                    '  Policy discovery progress: {0}% ({1}/{2} scopes)' -f
                    $progressPercent,
                    $scopeIndex,
                    $scopeTotal
                )
                while ($nextProgress -le $progressPercent) {
                    $nextProgress += 5
                }
            }
        }
        $scopeKey = $scope.Id.TrimEnd('/').ToLowerInvariant()
        $assignmentKeysByScope[$scopeKey] = @()
        try {
            $assignments = @(
                Get-RadarPolicyAssignmentAtScope `
                    -Scope $scope.Id
            )
        }
        catch {
            [void]$uncertainScopes.Add($scopeKey)
            [void]$warnings.Add(
                "Policy-assignment discovery failed at $($scope.Id): $($_.Exception.Message)"
            )
            continue
        }

        $scopeAssignmentKeys =
            New-Object System.Collections.Generic.HashSet[string] (
                [StringComparer]::OrdinalIgnoreCase
            )
        foreach ($assignment in $assignments) {
            $version = Get-RadarDefinitionVersion -InputObject $assignment
            if ($version.Warning) {
                try {
                    $assignment =
                        Resolve-RadarPolicyAssignmentVersion `
                            -Assignment $assignment
                }
                catch {
                    [void]$uncertainScopes.Add($scopeKey)
                    [void]$warnings.Add(
                        "Could not resolve the effective definition version for an assignment at '$($scope.Id)': $($_.Exception.Message)"
                    )
                }
            }

            $assignmentKey = Get-RadarPolicyAssignmentKey `
                -Assignment $assignment
            [void]$assignmentIds.Add($assignmentKey)
            [void]$scopeAssignmentKeys.Add($assignmentKey)
            if (-not $assignmentByKey.ContainsKey($assignmentKey)) {
                $assignmentByKey[$assignmentKey] = $assignment
            }
        }
        $assignmentKeysByScope[$scopeKey] = @($scopeAssignmentKeys)

        try {
            $activeExemptions = New-Object System.Collections.Generic.List[object]
            $exemptionParameters = @{
                Scope = $scope.Id
                ErrorAction = 'Stop'
                WarningAction = 'SilentlyContinue'
            }
            foreach (
                $exemption in @(
                    Get-AzPolicyExemption @exemptionParameters
                )
            ) {
                $expiresOn = Get-RadarPolicyProperty `
                    -InputObject $exemption `
                    -Name 'ExpiresOn'
                if ($expiresOn) {
                    try {
                        if (
                            ([datetime]$expiresOn).ToUniversalTime() -le
                            [datetime]::UtcNow
                        ) {
                            continue
                        }
                    }
                    catch {
                        [void]$uncertainScopes.Add($scopeKey)
                        [void]$warnings.Add(
                            "Could not parse policy exemption expiry '$expiresOn' at $($scope.Id)."
                        )
                    }
                }

                $exemptionId = [string](
                    Get-RadarPolicyProperty `
                        -InputObject $exemption `
                        -Name 'Id'
                )
                if ([string]::IsNullOrWhiteSpace($exemptionId)) {
                    $exemptionId = "$($scope.Id)::$(
                        Get-RadarPolicyProperty `
                            -InputObject $exemption `
                            -Name 'Name'
                    )"
                }
                [void]$exemptionIds.Add($exemptionId)
                [void]$activeExemptions.Add($exemption)
            }
            $exemptionsByScope[$scope.Id.ToLowerInvariant()] =
                $activeExemptions.ToArray()
        }
        catch {
            [void]$uncertainScopes.Add($scopeKey)
            [void]$warnings.Add(
                "Policy-exemption discovery failed at $($scope.Id): $($_.Exception.Message)"
            )
        }
    }
    Write-Progress `
        -Activity 'RADAR policy and exemption discovery' `
        -Completed

    if ($Scopes.Count -ge 20 -and $assignmentByKey.Count -gt 0) {
        Write-Host (
            '  Preloading exact policy definitions for {0} unique assignment(s)...' -f
            $assignmentByKey.Count
        )
        Import-RadarPolicyDefinitionGraphCache `
            -Assignments @($assignmentByKey.Values) `
            -DefinitionCache $definitionCache `
            -PolicySetCache $policySetCache
    }

    $assignmentIndex = 0
    $nextResolutionProgress = 5
    foreach ($assignmentKey in $assignmentByKey.Keys) {
        $assignmentIndex++
        if (-not $resolvedAssignmentCache.ContainsKey($assignmentKey)) {
            $resolvedAssignmentCache[$assignmentKey] =
                Resolve-RadarPolicyAssignment `
                    -Assignment $assignmentByKey[$assignmentKey] `
                    -DefinitionCache $definitionCache `
                    -PolicySetCache $policySetCache
        }
        if ($assignmentByKey.Count -gt 0) {
            $resolutionPercent = [math]::Floor(
                ($assignmentIndex / $assignmentByKey.Count) * 100
            )
            Write-Progress `
                -Activity 'RADAR policy definition resolution' `
                -Status (
                    "$resolutionPercent% - $assignmentIndex/" +
                    $assignmentByKey.Count
                ) `
                -PercentComplete $resolutionPercent
            if ($resolutionPercent -ge $nextResolutionProgress) {
                Write-Host (
                    '  Policy resolution progress: {0}% ({1}/{2} assignments)' -f
                    $resolutionPercent,
                    $assignmentIndex,
                    $assignmentByKey.Count
                )
                while (
                    $nextResolutionProgress -le
                    $resolutionPercent
                ) {
                    $nextResolutionProgress += 5
                }
            }
        }
    }
    Write-Progress `
        -Activity 'RADAR policy definition resolution' `
        -Completed

    foreach ($scope in $Scopes) {
        $scopeKey = $scope.Id.TrimEnd('/').ToLowerInvariant()
        $scopeRules = New-Object System.Collections.Generic.List[object]
        foreach (
            $assignmentKey in @(
                $assignmentKeysByScope[$scopeKey]
            )
        ) {
            foreach (
                $warning in @(
                    $resolvedAssignmentCache[$assignmentKey].Warnings
                )
            ) {
                [void]$uncertainScopes.Add($scopeKey)
                [void]$warnings.Add(
                    "$($scope.Id): $warning"
                )
            }
            foreach (
                $resolvedRule in @(
                    $resolvedAssignmentCache[$assignmentKey].Rules
                )
            ) {
                [void]$scopeRules.Add($resolvedRule)
            }
        }
        $rulesByScope[$scopeKey] = $scopeRules.ToArray()
    }

    $uniqueRuleKeys = New-Object System.Collections.Generic.HashSet[string] (
        [StringComparer]::OrdinalIgnoreCase
    )
    foreach ($resolved in $resolvedAssignmentCache.Values) {
        foreach ($rule in @($resolved.Rules)) {
            [void]$uniqueRuleKeys.Add(
                "$($rule.AssignmentId)::$($rule.ReferenceId)::$($rule.DefinitionName)"
            )
        }
    }

    [pscustomobject]@{
        RulesByScope = $rulesByScope
        ExemptionsByScope = $exemptionsByScope
        AssignmentCount = $assignmentIds.Count
        RelevantRuleCount = $uniqueRuleKeys.Count
        ExemptionCount = $exemptionIds.Count
        IsEvaluated = $true
        IsComplete = $uncertainScopes.Count -eq 0
        UncertainScopes = @($uncertainScopes | Sort-Object)
        Warnings = @($warnings | Sort-Object -Unique)
    }
}

function Test-RadarPolicyRuleExempted {
    param(
        [object]$Rule,
        [object[]]$Exemptions
    )

    foreach ($exemption in @($Exemptions)) {
        $policyAssignmentId = [string](
            Get-RadarPolicyProperty `
                -InputObject $exemption `
                -Name 'PolicyAssignmentId'
        )
        if (
            -not [string]::Equals(
                $policyAssignmentId.TrimEnd('/'),
                ([string]$Rule.AssignmentId).TrimEnd('/'),
                [System.StringComparison]::OrdinalIgnoreCase
            )
        ) {
            continue
        }

        $referenceIds = @(
            Get-RadarPolicyProperty `
                -InputObject $exemption `
                -Name 'PolicyDefinitionReferenceId' |
                Where-Object { $null -ne $_ }
        )
        if ($referenceIds.Count -eq 0 -or -not $Rule.ReferenceId) {
            return $true
        }
        if (
            @(
                $referenceIds |
                    Where-Object {
                        [string]::Equals(
                            [string]$_,
                            [string]$Rule.ReferenceId,
                            [System.StringComparison]::OrdinalIgnoreCase
                        )
                    }
            ).Count -gt 0
        ) {
            return $true
        }
    }

    return $false
}

function Get-RadarPolicyScopeApplicability {
    param(
        [object]$Rule,
        [string]$Scope,
        [object]$ScopeHierarchy
    )

    foreach ($notScope in @($Rule.NotScopes)) {
        if ([string]::IsNullOrWhiteSpace([string]$notScope)) { continue }
        $normalisedNotScope = ([string]$notScope).TrimEnd('/')
        $normalisedScope = $Scope.TrimEnd('/')
        if (
            $normalisedNotScope -like
            '/providers/Microsoft.Management/managementGroups/*'
        ) {
            if (-not $ScopeHierarchy) {
                return [pscustomobject]@{
                    State = 'Unknown'
                    Reason = "Management-group exclusion '$notScope' could not be resolved without a scope hierarchy."
                }
            }
            $relationship = Test-RadarScopeDescendsFrom `
                -Scope $normalisedScope `
                -RootScope $normalisedNotScope `
                -Hierarchy $ScopeHierarchy
            if ($relationship.State -eq 'True') {
                return [pscustomobject]@{
                    State = 'Excluded'
                    Reason = "Scope is excluded by management-group notScopes entry '$notScope'."
                }
            }
            if ($relationship.State -eq 'Unknown') {
                return [pscustomobject]@{
                    State = 'Unknown'
                    Reason = $relationship.Reason
                }
            }
            continue
        }

        if (
            $normalisedScope -ieq $normalisedNotScope -or
            $normalisedScope.StartsWith(
                "$normalisedNotScope/",
                [System.StringComparison]::OrdinalIgnoreCase
            )
        ) {
            return [pscustomobject]@{
                State = 'Excluded'
                Reason = "Scope is excluded by notScopes entry '$notScope'."
            }
        }

    }

    return [pscustomobject]@{
        State = 'Applies'
        Reason = $null
    }
}

function Get-RadarRoleDenyCoverage {
    param(
        [Parameter(Mandatory = $true)]
        [object]$Role,

        [string[]]$RoleScopes,

        [Parameter(Mandatory = $true)]
        [object]$PolicyInventory,

        [System.Collections.Generic.HashSet[string]]$DeniedRoleNames,

        [bool]$DiscoveryComplete = $true,

        [object]$ScopeHierarchy,

        [object[]]$AssignmentPaths = @(),

        [string]$TargetPrincipalType = 'User',

        [string]$TargetPrincipalId =
            '__RADAR_NON_EXEMPT_PRINCIPAL__',

        [hashtable]$PolicyEvaluationCache
    )

    if ($null -eq $PolicyEvaluationCache) {
        $PolicyEvaluationCache = @{}
    }
    if (@($AssignmentPaths).Count -eq 0) {
        $AssignmentPaths = @(
            [pscustomobject]@{
                Name = 'Direct role assignment'
                ResourceType =
                    'Microsoft.Authorization/roleAssignments'
            },
            [pscustomobject]@{
                Name = 'PIM active assignment request'
                ResourceType =
                    'Microsoft.Authorization/roleAssignmentScheduleRequests'
            },
            [pscustomobject]@{
                Name = 'PIM eligible assignment request'
                ResourceType =
                    'Microsoft.Authorization/roleEligibilityScheduleRequests'
            }
        )
    }

    $roleName = [string](
        Get-RadarPropertyValue -InputObject $Role -Name 'Name'
    )
    $roleKey = Get-RadarRoleKey -Role $Role
    $uniqueRoleScopes = @($RoleScopes | Sort-Object -Unique)
    if (
        $DeniedRoleNames -and
        $DeniedRoleNames.Contains($roleName)
    ) {
        return [pscustomobject]@{
            Status = 'Full'
            IsAlreadyDenied = $true
            DeniedScopeCount = @($RoleScopes).Count
            ScopeCount = @($RoleScopes).Count
            BlockingPolicies = @('Denied-roles CSV supplement')
            EvaluatedPolicies = @('Denied-roles CSV supplement')
            DeniedScopes = @($RoleScopes)
            UnblockedScopes = @()
            UnblockedAssignmentPaths = @()
            UnknownReasons = @()
            ScopeEvaluations = @(
                foreach ($roleScope in $uniqueRoleScopes) {
                    [pscustomobject]@{
                        Scope = $roleScope
                        GapStatus = 'Covered'
                        BlockingPolicies = @(
                            'Denied-roles CSV supplement'
                        )
                        EvaluatedPolicies = @(
                            'Denied-roles CSV supplement'
                        )
                        BlockedAssignmentPaths = @(
                            $AssignmentPaths |
                                ForEach-Object { $_.Name }
                        )
                        UnblockedAssignmentPaths = @()
                        BaselineAssignablePaths = @()
                        ExternalAssignmentPaths = @()
                        UnknownBaselineAssignablePaths = @()
                        UnknownExternalAssignmentPaths = @()
                        UnknownReasons = @()
                    }
                }
            )
        }
    }

    if (-not $PolicyInventory.IsEvaluated) {
        return [pscustomobject]@{
            Status = 'NotEvaluated'
            IsAlreadyDenied = $false
            DeniedScopeCount = 0
            ScopeCount = @($RoleScopes).Count
            BlockingPolicies = @()
            EvaluatedPolicies = @()
            DeniedScopes = @()
            UnblockedScopes = @($RoleScopes)
            UnblockedAssignmentPaths = @(
                foreach ($roleScope in $RoleScopes) {
                    foreach ($assignmentPath in $AssignmentPaths) {
                        "$roleScope :: $($assignmentPath.Name)"
                    }
                }
            )
            UnknownReasons = @('Live policy discovery was disabled.')
            ScopeEvaluations = @(
                foreach ($roleScope in $uniqueRoleScopes) {
                    [pscustomobject]@{
                        Scope = $roleScope
                        GapStatus = 'NotEvaluated'
                        BlockingPolicies = @()
                        EvaluatedPolicies = @()
                        BlockedAssignmentPaths = @()
                        UnblockedAssignmentPaths = @(
                            $AssignmentPaths |
                                ForEach-Object { $_.Name }
                        )
                        BaselineAssignablePaths = @(
                            $AssignmentPaths |
                                Where-Object {
                                    (
                                        Get-RadarPropertyValue `
                                            -InputObject $_ `
                                            -Name 'Reachability'
                                    ) -like
                                        'Baseline role can create*'
                                } |
                                ForEach-Object { $_.Name }
                        )
                        ExternalAssignmentPaths = @(
                            $AssignmentPaths |
                                Where-Object {
                                    (
                                        Get-RadarPropertyValue `
                                            -InputObject $_ `
                                            -Name 'Reachability'
                                    ) -notlike
                                        'Baseline role can create*'
                                } |
                                ForEach-Object { $_.Name }
                        )
                        UnknownBaselineAssignablePaths = @(
                            $AssignmentPaths |
                                Where-Object {
                                    (
                                        Get-RadarPropertyValue `
                                            -InputObject $_ `
                                            -Name 'Reachability'
                                    ) -like
                                        'Baseline role can create*'
                                } |
                                ForEach-Object { $_.Name }
                        )
                        UnknownExternalAssignmentPaths = @(
                            $AssignmentPaths |
                                Where-Object {
                                    (
                                        Get-RadarPropertyValue `
                                            -InputObject $_ `
                                            -Name 'Reachability'
                                    ) -notlike
                                        'Baseline role can create*'
                                } |
                                ForEach-Object { $_.Name }
                        )
                        UnknownReasons = @(
                            'Live policy discovery was disabled.'
                        )
                    }
                }
            )
        }
    }

    $blockedScopeCount = 0
    $blockingPolicies =
        New-Object System.Collections.Generic.HashSet[string] (
            [StringComparer]::OrdinalIgnoreCase
        )
    $evaluatedPolicies =
        New-Object System.Collections.Generic.HashSet[string] (
            [StringComparer]::OrdinalIgnoreCase
        )
    $deniedScopes = New-Object System.Collections.Generic.List[string]
    $unblockedScopes = New-Object System.Collections.Generic.List[string]
    $unblockedAssignmentPaths =
        New-Object System.Collections.Generic.List[string]
    $unknownReasons = New-Object System.Collections.Generic.List[string]
    $scopeEvaluations =
        New-Object System.Collections.Generic.List[object]
    $policyUncertainScopes = @(
        Get-RadarPropertyValue `
            -InputObject $PolicyInventory `
            -Name 'UncertainScopes'
    )
    foreach ($roleScope in @($RoleScopes | Sort-Object -Unique)) {
        $scopeUnknown = $false
        $scopeBlockingPolicies =
            New-Object System.Collections.Generic.HashSet[string] (
                [StringComparer]::OrdinalIgnoreCase
            )
        $scopeEvaluatedPolicies =
            New-Object System.Collections.Generic.HashSet[string] (
                [StringComparer]::OrdinalIgnoreCase
            )
        $scopeBlockedPaths =
            New-Object System.Collections.Generic.List[string]
        $scopeUnblockedPaths =
            New-Object System.Collections.Generic.List[string]
        $scopeBaselineAssignablePaths =
            New-Object System.Collections.Generic.List[string]
        $scopeExternalAssignmentPaths =
            New-Object System.Collections.Generic.List[string]
        $scopeUnknownBaselineAssignablePaths =
            New-Object System.Collections.Generic.List[string]
        $scopeUnknownExternalAssignmentPaths =
            New-Object System.Collections.Generic.List[string]
        $scopeUnknownReasons =
            New-Object System.Collections.Generic.List[string]
        $normalisedRoleScope = $roleScope.TrimEnd('/')
        if ([string]::IsNullOrWhiteSpace($normalisedRoleScope)) {
            $normalisedRoleScope = '/'
        }
        $scopeKey = $normalisedRoleScope.ToLowerInvariant()
        if (
            $policyUncertainScopes -contains $scopeKey
        ) {
            $scopeUnknown = $true
            $reason =
                "Policy or exemption discovery was incomplete at '$roleScope'."
            [void]$unknownReasons.Add($reason)
            [void]$scopeUnknownReasons.Add($reason)
        }
        $rules = if ($PolicyInventory.RulesByScope.ContainsKey($scopeKey)) {
            @($PolicyInventory.RulesByScope[$scopeKey])
        }
        else {
            @()
        }
        $exemptions = if (
            $PolicyInventory.ExemptionsByScope.ContainsKey($scopeKey)
        ) {
            @($PolicyInventory.ExemptionsByScope[$scopeKey])
        }
        else {
            @()
        }

        $blockedPathCount = 0
        $unblockedPathCount = 0
        foreach ($assignmentPath in $AssignmentPaths) {
            $pathBlocked = $false
            $pathUnknown = $false
            foreach ($rule in $rules) {
                if (
                    Test-RadarPolicyRuleExempted `
                        -Rule $rule `
                        -Exemptions $exemptions
                ) {
                    continue
                }
                $applicability = Get-RadarPolicyScopeApplicability `
                    -Rule $rule `
                    -Scope $roleScope `
                    -ScopeHierarchy $ScopeHierarchy
                if ($applicability.State -eq 'Excluded') { continue }
                if ($applicability.State -eq 'Unknown') {
                    $pathUnknown = $true
                    $policyEvidence =
                        "$($rule.AssignmentName) [$($rule.AssignmentScope)] via $($assignmentPath.Name): Scope applicability unknown"
                    [void]$evaluatedPolicies.Add($policyEvidence)
                    [void]$scopeEvaluatedPolicies.Add(
                        $policyEvidence
                    )
                    $reason =
                        "$($rule.AssignmentName): $($applicability.Reason)"
                    [void]$unknownReasons.Add($reason)
                    [void]$scopeUnknownReasons.Add($reason)
                    continue
                }
                if ($rule.UnsupportedReason) {
                    $pathUnknown = $true
                    $policyEvidence =
                        "$($rule.AssignmentName) [$($rule.AssignmentScope)] via $($assignmentPath.Name): Evaluation unknown"
                    [void]$evaluatedPolicies.Add($policyEvidence)
                    [void]$scopeEvaluatedPolicies.Add(
                        $policyEvidence
                    )
                    $reason =
                        "$($rule.AssignmentName): $($rule.UnsupportedReason)"
                    [void]$unknownReasons.Add($reason)
                    [void]$scopeUnknownReasons.Add($reason)
                    continue
                }

                $ruleKey = @(
                    [string]$rule.AssignmentId,
                    [string]$rule.ReferenceId,
                    [string]$rule.DefinitionName
                ) -join [char]30
                $scopeSensitive = [bool](
                    Get-RadarPropertyValue `
                        -InputObject $rule `
                        -Name 'ScopeSensitive'
                )
                $evaluation = $null
                if ($scopeSensitive) {
                    $probeKey = @(
                        $roleKey,
                        $ruleKey,
                        [string]$assignmentPath.ResourceType,
                        $TargetPrincipalType,
                        $TargetPrincipalId,
                        'scope-probe'
                    ) -join [char]31
                    if (
                        -not $PolicyEvaluationCache.ContainsKey(
                            $probeKey
                        )
                    ) {
                        $PolicyEvaluationCache[$probeKey] =
                            Test-RadarPolicyRuleForRole `
                                -PolicyRule $rule.PolicyRule `
                                -Role $Role `
                                -Parameters $rule.Parameters `
                                -AssignmentResourceType (
                                    $assignmentPath.ResourceType
                                ) `
                                -TargetPrincipalType (
                                    $TargetPrincipalType
                                ) `
                                -TargetPrincipalId (
                                    $TargetPrincipalId
                                )
                    }
                    $probeEvaluation =
                        $PolicyEvaluationCache[$probeKey]
                    if ($probeEvaluation.State -ne 'Unknown') {
                        $evaluation = $probeEvaluation
                    }
                }

                if ($null -eq $evaluation) {
                    $scopeCacheKey = if (
                        $scopeSensitive
                    ) {
                        $roleScope.ToLowerInvariant()
                    }
                    else {
                        ''
                    }
                    $evaluationKey = @(
                        $roleKey,
                        $ruleKey,
                        [string]$assignmentPath.ResourceType,
                        $TargetPrincipalType,
                        $TargetPrincipalId,
                        $scopeCacheKey
                    ) -join [char]31
                    if (
                        -not $PolicyEvaluationCache.ContainsKey(
                            $evaluationKey
                        )
                    ) {
                        $PolicyEvaluationCache[$evaluationKey] =
                            Test-RadarPolicyRuleForRole `
                                -PolicyRule $rule.PolicyRule `
                                -Role $Role `
                                -Parameters $rule.Parameters `
                                -AssignmentResourceType (
                                    $assignmentPath.ResourceType
                                ) `
                                -AssignmentScope $roleScope `
                                -TargetPrincipalType (
                                    $TargetPrincipalType
                                ) `
                                -TargetPrincipalId (
                                    $TargetPrincipalId
                                )
                    }
                    $evaluation =
                        $PolicyEvaluationCache[$evaluationKey]
                }
                if ($evaluation.State -eq 'Blocked') {
                    $pathBlocked = $true
                    $policyEvidence =
                        "$($rule.AssignmentName) [$($rule.AssignmentScope)] via $($assignmentPath.Name)"
                    [void]$blockingPolicies.Add($policyEvidence)
                    [void]$scopeBlockingPolicies.Add($policyEvidence)
                    [void]$evaluatedPolicies.Add(
                        "${policyEvidence}: Blocked"
                    )
                    [void]$scopeEvaluatedPolicies.Add(
                        "${policyEvidence}: Blocked"
                    )
                }
                elseif ($evaluation.State -eq 'Unknown') {
                    $pathUnknown = $true
                    $policyEvidence =
                        "$($rule.AssignmentName) [$($rule.AssignmentScope)] via $($assignmentPath.Name): Evaluation unknown"
                    [void]$evaluatedPolicies.Add($policyEvidence)
                    [void]$scopeEvaluatedPolicies.Add(
                        $policyEvidence
                    )
                    $reason =
                        "$($rule.AssignmentName) via $($assignmentPath.Name): $($evaluation.Reason)"
                    [void]$unknownReasons.Add($reason)
                    [void]$scopeUnknownReasons.Add($reason)
                }
                else {
                    $policyEvidence =
                        "$($rule.AssignmentName) [$($rule.AssignmentScope)] via $($assignmentPath.Name): Permitted"
                    [void]$evaluatedPolicies.Add($policyEvidence)
                    [void]$scopeEvaluatedPolicies.Add(
                        $policyEvidence
                    )
                }
            }

            if ($pathBlocked) {
                $blockedPathCount++
                [void]$scopeBlockedPaths.Add(
                    $assignmentPath.Name
                )
            }
            elseif ($pathUnknown) {
                $scopeUnknown = $true
                $reachability = [string](
                    Get-RadarPropertyValue `
                        -InputObject $assignmentPath `
                        -Name 'Reachability'
                )
                if (
                    $reachability -like
                    'Baseline role can create*'
                ) {
                    [void]$scopeUnknownBaselineAssignablePaths.Add(
                        $assignmentPath.Name
                    )
                }
                else {
                    [void]$scopeUnknownExternalAssignmentPaths.Add(
                        $assignmentPath.Name
                    )
                }
                $reason =
                    "$($assignmentPath.Name) coverage at '$roleScope' is uncertain."
                [void]$unknownReasons.Add($reason)
                [void]$scopeUnknownReasons.Add($reason)
            }
            else {
                $unblockedPathCount++
                [void]$scopeUnblockedPaths.Add(
                    $assignmentPath.Name
                )
                $reachability = [string](
                    Get-RadarPropertyValue `
                        -InputObject $assignmentPath `
                        -Name 'Reachability'
                )
                if (
                    $reachability -like
                    'Baseline role can create*'
                ) {
                    [void]$scopeBaselineAssignablePaths.Add(
                        $assignmentPath.Name
                    )
                }
                else {
                    [void]$scopeExternalAssignmentPaths.Add(
                        $assignmentPath.Name
                    )
                }
                [void]$unblockedAssignmentPaths.Add(
                    "$roleScope :: $($assignmentPath.Name)"
                )
            }
        }

        if (
            $blockedPathCount -eq $AssignmentPaths.Count -and
            -not $scopeUnknown
        ) {
            $blockedScopeCount++
            [void]$deniedScopes.Add($roleScope)
        }
        else {
            [void]$unblockedScopes.Add($roleScope)
            if ($scopeUnknown -and $unblockedPathCount -eq 0) {
                $reason =
                    "Deny coverage at '$roleScope' is uncertain."
                [void]$unknownReasons.Add($reason)
                [void]$scopeUnknownReasons.Add($reason)
            }
        }

        $scopeGapStatus = if (
            $blockedPathCount -eq $AssignmentPaths.Count -and
            -not $scopeUnknown
        ) {
            'Covered'
        }
        elseif ($unblockedPathCount -gt 0) {
            'Gap'
        }
        else {
            'Unknown'
        }
        [void]$scopeEvaluations.Add([pscustomobject]@{
            Scope = $roleScope
            GapStatus = $scopeGapStatus
            BlockingPolicies = @(
                $scopeBlockingPolicies |
                    Sort-Object
            )
            EvaluatedPolicies = @(
                $scopeEvaluatedPolicies |
                    Sort-Object
            )
            BlockedAssignmentPaths = @(
                $scopeBlockedPaths |
                    Sort-Object -Unique
            )
            UnblockedAssignmentPaths = @(
                $scopeUnblockedPaths |
                    Sort-Object -Unique
            )
            BaselineAssignablePaths = @(
                $scopeBaselineAssignablePaths |
                    Sort-Object -Unique
            )
            ExternalAssignmentPaths = @(
                $scopeExternalAssignmentPaths |
                    Sort-Object -Unique
            )
            UnknownBaselineAssignablePaths = @(
                $scopeUnknownBaselineAssignablePaths |
                    Sort-Object -Unique
            )
            UnknownExternalAssignmentPaths = @(
                $scopeUnknownExternalAssignmentPaths |
                    Sort-Object -Unique
            )
            UnknownReasons = @(
                $scopeUnknownReasons |
                    Sort-Object -Unique
            )
        })
    }

    $scopeCount = $uniqueRoleScopes.Count
    $status = if ($scopeCount -eq 0) {
        'Unknown'
    }
    elseif ($blockedScopeCount -eq $scopeCount) {
        'Full'
    }
    elseif ($blockedScopeCount -gt 0) {
        'Partial'
    }
    elseif ($unknownReasons.Count -gt 0) {
        'Unknown'
    }
    else {
        'None'
    }
    if ($status -eq 'Full' -and -not $DiscoveryComplete) {
        $status = 'Unknown'
        $reason =
            'Discovery was incomplete, so full deny coverage cannot be proven.'
        [void]$unknownReasons.Add($reason)
        foreach ($scopeEvaluation in $scopeEvaluations) {
            if ($scopeEvaluation.GapStatus -eq 'Covered') {
                $scopeEvaluation.GapStatus = 'Unknown'
                $scopeEvaluation.UnknownReasons = @(
                    @($scopeEvaluation.UnknownReasons) +
                    $reason |
                        Sort-Object -Unique
                )
            }
        }
    }

    [pscustomobject]@{
        Status = $status
        IsAlreadyDenied = ($status -eq 'Full')
        DeniedScopeCount = $blockedScopeCount
        ScopeCount = $scopeCount
        BlockingPolicies = @($blockingPolicies | Sort-Object)
        EvaluatedPolicies = @($evaluatedPolicies | Sort-Object)
        DeniedScopes = @($deniedScopes | Sort-Object -Unique)
        UnblockedScopes = @($unblockedScopes | Sort-Object -Unique)
        UnblockedAssignmentPaths = @(
            $unblockedAssignmentPaths |
                Sort-Object -Unique
        )
        UnknownReasons = @($unknownReasons | Sort-Object -Unique)
        ScopeEvaluations = $scopeEvaluations.ToArray()
    }
}

function Update-RadarAnalysisProgress {
    param(
        [Parameter(Mandatory = $true)]
        [object]$State,
        [string]$CurrentContext
    )

    $State.Processed++
    if ($State.Total -le 0) { return }
    $percent = [math]::Min(
        100,
        [math]::Floor(($State.Processed / $State.Total) * 100)
    )
    Write-Progress `
        -Activity 'RADAR role/action gap evaluation' `
        -Status "$percent% - $CurrentContext" `
        -PercentComplete $percent

    if ($percent -lt $State.NextConsolePercent) { return }
    $elapsed = $State.Stopwatch.Elapsed
    $remaining = if (
        $State.Processed -gt 0 -and
        $State.Processed -lt $State.Total
    ) {
        [timespan]::FromTicks(
            [long](
                ($elapsed.Ticks / $State.Processed) *
                ($State.Total - $State.Processed)
            )
        )
    }
    else {
        [timespan]::Zero
    }
    Write-Host (
        '  Evaluation progress: {0}% ({1}/{2} role-context pairs, elapsed {3:hh\:mm\:ss}, estimated remaining {4:hh\:mm\:ss})' -f
        $percent,
        $State.Processed,
        $State.Total,
        $elapsed,
        $remaining
    )
    while ($State.NextConsolePercent -le $percent) {
        $State.NextConsolePercent += 5
    }
}

function Get-RadarCoverageCsvPath {
    param(
        [Parameter(Mandatory = $true)]
        [string]$MatchCsvPath
    )

    $directory = Split-Path -Parent $MatchCsvPath
    $fileName = (
        [System.IO.Path]::GetFileNameWithoutExtension($MatchCsvPath) +
        '-coverage.csv'
    )
    if ($directory) {
        return Join-Path $directory $fileName
    }
    return $fileName
}

function Get-RadarScopeMapCsvPath {
    param(
        [Parameter(Mandatory = $true)]
        [string]$MatchCsvPath
    )

    $directory = Split-Path -Parent $MatchCsvPath
    $fileName = (
        [System.IO.Path]::GetFileNameWithoutExtension($MatchCsvPath) +
        '-scope-map.csv'
    )
    if ($directory) {
        return Join-Path $directory $fileName
    }
    return $fileName
}

function Get-RadarScopeMapHtmlPath {
    param(
        [Parameter(Mandatory = $true)]
        [string]$ReportHtmlPath
    )

    $directory = Split-Path -Parent $ReportHtmlPath
    $fileName = (
        [System.IO.Path]::GetFileNameWithoutExtension(
            $ReportHtmlPath
        ) +
        '-scope-map.html'
    )
    if ($directory) {
        return Join-Path $directory $fileName
    }
    return $fileName
}

function Get-RadarControlGapMap {
    param(
        [AllowEmptyCollection()]
        [object[]]$Results,

        [hashtable]$ScopeById = @{},

        [object]$Hierarchy,

        [hashtable]$BaselineAssignmentEvidence = @{},

        [switch]$IncludeSubtreeControlEvidence
    )

    $groups =
        [System.Collections.Generic.Dictionary[string, object]]::new(
            [StringComparer]::OrdinalIgnoreCase
        )
    $postureEvidenceGroups =
        [System.Collections.Generic.Dictionary[string, object]]::new(
            [StringComparer]::OrdinalIgnoreCase
        )
    $newStringSet = {
        return ,(
            [System.Collections.Generic.HashSet[string]]::new(
                [StringComparer]::OrdinalIgnoreCase
            )
        )
    }
    $addValues = {
        param(
            [System.Collections.Generic.HashSet[string]]$Set,
            [object[]]$Values
        )
        foreach ($value in @($Values)) {
            if (
                -not [string]::IsNullOrWhiteSpace(
                    [string]$value
                )
            ) {
                [void]$Set.Add([string]$value)
            }
        }
    }
    foreach (
        $result in @(
            $Results |
                Where-Object {
                    $_.AnalysisMode -eq 'BaselineNotActions'
                }
        )
    ) {
        foreach (
            $scopeEvaluation in @(
                Get-RadarPropertyValue `
                    -InputObject $result `
                    -Name 'ScopeEvaluations'
            )
        ) {
            if ($null -eq $scopeEvaluation) { continue }
            $scopeId = [string](
                Get-RadarPropertyValue `
                    -InputObject $scopeEvaluation `
                    -Name 'Scope'
            )
            if ([string]::IsNullOrWhiteSpace($scopeId)) {
                continue
            }
            $scopeKey = $scopeId.TrimEnd('/').ToLowerInvariant()
            $scopeObject = if (
                $ScopeById.ContainsKey($scopeKey)
            ) {
                $ScopeById[$scopeKey]
            }
            else {
                New-RadarScope -Id $scopeId
            }
            $ancestorScopes = @()
            $ancestorLookupKey = $scopeKey
            if (
                $null -ne $Hierarchy -and
                -not $Hierarchy.AncestorsByScope.ContainsKey(
                    $ancestorLookupKey
                )
            ) {
                $subscriptionMatch = [regex]::Match(
                    $scopeId,
                    '(?i)^(/subscriptions/[^/]+)'
                )
                if ($subscriptionMatch.Success) {
                    $ancestorLookupKey =
                        $subscriptionMatch.Groups[1].Value.
                            ToLowerInvariant()
                }
            }
            if (
                $null -ne $Hierarchy -and
                $Hierarchy.AncestorsByScope.ContainsKey(
                    $ancestorLookupKey
                )
            ) {
                $ancestorScopes = @(
                    $Hierarchy.AncestorsByScope[
                        $ancestorLookupKey
                    ]
                )
            }
            if (
                $scopeObject.Type -notin @(
                    'ManagementGroup',
                    'Subscription'
                )
            ) {
                $subscriptionMatch = [regex]::Match(
                    $scopeId,
                    '(?i)^(/subscriptions/[^/]+)'
                )
                if (
                    $subscriptionMatch.Success -and
                    $ancestorScopes -notcontains
                        $subscriptionMatch.Groups[1].Value
                ) {
                    $ancestorScopes +=
                        $subscriptionMatch.Groups[1].Value
                }
            }
            $parentScope = if ($ancestorScopes.Count -gt 0) {
                [string]$ancestorScopes[-1]
            }
            else {
                ''
            }
            $parentScopeName = ''
            if (-not [string]::IsNullOrWhiteSpace($parentScope)) {
                $parentKey =
                    $parentScope.TrimEnd('/').ToLowerInvariant()
                $parentObject = if (
                    $ScopeById.ContainsKey($parentKey)
                ) {
                    $ScopeById[$parentKey]
                }
                else {
                    New-RadarScope -Id $parentScope
                }
                $parentScopeName = $parentObject.DisplayName
            }
            $roleLabel = if ($result.RoleId) {
                "$($result.RoleName) [$($result.RoleId)]"
            }
            else {
                [string]$result.RoleName
            }
            $blockedAssignmentPaths = @(
                Get-RadarPropertyValue `
                    -InputObject $scopeEvaluation `
                    -Name 'BlockedAssignmentPaths' |
                    Where-Object {
                        -not [string]::IsNullOrWhiteSpace(
                            [string]$_
                        )
                    }
            )
            if (
                $IncludeSubtreeControlEvidence -and
                $scopeObject.Type -notin @(
                    'ManagementGroup',
                    'Subscription'
                ) -and
                $blockedAssignmentPaths.Count -gt 0
            ) {
                $evidenceKey = @(
                    $result.BaselineRoleId,
                    $result.BaselineScope,
                    $scopeId,
                    $result.RestrictedAction
                ) -join [char]31
                if (
                    -not $postureEvidenceGroups.ContainsKey(
                        $evidenceKey
                    )
                ) {
                    $postureEvidenceGroups[$evidenceKey] =
                        [pscustomobject]@{
                            EvaluationScopeType =
                                $scopeObject.Type
                            EvaluationScopeName =
                                $scopeObject.DisplayName
                            EvaluationScope = $scopeId
                            AncestorScopes = @($ancestorScopes)
                            BaselineRoleName =
                                $result.BaselineRoleName
                            BaselineRoleId =
                                $result.BaselineRoleId
                            BaselineScope =
                                $result.BaselineScope
                            RestrictedAction =
                                $result.RestrictedAction
                            PolicyControlledRoles =
                                & $newStringSet
                        }
                }
                [void]$postureEvidenceGroups[
                    $evidenceKey
                ].PolicyControlledRoles.Add($roleLabel)
                continue
            }
            if (
                $scopeObject.Type -notin @(
                    'ManagementGroup',
                    'Subscription'
                )
            ) {
                continue
            }
            $groupKey = @(
                $result.BaselineRoleId,
                $result.BaselineScope,
                $scopeId,
                $result.RestrictedAction
            ) -join [char]31
            if (-not $groups.ContainsKey($groupKey)) {
                $assignmentEvidenceKey =
                    Get-RadarBaselineAssignmentEvidenceKey `
                        -BaselineRoleId $result.BaselineRoleId `
                        -BaselineScope $result.BaselineScope `
                        -EvaluationScope $scopeId
                $assignmentEvidence = if (
                    $BaselineAssignmentEvidence.ContainsKey(
                        $assignmentEvidenceKey
                    )
                ) {
                    $BaselineAssignmentEvidence[
                        $assignmentEvidenceKey
                    ]
                }
                else {
                    [pscustomobject]@{
                        State = 'AssignmentUnknown'
                        EffectiveDirectAssignmentCount = 0
                        PrincipalTypes = @()
                        AssignmentScopes = @()
                        Warnings = @(
                            'Direct baseline-role assignment evidence is unavailable.'
                        )
                    }
                }
                $groups[$groupKey] = [pscustomobject]@{
                    EvaluationScopeType =
                        $scopeObject.Type
                    EvaluationScopeName =
                        $scopeObject.DisplayName
                    EvaluationScope = $scopeId
                    ParentScopeName = $parentScopeName
                    ParentScope = $parentScope
                    AncestorScopes = @($ancestorScopes)
                    BaselineRoleName =
                        $result.BaselineRoleName
                    BaselineRoleId =
                        $result.BaselineRoleId
                    BaselineScope =
                        $result.BaselineScope
                    RestrictedAction =
                        $result.RestrictedAction
                    IntentSource =
                        "$($result.BaselineRoleName) NotActions"
                    BaselineAssignmentState =
                        $assignmentEvidence.State
                    EffectiveDirectAssignmentCount =
                        $assignmentEvidence.EffectiveDirectAssignmentCount
                    BaselinePrincipalTypes = @(
                        $assignmentEvidence.PrincipalTypes
                    )
                    BaselineAssignmentScopes = @(
                        $assignmentEvidence.AssignmentScopes
                    )
                    AssignmentWarnings = @(
                        $assignmentEvidence.Warnings
                    )
                    ConfirmedGapRoles = & $newStringSet
                    BaselineAssignableRoles = & $newStringSet
                    ExternalAssignmentRoles = & $newStringSet
                    UnknownBaselineAssignableRoles =
                        & $newStringSet
                    UnknownExternalAssignmentRoles =
                        & $newStringSet
                    UnknownRoles = & $newStringSet
                    CoveredRoles = & $newStringSet
                    PolicyControlledRoles = & $newStringSet
                    BlockingPolicies = & $newStringSet
                    UnblockedAssignmentPaths = & $newStringSet
                    CoverageWarnings = & $newStringSet
                }
            }
            $group = $groups[$groupKey]
            $gapStatus = [string](
                Get-RadarPropertyValue `
                    -InputObject $scopeEvaluation `
                    -Name 'GapStatus'
            )
            switch ($gapStatus) {
                'Gap' {
                    [void]$group.ConfirmedGapRoles.Add(
                        $roleLabel
                    )
                    $canBaselineAssign = @(
                        Get-RadarPropertyValue `
                            -InputObject $scopeEvaluation `
                            -Name 'BaselineAssignablePaths'
                    ).Count -gt 0
                    if ($canBaselineAssign) {
                        [void]$group.BaselineAssignableRoles.Add(
                            $roleLabel
                        )
                    }
                    $hasExternalPath = @(
                        Get-RadarPropertyValue `
                            -InputObject $scopeEvaluation `
                            -Name 'ExternalAssignmentPaths'
                    ).Count -gt 0
                    if ($hasExternalPath) {
                        [void]$group.ExternalAssignmentRoles.Add(
                            $roleLabel
                        )
                    }
                }
                'Covered' {
                    [void]$group.CoveredRoles.Add($roleLabel)
                }
                default {
                    [void]$group.UnknownRoles.Add($roleLabel)
                }
            }
            $unknownBaselinePaths = @(
                Get-RadarPropertyValue `
                    -InputObject $scopeEvaluation `
                    -Name 'UnknownBaselineAssignablePaths' |
                    Where-Object {
                        -not [string]::IsNullOrWhiteSpace(
                            [string]$_
                        )
                    }
            )
            if (
                $unknownBaselinePaths.Count -gt 0
            ) {
                [void]$group.UnknownBaselineAssignableRoles.Add(
                    $roleLabel
                )
            }
            $unknownExternalPaths = @(
                Get-RadarPropertyValue `
                    -InputObject $scopeEvaluation `
                    -Name 'UnknownExternalAssignmentPaths' |
                    Where-Object {
                        -not [string]::IsNullOrWhiteSpace(
                            [string]$_
                        )
                    }
            )
            if (
                $unknownExternalPaths.Count -gt 0
            ) {
                [void]$group.UnknownExternalAssignmentRoles.Add(
                    $roleLabel
                )
            }
            if ($blockedAssignmentPaths.Count -gt 0) {
                [void]$group.PolicyControlledRoles.Add(
                    $roleLabel
                )
            }
            & $addValues `
                $group.BlockingPolicies `
                @(
                    Get-RadarPropertyValue `
                        -InputObject $scopeEvaluation `
                        -Name 'BlockingPolicies'
                )
            & $addValues `
                $group.UnblockedAssignmentPaths `
                @(
                    Get-RadarPropertyValue `
                        -InputObject $scopeEvaluation `
                        -Name 'UnblockedAssignmentPaths'
                )
            & $addValues `
                $group.CoverageWarnings `
                @(
                    Get-RadarPropertyValue `
                        -InputObject $scopeEvaluation `
                        -Name 'UnknownReasons'
                )
        }
    }

    $mapRows = @(
        $groups.Values |
            ForEach-Object {
                $group = $_
                $gapRoles = @(
                    $group.ConfirmedGapRoles |
                        Sort-Object
                )
                $selfRoles = @(
                    $group.BaselineAssignableRoles |
                        Sort-Object
                )
                $externalRoles = @(
                    $group.ExternalAssignmentRoles |
                        Sort-Object
                )
                $unknownSelfRoles = @(
                    $group.UnknownBaselineAssignableRoles |
                        Sort-Object
                )
                $unknownExternalRoles = @(
                    $group.UnknownExternalAssignmentRoles |
                        Sort-Object
                )
                $unknownRoles = @(
                    $group.UnknownRoles |
                        Sort-Object
                )
                $coveredRoles = @(
                    $group.CoveredRoles |
                        Sort-Object
                )
                $policyControlledRoles = @(
                    $group.PolicyControlledRoles |
                        Sort-Object
                )
                $mapStatus = if ($gapRoles.Count -gt 0) {
                    'Gap'
                }
                elseif ($unknownRoles.Count -gt 0) {
                    'Unknown'
                }
                else {
                    'Covered'
                }
                $baselineAccessStatus = if ($selfRoles.Count -gt 0) {
                    switch ($group.BaselineAssignmentState) {
                        'DirectAssignmentObserved' {
                            'DirectAssignmentObserved'
                        }
                        'NoDirectAssignment' {
                            'BaselineCapable'
                        }
                        default { 'AssignmentUnknown' }
                    }
                }
                elseif ($unknownSelfRoles.Count -gt 0) {
                    'Unknown'
                }
                elseif ($externalRoles.Count -gt 0) {
                    'ExternalOnly'
                }
                elseif ($unknownRoles.Count -gt 0) {
                    'Unknown'
                }
                else {
                    'Covered'
                }

                [pscustomobject]@{
                    EvaluationScopeType =
                        $group.EvaluationScopeType
                    EvaluationScopeName =
                        $group.EvaluationScopeName
                    EvaluationScope =
                        $group.EvaluationScope
                    ParentScopeName =
                        $group.ParentScopeName
                    ParentScope =
                        $group.ParentScope
                    AncestorScopes = @(
                        $group.AncestorScopes
                    ) -join '; '
                    BaselineRoleName =
                        $group.BaselineRoleName
                    BaselineRoleId =
                        $group.BaselineRoleId
                    BaselineScope =
                        $group.BaselineScope
                    RestrictedAction =
                        $group.RestrictedAction
                    IntentSource =
                        $group.IntentSource
                    GapStatus = $mapStatus
                    BaselineAccessStatus =
                        $baselineAccessStatus
                    BaselineAssignmentState =
                        $group.BaselineAssignmentState
                    EffectiveDirectAssignmentCount =
                        $group.EffectiveDirectAssignmentCount
                    BaselinePrincipalTypes = @(
                        $group.BaselinePrincipalTypes |
                            Sort-Object -Unique
                    ) -join '; '
                    BaselineAssignmentScopes = @(
                        $group.BaselineAssignmentScopes |
                            Sort-Object -Unique
                    ) -join '; '
                    AssignmentWarnings = @(
                        $group.AssignmentWarnings |
                            Sort-Object -Unique
                    ) -join '; '
                    ConfirmedGapRoleCount = $gapRoles.Count
                    ConfirmedGapRoles = $gapRoles -join '; '
                    BaselineAssignableRoleCount =
                        $selfRoles.Count
                    BaselineAssignableRoles =
                        $selfRoles -join '; '
                    ExternalAssignmentRoleCount =
                        $externalRoles.Count
                    ExternalAssignmentRoles =
                        $externalRoles -join '; '
                    UnknownBaselineAssignableRoleCount =
                        $unknownSelfRoles.Count
                    UnknownBaselineAssignableRoles =
                        $unknownSelfRoles -join '; '
                    UnknownExternalAssignmentRoleCount =
                        $unknownExternalRoles.Count
                    UnknownExternalAssignmentRoles =
                        $unknownExternalRoles -join '; '
                    UnknownRoleCount = $unknownRoles.Count
                    UnknownRoles = $unknownRoles -join '; '
                    CoveredRoleCount = $coveredRoles.Count
                    CoveredRoles = $coveredRoles -join '; '
                    PolicyControlledRoleCount =
                        $policyControlledRoles.Count
                    PolicyControlledRoles =
                        $policyControlledRoles -join '; '
                    BlockingPolicies = @(
                        $group.BlockingPolicies |
                            Sort-Object -Unique
                    ) -join '; '
                    UnblockedAssignmentPaths = @(
                        $group.UnblockedAssignmentPaths |
                            Sort-Object -Unique
                    ) -join '; '
                    CoverageWarnings = @(
                        $group.CoverageWarnings |
                            Sort-Object -Unique
                    ) -join '; '
                }
            } |
            Sort-Object `
                EvaluationScopeType,
                AncestorScopes,
                ParentScope,
                EvaluationScopeName,
                BaselineRoleName,
                RestrictedAction
    )
    $postureEvidenceRows = @(
        $postureEvidenceGroups.Values |
            ForEach-Object {
                [pscustomobject]@{
                    PostureEvidenceOnly = $true
                    EvaluationScopeType =
                        $_.EvaluationScopeType
                    EvaluationScopeName =
                        $_.EvaluationScopeName
                    EvaluationScope =
                        $_.EvaluationScope
                    AncestorScopes = @(
                        $_.AncestorScopes
                    ) -join '; '
                    BaselineRoleName =
                        $_.BaselineRoleName
                    BaselineRoleId =
                        $_.BaselineRoleId
                    BaselineScope =
                        $_.BaselineScope
                    RestrictedAction =
                        $_.RestrictedAction
                    PolicyControlledRoles = @(
                        $_.PolicyControlledRoles |
                            Sort-Object
                    ) -join '; '
                }
            }
    )
    return @($mapRows) + @($postureEvidenceRows)
}

function Add-RadarSubtreeControlPosture {
    <#
    Adds a legacy-compatible remediation view to exact scope-map rows. A role
    available at a scope is treated as represented in that scope's subtree
    control configuration when any exact descendant row has policy evidence
    blocking at least one assignment path for that role.

    This intentionally describes configuration posture, not exact enforcement:
    descendant policy does not apply upwards to the parent scope.
    #>
    param(
        [AllowEmptyCollection()]
        [object[]]$Rows
    )

    $rowByKey =
        [System.Collections.Generic.Dictionary[string, object]]::new(
            [StringComparer]::OrdinalIgnoreCase
        )
    $controlledRolesByKey =
        [System.Collections.Generic.Dictionary[string, object]]::new(
            [StringComparer]::OrdinalIgnoreCase
        )
    $getKey = {
        param(
            [object]$Row,
            [string]$EvaluationScope
        )
        return @(
            [string](
                Get-RadarPropertyValue `
                    -InputObject $Row `
                    -Name 'BaselineRoleId'
            ),
            [string](
                Get-RadarPropertyValue `
                    -InputObject $Row `
                    -Name 'BaselineScope'
            ),
            $EvaluationScope.TrimEnd('/'),
            [string](
                Get-RadarPropertyValue `
                    -InputObject $Row `
                    -Name 'RestrictedAction'
            )
        ) -join [char]31
    }
    $splitValues = {
        param(
            [object]$Row,
            [string]$Property
        )
        return @(
            [string](
                Get-RadarPropertyValue `
                    -InputObject $Row `
                    -Name $Property
            ) -split '; ' |
                Where-Object {
                    -not [string]::IsNullOrWhiteSpace($_)
                }
        )
    }

    foreach ($row in $Rows) {
        if (
            [bool](
                Get-RadarPropertyValue `
                    -InputObject $row `
                    -Name 'PostureEvidenceOnly'
            )
        ) {
            continue
        }
        $scope = [string](
            Get-RadarPropertyValue `
                -InputObject $row `
                -Name 'EvaluationScope'
        )
        if ([string]::IsNullOrWhiteSpace($scope)) {
            continue
        }
        $rowByKey[(& $getKey $row $scope)] = $row
    }

    foreach ($row in $Rows) {
        $controlledRoles = @(
            & $splitValues $row 'PolicyControlledRoles'
        )
        if ($controlledRoles.Count -eq 0) { continue }
        $scope = [string](
            Get-RadarPropertyValue `
                -InputObject $row `
                -Name 'EvaluationScope'
        )
        $targetScopes = @(
            @($scope) +
            @(
                [string](
                    Get-RadarPropertyValue `
                        -InputObject $row `
                        -Name 'AncestorScopes'
                ) -split '; ' |
                    Where-Object {
                        -not [string]::IsNullOrWhiteSpace($_)
                    }
            ) |
                Sort-Object -Unique
        )
        foreach ($targetScope in $targetScopes) {
            $targetKey = & $getKey $row $targetScope
            if (-not $rowByKey.ContainsKey($targetKey)) {
                continue
            }
            if (-not $controlledRolesByKey.ContainsKey($targetKey)) {
                $controlledRolesByKey[$targetKey] =
                    [System.Collections.Generic.HashSet[string]]::new(
                        [StringComparer]::OrdinalIgnoreCase
                    )
            }
            foreach ($controlledRole in $controlledRoles) {
                [void]$controlledRolesByKey[$targetKey].Add(
                    $controlledRole
                )
            }
        }
    }

    foreach ($row in $Rows) {
        if (
            [bool](
                Get-RadarPropertyValue `
                    -InputObject $row `
                    -Name 'PostureEvidenceOnly'
            )
        ) {
            continue
        }
        $scope = [string](
            Get-RadarPropertyValue `
                -InputObject $row `
                -Name 'EvaluationScope'
        )
        $key = & $getKey $row $scope
        $availableRoles =
            [System.Collections.Generic.HashSet[string]]::new(
                [StringComparer]::OrdinalIgnoreCase
            )
        foreach (
            $property in @(
                'ConfirmedGapRoles',
                'UnknownRoles',
                'CoveredRoles'
            )
        ) {
            foreach ($role in @(& $splitValues $row $property)) {
                [void]$availableRoles.Add($role)
            }
        }
        $subtreeControlledRoles =
            New-Object System.Collections.Generic.List[string]
        $subtreeGapRoles =
            New-Object System.Collections.Generic.List[string]
        foreach ($role in $availableRoles) {
            if (
                $controlledRolesByKey.ContainsKey($key) -and
                $controlledRolesByKey[$key].Contains($role)
            ) {
                [void]$subtreeControlledRoles.Add($role)
            }
            else {
                [void]$subtreeGapRoles.Add($role)
            }
        }
        $status = if ($subtreeGapRoles.Count -gt 0) {
            'Gap'
        }
        else {
            'Covered'
        }
        $subtreeGapRoles.Sort(
            [StringComparer]::OrdinalIgnoreCase
        )
        $subtreeControlledRoles.Sort(
            [StringComparer]::OrdinalIgnoreCase
        )
        $propertyValues = @{
            SubtreeControlStatus = $status
            SubtreeGapRoleCount = $subtreeGapRoles.Count
            SubtreeGapRoles = $subtreeGapRoles -join '; '
            SubtreeControlledRoleCount =
                $subtreeControlledRoles.Count
            SubtreeControlledRoles =
                $subtreeControlledRoles -join '; '
        }
        foreach ($propertyName in $propertyValues.Keys) {
            $property = $row.PSObject.Properties[$propertyName]
            if ($null -ne $property) {
                $property.Value = $propertyValues[$propertyName]
            }
            else {
                $row.PSObject.Properties.Add(
                    [System.Management.Automation.PSNoteProperty]::new(
                        $propertyName,
                        $propertyValues[$propertyName]
                    )
                )
            }
        }
    }
    return @(
        $Rows |
            Where-Object {
                -not [bool](
                    Get-RadarPropertyValue `
                        -InputObject $_ `
                        -Name 'PostureEvidenceOnly'
                )
            }
    )
}

function Export-RadarControlGapMap {
    param(
        [AllowEmptyCollection()]
        [object[]]$Rows,

        [Parameter(Mandatory = $true)]
        [string]$Path
    )

    $suffix = ".tmp.$PID.$([guid]::NewGuid().ToString('N'))"
    $tempPath = "$Path$suffix"
    try {
        if (@($Rows).Count -gt 0) {
            $Rows |
                Select-Object `
                    EvaluationScopeType,
                    EvaluationScopeName,
                    EvaluationScope,
                    ParentScopeName,
                    ParentScope,
                    AncestorScopes,
                    BaselineRoleName,
                    BaselineRoleId,
                    BaselineScope,
                    RestrictedAction,
                    IntentSource,
                    PrincipalGapStatus,
                    NetNewGapActionCount,
                    NetNewGapPrincipalCount,
                    NetNewGapPrincipals,
                    NetNewGapRoleCount,
                    NetNewGapRoles,
                    NetNewGapPolicies,
                    NetNewGapPaths,
                    UnknownPrincipalCount,
                    UnknownPrincipalRowCount,
                    UnknownPrincipals,
                    MissingPrincipalCount,
                    MissingPrincipalRowCount,
                    MissingPrincipals,
                    PrincipalGapWarnings,
                    GapStatus,
                    BaselineAccessStatus,
                    BaselineAssignmentState,
                    EffectiveDirectAssignmentCount,
                    BaselinePrincipalTypes,
                    BaselineAssignmentScopes,
                    AssignmentWarnings,
                    ConfirmedGapRoleCount,
                    ConfirmedGapRoles,
                    BaselineAssignableRoleCount,
                    BaselineAssignableRoles,
                    ExternalAssignmentRoleCount,
                    ExternalAssignmentRoles,
                    UnknownBaselineAssignableRoleCount,
                    UnknownBaselineAssignableRoles,
                    UnknownExternalAssignmentRoleCount,
                    UnknownExternalAssignmentRoles,
                    UnknownRoleCount,
                    UnknownRoles,
                    CoveredRoleCount,
                    CoveredRoles,
                    PolicyControlledRoleCount,
                    PolicyControlledRoles,
                    SubtreeControlStatus,
                    SubtreeGapRoleCount,
                    SubtreeGapRoles,
                    SubtreeControlledRoleCount,
                    SubtreeControlledRoles,
                    BlockingPolicies,
                    UnblockedAssignmentPaths,
                    CoverageWarnings |
                Export-Csv `
                    -LiteralPath $tempPath `
                    -NoTypeInformation
        }
        else {
            Set-Content `
                -LiteralPath $tempPath `
                -Encoding UTF8 `
                -Value '"EvaluationScopeType","EvaluationScopeName","EvaluationScope","ParentScopeName","ParentScope","AncestorScopes","BaselineRoleName","BaselineRoleId","BaselineScope","RestrictedAction","IntentSource","PrincipalGapStatus","NetNewGapActionCount","NetNewGapPrincipalCount","NetNewGapPrincipals","NetNewGapRoleCount","NetNewGapRoles","NetNewGapPolicies","NetNewGapPaths","UnknownPrincipalCount","UnknownPrincipalRowCount","UnknownPrincipals","MissingPrincipalCount","MissingPrincipalRowCount","MissingPrincipals","PrincipalGapWarnings","GapStatus","BaselineAccessStatus","BaselineAssignmentState","EffectiveDirectAssignmentCount","BaselinePrincipalTypes","BaselineAssignmentScopes","AssignmentWarnings","ConfirmedGapRoleCount","ConfirmedGapRoles","BaselineAssignableRoleCount","BaselineAssignableRoles","ExternalAssignmentRoleCount","ExternalAssignmentRoles","UnknownBaselineAssignableRoleCount","UnknownBaselineAssignableRoles","UnknownExternalAssignmentRoleCount","UnknownExternalAssignmentRoles","UnknownRoleCount","UnknownRoles","CoveredRoleCount","CoveredRoles","PolicyControlledRoleCount","PolicyControlledRoles","SubtreeControlStatus","SubtreeGapRoleCount","SubtreeGapRoles","SubtreeControlledRoleCount","SubtreeControlledRoles","BlockingPolicies","UnblockedAssignmentPaths","CoverageWarnings"'
        }
        Move-Item `
            -LiteralPath $tempPath `
            -Destination $Path `
            -Force
    }
    finally {
        if (Test-Path -LiteralPath $tempPath) {
            Remove-Item -LiteralPath $tempPath -Force
        }
    }
}

function Resolve-RadarFileSystemPath {
    param(
        [Parameter(Mandatory = $true)]
        [string]$Path
    )

    return $ExecutionContext.SessionState.Path.
        GetUnresolvedProviderPathFromPSPath($Path)
}

function Test-RadarOwnedGenerationPath {
    param(
        [string]$CandidatePath,
        [string]$ReportPath
    )

    if (
        [string]::IsNullOrWhiteSpace($CandidatePath) -or
        [string]::IsNullOrWhiteSpace($ReportPath)
    ) {
        return $false
    }
    try {
        $candidateFull =
            Resolve-RadarFileSystemPath -Path $CandidatePath
        $reportFull =
            Resolve-RadarFileSystemPath -Path $ReportPath
    }
    catch {
        return $false
    }

    $pathComparison = if (
        [System.Environment]::OSVersion.Platform -eq
        [System.PlatformID]::Win32NT
    ) {
        [System.StringComparison]::OrdinalIgnoreCase
    }
    else {
        [System.StringComparison]::Ordinal
    }
    $sameDirectory = [string]::Equals(
        [System.IO.Path]::GetDirectoryName($candidateFull),
        [System.IO.Path]::GetDirectoryName($reportFull),
        $pathComparison
    )
    $expectedPrefix = (
        [System.IO.Path]::GetFileName($reportFull) +
        '.generation-'
    )
    $ownedName = [System.IO.Path]::GetFileName(
        $candidateFull
    ).StartsWith(
        $expectedPrefix,
        [System.StringComparison]::Ordinal
    )
    return $sameDirectory -and $ownedName
}

function Get-RadarCoverageKey {
    param(
        [string]$AnalysisMode,
        [string]$BaselineRoleId,
        [string]$BaselineScope,
        [string]$RoleId,
        [string]$AssignmentPath,
        [string[]]$AdditionalWarnings = @()
    )

    $identity = @(
        $AnalysisMode,
        $BaselineRoleId,
        $BaselineScope,
        $RoleId,
        $AssignmentPath,
        (@($AdditionalWarnings | Sort-Object -Unique) -join [char]30)
    ) -join [char]31
    $sha = [System.Security.Cryptography.SHA256]::Create()
    try {
        $hash = $sha.ComputeHash(
            [System.Text.Encoding]::UTF8.GetBytes($identity)
        )
    }
    finally {
        $sha.Dispose()
    }
    return 'CV-' + (
        [System.BitConverter]::ToString($hash).
            Replace('-', '').
            Substring(0, 16)
    )
}

function Get-RadarAssignmentPathCacheKey {
    param([object[]]$AssignmentPaths = @())

    return @(
        $AssignmentPaths |
            ForEach-Object {
                @(
                    [string](
                        Get-RadarPropertyValue `
                            -InputObject $_ `
                            -Name 'Name'
                    ),
                    [string](
                        Get-RadarPropertyValue `
                            -InputObject $_ `
                            -Name 'ResourceType'
                    ),
                    [string](
                        Get-RadarPropertyValue `
                            -InputObject $_ `
                            -Name 'Reachability'
                    )
                ) -join [char]30
            }
    ) -join [char]29
}

function Export-RadarCsvReports {
    param(
        [Parameter(Mandatory = $true)]
        [AllowEmptyCollection()]
        [object[]]$Results,

        [Parameter(Mandatory = $true)]
        [string]$MatchCsvPath,

        [Parameter(Mandatory = $true)]
        [string]$CoverageCsvPath
    )

    $generation = (
        (Get-Date).ToUniversalTime().ToString('yyyyMMddTHHmmssfffZ') +
        '-' +
        [guid]::NewGuid().ToString('N').Substring(0, 8)
    )
    $matchGeneration = "$MatchCsvPath.generation-$generation"
    $coverageGeneration =
        "$CoverageCsvPath.generation-$generation"
    $manifestPath = "$MatchCsvPath.manifest.json"
    $suffix = ".tmp.$PID.$([guid]::NewGuid().ToString('N'))"
    $manifestTemp = "$manifestPath$suffix"
    $matchTemp = "$MatchCsvPath$suffix"
    $coverageTemp = "$CoverageCsvPath$suffix"
    $published = $false
    $previousGenerationPaths = @()
    if (Test-Path -LiteralPath $manifestPath) {
        try {
            $previousManifest = (
                Get-Content -LiteralPath $manifestPath -Raw
            ) | ConvertFrom-Json
            $previousGenerationPaths = @()
            if (
                Test-RadarOwnedGenerationPath `
                    -CandidatePath $previousManifest.MatchCsv `
                    -ReportPath $MatchCsvPath
            ) {
                $previousGenerationPaths +=
                    [string]$previousManifest.MatchCsv
            }
            if (
                Test-RadarOwnedGenerationPath `
                    -CandidatePath $previousManifest.CoverageCsv `
                    -ReportPath $CoverageCsvPath
            ) {
                $previousGenerationPaths +=
                    [string]$previousManifest.CoverageCsv
            }
        }
        catch {
            $previousGenerationPaths = @()
        }
    }

    try {
        $matchRows = @(
            $Results |
            Select-Object `
                AnalysisMode,
                BaselineRoleName,
                BaselineRoleId,
                BaselineScope,
                RestrictionSource,
                AssignmentPath,
                RoleName,
                RoleId,
                IsCustom,
                RestrictedAction,
                MatchedPattern,
                CoverageKey,
                IsAlreadyDenied,
                DenyCoverage,
                DeniedScopeCount,
                EvaluatedScopeCount,
                BlockingPolicyCount,
                UnblockedScopeCount,
                UnblockedAssignmentPathCount,
                CoverageWarningCount
        )
        if ($matchRows.Count -gt 0) {
            $matchRows |
                Export-Csv `
                -LiteralPath $matchGeneration `
                -NoTypeInformation
        }
        else {
            Set-Content `
                -LiteralPath $matchGeneration `
                -Encoding UTF8 `
                -Value '"AnalysisMode","BaselineRoleName","BaselineRoleId","BaselineScope","RestrictionSource","AssignmentPath","RoleName","RoleId","IsCustom","RestrictedAction","MatchedPattern","CoverageKey","IsAlreadyDenied","DenyCoverage","DeniedScopeCount","EvaluatedScopeCount","BlockingPolicyCount","UnblockedScopeCount","UnblockedAssignmentPathCount","CoverageWarningCount"'
        }

        $coverageRows = @(
            $Results |
                Group-Object CoverageKey |
            ForEach-Object { $_.Group[0] } |
            Sort-Object CoverageKey |
            Select-Object `
                CoverageKey,
                AnalysisMode,
                BaselineRoleName,
                BaselineRoleId,
                BaselineScope,
                RoleName,
                RoleId,
                IsAlreadyDenied,
                DenyCoverage,
                DeniedScopeCount,
                EvaluatedScopeCount,
                BlockingPolicies,
                DeniedScopes,
                UnblockedScopes,
                UnblockedAssignmentPaths,
                CoverageWarnings
        )
        if ($coverageRows.Count -gt 0) {
            $coverageRows |
                Export-Csv `
                -LiteralPath $coverageGeneration `
                -NoTypeInformation
        }
        else {
            Set-Content `
                -LiteralPath $coverageGeneration `
                -Encoding UTF8 `
                -Value '"CoverageKey","AnalysisMode","BaselineRoleName","BaselineRoleId","BaselineScope","RoleName","RoleId","IsAlreadyDenied","DenyCoverage","DeniedScopeCount","EvaluatedScopeCount","BlockingPolicies","DeniedScopes","UnblockedScopes","UnblockedAssignmentPaths","CoverageWarnings"'
        }

        [pscustomobject]@{
            Generation = $generation
            MatchCsv = Resolve-RadarFileSystemPath `
                -Path $matchGeneration
            CoverageCsv =
                Resolve-RadarFileSystemPath `
                    -Path $coverageGeneration
            PublishedAt = (
                Get-Date
            ).ToUniversalTime().ToString('o')
        } |
            ConvertTo-Json |
            Set-Content `
                -LiteralPath $manifestTemp `
                -Encoding UTF8

        # The manifest is the atomic publication point for a consistent pair.
        Move-Item `
            -LiteralPath $manifestTemp `
            -Destination $manifestPath `
            -Force
        $published = $true

        # Conventional filenames remain convenient after successful runs. If
        # interrupted here, the manifest still points to a consistent pair.
        Copy-Item `
            -LiteralPath $coverageGeneration `
            -Destination $coverageTemp `
            -Force
        Copy-Item `
            -LiteralPath $matchGeneration `
            -Destination $matchTemp `
            -Force
        Move-Item `
            -LiteralPath $coverageTemp `
            -Destination $CoverageCsvPath `
            -Force
        Move-Item `
            -LiteralPath $matchTemp `
            -Destination $MatchCsvPath `
            -Force

        foreach ($previousPath in $previousGenerationPaths) {
            if (
                $previousPath -and
                $previousPath -notin @(
                    $matchGeneration,
                    $coverageGeneration
                ) -and
                (Test-Path -LiteralPath $previousPath)
            ) {
                Remove-Item -LiteralPath $previousPath -Force
            }
        }
    }
    finally {
        foreach (
            $tempPath in @(
                $manifestTemp,
                $matchTemp,
                $coverageTemp
            )
        ) {
            if (Test-Path -LiteralPath $tempPath) {
                Remove-Item -LiteralPath $tempPath -Force
            }
        }
        if (-not $published) {
            foreach (
                $generationPath in @(
                    $matchGeneration,
                    $coverageGeneration
                )
            ) {
                if (Test-Path -LiteralPath $generationPath) {
                    Remove-Item `
                        -LiteralPath $generationPath `
                        -Force
                }
            }
        }
    }
}

function Remove-RadarCsvReportSet {
    param(
        [string]$MatchCsvPath,
        [string]$CoverageCsvPath
    )

    $manifestPath = "$MatchCsvPath.manifest.json"
    $generationPaths = @()
    if (Test-Path -LiteralPath $manifestPath) {
        try {
            $manifest = (
                Get-Content -LiteralPath $manifestPath -Raw
            ) | ConvertFrom-Json
            if (
                Test-RadarOwnedGenerationPath `
                    -CandidatePath $manifest.MatchCsv `
                    -ReportPath $MatchCsvPath
            ) {
                $generationPaths += [string]$manifest.MatchCsv
            }
            if (
                Test-RadarOwnedGenerationPath `
                    -CandidatePath $manifest.CoverageCsv `
                    -ReportPath $CoverageCsvPath
            ) {
                $generationPaths += [string]$manifest.CoverageCsv
            }
        }
        catch {
            $generationPaths = @()
        }
    }
    foreach (
        $path in @(
            $MatchCsvPath,
            $CoverageCsvPath,
            $manifestPath,
            @($generationPaths)
        )
    ) {
        if ($path -and (Test-Path -LiteralPath $path)) {
            Remove-Item -LiteralPath $path -Force
        }
    }
}

function Get-RadarReportHealthWarning {
    param(
        [AllowEmptyCollection()]
        [object[]]$Results
    )

    $targets = @(
        $Results |
            Group-Object {
                "$($_.AnalysisMode)$([char]31)$($_.BaselineRoleId)$([char]31)$($_.BaselineScope)$([char]31)$($_.RoleId)"
            } |
            ForEach-Object { $_.Group[0] }
    )
    if ($targets.Count -eq 0) { return $null }

    $uncertainCount = @(
        $targets |
            Where-Object {
                $_.DenyCoverage -in @('Unknown', 'NotEvaluated')
            }
    ).Count
    if ($uncertainCount -eq $targets.Count) {
        return (
            'Every baseline/role pair has uncertain policy coverage. ' +
            'The files are structurally valid but the report is not ' +
            'operationally actionable; review discovery and coverage ' +
            'warnings before using it for remediation.'
        )
    }

    return $null
}

# --- Principal correlation helpers -------------------------------------

function Get-RadarPrincipalScopeAssignmentKey {
    param(
        [string]$PrincipalId,
        [string]$Scope
    )

    $normalisedScope = ([string]$Scope).TrimEnd('/').ToLowerInvariant()
    if ([string]::IsNullOrWhiteSpace($normalisedScope)) {
        $normalisedScope = '/'
    }
    return @(
        ([string]$PrincipalId).ToLowerInvariant(),
        $normalisedScope
    ) -join [char]31
}

function New-RadarPrincipalScopeAssignmentIndex {
    param([object[]]$Assignments = @())

    $index = @{}
    foreach ($assignment in $Assignments) {
        $principalId = [string](
            Get-RadarPropertyValue `
                -InputObject $assignment `
                -Name 'PrincipalId'
        )
        $assignmentScope = [string](
            Get-RadarPropertyValue `
                -InputObject $assignment `
                -Name 'AssignmentScope'
        )
        if (
            [string]::IsNullOrWhiteSpace($principalId) -or
            [string]::IsNullOrWhiteSpace($assignmentScope)
        ) {
            continue
        }
        $key = Get-RadarPrincipalScopeAssignmentKey `
            -PrincipalId $principalId `
            -Scope $assignmentScope
        if (-not $index.ContainsKey($key)) {
            $index[$key] =
                New-Object System.Collections.Generic.List[object]
        }
        [void]$index[$key].Add($assignment)
    }
    return $index
}

function ConvertFrom-RadarSecureToken {
    param([object]$Token)

    if ($Token -isnot [System.Security.SecureString]) {
        return [string]$Token
    }
    $pointer = [Runtime.InteropServices.Marshal]::SecureStringToBSTR(
        $Token
    )
    try {
        return [Runtime.InteropServices.Marshal]::PtrToStringBSTR(
            $pointer
        )
    }
    finally {
        [Runtime.InteropServices.Marshal]::ZeroFreeBSTR($pointer)
    }
}

function Get-RadarPrincipalDirectoryEvidence {
    <#
    Resolves account enabled state and transitive group IDs for supported
    source-role holders through bounded Microsoft Graph JSON batches. Graph
    pagination is re-queued into subsequent batches rather than serialised per
    principal.
    #>
    param(
        [object]$BaselineAssignmentInventory,
        [int]$GraphBatchSize = 20,
        [switch]$NoPrincipalCorrelation
    )

    $evidenceByPrincipal = @{}
    $warnings = New-Object System.Collections.Generic.List[string]
    if ($NoPrincipalCorrelation) {
        return [pscustomobject]@{
            IsEvaluated = $false
            IsComplete = $false
            EvidenceByPrincipal = @{}
            GroupIds = @()
            Warnings = @(
                'Microsoft Graph directory correlation was disabled with principal correlation.'
            )
            Source = 'Disabled'
        }
    }
    $newPrincipalEvidence = {
        param(
            [string]$PrincipalId,
            [string]$PrincipalType
        )

        return [pscustomobject]@{
            PrincipalId = $PrincipalId
            PrincipalType = $PrincipalType
            DirectoryObjectState = 'Unknown'
            AccountEnabled = $null
            GroupIds =
                New-Object System.Collections.Generic.HashSet[string] (
                    [StringComparer]::OrdinalIgnoreCase
                )
            SourceGroupIds =
                New-Object System.Collections.Generic.HashSet[string] (
                    [StringComparer]::OrdinalIgnoreCase
                )
            MemberIds =
                New-Object System.Collections.Generic.HashSet[string] (
                    [StringComparer]::OrdinalIgnoreCase
                )
            ObjectEvidenceComplete = $false
            MembershipEvidenceComplete = $false
            UserMemberEvidenceComplete = $false
            ServicePrincipalMemberEvidenceComplete = $false
            IsComplete = $false
            Warnings =
                New-Object System.Collections.Generic.List[string]
        }
    }
    foreach (
        $assignment in @(
            $BaselineAssignmentInventory.Assignments |
                Where-Object {
                    [string]$_.PrincipalType -in @(
                        'User',
                        'ServicePrincipal',
                        'Group'
                    ) -and
                    -not [string]::IsNullOrWhiteSpace(
                        [string]$_.PrincipalId
                    )
                }
        )
    ) {
        $principalId = [string]$assignment.PrincipalId
        $key = $principalId.ToLowerInvariant()
        if ($evidenceByPrincipal.ContainsKey($key)) { continue }
        $evidenceByPrincipal[$key] = & $newPrincipalEvidence `
            -PrincipalId $principalId `
            -PrincipalType ([string]$assignment.PrincipalType)
    }
    if ($evidenceByPrincipal.Count -eq 0) {
        return [pscustomobject]@{
            IsEvaluated = $true
            IsComplete = [bool]$BaselineAssignmentInventory.IsComplete
            EvidenceByPrincipal = @{}
            GroupIds = @()
            Warnings = @($BaselineAssignmentInventory.Warnings)
            Source = 'Not required'
        }
    }
    $GraphBatchSize = [math]::Max(1, [math]::Min(20, $GraphBatchSize))

    try {
        $tokenResponse = Get-AzAccessToken `
            -ResourceUrl 'https://graph.microsoft.com/' `
            -ErrorAction Stop `
            -WarningAction SilentlyContinue
        $token = ConvertFrom-RadarSecureToken `
            -Token (
                Get-RadarPropertyValue `
                    -InputObject $tokenResponse `
                    -Name 'Token'
            )
        if ([string]::IsNullOrWhiteSpace($token)) {
            throw 'Microsoft Graph access token was empty.'
        }
    }
    catch {
        $warning =
            "Microsoft Graph directory evidence is unavailable: $($_.Exception.Message)"
        [void]$warnings.Add($warning)
        foreach ($evidence in $evidenceByPrincipal.Values) {
            [void]$evidence.Warnings.Add($warning)
        }
        return [pscustomobject]@{
            IsEvaluated = $false
            IsComplete = $false
            EvidenceByPrincipal = $evidenceByPrincipal
            GroupIds = @()
            Warnings = $warnings.ToArray()
            Source = 'Microsoft Graph'
        }
    }

    $pending = New-Object System.Collections.Generic.Queue[object]
    $queuedRequestKeys =
        New-Object System.Collections.Generic.HashSet[string] (
            [StringComparer]::OrdinalIgnoreCase
        )
    $enqueueRequest = {
        param(
            [string]$PrincipalKey,
            [string]$Kind,
            [string]$Url
        )

        $requestKey = @(
            $PrincipalKey,
            $Kind,
            $Url
        ) -join [char]31
        if ($queuedRequestKeys.Add($requestKey)) {
            $pending.Enqueue([pscustomobject]@{
                PrincipalKey = $PrincipalKey
                Kind = $Kind
                Url = $Url
            })
        }
    }
    $requestSequence = 0
    foreach ($evidence in $evidenceByPrincipal.Values) {
        if ($evidence.PrincipalType -eq 'Group') {
            foreach (
                $request in @(
                    [pscustomobject]@{
                        Kind = 'Object'
                        Url = "/groups/$($evidence.PrincipalId)?`$select=id"
                    },
                    [pscustomobject]@{
                        Kind = 'GroupUsers'
                        Url = "/groups/$($evidence.PrincipalId)/transitiveMembers/microsoft.graph.user?`$select=id,accountEnabled&`$count=true&`$top=999"
                    },
                    [pscustomobject]@{
                        Kind = 'GroupServicePrincipals'
                        Url = "/groups/$($evidence.PrincipalId)/transitiveMembers/microsoft.graph.servicePrincipal?`$select=id,accountEnabled&`$count=true&`$top=999"
                    }
                )
            ) {
                & $enqueueRequest `
                    -PrincipalKey $evidence.PrincipalId.ToLowerInvariant() `
                    -Kind $request.Kind `
                    -Url $request.Url
            }
            continue
        }

        $entitySet = if (
            $evidence.PrincipalType -eq 'ServicePrincipal'
        ) {
            'servicePrincipals'
        }
        else {
            'users'
        }
        foreach (
            $request in @(
                [pscustomobject]@{
                    Kind = 'Object'
                    Url = "/$entitySet/$($evidence.PrincipalId)?`$select=id,accountEnabled"
                },
                [pscustomobject]@{
                    Kind = 'Groups'
                    Url = "/$entitySet/$($evidence.PrincipalId)/transitiveMemberOf/microsoft.graph.group?`$select=id&`$count=true&`$top=999"
                }
            )
        ) {
            & $enqueueRequest `
                -PrincipalKey $evidence.PrincipalId.ToLowerInvariant() `
                -Kind $request.Kind `
                -Url $request.Url
        }
    }

    $processedRequestCount = 0
    while ($pending.Count -gt 0) {
        $batchRequests = New-Object System.Collections.Generic.List[object]
        $requestById = @{}
        while (
            $pending.Count -gt 0 -and
            $batchRequests.Count -lt $GraphBatchSize
        ) {
            $request = $pending.Dequeue()
            $requestSequence++
            $batchId = [string]$requestSequence
            $requestById[$batchId] = $request
            $batchRequest = [ordered]@{
                id = $batchId
                method = 'GET'
                url = $request.Url
            }
            if (
                $request.Kind -in @(
                    'Groups',
                    'GroupUsers',
                    'GroupServicePrincipals'
                )
            ) {
                $batchRequest.headers = @{
                    ConsistencyLevel = 'eventual'
                }
            }
            [void]$batchRequests.Add($batchRequest)
        }
        $processedRequestCount += $batchRequests.Count
        if ($processedRequestCount -gt 100000) {
            [void]$warnings.Add(
                'Microsoft Graph directory pagination exceeded the safety limit.'
            )
            break
        }
        try {
            $batchResponse = Invoke-RestMethod `
                -Method Post `
                -Uri 'https://graph.microsoft.com/v1.0/$batch' `
                -Headers @{ Authorization = "Bearer $token" } `
                -ContentType 'application/json' `
                -Body (
                    @{ requests = $batchRequests.ToArray() } |
                        ConvertTo-Json -Depth 8 -Compress
                ) `
                -ErrorAction Stop
        }
        catch {
            $warning =
                "Microsoft Graph directory batch failed: $($_.Exception.Message)"
            [void]$warnings.Add($warning)
            foreach ($request in $requestById.Values) {
                [void]$evidenceByPrincipal[
                    $request.PrincipalKey
                ].Warnings.Add($warning)
            }
            continue
        }
        $orderedResponses = @(
            @($batchResponse.responses) |
                Sort-Object {
                    $responseId = [string]$_.id
                    if (
                        $requestById.ContainsKey($responseId) -and
                        $requestById[$responseId].Kind -eq 'Object'
                    ) {
                        0
                    }
                    else {
                        1
                    }
                }
        )
        foreach ($response in $orderedResponses) {
            $responseId = [string]$response.id
            if (-not $requestById.ContainsKey($responseId)) {
                continue
            }
            $request = $requestById[$responseId]
            $evidence =
                $evidenceByPrincipal[$request.PrincipalKey]
            if (
                $evidence.DirectoryObjectState -eq 'Missing' -and
                $request.Kind -ne 'Object'
            ) {
                continue
            }
            $statusCode = [int]$response.status
            if ($statusCode -lt 200 -or $statusCode -ge 300) {
                if (
                    $request.Kind -eq 'Object' -and
                    $statusCode -eq 404
                ) {
                    $evidence.DirectoryObjectState = 'Missing'
                    $evidence.ObjectEvidenceComplete = $true
                    $evidence.MembershipEvidenceComplete = $true
                    $evidence.UserMemberEvidenceComplete = $true
                    $evidence.ServicePrincipalMemberEvidenceComplete =
                        $true
                    [void]$evidence.Warnings.Add(
                        'Microsoft Graph directory object was not found (HTTP 404).'
                    )
                    continue
                }
                $warning =
                    "Microsoft Graph $($request.Kind.ToLowerInvariant()) evidence returned HTTP $statusCode."
                [void]$warnings.Add($warning)
                [void]$evidence.Warnings.Add($warning)
                continue
            }
            if ($request.Kind -eq 'Object') {
                $evidence.DirectoryObjectState = 'Present'
                if ($evidence.PrincipalType -eq 'Group') {
                    $evidence.ObjectEvidenceComplete = $true
                    continue
                }
                $enabled = Get-RadarPropertyValue `
                    -InputObject $response.body `
                    -Name 'accountEnabled'
                if ($null -eq $enabled) {
                    [void]$evidence.Warnings.Add(
                        'Microsoft Graph did not return accountEnabled.'
                    )
                }
                else {
                    $evidence.AccountEnabled = [bool]$enabled
                    $evidence.ObjectEvidenceComplete = $true
                }
                continue
            }
            if (
                $request.Kind -in @(
                    'GroupUsers',
                    'GroupServicePrincipals'
                )
            ) {
                $memberType = if (
                    $request.Kind -eq 'GroupUsers'
                ) {
                    'User'
                }
                else {
                    'ServicePrincipal'
                }
                foreach (
                    $member in @(
                        Get-RadarPropertyValue `
                            -InputObject $response.body `
                            -Name 'value'
                    )
                ) {
                    $memberId = [string](
                        Get-RadarPropertyValue `
                            -InputObject $member `
                            -Name 'id'
                    )
                    if ([string]::IsNullOrWhiteSpace($memberId)) {
                        [void]$evidence.Warnings.Add(
                            'Microsoft Graph returned a group member without an object ID.'
                        )
                        continue
                    }
                    $memberKey = $memberId.ToLowerInvariant()
                    if (-not $evidenceByPrincipal.ContainsKey($memberKey)) {
                        $evidenceByPrincipal[$memberKey] =
                            & $newPrincipalEvidence `
                                -PrincipalId $memberId `
                                -PrincipalType $memberType
                    }
                    $memberEvidence =
                        $evidenceByPrincipal[$memberKey]
                    if (
                        $memberEvidence.PrincipalType -ne $memberType
                    ) {
                        [void]$memberEvidence.Warnings.Add(
                            'Microsoft Graph returned conflicting directory object types.'
                        )
                    }
                    [void]$evidence.MemberIds.Add($memberId)
                    [void]$memberEvidence.SourceGroupIds.Add(
                        $evidence.PrincipalId
                    )
                    $enabled = Get-RadarPropertyValue `
                        -InputObject $member `
                        -Name 'accountEnabled'
                    if (
                        $memberEvidence.DirectoryObjectState -eq
                            'Missing'
                    ) {
                        continue
                    }
                    elseif ($null -ne $enabled) {
                        $memberEvidence.DirectoryObjectState =
                            'Present'
                        $memberEvidence.AccountEnabled =
                            [bool]$enabled
                        $memberEvidence.ObjectEvidenceComplete =
                            $true
                    }
                    else {
                        [void]$memberEvidence.Warnings.Add(
                            'Microsoft Graph did not return accountEnabled for a group member.'
                        )
                    }
                    $entitySet = if (
                        $memberType -eq 'User'
                    ) {
                        'users'
                    }
                    else {
                        'servicePrincipals'
                    }
                    if ($null -eq $enabled) {
                        & $enqueueRequest `
                            -PrincipalKey $memberKey `
                            -Kind 'Object' `
                            -Url "/$entitySet/$($memberId)?`$select=id,accountEnabled"
                    }
                    & $enqueueRequest `
                        -PrincipalKey $memberKey `
                        -Kind 'Groups' `
                        -Url "/$entitySet/$memberId/transitiveMemberOf/microsoft.graph.group?`$select=id&`$count=true&`$top=999"
                }
                $nextLink = [string](
                    Get-RadarPropertyValue `
                        -InputObject $response.body `
                        -Name '@odata.nextLink'
                )
                if ([string]::IsNullOrWhiteSpace($nextLink)) {
                    if ($request.Kind -eq 'GroupUsers') {
                        $evidence.UserMemberEvidenceComplete = $true
                    }
                    else {
                        $evidence.
                            ServicePrincipalMemberEvidenceComplete =
                            $true
                    }
                }
                else {
                    $relativeUrl = $nextLink -replace
                        '^https://graph\.microsoft\.com/v1\.0',
                        ''
                    & $enqueueRequest `
                        -PrincipalKey $request.PrincipalKey `
                        -Kind $request.Kind `
                        -Url $relativeUrl
                }
                continue
            }
            foreach (
                $group in @(
                    Get-RadarPropertyValue `
                        -InputObject $response.body `
                        -Name 'value'
                )
            ) {
                $groupId = [string](
                    Get-RadarPropertyValue `
                        -InputObject $group `
                        -Name 'id'
                )
                if (-not [string]::IsNullOrWhiteSpace($groupId)) {
                    [void]$evidence.GroupIds.Add($groupId)
                }
            }
            $nextLink = [string](
                Get-RadarPropertyValue `
                    -InputObject $response.body `
                    -Name '@odata.nextLink'
            )
            if ([string]::IsNullOrWhiteSpace($nextLink)) {
                $evidence.MembershipEvidenceComplete = $true
            }
            else {
                $relativeUrl = $nextLink -replace
                    '^https://graph\.microsoft\.com/v1\.0',
                    ''
                & $enqueueRequest `
                    -PrincipalKey $request.PrincipalKey `
                    -Kind 'Groups' `
                    -Url $relativeUrl
            }
        }
    }

    $allGroupIds =
        New-Object System.Collections.Generic.HashSet[string] (
            [StringComparer]::OrdinalIgnoreCase
        )
    foreach ($evidence in $evidenceByPrincipal.Values) {
        $evidence.IsComplete = if (
            $evidence.DirectoryObjectState -eq 'Missing'
        ) {
            $true
        }
        elseif ($evidence.PrincipalType -eq 'Group') {
            (
                $evidence.ObjectEvidenceComplete -and
                $evidence.UserMemberEvidenceComplete -and
                $evidence.ServicePrincipalMemberEvidenceComplete
            )
        }
        else {
            (
                $evidence.ObjectEvidenceComplete -and
                $evidence.MembershipEvidenceComplete
            )
        }
        if (-not $evidence.IsComplete) {
            [void]$evidence.Warnings.Add(
                'Directory object, enabled-state, membership or group-expansion evidence is incomplete.'
            )
        }
        foreach ($groupId in $evidence.GroupIds) {
            [void]$allGroupIds.Add($groupId)
        }
    }
    return [pscustomobject]@{
        IsEvaluated = $true
        IsComplete = (
            [bool]$BaselineAssignmentInventory.IsComplete -and
            @(
                $evidenceByPrincipal.Values |
                    Where-Object { -not $_.IsComplete }
            ).Count -eq 0
        )
        EvidenceByPrincipal = $evidenceByPrincipal
        GroupIds = @($allGroupIds | Sort-Object)
        Warnings = @(
            @($BaselineAssignmentInventory.Warnings) +
            @($warnings) +
            @(
                $evidenceByPrincipal.Values |
                    ForEach-Object {
                        @($_.Warnings)
                    }
            ) |
                Sort-Object -Unique
        )
        Source = 'Microsoft Graph'
    }
}

function Get-RadarPrincipalRoleAssignmentInventory {
    <#
    Retrieves every visible direct RBAC assignment held by source-role holders
    and their transitive groups. Tenant-scoped, principal-filtered Resource
    Graph queries use bounded batches; no per-scope assignment calls are made.
    #>
    param(
        [object]$BaselineAssignmentInventory,
        [object]$DirectoryEvidence,
        [ValidateRange(1, 500)]
        [int]$PrincipalBatchSize = 300,
        [switch]$NoPrincipalCorrelation
    )

    $warnings = New-Object System.Collections.Generic.List[string]
    $principalIds = @(
        @(
            @($BaselineAssignmentInventory.Assignments) |
                ForEach-Object {
                    [string](
                        Get-RadarPropertyValue `
                            -InputObject $_ `
                            -Name 'PrincipalId'
                    )
                }
        ) +
        @(
            Get-RadarPropertyValue `
                -InputObject $DirectoryEvidence `
                -Name 'EvidenceByPrincipal' |
                ForEach-Object {
                    @($_.Values) |
                        ForEach-Object {
                            [string](
                                Get-RadarPropertyValue `
                                    -InputObject $_ `
                                    -Name 'PrincipalId'
                            )
                        }
                }
        ) +
        @(
            Get-RadarPropertyValue `
                -InputObject $DirectoryEvidence `
                -Name 'GroupIds'
        ) |
            Where-Object {
                -not [string]::IsNullOrWhiteSpace($_)
            } |
            Sort-Object -Unique
    )
    if ($NoPrincipalCorrelation) {
        return [pscustomobject]@{
            IsEvaluated = $false
            IsComplete = $false
            Assignments = @()
            AssignmentCount = 0
            AssignmentsByPrincipalAndScope = @{}
            Warnings = @(
                'Principal-level direct-RBAC correlation was disabled.'
            )
            Source = 'Disabled'
        }
    }
    if (-not $BaselineAssignmentInventory.IsEvaluated) {
        return [pscustomobject]@{
            IsEvaluated = $false
            IsComplete = $false
            Assignments = @()
            AssignmentCount = 0
            AssignmentsByPrincipalAndScope = @{}
            Warnings = @(
                @($BaselineAssignmentInventory.Warnings) +
                'Source-role holders were unavailable for principal correlation.'
            )
            Source = 'Unavailable'
        }
    }
    if ($principalIds.Count -eq 0) {
        return [pscustomobject]@{
            IsEvaluated = $true
            IsComplete = [bool]$BaselineAssignmentInventory.IsComplete
            Assignments = @()
            AssignmentCount = 0
            AssignmentsByPrincipalAndScope = @{}
            Warnings = @($BaselineAssignmentInventory.Warnings)
            Source = 'Not required'
        }
    }
    if (-not (Get-Command Search-AzGraph -ErrorAction SilentlyContinue)) {
        return [pscustomobject]@{
            IsEvaluated = $false
            IsComplete = $false
            Assignments = @()
            AssignmentCount = 0
            AssignmentsByPrincipalAndScope = @{}
            Warnings = @(
                'Azure Resource Graph is required for principal-level direct-RBAC correlation.'
            )
            Source = 'Unavailable'
        }
    }

    $assignments = New-Object System.Collections.Generic.List[object]
    $assignmentIds =
        New-Object System.Collections.Generic.HashSet[string] (
            [StringComparer]::OrdinalIgnoreCase
        )
    for (
        $batchStart = 0;
        $batchStart -lt $principalIds.Count;
        $batchStart += $PrincipalBatchSize
    ) {
        $batchEnd = [math]::Min(
            $batchStart + $PrincipalBatchSize - 1,
            $principalIds.Count - 1
        )
        $principalFilter = @(
            $principalIds[$batchStart..$batchEnd] |
                ForEach-Object {
                    "'" + $_.Replace("'", "''") + "'"
                }
        ) -join ', '
        $query = @"
authorizationresources
| where type =~ 'microsoft.authorization/roleassignments'
| extend
    RoleDefinitionId = tostring(properties.roleDefinitionId),
    AssignmentScope = tostring(properties.scope),
    PrincipalId = tostring(properties.principalId),
    PrincipalType = tostring(properties.principalType),
    Condition = tostring(properties.condition),
    ConditionVersion = tostring(properties.conditionVersion)
| where PrincipalId in~ ($principalFilter)
| extend RoleDefinitionGuid = tolower(
    extract('([^/]+)$', 1, RoleDefinitionId)
)
| project
    id,
    AssignmentId = id,
    AssignmentScope,
    PrincipalId,
    PrincipalType,
    Condition,
    ConditionVersion,
    RoleDefinitionId,
    RoleDefinitionGuid
"@
        $graphParameters = @{
            Query = $query
            First = 1000
            ErrorAction = 'Stop'
            UseTenantScope = $true
        }
        $skip = 0
        $skipToken = $null
        try {
            do {
                if ($skipToken) {
                    $graphParameters.SkipToken = $skipToken
                    [void]$graphParameters.Remove('Skip')
                }
                elseif ($skip -gt 0) {
                    $graphParameters.Skip = $skip
                    [void]$graphParameters.Remove('SkipToken')
                }
                $response = Search-AzGraph @graphParameters
                $wrappedResponse = Test-RadarHasProperty `
                    -InputObject $response `
                    -Name 'Data'
                if ($wrappedResponse) {
                    $page = @(
                        Get-RadarPropertyValue `
                            -InputObject $response `
                            -Name 'Data' |
                            Where-Object { $null -ne $_ }
                    )
                    $skipToken = [string](
                        Get-RadarPropertyValue `
                            -InputObject $response `
                            -Name 'SkipToken'
                    )
                }
                else {
                    $page = @(
                        $response |
                            Where-Object { $null -ne $_ }
                    )
                    $skip += $page.Count
                    $skipToken = $null
                }
                foreach ($row in $page) {
                $assignmentId = [string](
                    Get-RadarPropertyValue `
                        -InputObject $row `
                        -Name 'AssignmentId'
                )
                if ([string]::IsNullOrWhiteSpace($assignmentId)) {
                    $assignmentId = [string](
                        Get-RadarPropertyValue `
                            -InputObject $row `
                            -Name 'Id'
                    )
                }
                if (
                    [string]::IsNullOrWhiteSpace($assignmentId) -or
                    -not $assignmentIds.Add($assignmentId)
                ) {
                    continue
                }
                $assignmentScope = [string](
                    Get-RadarPropertyValue `
                        -InputObject $row `
                        -Name 'AssignmentScope'
                )
                if ([string]::IsNullOrWhiteSpace($assignmentScope)) {
                    $marker =
                        '/providers/Microsoft.Authorization/roleAssignments/'
                    $markerIndex = $assignmentId.IndexOf(
                        $marker,
                        [System.StringComparison]::OrdinalIgnoreCase
                    )
                    if ($markerIndex -gt 0) {
                        $assignmentScope =
                            $assignmentId.Substring(0, $markerIndex)
                    }
                }
                if ([string]::IsNullOrWhiteSpace($assignmentScope)) {
                    [void]$warnings.Add(
                        "Role assignment '$assignmentId' has no readable scope."
                    )
                    continue
                }
                $roleDefinitionId = [string](
                    Get-RadarPropertyValue `
                        -InputObject $row `
                        -Name 'RoleDefinitionId'
                )
                $roleDefinitionGuid = [string](
                    Get-RadarPropertyValue `
                        -InputObject $row `
                        -Name 'RoleDefinitionGuid'
                )
                if ([string]::IsNullOrWhiteSpace($roleDefinitionGuid)) {
                    $roleDefinitionGuid =
                        Get-RadarRoleDefinitionGuid `
                            -RoleOrId $roleDefinitionId
                }
                    [void]$assignments.Add([pscustomobject]@{
                    AssignmentId = $assignmentId
                    AssignmentScope = $assignmentScope.TrimEnd('/')
                    PrincipalId = [string](
                        Get-RadarPropertyValue `
                            -InputObject $row `
                            -Name 'PrincipalId'
                    )
                    PrincipalType = [string](
                        Get-RadarPropertyValue `
                            -InputObject $row `
                            -Name 'PrincipalType'
                    )
                    RoleDefinitionId = $roleDefinitionId
                    RoleDefinitionGuid =
                        $roleDefinitionGuid.ToLowerInvariant()
                    Condition = [string](
                        Get-RadarPropertyValue `
                            -InputObject $row `
                            -Name 'Condition'
                    )
                    ConditionVersion = [string](
                        Get-RadarPropertyValue `
                            -InputObject $row `
                            -Name 'ConditionVersion'
                    )
                    })
                }
                if (
                    ($wrappedResponse -and -not $skipToken) -or
                    (-not $wrappedResponse -and $page.Count -lt 1000)
                ) {
                    break
                }
            } while ($true)
        }
        catch {
            [void]$warnings.Add(
                "Principal direct-RBAC assignment batch discovery failed: $($_.Exception.Message)"
            )
        }
    }

    $assignmentArray = $assignments.ToArray()
    return [pscustomobject]@{
        IsEvaluated = $true
        IsComplete = (
            $warnings.Count -eq 0 -and
            [bool]$BaselineAssignmentInventory.IsComplete
        )
        Assignments = $assignmentArray
        AssignmentCount = $assignmentArray.Count
        AssignmentsByPrincipalAndScope =
            New-RadarPrincipalScopeAssignmentIndex `
                -Assignments $assignmentArray
        Warnings = @(
            @($BaselineAssignmentInventory.Warnings) +
            $warnings.ToArray() |
                Sort-Object -Unique
        )
        Source = 'Azure Resource Graph'
    }
}

function Get-RadarEffectivePrincipalAssignments {
    param(
        [object]$AssignmentInventory,
        [string]$PrincipalId,
        [string[]]$TransitiveGroupIds = @(),
        [string]$EvaluationScope,
        [object]$Hierarchy
    )

    $effective =
        New-Object System.Collections.Generic.List[object]
    $effectiveIds =
        New-Object System.Collections.Generic.HashSet[string] (
            [StringComparer]::OrdinalIgnoreCase
        )
    $candidateScopes =
        New-Object System.Collections.Generic.HashSet[string] (
            [StringComparer]::OrdinalIgnoreCase
        )
    $evaluationKey =
        $EvaluationScope.TrimEnd('/').ToLowerInvariant()
    if ([string]::IsNullOrWhiteSpace($evaluationKey)) {
        $evaluationKey = '/'
    }
    [void]$candidateScopes.Add($evaluationKey)
    [void]$candidateScopes.Add('/')
    if (
        $Hierarchy -and
        $Hierarchy.AncestorsByScope.ContainsKey($evaluationKey)
    ) {
        foreach ($ancestor in @(
            $Hierarchy.AncestorsByScope[$evaluationKey]
        )) {
            $ancestorKey =
                ([string]$ancestor).TrimEnd('/').ToLowerInvariant()
            if ([string]::IsNullOrWhiteSpace($ancestorKey)) {
                $ancestorKey = '/'
            }
            [void]$candidateScopes.Add($ancestorKey)
        }
    }

    $index = Get-RadarPropertyValue `
        -InputObject $AssignmentInventory `
        -Name 'AssignmentsByPrincipalAndScope'
    if ($null -eq $index) {
        $index = New-RadarPrincipalScopeAssignmentIndex `
            -Assignments @($AssignmentInventory.Assignments)
    }
    $subjectIds = @(
        @($PrincipalId) +
        @($TransitiveGroupIds) |
            Where-Object {
                -not [string]::IsNullOrWhiteSpace($_)
            } |
            Sort-Object -Unique
    )
    foreach ($subjectId in $subjectIds) {
        foreach ($candidateScope in $candidateScopes) {
            $key = Get-RadarPrincipalScopeAssignmentKey `
                -PrincipalId $subjectId `
                -Scope $candidateScope
            if (-not $index.ContainsKey($key)) { continue }
            foreach ($assignment in $index[$key].ToArray()) {
                $assignmentId = [string]$assignment.AssignmentId
                if ($effectiveIds.Add($assignmentId)) {
                    [void]$effective.Add($assignment)
                }
            }
        }
    }

    $relationshipUnknown = $false
    foreach (
        $assignment in @(
            $AssignmentInventory.Assignments |
                Where-Object {
                    $subjectIds -contains [string]$_.PrincipalId
                }
        )
    ) {
        if ($effectiveIds.Contains([string]$assignment.AssignmentId)) {
            continue
        }
        $relationship = Test-RadarScopeDescendsFrom `
            -Scope $EvaluationScope `
            -RootScope $assignment.AssignmentScope `
            -Hierarchy $Hierarchy
        if ($relationship.State -eq 'True') {
            if ($effectiveIds.Add([string]$assignment.AssignmentId)) {
                [void]$effective.Add($assignment)
            }
        }
        elseif ($relationship.State -eq 'Unknown') {
            $relationshipUnknown = $true
        }
    }

    return [pscustomobject]@{
        Assignments = $effective.ToArray()
        IsComplete = (
            [bool]$AssignmentInventory.IsComplete -and
            -not $relationshipUnknown
        )
        Warnings = @(
            @($AssignmentInventory.Warnings) +
            $(if ($relationshipUnknown) {
                "At least one direct or transitive-group assignment for principal '$PrincipalId' could not be placed safely at '$EvaluationScope'."
            }) |
                Where-Object {
                    -not [string]::IsNullOrWhiteSpace($_)
                } |
                Sort-Object -Unique
        )
    }
}

function Get-RadarExistingCapabilityCoverage {
    <#
    Subtracts the union of visible existing permission blocks from the exact
    capability represented by the candidate role and restricted action.
    #>
    param(
        [object]$CandidateRole,
        [string]$RestrictedAction,
        [object[]]$ExistingRoles = @(),
        [ValidateRange(1, 65536)]
        [int]$MaxResidualTerms = 4096
    )

    $targets = New-Object System.Collections.Generic.List[object]
    foreach (
        $candidatePermission in @(
            Get-RolePermissionBlock -Role $CandidateRole
        )
    ) {
        foreach ($candidateAction in @($candidatePermission.Actions)) {
            if (
                Test-RadarGlobDifferenceExists `
                    -IncludePatterns @(
                        $candidateAction,
                        $RestrictedAction
                    ) `
                    -ExcludePatterns @(
                        $candidatePermission.NotActions
                    )
            ) {
                [void]$targets.Add([pscustomobject]@{
                    Action = $candidateAction
                    NotActions = @(
                        $candidatePermission.NotActions
                    )
                })
            }
        }
    }
    if ($targets.Count -eq 0) {
        return [pscustomobject]@{
            State = 'Unknown'
            HasAnyOverlap = $false
            Reason =
                'The candidate granting capability could not be represented.'
        }
    }

    $existingPermissions = @(
        foreach ($existingRole in $ExistingRoles) {
            foreach (
                $permission in @(
                    Get-RolePermissionBlock -Role $existingRole
                )
            ) {
                foreach ($action in @($permission.Actions)) {
                    [pscustomobject]@{
                        Action = $action
                        NotActions = @($permission.NotActions)
                    }
                }
            }
        }
    )
    $hasAnyOverlap = $false
    foreach ($target in $targets) {
        foreach ($existingPermission in $existingPermissions) {
            if (
                Test-RadarGlobDifferenceExists `
                    -IncludePatterns @(
                        $target.Action,
                        $RestrictedAction,
                        $existingPermission.Action
                    ) `
                    -ExcludePatterns @(
                        @($target.NotActions) +
                        @($existingPermission.NotActions)
                    )
            ) {
                $hasAnyOverlap = $true
            }
        }
    }

    foreach ($target in $targets) {
        $residualTerms = @(
            [pscustomobject]@{
                Includes = @(
                    $target.Action,
                    $RestrictedAction |
                        Sort-Object -Unique
                )
                Excludes = @(
                    $target.NotActions |
                        Sort-Object -Unique
                )
            }
        )
        foreach ($existingPermission in $existingPermissions) {
            $nextTerms =
                New-Object System.Collections.Generic.List[object]
            $termKeys =
                New-Object System.Collections.Generic.HashSet[string] (
                    [StringComparer]::OrdinalIgnoreCase
                )
            foreach ($term in $residualTerms) {
                $branches =
                    New-Object System.Collections.Generic.List[object]
                [void]$branches.Add([pscustomobject]@{
                    Includes = @($term.Includes)
                    Excludes = @(
                        @($term.Excludes) +
                        $existingPermission.Action
                    )
                })
                foreach (
                    $notAction in @(
                        $existingPermission.NotActions
                    )
                ) {
                    [void]$branches.Add([pscustomobject]@{
                        Includes = @(
                            @($term.Includes) +
                            $existingPermission.Action +
                            $notAction
                        )
                        Excludes = @($term.Excludes)
                    })
                }
                foreach ($branch in $branches) {
                    $includes = @(
                        $branch.Includes |
                            Where-Object {
                                -not [string]::IsNullOrWhiteSpace($_)
                            } |
                            ForEach-Object {
                                $_.ToLowerInvariant()
                            } |
                            Sort-Object -Unique
                    )
                    $excludes = @(
                        $branch.Excludes |
                            Where-Object {
                                -not [string]::IsNullOrWhiteSpace($_)
                            } |
                            ForEach-Object {
                                $_.ToLowerInvariant()
                            } |
                            Sort-Object -Unique
                    )
                    if (
                        -not (
                            Test-RadarGlobDifferenceExists `
                                -IncludePatterns $includes `
                                -ExcludePatterns $excludes
                        )
                    ) {
                        continue
                    }
                    $termKey = @(
                        $includes -join [char]30,
                        $excludes -join [char]30
                    ) -join [char]31
                    if ($termKeys.Add($termKey)) {
                        [void]$nextTerms.Add([pscustomobject]@{
                            Includes = $includes
                            Excludes = $excludes
                        })
                    }
                    if ($nextTerms.Count -gt $MaxResidualTerms) {
                        return [pscustomobject]@{
                            State = 'Unknown'
                            HasAnyOverlap = $hasAnyOverlap
                            Reason =
                                "Existing capability subtraction exceeded the $MaxResidualTerms-term safety limit."
                        }
                    }
                }
            }
            $residualTerms = @($nextTerms.ToArray())
            if ($residualTerms.Count -eq 0) { break }
        }
        if ($residualTerms.Count -gt 0) {
            return [pscustomobject]@{
                State = 'NetNewDelta'
                HasAnyOverlap = $hasAnyOverlap
                Reason = $null
            }
        }
    }

    return [pscustomobject]@{
        State = 'Full'
        HasAnyOverlap = $hasAnyOverlap
        Reason = $null
    }
}

function Get-RadarPrincipalExistingAccess {
    param(
        [string]$PrincipalId,
        [string]$PrincipalType,
        [object]$Holder,
        [object]$HolderEvidence,
        [object]$DirectoryEvidence,
        [object]$PrincipalAssignmentInventory,
        [string]$EvaluationScope,
        [string]$RestrictedAction,
        [object]$GrantingRole,
        [object]$Hierarchy,
        [hashtable]$RoleByKey,
        [hashtable]$ExistingAccessCache
    )

    if ($null -eq $ExistingAccessCache) {
        $ExistingAccessCache = @{}
    }
    $directoryPrincipalEvidence = $null
    $directoryEvidenceByPrincipal =
        Get-RadarPropertyValue `
            -InputObject $DirectoryEvidence `
            -Name 'EvidenceByPrincipal'
    if (
        -not [string]::IsNullOrWhiteSpace($PrincipalId) -and
        $null -ne $directoryEvidenceByPrincipal -and
        $directoryEvidenceByPrincipal.ContainsKey(
            $PrincipalId.ToLowerInvariant()
        )
    ) {
        $directoryPrincipalEvidence =
            $directoryEvidenceByPrincipal[
                $PrincipalId.ToLowerInvariant()
            ]
    }
    $groupIds = @(
        if ($null -ne $directoryPrincipalEvidence) {
            $directoryPrincipalEvidence.GroupIds |
                Sort-Object -Unique
        }
    )
    $directoryObjectState = if (
        $null -ne $directoryPrincipalEvidence
    ) {
        [string](
            Get-RadarPropertyValue `
                -InputObject $directoryPrincipalEvidence `
                -Name 'DirectoryObjectState'
        )
    }
    else {
        'Unknown'
    }
    $principalEnabledStatus = if (
        $directoryObjectState -eq 'Missing'
    ) {
        'Missing'
    }
    elseif (
        $null -ne $directoryPrincipalEvidence -and
        $directoryPrincipalEvidence.IsComplete
    ) {
        if ($directoryPrincipalEvidence.AccountEnabled) {
            'Enabled'
        }
        else {
            'Disabled'
        }
    }
    else {
        'Unknown'
    }
    $evidenceCompleteness = @(
        "source:$($HolderEvidence.IsComplete)",
        "conditioned:$($Holder.SourceAssignmentConditioned)",
        "directory:$($null -ne $directoryPrincipalEvidence -and $directoryPrincipalEvidence.IsComplete)",
        "directoryObject:$directoryObjectState",
        "enabled:$principalEnabledStatus",
        "groupCount:$($groupIds.Count)",
        "assignmentsEvaluated:$($PrincipalAssignmentInventory.IsEvaluated)",
        "assignmentsComplete:$($PrincipalAssignmentInventory.IsComplete)",
        "assignmentCount:$(
            Get-RadarPropertyValue `
                -InputObject $PrincipalAssignmentInventory `
                -Name 'AssignmentCount'
        )"
    ) -join [char]30
    $cacheKey = @(
        $PrincipalId.ToLowerInvariant(),
        $PrincipalType.ToLowerInvariant(),
        $EvaluationScope.TrimEnd('/').ToLowerInvariant(),
        $RestrictedAction.ToLowerInvariant(),
        $evidenceCompleteness
    ) -join [char]31

    if (-not $ExistingAccessCache.ContainsKey($cacheKey)) {
        $warnings = New-Object System.Collections.Generic.List[string]
        if ($null -ne $directoryPrincipalEvidence) {
            foreach (
                $warning in @(
                    $directoryPrincipalEvidence.Warnings
                )
            ) {
                [void]$warnings.Add($warning)
            }
        }
        $fixedStatus = $null
        $unconditionedRoles =
            New-Object System.Collections.Generic.List[object]
        $conditionedRoles =
            New-Object System.Collections.Generic.List[object]

        if (
            [string]::IsNullOrWhiteSpace($PrincipalId) -or
            [string]::IsNullOrWhiteSpace($PrincipalType)
        ) {
            $fixedStatus = 'Unknown'
        }
        elseif (        $directoryObjectState -eq 'Missing'
        ) {
        $fixedStatus = 'PrincipalMissing'
        }
        elseif (
        $PrincipalType -eq 'Group') {
        $fixedStatus = 'Unknown'
        [void]$warnings.Add(
            'Source Group membership expansion is incomplete, so the group-level holder remains non-actionable.'
        )
        }
        elseif (
            $PrincipalType -notin @(
                'User',
                'ServicePrincipal'
            )
        ) {
            $fixedStatus = 'Unknown'
            [void]$warnings.Add(
                "Principal type '$PrincipalType' is unsupported."
            )
        }
        elseif ($Holder.SourceAssignmentConditioned) {
            $fixedStatus = 'Unknown'
        }
        elseif (-not $HolderEvidence.IsComplete) {
            $fixedStatus = 'Unknown'
        }
        elseif (
            $null -eq $directoryPrincipalEvidence -or
            -not $directoryPrincipalEvidence.IsComplete
        ) {
            $fixedStatus = 'Unknown'
            [void]$warnings.Add(
                'Microsoft Graph enabled-state or transitive-group evidence is unavailable or incomplete.'
            )
        }
        elseif ($principalEnabledStatus -eq 'Disabled') {
            $fixedStatus = 'PrincipalDisabled'
        }
        elseif (
            -not $PrincipalAssignmentInventory.IsEvaluated -or
            -not $PrincipalAssignmentInventory.IsComplete
        ) {
            $fixedStatus = 'Unknown'
            foreach (
                $warning in @(
                    $PrincipalAssignmentInventory.Warnings
                )
            ) {
                [void]$warnings.Add($warning)
            }
        }
        else {
            $effectiveExisting =
                Get-RadarEffectivePrincipalAssignments `
                    -AssignmentInventory (
                        $PrincipalAssignmentInventory
                    ) `
                    -PrincipalId $PrincipalId `
                    -TransitiveGroupIds $groupIds `
                    -EvaluationScope $EvaluationScope `
                    -Hierarchy $Hierarchy
            if (-not $effectiveExisting.IsComplete) {
                $fixedStatus = 'Unknown'
            }
            foreach ($warning in @($effectiveExisting.Warnings)) {
                [void]$warnings.Add($warning)
            }
            foreach (
                $existingAssignment in @(
                    $effectiveExisting.Assignments
                )
            ) {
                $existingRoleKey = [string](
                    Get-RadarPropertyValue `
                        -InputObject $existingAssignment `
                        -Name 'RoleDefinitionGuid'
                )
                if (
                    [string]::IsNullOrWhiteSpace(
                        $existingRoleKey
                    )
                ) {
                    $existingRoleKey =
                        Get-RadarRoleDefinitionGuid `
                            -RoleOrId (
                                Get-RadarPropertyValue `
                                    -InputObject $existingAssignment `
                                    -Name 'RoleDefinitionId'
                            )
                }
                if (
                    -not $RoleByKey.ContainsKey(
                        $existingRoleKey.ToLowerInvariant()
                    )
                ) {
                    $fixedStatus = 'Unknown'
                    [void]$warnings.Add(
                        'An effective direct or group assignment references an unavailable role definition, so existing access cannot be excluded.'
                    )
                    continue
                }
                $existingRole =
                    $RoleByKey[
                        $existingRoleKey.ToLowerInvariant()
                    ]
                if (
                    [string]::IsNullOrWhiteSpace(
                        [string]$existingAssignment.Condition
                    )
                ) {
                    [void]$unconditionedRoles.Add($existingRole)
                }
                else {
                    [void]$conditionedRoles.Add($existingRole)
                }
            }
        }
        $ExistingAccessCache[$cacheKey] = [pscustomobject]@{
            FixedStatus = $fixedStatus
            PrincipalEnabledStatus = $principalEnabledStatus
            GroupIds = $groupIds
            UnconditionedRoles = $unconditionedRoles.ToArray()
            ConditionedRoles = $conditionedRoles.ToArray()
            Warnings = @(
                $warnings |
                    Where-Object {
                        -not [string]::IsNullOrWhiteSpace($_)
                    } |
                    Sort-Object -Unique
            )
            Evaluations = @{}
        }
    }

    $cacheEntry = $ExistingAccessCache[$cacheKey]
    if ($cacheEntry.FixedStatus) {
        return [pscustomobject]@{
            Status = $cacheEntry.FixedStatus
            PrincipalEnabledStatus =
                $cacheEntry.PrincipalEnabledStatus
            GroupIds = @($cacheEntry.GroupIds)
            Warnings = @($cacheEntry.Warnings)
        }
    }
    if ($null -eq $GrantingRole) {
        return [pscustomobject]@{
            Status = 'Unknown'
            PrincipalEnabledStatus =
                $cacheEntry.PrincipalEnabledStatus
            GroupIds = @($cacheEntry.GroupIds)
            Warnings = @(
                @($cacheEntry.Warnings) +
                'The granting role definition is unavailable.'
            )
        }
    }

    $candidateKey = Get-RadarRoleKey -Role $GrantingRole
    if (-not $cacheEntry.Evaluations.ContainsKey($candidateKey)) {
        $evaluationWarnings =
            New-Object System.Collections.Generic.List[string]
        $unconditionedCoverage =
            Get-RadarExistingCapabilityCoverage `
                -CandidateRole $GrantingRole `
                -RestrictedAction $RestrictedAction `
                -ExistingRoles $cacheEntry.UnconditionedRoles
        $conditionedCoverage =
            Get-RadarExistingCapabilityCoverage `
                -CandidateRole $GrantingRole `
                -RestrictedAction $RestrictedAction `
                -ExistingRoles $cacheEntry.ConditionedRoles
        $status = if ($unconditionedCoverage.State -eq 'Full') {
            'AlreadyHasAction'
        }
        elseif (
            $unconditionedCoverage.State -eq 'Unknown' -or
            $conditionedCoverage.State -eq 'Unknown' -or
            $conditionedCoverage.HasAnyOverlap
        ) {
            if ($conditionedCoverage.HasAnyOverlap) {
                [void]$evaluationWarnings.Add(
                    'An effective conditioned direct or group assignment overlaps the candidate capability; its ABAC condition was not evaluated.'
                )
            }
            if ($unconditionedCoverage.State -eq 'Unknown') {
                [void]$evaluationWarnings.Add(
                    $unconditionedCoverage.Reason
                )
            }
            if ($conditionedCoverage.State -eq 'Unknown') {
                [void]$evaluationWarnings.Add(
                    $conditionedCoverage.Reason
                )
            }
            'Unknown'
        }
        elseif (
            $unconditionedCoverage.State -eq 'NetNewDelta'
        ) {
            if ($unconditionedCoverage.HasAnyOverlap) {
                'NetNewDelta'
            }
            else {
                'NoExistingAction'
            }
        }
        $cacheEntry.Evaluations[$candidateKey] =
            [pscustomobject]@{
                Status = $status
                Warnings = @(
                    $evaluationWarnings |
                        Where-Object {
                            -not [string]::IsNullOrWhiteSpace($_)
                        } |
                        Sort-Object -Unique
                )
            }
    }
    $candidateEvaluation =
        $cacheEntry.Evaluations[$candidateKey]
    return [pscustomobject]@{
        Status = $candidateEvaluation.Status
        PrincipalEnabledStatus =
            $cacheEntry.PrincipalEnabledStatus
        GroupIds = @($cacheEntry.GroupIds)
        Warnings = @(
            @($cacheEntry.Warnings) +
            @($candidateEvaluation.Warnings) |
                Sort-Object -Unique
        )
    }
}

function Get-RadarPrincipalGap {
    <#
    Correlates actual source-role holders with their effective direct RBAC,
    baseline-reachable assignment paths and principal-specific policy outcome.
    Microsoft Graph supplies enabled state and transitive group membership for
    User and ServicePrincipal holders and expands source Groups to transitive
    User and ServicePrincipal members. PIM source-role schedules remain outside
    this evidence model.
    #>
    param(
        [AllowEmptyCollection()]
        [object[]]$Results,
        [object[]]$BaselineContexts,
        [object]$BaselineAssignmentInventory,
        [object]$DirectoryEvidence,
        [object]$PrincipalAssignmentInventory,
        [object[]]$Roles,
        [object]$Hierarchy,
        [object]$PolicyInventory,
        [System.Collections.Generic.HashSet[string]]$DeniedRoleNames,
        [bool]$DiscoveryComplete = $true,
        [hashtable]$PolicyEvaluationCache,
        [hashtable]$PrincipalPolicyCache,
        [hashtable]$ExistingAccessCache
    )

    if ($null -eq $PolicyEvaluationCache) {
        $PolicyEvaluationCache = @{}
    }
    if ($null -eq $PrincipalPolicyCache) {
        $PrincipalPolicyCache = @{}
    }
    if ($null -eq $ExistingAccessCache) {
        $ExistingAccessCache = @{}
    }
    $roleByKey = @{}
    foreach ($role in $Roles) {
        $roleByKey[(Get-RadarRoleKey -Role $role)] = $role
        $roleByKey[(Get-RadarRoleDefinitionGuid -RoleOrId $role)] = $role
    }
    $contextByKey = @{}
    foreach ($context in $BaselineContexts) {
        $key = @(
            ([string]$context.BaselineRoleId).ToLowerInvariant(),
            ([string]$context.BaselineScope).TrimEnd('/').ToLowerInvariant()
        ) -join [char]31
        $contextByKey[$key] = $context
    }
    $holderCache = @{}
    $rows = New-Object System.Collections.Generic.List[object]
    $rowKeys =
        New-Object System.Collections.Generic.HashSet[string] (
            [StringComparer]::OrdinalIgnoreCase
        )

    foreach (
        $result in @(
            $Results |
                Where-Object {
                    $_.AnalysisMode -eq 'BaselineNotActions'
                }
        )
    ) {
        $contextKey = @(
            ([string]$result.BaselineRoleId).ToLowerInvariant(),
            ([string]$result.BaselineScope).TrimEnd('/').ToLowerInvariant()
        ) -join [char]31
        $context = if ($contextByKey.ContainsKey($contextKey)) {
            $contextByKey[$contextKey]
        }
        else {
            $null
        }
        foreach (
            $scopeEvaluation in @(
                Get-RadarPropertyValue `
                    -InputObject $result `
                    -Name 'ScopeEvaluations'
            )
        ) {
            if ($null -eq $scopeEvaluation) { continue }
            $evaluationScope = [string](
                Get-RadarPropertyValue `
                    -InputObject $scopeEvaluation `
                    -Name 'Scope'
            )
            $scopeObject = New-RadarScope -Id $evaluationScope
            if (
                $scopeObject.Type -notin @(
                    'ManagementGroup',
                    'Subscription'
                )
            ) {
                continue
            }
            $holderKey = @(
                $contextKey,
                $evaluationScope.TrimEnd('/').ToLowerInvariant()
            ) -join [char]31
            if (-not $holderCache.ContainsKey($holderKey)) {
                $baselineRoleGuid =
                    Get-RadarRoleDefinitionGuid `
                        -RoleOrId $result.BaselineRoleId
                $candidateSourceAssignments = @(
                    $BaselineAssignmentInventory.Assignments |
                        Where-Object {
                            [string]::Equals(
                                [string]$_.RoleDefinitionGuid,
                                $baselineRoleGuid,
                                [System.StringComparison]::OrdinalIgnoreCase
                            )
                        }
                )
                $effectiveSourceAssignments =
                    New-Object System.Collections.Generic.List[object]
                $sourceRelationshipUnknown = $false
                foreach ($sourceAssignment in $candidateSourceAssignments) {
                    $relationship = Test-RadarScopeDescendsFrom `
                        -Scope $evaluationScope `
                        -RootScope $sourceAssignment.AssignmentScope `
                        -Hierarchy $Hierarchy
                    if ($relationship.State -eq 'True') {
                        [void]$effectiveSourceAssignments.Add(
                            $sourceAssignment
                        )
                    }
                    elseif ($relationship.State -eq 'Unknown') {
                        $sourceRelationshipUnknown = $true
                    }
                }
                $holdersByKey = @{}
                foreach (
                    $sourceAssignment in $effectiveSourceAssignments
                ) {
                    $sourcePrincipalId =
                        [string]$sourceAssignment.PrincipalId
                    $sourcePrincipalType =
                        [string]$sourceAssignment.PrincipalType
                    $effectiveSubjects =
                        New-Object System.Collections.Generic.List[object]
                    if (
                        $sourcePrincipalType -eq 'Group' -and
                        -not [string]::IsNullOrWhiteSpace(
                            $sourcePrincipalId
                        )
                    ) {
                        $groupEvidence = $null
                        $directoryEvidenceByPrincipal =
                            Get-RadarPropertyValue `
                                -InputObject $DirectoryEvidence `
                                -Name 'EvidenceByPrincipal'
                        $sourcePrincipalKey =
                            $sourcePrincipalId.ToLowerInvariant()
                        if (
                            $null -ne $directoryEvidenceByPrincipal -and
                            $directoryEvidenceByPrincipal.ContainsKey(
                                $sourcePrincipalKey
                            )
                        ) {
                            $groupEvidence =
                                $directoryEvidenceByPrincipal[
                                    $sourcePrincipalKey
                                ]
                        }
                        $groupState = if ($null -ne $groupEvidence) {
                            [string](
                                Get-RadarPropertyValue `
                                    -InputObject $groupEvidence `
                                    -Name 'DirectoryObjectState'
                            )
                        }
                        else {
                            'Unknown'
                        }
                        if (
                            $null -ne $groupEvidence -and
                            [string]$groupEvidence.PrincipalType -eq
                                'Group' -and
                            $groupState -eq 'Present'
                        ) {
                            foreach (
                                $memberId in @(
                                    $groupEvidence.MemberIds |
                                        Sort-Object -Unique
                                )
                            ) {
                                $memberKey =
                                    ([string]$memberId).
                                        ToLowerInvariant()
                                $memberEvidence = if (
                                    $directoryEvidenceByPrincipal.
                                        ContainsKey($memberKey)
                                ) {
                                    $directoryEvidenceByPrincipal[
                                        $memberKey
                                    ]
                                }
                                else {
                                    $null
                                }
                                [void]$effectiveSubjects.Add(
                                    [pscustomobject]@{
                                        PrincipalId =
                                            [string]$memberId
                                        PrincipalType = [string](
                                            Get-RadarPropertyValue `
                                                -InputObject (
                                                    $memberEvidence
                                                ) `
                                                -Name 'PrincipalType'
                                        )
                                        SourcePrincipalId =
                                            $sourcePrincipalId
                                        SourceViaGroup = $true
                                        Warnings = @()
                                    }
                                )
                            }
                            if (-not [bool]$groupEvidence.IsComplete) {
                                [void]$effectiveSubjects.Add(
                                    [pscustomobject]@{
                                        PrincipalId =
                                            $sourcePrincipalId
                                        PrincipalType = 'Group'
                                        SourcePrincipalId =
                                            $sourcePrincipalId
                                        SourceViaGroup = $false
                                        Warnings = @(
                                            'Source Group membership expansion is incomplete.'
                                        )
                                    }
                                )
                            }
                        }
                        else {
                            [void]$effectiveSubjects.Add(
                                [pscustomobject]@{
                                    PrincipalId = $sourcePrincipalId
                                    PrincipalType = 'Group'
                                    SourcePrincipalId =
                                        $sourcePrincipalId
                                    SourceViaGroup = $false
                                    Warnings = @(
                                        if ($groupState -eq 'Missing') {
                                            'The source Group directory object is missing.'
                                        }
                                        else {
                                            'Source Group membership expansion is incomplete.'
                                        }
                                    )
                                }
                            )
                        }
                    }
                    else {
                        [void]$effectiveSubjects.Add(
                            [pscustomobject]@{
                                PrincipalId = $sourcePrincipalId
                                PrincipalType = $sourcePrincipalType
                                SourcePrincipalId =
                                    $sourcePrincipalId
                                SourceViaGroup = $false
                                Warnings = @()
                            }
                        )
                    }

                    foreach ($subject in $effectiveSubjects) {
                        $principalId = [string]$subject.PrincipalId
                        $principalKey = if (
                            [string]::IsNullOrWhiteSpace($principalId)
                        ) {
                            "missing:$($sourceAssignment.AssignmentId)"
                        }
                        else {
                            $principalId.ToLowerInvariant()
                        }
                        if (
                            -not $holdersByKey.ContainsKey(
                                $principalKey
                            )
                        ) {
                            $holdersByKey[$principalKey] =
                                [pscustomobject]@{
                                    PrincipalId = $principalId
                                    PrincipalTypes =
                                        New-Object System.Collections.Generic.HashSet[string] (
                                            [StringComparer]::OrdinalIgnoreCase
                                        )
                                    SourcePrincipalIds =
                                        New-Object System.Collections.Generic.HashSet[string] (
                                            [StringComparer]::OrdinalIgnoreCase
                                        )
                                    SourceViaGroup = $false
                                    SourceAssignmentScopes =
                                        New-Object System.Collections.Generic.HashSet[string] (
                                            [StringComparer]::OrdinalIgnoreCase
                                        )
                                    HasUnconditionedSourceAssignment =
                                        $false
                                    HasConditionedSourceAssignment =
                                        $false
                                    Warnings =
                                        New-Object System.Collections.Generic.List[string]
                                }
                        }
                        $holder = $holdersByKey[$principalKey]
                        $principalType = [string]$subject.PrincipalType
                        if (
                            -not [string]::IsNullOrWhiteSpace(
                                $principalType
                            )
                        ) {
                            [void]$holder.PrincipalTypes.Add(
                                $principalType
                            )
                        }
                        if (
                            -not [string]::IsNullOrWhiteSpace(
                                [string]$subject.SourcePrincipalId
                            )
                        ) {
                            [void]$holder.SourcePrincipalIds.Add(
                                [string]$subject.SourcePrincipalId
                            )
                        }
                        if ([bool]$subject.SourceViaGroup) {
                            $holder.SourceViaGroup = $true
                        }
                        [void]$holder.SourceAssignmentScopes.Add(
                            [string]$sourceAssignment.AssignmentScope
                        )
                        foreach ($warning in @($subject.Warnings)) {
                            [void]$holder.Warnings.Add($warning)
                        }
                        if (
                            [string]::IsNullOrWhiteSpace(
                                [string]$sourceAssignment.Condition
                            )
                        ) {
                            $holder.HasUnconditionedSourceAssignment =
                                $true
                        }
                        else {
                            $holder.HasConditionedSourceAssignment =
                                $true
                        }
                    }
                }
                $holders = @(
                    $holdersByKey.Values |
                        ForEach-Object {
                            $holder = $_
                            $types = @($holder.PrincipalTypes)
                            $principalType = if ($types.Count -eq 1) {
                                $types[0]
                            }
                            else {
                                ''
                            }
                            $holderWarnings = @(
                                $(if (
                                    [string]::IsNullOrWhiteSpace(
                                        $holder.PrincipalId
                                    )
                                ) {
                                    'The source-role assignment has no readable principal ID.'
                                }) +
                                $(if ($types.Count -eq 0) {
                                    'The source-role assignment has no readable principal type.'
                                }) +
                                $(if ($types.Count -gt 1) {
                                    'Conflicting principal types were observed for the source-role holder.'
                                }) +
                                $(if (
                                    -not $holder.HasUnconditionedSourceAssignment -and
                                    $holder.HasConditionedSourceAssignment
                                ) {
                                    'The effective source-role assignment is conditioned and cannot be treated as active without ABAC evaluation.'
                                }) |
                                    Where-Object {
                                        -not [string]::IsNullOrWhiteSpace($_)
                                    }
                            )
                            [pscustomobject]@{
                                PrincipalId = $holder.PrincipalId
                                PrincipalType = $principalType
                                SourcePrincipalId = @(
                                    $holder.SourcePrincipalIds |
                                        Sort-Object
                                ) -join '; '
                                SourceViaGroup =
                                    [bool]$holder.SourceViaGroup
                                SourceAssignmentScopes = @(
                                    $holder.SourceAssignmentScopes |
                                        Sort-Object
                                )
                                SourceAssignmentConditioned = (
                                    -not $holder.HasUnconditionedSourceAssignment -and
                                    $holder.HasConditionedSourceAssignment
                                )
                                Warnings = @(
                                    @($holder.Warnings) +
                                    $holderWarnings |
                                        Where-Object {
                                            -not [string]::IsNullOrWhiteSpace(
                                                $_
                                            )
                                        } |
                                        Sort-Object -Unique
                                )
                            }
                        }
                )
                $holderCache[$holderKey] = [pscustomobject]@{
                    Holders = $holders
                    IsComplete = (
                        [bool]$BaselineAssignmentInventory.IsComplete -and
                        -not $sourceRelationshipUnknown
                    )
                    Warnings = @(
                        @($BaselineAssignmentInventory.Warnings) +
                        $(if ($sourceRelationshipUnknown) {
                            "At least one source-role assignment could not be placed safely at '$evaluationScope'."
                        }) |
                            Where-Object {
                                -not [string]::IsNullOrWhiteSpace($_)
                            } |
                            Sort-Object -Unique
                    )
                }
            }
            $holderEvidence = $holderCache[$holderKey]
            $holders = @($holderEvidence.Holders)
            if ($holders.Count -eq 0) {
                if ($holderEvidence.IsComplete) {
                    continue
                }
                $holders = @(
                    [pscustomobject]@{
                        PrincipalId = ''
                        PrincipalType = ''
                        SourcePrincipalId = ''
                        SourceViaGroup = $false
                        SourceAssignmentScopes = @()
                        SourceAssignmentConditioned = $false
                        Warnings = @(
                            @($holderEvidence.Warnings) +
                            'No source-role holder could be proven because assignment evidence is incomplete.'
                        )
                    }
                )
            }

            foreach ($holder in $holders) {
                $principalId = [string]$holder.PrincipalId
                $principalType = [string]$holder.PrincipalType
                $grantingRole = $null
                $grantingRoleKey =
                    Get-RadarRoleDefinitionGuid `
                        -RoleOrId $result.RoleId
                if ($roleByKey.ContainsKey($grantingRoleKey)) {
                    $grantingRole = $roleByKey[$grantingRoleKey]
                }
                elseif (
                    $roleByKey.ContainsKey(
                        ([string]$result.RoleId).ToLowerInvariant()
                    )
                ) {
                    $grantingRole =
                        $roleByKey[
                            ([string]$result.RoleId).ToLowerInvariant()
                        ]
                }

                $availablePaths = @(
                    if ($null -ne $context) {
                        @($context.AssignmentPaths) |
                            Where-Object {
                                [string](
                                    Get-RadarPropertyValue `
                                        -InputObject $_ `
                                        -Name 'Reachability'
                                ) -like 'Baseline role can create*'
                            }
                    }
                )
                $warnings = New-Object System.Collections.Generic.List[string]
                foreach (
                    $warning in @(
                        @($holder.Warnings) +
                        @($holderEvidence.Warnings)
                    )
                ) {
                    if (-not [string]::IsNullOrWhiteSpace($warning)) {
                        [void]$warnings.Add($warning)
                    }
                }

                $holderDirectoryState = 'Unknown'
                $directoryEvidenceByPrincipal =
                    Get-RadarPropertyValue `
                        -InputObject $DirectoryEvidence `
                        -Name 'EvidenceByPrincipal'
                if (
                    -not [string]::IsNullOrWhiteSpace(
                        $principalId
                    ) -and
                    $null -ne $directoryEvidenceByPrincipal -and
                    $directoryEvidenceByPrincipal.ContainsKey(
                        $principalId.ToLowerInvariant()
                    )
                ) {
                    $holderDirectoryState = [string](
                        Get-RadarPropertyValue `
                            -InputObject (
                                $directoryEvidenceByPrincipal[
                                    $principalId.ToLowerInvariant()
                                ]
                            ) `
                            -Name 'DirectoryObjectState'
                    )
                }
                $existingAccess = if ($availablePaths.Count -eq 0) {
                    if ($holderDirectoryState -eq 'Missing') {
                        [pscustomobject]@{
                            Status = 'PrincipalMissing'
                            PrincipalEnabledStatus = 'Missing'
                            GroupIds = @()
                            Warnings = @()
                        }
                    }
                    else {
                        [pscustomobject]@{
                            Status = 'NotEvaluated'
                            PrincipalEnabledStatus = 'NotEvaluated'
                            GroupIds = @()
                            Warnings = @()
                        }
                    }
                }
                else {
                    Get-RadarPrincipalExistingAccess `
                        -PrincipalId $principalId `
                        -PrincipalType $principalType `
                        -Holder $holder `
                        -HolderEvidence $holderEvidence `
                        -DirectoryEvidence $DirectoryEvidence `
                        -PrincipalAssignmentInventory (
                            $PrincipalAssignmentInventory
                        ) `
                        -EvaluationScope $evaluationScope `
                        -RestrictedAction (
                            $result.RestrictedAction
                        ) `
                        -GrantingRole $grantingRole `
                        -Hierarchy $Hierarchy `
                        -RoleByKey $roleByKey `
                        -ExistingAccessCache $ExistingAccessCache
                }
                $existingAccessStatus = $existingAccess.Status
                $principalEnabledStatus =
                    $existingAccess.PrincipalEnabledStatus
                $transitiveGroupIds = @(
                    $existingAccess.GroupIds
                )
                foreach ($warning in @($existingAccess.Warnings)) {
                    [void]$warnings.Add($warning)
                }

                $assignmentPolicyStatus = 'Unknown'
                $policyIntentEvidence = @()
                $policyWarnings = @()
                if ($existingAccessStatus -eq 'PrincipalMissing') {
                    $assignmentPolicyStatus = 'NotApplicable'
                    $policyIntentEvidence = @(
                        'Not applicable: principal directory object is missing.'
                    )
                }
                elseif ($existingAccessStatus -eq 'PrincipalDisabled') {
                    $assignmentPolicyStatus = 'NotApplicable'
                    $policyIntentEvidence = @(
                        'Not applicable: principal is disabled.'
                    )
                }
                elseif ($availablePaths.Count -eq 0) {
                    $assignmentPolicyStatus =
                        'NoBaselineReachablePath'
                    $policyIntentEvidence = @(
                        'Not applicable: no source-reachable assignment path.'
                    )
                }
                elseif (
                    $null -eq $grantingRole -or
                    [string]::IsNullOrWhiteSpace($principalId) -or
                    [string]::IsNullOrWhiteSpace($principalType) -or
                    $principalType -notin @(
                        'User',
                        'ServicePrincipal'
                    ) -or
                    $holder.SourceAssignmentConditioned -or
                    -not $holderEvidence.IsComplete
                ) {
                    $assignmentPolicyStatus = 'Unknown'
                    $policyIntentEvidence = @(
                        'Candidate-specific policy evidence is unavailable.'
                    )
                    if ($null -eq $grantingRole) {
                        [void]$warnings.Add(
                            'The granting role definition is unavailable.'
                        )
                    }
                }
                else {
                    $pathKey = Get-RadarAssignmentPathCacheKey `
                        -AssignmentPaths $availablePaths
                    $policyCacheKey = @(
                        $principalId.ToLowerInvariant(),
                        $principalType.ToLowerInvariant(),
                        $grantingRoleKey,
                        $contextKey,
                        $evaluationScope.ToLowerInvariant(),
                        $pathKey
                    ) -join [char]31
                    if (
                        -not $PrincipalPolicyCache.ContainsKey(
                            $policyCacheKey
                        )
                    ) {
                        $PrincipalPolicyCache[$policyCacheKey] =
                            Get-RadarRoleDenyCoverage `
                                -Role $grantingRole `
                                -RoleScopes @($evaluationScope) `
                                -PolicyInventory $PolicyInventory `
                                -DeniedRoleNames $DeniedRoleNames `
                                -DiscoveryComplete $DiscoveryComplete `
                                -ScopeHierarchy $Hierarchy `
                                -AssignmentPaths $availablePaths `
                                -TargetPrincipalType $principalType `
                                -TargetPrincipalId $principalId `
                                -PolicyEvaluationCache (
                                    $PolicyEvaluationCache
                                )
                    }
                    $principalCoverage =
                        $PrincipalPolicyCache[$policyCacheKey]
                    $principalScopeEvaluation = @(
                        $principalCoverage.ScopeEvaluations |
                            Where-Object {
                                [string]::Equals(
                                    [string]$_.Scope,
                                    $evaluationScope,
                                    [System.StringComparison]::OrdinalIgnoreCase
                                )
                            }
                    ) | Select-Object -First 1
                    $scopePolicyUnknownReasons = @(
                        @(
                            if ($principalScopeEvaluation) {
                                @(
                                    $principalScopeEvaluation.
                                        UnknownReasons
                                )
                            }
                        ) +
                        @($principalCoverage.UnknownReasons) |
                            Where-Object {
                                -not [string]::IsNullOrWhiteSpace($_)
                            } |
                            Sort-Object -Unique
                    )
                    $policyIntentEvidence = @(
                        if ($principalScopeEvaluation) {
                            @(
                                Get-RadarPropertyValue `
                                    -InputObject (
                                        $principalScopeEvaluation
                                    ) `
                                    -Name 'EvaluatedPolicies'
                            )
                        }
                    )
                    if ($policyIntentEvidence.Count -eq 0) {
                        $policyIntentEvidence = @(
                            if (
                                -not [bool](
                                    Get-RadarPropertyValue `
                                        -InputObject $PolicyInventory `
                                        -Name 'IsEvaluated'
                                )
                            ) {
                                'Role-assignment policy was not evaluated for this principal, role and path.'
                            }
                            elseif (
                                $scopePolicyUnknownReasons.Count -gt 0
                            ) {
                                'Role-assignment policy evidence is incomplete for this principal, role and path.'
                            }
                            else {
                                'No applicable role-assignment deny policy was evaluated for this principal, role and path.'
                            }
                        )
                    }
                    elseif (
                        $scopePolicyUnknownReasons.Count -gt 0
                    ) {
                        $policyIntentEvidence +=
                            'Role-assignment policy evidence is incomplete for this principal, role and path.'
                    }
                    if (
                        $principalScopeEvaluation -and
                        $principalScopeEvaluation.GapStatus -eq 'Gap' -and
                        $scopePolicyUnknownReasons.Count -eq 0 -and
                        @(
                            $principalScopeEvaluation.
                                UnknownBaselineAssignablePaths
                        ).Count -eq 0 -and
                        @(
                            $principalScopeEvaluation.
                                BaselineAssignablePaths
                        ).Count -gt 0
                    ) {
                        $assignmentPolicyStatus = 'Permitted'
                    }
                    elseif (
                        $principalScopeEvaluation -and
                        $principalScopeEvaluation.GapStatus -eq 'Covered'
                    ) {
                        $assignmentPolicyStatus = 'Blocked'
                    }
                    else {
                        $assignmentPolicyStatus = 'Unknown'
                    }
                    $policyWarnings = $scopePolicyUnknownReasons
                    foreach ($warning in $policyWarnings) {
                        [void]$warnings.Add($warning)
                    }
                }

                $netNewGapStatus = if (
                    $existingAccessStatus -eq 'AlreadyHasAction'
                ) {
                    'AlreadyHasAction'
                }
                elseif (
                    $existingAccessStatus -eq 'PrincipalMissing'
                ) {
                    'PrincipalMissing'
                }
                elseif (
                    $existingAccessStatus -eq 'PrincipalDisabled'
                ) {
                    'PrincipalDisabled'
                }
                elseif ($existingAccessStatus -eq 'Unknown') {
                    'Unknown'
                }
                elseif (
                    $assignmentPolicyStatus -eq
                    'NoBaselineReachablePath'
                ) {
                    'NoBaselineReachablePath'
                }
                elseif ($assignmentPolicyStatus -eq 'Blocked') {
                    'PolicyBlocked'
                }
                elseif ($assignmentPolicyStatus -eq 'Permitted') {
                    'NetNewGap'
                }
                else {
                    'Unknown'
                }
                $rowKey = @(
                    $principalId,
                    $principalType,
                    $result.BaselineRoleId,
                    $result.BaselineScope,
                    $evaluationScope,
                    $result.RestrictedAction,
                    $result.RoleId
                ) -join [char]31
                if (-not $rowKeys.Add($rowKey)) { continue }
                [void]$rows.Add([pscustomobject]@{
                    PrincipalId = $principalId
                    PrincipalType = $principalType
                    SourcePrincipalId =
                        [string]$holder.SourcePrincipalId
                    SourceViaGroup =
                        [bool]$holder.SourceViaGroup
                    BaselineRoleName = $result.BaselineRoleName
                    BaselineRoleId = $result.BaselineRoleId
                    BaselineScope = $result.BaselineScope
                    SourceAssignmentScopes = @(
                        $holder.SourceAssignmentScopes
                    ) -join '; '
                    EvaluationScope = $evaluationScope
                    RestrictedAction = $result.RestrictedAction
                    GrantingRoleName = $result.RoleName
                    GrantingRoleId = $result.RoleId
                    PrincipalEnabledStatus =
                        $principalEnabledStatus
                    TransitiveGroupCount =
                        $transitiveGroupIds.Count
                    ExistingAccessStatus = $existingAccessStatus
                    AssignmentPolicyStatus =
                        $assignmentPolicyStatus
                    PolicyIntentEvidence =
                        $policyIntentEvidence -join '; '
                    NetNewGapStatus = $netNewGapStatus
                    AvailableAssignmentPaths = @(
                        $availablePaths |
                            ForEach-Object {
                                "$($_.Name) [$($_.ResourceType)]"
                            } |
                            Sort-Object -Unique
                    ) -join '; '
                    EvidenceModel =
                        'Microsoft Graph enabled state, source Group expansion and transitive groups plus visible effective direct RBAC'
                    Warnings = @(
                        $warnings |
                            Where-Object {
                                -not [string]::IsNullOrWhiteSpace($_)
                            } |
                            Sort-Object -Unique
                    ) -join '; '
                })
            }
        }
    }
    return @(
        $rows.ToArray() |
            Sort-Object `
                BaselineRoleName,
                BaselineScope,
                EvaluationScope,
                PrincipalType,
                PrincipalId,
                RestrictedAction,
                GrantingRoleName
    )
}

function Get-RadarPrincipalGapCsvPath {
    param(
        [Parameter(Mandatory = $true)]
        [string]$MatchCsvPath
    )

    $directory = Split-Path -Parent $MatchCsvPath
    $fileName = (
        [System.IO.Path]::GetFileNameWithoutExtension($MatchCsvPath) +
        '-principal-gaps.csv'
    )
    if ($directory) {
        return Join-Path $directory $fileName
    }
    return $fileName
}

function Add-RadarPrincipalGapSummary {
    param(
        [AllowEmptyCollection()]
        [object[]]$Rows,
        [AllowEmptyCollection()]
        [object[]]$PrincipalGaps
    )

    $principalRowsByKey = @{}
    foreach ($principalGap in $PrincipalGaps) {
        $key = @(
            [string]$principalGap.BaselineRoleId,
            ([string]$principalGap.BaselineScope).TrimEnd('/'),
            ([string]$principalGap.EvaluationScope).TrimEnd('/'),
            [string]$principalGap.RestrictedAction
        ) -join [char]31
        if (-not $principalRowsByKey.ContainsKey($key)) {
            $principalRowsByKey[$key] =
                New-Object System.Collections.Generic.List[object]
        }
        [void]$principalRowsByKey[$key].Add($principalGap)
    }
    foreach ($row in $Rows) {
        $key = @(
            [string]$row.BaselineRoleId,
            ([string]$row.BaselineScope).TrimEnd('/'),
            ([string]$row.EvaluationScope).TrimEnd('/'),
            [string]$row.RestrictedAction
        ) -join [char]31
        $principalRows = @(
            if ($principalRowsByKey.ContainsKey($key)) {
                $principalRowsByKey[$key].ToArray()
            }
        )
        $netNewRows = @(
            $principalRows |
                Where-Object {
                    $_.NetNewGapStatus -eq 'NetNewGap'
                }
        )
        $unknownRows = @(
            $principalRows |
                Where-Object {
                    $_.NetNewGapStatus -eq 'Unknown'
                }
        )
        $missingRows = @(
            $principalRows |
                Where-Object {
                    $_.NetNewGapStatus -eq 'PrincipalMissing'
                }
        )
        $principalStatus = if ($netNewRows.Count -gt 0) {
            'NetNewGap'
        }
        elseif ($unknownRows.Count -gt 0) {
            'Unknown'
        }
        elseif (
            $principalRows.Count -gt 0 -and
            $missingRows.Count -eq $principalRows.Count
        ) {
            'PrincipalMissing'
        }
        elseif ($principalRows.Count -eq 0) {
            if ($row.BaselineAssignmentState -eq 'NoDirectAssignment') {
                'NoObservedHolder'
            }
            else {
                'Unknown'
            }
        }
        else {
            'NoNetNewGap'
        }
        $propertyValues = @{
            PrincipalGapStatus = $principalStatus
            NetNewGapActionCount = if ($netNewRows.Count -gt 0) {
                1
            }
            else {
                0
            }
            NetNewGapPrincipalCount = @(
                $netNewRows |
                    ForEach-Object { $_.PrincipalId } |
                    Where-Object {
                        -not [string]::IsNullOrWhiteSpace($_)
                    } |
                    Sort-Object -Unique
            ).Count
            NetNewGapPrincipals = @(
                $netNewRows |
                    Where-Object {
                        -not [string]::IsNullOrWhiteSpace(
                            [string]$_.PrincipalId
                        )
                    } |
                    ForEach-Object {
                        "$($_.PrincipalId) [$($_.PrincipalType)]"
                    } |
                    Sort-Object -Unique
            ) -join '; '
            NetNewGapRoleCount = @(
                $netNewRows |
                    ForEach-Object { $_.GrantingRoleId } |
                    Sort-Object -Unique
            ).Count
            NetNewGapRoles = @(
                $netNewRows |
                    ForEach-Object {
                        "$($_.GrantingRoleName) [$($_.GrantingRoleId)]"
                    } |
                    Sort-Object -Unique
            ) -join '; '
            NetNewGapPolicies = @(
                $netNewRows |
                    ForEach-Object {
                        [string](
                            Get-RadarPropertyValue `
                                -InputObject $_ `
                                -Name 'PolicyIntentEvidence'
                        ) -split '; '
                    } |
                    Where-Object {
                        -not [string]::IsNullOrWhiteSpace($_)
                    } |
                    Sort-Object -Unique
            ) -join '; '
            NetNewGapPaths = @(
                $netNewRows |
                    ForEach-Object {
                        $policy = if (
                            [string]::IsNullOrWhiteSpace(
                                [string](
                                    Get-RadarPropertyValue `
                                        -InputObject $_ `
                                        -Name 'PolicyIntentEvidence'
                                )
                            )
                        ) {
                            'Policy evidence unavailable'
                        }
                        else {
                            [string](
                                Get-RadarPropertyValue `
                                    -InputObject $_ `
                                    -Name 'PolicyIntentEvidence'
                            )
                        }
                        "$($_.PrincipalId) [$($_.PrincipalType)] -> $($_.RestrictedAction) via $($_.GrantingRoleName) [$($_.GrantingRoleId)] | Policy: $policy"
                    } |
                    Sort-Object -Unique
            ) -join ' || '
            UnknownPrincipalCount = @(
                $unknownRows |
                    ForEach-Object { $_.PrincipalId } |
                    Where-Object {
                        -not [string]::IsNullOrWhiteSpace($_)
                    } |
                    Sort-Object -Unique
            ).Count
            UnknownPrincipalRowCount = $unknownRows.Count
            UnknownPrincipals = @(
                $unknownRows |
                    Where-Object {
                        -not [string]::IsNullOrWhiteSpace(
                            [string]$_.PrincipalId
                        )
                    } |
                    ForEach-Object {
                        "$($_.PrincipalId) [$($_.PrincipalType)]"
                    } |
                    Sort-Object -Unique
            ) -join '; '
            MissingPrincipalCount = @(
                $missingRows |
                    ForEach-Object { $_.PrincipalId } |
                    Where-Object {
                        -not [string]::IsNullOrWhiteSpace($_)
                    } |
                    Sort-Object -Unique
            ).Count
            MissingPrincipalRowCount = $missingRows.Count
            MissingPrincipals = @(
                $missingRows |
                    Where-Object {
                        -not [string]::IsNullOrWhiteSpace(
                            [string]$_.PrincipalId
                        )
                    } |
                    ForEach-Object {
                        "$($_.PrincipalId) [$($_.PrincipalType)]"
                    } |
                    Sort-Object -Unique
            ) -join '; '
            PrincipalGapWarnings = @(
                $principalRows |
                    ForEach-Object {
                        [string]$_.Warnings -split '; '
                    } |
                    Where-Object {
                        -not [string]::IsNullOrWhiteSpace($_)
                    } |
                    Sort-Object -Unique
            ) -join '; '
        }
        foreach ($propertyName in $propertyValues.Keys) {
            $property = $row.PSObject.Properties[$propertyName]
            if ($null -ne $property) {
                $property.Value = $propertyValues[$propertyName]
            }
            else {
                $row.PSObject.Properties.Add(
                    [System.Management.Automation.PSNoteProperty]::new(
                        $propertyName,
                        $propertyValues[$propertyName]
                    )
                )
            }
        }
    }
    return $Rows
}

function Export-RadarPrincipalGap {
    param(
        [AllowEmptyCollection()]
        [object[]]$Rows,
        [Parameter(Mandatory = $true)]
        [string]$Path
    )

    $suffix = ".tmp.$PID.$([guid]::NewGuid().ToString('N'))"
    $tempPath = "$Path$suffix"
    try {
        if (@($Rows).Count -gt 0) {
            $Rows |
                Select-Object `
                    PrincipalId,
                    PrincipalType,
                    SourcePrincipalId,
                    SourceViaGroup,
                    BaselineRoleName,
                    BaselineRoleId,
                    BaselineScope,
                    SourceAssignmentScopes,
                    EvaluationScope,
                    RestrictedAction,
                    GrantingRoleName,
                    GrantingRoleId,
                    PrincipalEnabledStatus,
                    TransitiveGroupCount,
                    ExistingAccessStatus,
                    AssignmentPolicyStatus,
                    PolicyIntentEvidence,
                    NetNewGapStatus,
                    AvailableAssignmentPaths,
                    EvidenceModel,
                    Warnings |
                Export-Csv `
                    -LiteralPath $tempPath `
                    -NoTypeInformation
        }
        else {
            Set-Content `
                -LiteralPath $tempPath `
                -Encoding UTF8 `
                -Value '"PrincipalId","PrincipalType","SourcePrincipalId","SourceViaGroup","BaselineRoleName","BaselineRoleId","BaselineScope","SourceAssignmentScopes","EvaluationScope","RestrictedAction","GrantingRoleName","GrantingRoleId","PrincipalEnabledStatus","TransitiveGroupCount","ExistingAccessStatus","AssignmentPolicyStatus","PolicyIntentEvidence","NetNewGapStatus","AvailableAssignmentPaths","EvidenceModel","Warnings"'
        }
        Move-Item `
            -LiteralPath $tempPath `
            -Destination $Path `
            -Force
    }
    finally {
        if (Test-Path -LiteralPath $tempPath) {
            Remove-Item -LiteralPath $tempPath -Force
        }
    }
}


# --- Main ---------------------------------------------------------------

Connect-RadarAzAccount

$csvActions = @()
if ($InputCsv) {
    $csvActions = @(
        Import-RadarRestrictedActionCsv -Path $InputCsv
    )

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

Write-Host 'Discovering Azure estate scopes...'
$scopeDiscovery = Get-RadarScanScope `
    -ExplicitScope $Scope `
    -ManagementGroup $ManagementGroup `
    -CurrentSubscriptionOnly:$CurrentSubscriptionOnly
$scanScopes = @($scopeDiscovery.Scopes)
Write-Host "  Scopes discovered:    $($scanScopes.Count)"
Write-Host "    Management groups:  $(@($scanScopes | Where-Object { $_.Type -eq 'ManagementGroup' }).Count)"
Write-Host "    Subscriptions:      $(@($scanScopes | Where-Object { $_.Type -eq 'Subscription' }).Count)"

Write-Host 'Fetching Azure role definitions...'
$roleInventory = Get-RadarRoleInventory `
    -Scopes $scanScopes `
    -BuiltInOnly:$BuiltInOnly `
    -UseTenantDiscovery:(
        $scopeDiscovery.DiscoveryMode -eq 'Estate'
    )
$roles = @($roleInventory.Roles)
$builtInRoles = @($roleInventory.BuiltInRoles)
$customRoles = @($roleInventory.CustomRoles)
Write-Host "  Built-in roles found: $($builtInRoles.Count)"
Write-Host "  Custom roles found:   $($customRoles.Count) ($($roleInventory.CustomRoleSource))"

if ($roles.Count -eq 0) {
    throw 'No role definitions were discovered. Check the Azure context and read access.'
}
if (
    @(
        $roles |
            Where-Object {
                @(Get-RoleProperty -Role $_ -Name 'Actions').Count -gt 0
            }
    ).Count -eq 0
) {
    throw 'Role definitions were returned without readable Actions. Check the installed Az.Resources version and object shape.'
}

# Build one scope universe containing the estate hierarchy and every explicit
# custom-role AssignableScope. Baseline subtrees and granting-role availability
# are derived from this same index.
$knownScopeById = @{}
foreach ($scanScope in $scanScopes) {
    $knownScopeById[$scanScope.Id.TrimEnd('/').ToLowerInvariant()] =
        $scanScope
}
foreach ($customRole in $customRoles) {
    foreach (
        $assignableScope in @(
            Get-RadarPropertyValue `
                -InputObject $customRole `
                -Name 'AssignableScopes' |
                Where-Object {
                    -not [string]::IsNullOrWhiteSpace($_)
                }
        )
    ) {
        $normalisedScope = ([string]$assignableScope).TrimEnd('/')
        if ([string]::IsNullOrWhiteSpace($normalisedScope)) {
            $normalisedScope = '/'
        }
        $key = $normalisedScope.ToLowerInvariant()
        if (-not $knownScopeById.ContainsKey($key)) {
            $knownScopeById[$key] =
                New-RadarScope -Id $normalisedScope
        }
    }
}

$policyBoundaryInventory = Get-RadarPolicyBoundaryScope `
    -Scopes $scanScopes `
    -UseTenantDiscovery:(
        $scopeDiscovery.DiscoveryMode -eq 'Estate'
    ) `
    -NoPolicyDiscovery:$NoPolicyDiscovery
foreach ($boundaryScope in $policyBoundaryInventory.Scopes) {
    $knownScopeById[
        $boundaryScope.Id.TrimEnd('/').ToLowerInvariant()
    ] = $boundaryScope
}

$scopeHierarchy = Get-RadarScopeHierarchy `
    -KnownScopes @($knownScopeById.Values) `
    -RequiredScopes $scanScopes
foreach ($hierarchyScope in $scopeHierarchy.Scopes) {
    $knownScopeById[
        $hierarchyScope.Id.TrimEnd('/').ToLowerInvariant()
    ] = $hierarchyScope
}
$accessibleSubscriptionIds =
    New-Object System.Collections.Generic.HashSet[string] (
        [StringComparer]::OrdinalIgnoreCase
    )
$hasRequestedManagementGroup = @(
    $scanScopes |
        Where-Object { $_.Type -eq 'ManagementGroup' }
).Count -gt 0
foreach ($requestedScope in $scanScopes) {
    $subscriptionMatch = [regex]::Match(
        $requestedScope.Id,
        '(?i)^/subscriptions/([^/]+)'
    )
    if ($subscriptionMatch.Success) {
        [void]$accessibleSubscriptionIds.Add(
            $subscriptionMatch.Groups[1].Value
        )
    }
}
if ($hasRequestedManagementGroup) {
    $requestedManagementGroupIds = @(
        $scanScopes |
            Where-Object { $_.Type -eq 'ManagementGroup' } |
            ForEach-Object { $_.Id.TrimEnd('/') }
    )
    foreach (
        $hierarchySubscription in @(
            $scopeHierarchy.Scopes |
                Where-Object { $_.Type -eq 'Subscription' }
        )
    ) {
        $subscriptionKey =
            $hierarchySubscription.Id.TrimEnd('/').ToLowerInvariant()
        if (
            -not $scopeHierarchy.AncestorsByScope.ContainsKey(
                $subscriptionKey
            )
        ) {
            continue
        }
        $isRequestedDescendant = @(
            $scopeHierarchy.AncestorsByScope[$subscriptionKey] |
                Where-Object {
                    $ancestor = [string]$_
                    @(
                        $requestedManagementGroupIds |
                            Where-Object {
                                [string]::Equals(
                                    $_,
                                    $ancestor,
                                    [System.StringComparison]::OrdinalIgnoreCase
                                )
                            }
                    ).Count -gt 0
                }
        ).Count -gt 0
        if ($isRequestedDescendant) {
            [void]$accessibleSubscriptionIds.Add(
                ($hierarchySubscription.Id -split '/')[2]
            )
        }
    }
}
$externalScopeKeys = @(
    foreach ($knownScopeKey in @($knownScopeById.Keys)) {
        $subscriptionMatch = [regex]::Match(
            $knownScopeById[$knownScopeKey].Id,
            '(?i)^/subscriptions/([^/]+)'
        )
        if (
            $subscriptionMatch.Success -and
            -not $accessibleSubscriptionIds.Contains(
                $subscriptionMatch.Groups[1].Value
            )
        ) {
            $knownScopeKey
        }
    }
)
foreach ($externalScopeKey in $externalScopeKeys) {
    $knownScopeById.Remove($externalScopeKey)
}
if ($externalScopeKeys.Count -gt 0) {
    Write-Host "  Excluded scopes outside the active tenant subscription set: $($externalScopeKeys.Count)"
}

$scopeLimitWarnings = New-Object System.Collections.Generic.List[string]
if ($scopeDiscovery.DiscoveryMode -ne 'Estate') {
    $limitedScopeById = @{}
    foreach ($candidateScope in $knownScopeById.Values) {
        $includeCandidate = $false
        foreach ($requestedRoot in $scanScopes) {
            $relationship = Test-RadarScopeDescendsFrom `
                -Scope $candidateScope.Id `
                -RootScope $requestedRoot.Id `
                -Hierarchy $scopeHierarchy
            if ($relationship.State -eq 'True') {
                $includeCandidate = $true
                break
            }
            if ($relationship.State -eq 'Unknown') {
                [void]$scopeLimitWarnings.Add(
                    "Scope '$($candidateScope.Id)' was excluded from the limited scan because its relationship to requested root '$($requestedRoot.Id)' could not be resolved."
                )
            }
        }
        if ($includeCandidate) {
            $limitedScopeById[
                $candidateScope.Id.TrimEnd('/').ToLowerInvariant()
            ] = $candidateScope
        }
    }
    foreach ($requestedRoot in $scanScopes) {
        $limitedScopeById[
            $requestedRoot.Id.TrimEnd('/').ToLowerInvariant()
        ] = $requestedRoot
    }
    $knownScopeById = $limitedScopeById
}
$knownScopes = @($knownScopeById.Values | Sort-Object Type, Id)
$scopeLimitComplete = $scopeLimitWarnings.Count -eq 0

# Dynamic restrictions remain partitioned by baseline role and exact
# AssignableScope. CSV restrictions retain their separate estate-wide audit.
$dynamicActions = @()
$dynamicSourceRoleNames = @()
$baselineContextInventory = [pscustomobject]@{
    Contexts = @()
    IsComplete = $true
    Warnings = @()
}
if ($DynamicRestrictedActions) {
    $baselineSelection = Get-RadarBaselineRole `
        -Roles $customRoles `
        -Pattern $BaselineRolePattern
    $sourceRoles = @($baselineSelection.Roles)
    $dynamicSourceRoleNames = @(
        $sourceRoles |
            ForEach-Object {
                Get-RadarPropertyValue -InputObject $_ -Name 'Name'
            } |
            Sort-Object
    )
    $baselineContextInventory = Get-RadarBaselineContext `
        -BaselineRoles $sourceRoles `
        -KnownScopes $knownScopes `
        -Hierarchy $scopeHierarchy
    $dynamicActions = @(
        $baselineContextInventory.Contexts |
            ForEach-Object { $_.RestrictedActions } |
            Sort-Object -Unique
    )

    if ($sourceRoles.Count -eq 0) {
        if ($BaselineRolePattern.Count -gt 0) {
            Write-Warning "Dynamic mode: no custom wildcard roles matched the explicit baseline pattern(s): $($BaselineRolePattern -join ', ')."
        }
        else {
            Write-Warning 'Dynamic mode: no usable Owner/Contributor/Baseline wildcard roles were auto-detected.'
        }
    }
    else {
        $selectionLabel = if (
            $baselineSelection.SelectionMode -eq 'Automatic'
        ) {
            'auto-selected'
        }
        else {
            'pattern-matched'
        }
        Write-Host "  Baseline roles:       $($sourceRoles.Count) $selectionLabel role(s)"
        Write-Host "  Baseline contexts:    $($baselineContextInventory.Contexts.Count) role/AssignableScope pair(s)"
        Write-Host "  Dynamic actions:      $($dynamicActions.Count) unique NotAction(s)"
        foreach ($sourceRoleName in $dynamicSourceRoleNames) {
            Write-Host "    - $sourceRoleName"
        }
    }

    if (
        $dynamicActions.Count -eq 0 -and
        $csvActions.Count -eq 0 -and
        $BaselineRolePattern.Count -eq 0 -and
        (Test-Path -LiteralPath $defaultInputCsv)
    ) {
        $csvActions = @(
            Import-RadarRestrictedActionCsv -Path $defaultInputCsv
        )
        $InputCsv = $defaultInputCsv
        Write-Warning "Dynamic derivation produced no actions; falling back to bundled input CSV $defaultInputCsv."
    }
}

Write-Host 'Correlating direct baseline-role assignments...'
$baselineAssignmentInventory =
    Get-RadarBaselineRoleAssignmentInventory `
        -BaselineContexts $baselineContextInventory.Contexts `
        -NoAssignmentDiscovery:$NoAssignmentDiscovery
$baselineAssignmentEvidence =
    Get-RadarBaselineAssignmentEvidenceMap `
        -BaselineContexts $baselineContextInventory.Contexts `
        -AssignmentInventory $baselineAssignmentInventory `
        -Hierarchy $scopeHierarchy
$relevantBaselineAssignmentCount =
    Get-RadarRelevantBaselineAssignmentCount `
        -EvidenceByKey $baselineAssignmentEvidence
Write-Host (
    '  Relevant direct assignments discovered: ' +
    $relevantBaselineAssignmentCount +
    ' (' +
    $baselineAssignmentInventory.Source +
    ')'
)
foreach ($assignmentWarning in $baselineAssignmentInventory.Warnings) {
    Write-Warning $assignmentWarning
}

Write-Host 'Resolving source-holder directory evidence...'
$principalDirectoryEvidence =
    Get-RadarPrincipalDirectoryEvidence `
        -BaselineAssignmentInventory $baselineAssignmentInventory `
        -NoPrincipalCorrelation:$NoPrincipalCorrelation
Write-Host (
    '  Transitive groups discovered: ' +
    @($principalDirectoryEvidence.GroupIds).Count +
    ' (' +
    $principalDirectoryEvidence.Source +
    ')'
)
foreach (
    $directoryWarning in
        $principalDirectoryEvidence.Warnings
) {
    Write-Warning $directoryWarning
}

Write-Host 'Correlating source-holder direct RBAC assignments...'
$principalAssignmentInventory =
    Get-RadarPrincipalRoleAssignmentInventory `
        -BaselineAssignmentInventory $baselineAssignmentInventory `
        -DirectoryEvidence $principalDirectoryEvidence `
        -NoPrincipalCorrelation:$NoPrincipalCorrelation
Write-Host (
    '  Principal direct assignments discovered: ' +
    $principalAssignmentInventory.AssignmentCount +
    ' (' +
    $principalAssignmentInventory.Source +
    ')'
)
foreach (
    $principalAssignmentWarning in
        $principalAssignmentInventory.Warnings
) {
    Write-Warning $principalAssignmentWarning
}

$restrictedActions = @(
    @($csvActions) + @($dynamicActions) |
        Where-Object {
            -not [string]::IsNullOrWhiteSpace($_)
        } |
        ForEach-Object { $_.Trim() } |
        Sort-Object -Unique
)
if ($restrictedActions.Count -eq 0) {
    throw 'No restricted actions to evaluate. Provide -InputCsv, broaden -BaselineRolePattern, or ensure an Owner/Contributor/Baseline wildcard role is visible.'
}
Write-Host "Total restricted actions to evaluate: $($restrictedActions.Count)"

$policyScopeById = @{}
if ($csvActions.Count -gt 0) {
    foreach ($knownScope in $knownScopes) {
        $policyScopeById[
            $knownScope.Id.TrimEnd('/').ToLowerInvariant()
        ] = $knownScope
    }
}
foreach ($baselineContext in $baselineContextInventory.Contexts) {
    foreach ($evaluationScope in $baselineContext.EvaluationScopes) {
        $policyScopeById[
            $evaluationScope.Id.TrimEnd('/').ToLowerInvariant()
        ] = $evaluationScope
    }
}
$policyScopes = @($policyScopeById.Values | Sort-Object Type, Id)

Write-Host "Discovering effective deny policies across $($policyScopes.Count) evaluation scope(s)..."
$policyInventory = Get-RadarPolicyInventory `
    -Scopes $policyScopes `
    -NoPolicyDiscovery:$NoPolicyDiscovery
$boundaryUncertainScopes =
    New-Object System.Collections.Generic.HashSet[string] (
        [StringComparer]::OrdinalIgnoreCase
    )
foreach ($uncertainRoot in $policyBoundaryInventory.UncertainRootScopes) {
    foreach ($policyScope in $policyScopes) {
        $relationship = Test-RadarScopeDescendsFrom `
            -Scope $policyScope.Id `
            -RootScope $uncertainRoot `
            -Hierarchy $scopeHierarchy
        if ($relationship.State -ne 'False') {
            $normalisedScope = $policyScope.Id.TrimEnd('/')
            if ([string]::IsNullOrWhiteSpace($normalisedScope)) {
                $normalisedScope = '/'
            }
            [void]$boundaryUncertainScopes.Add(
                $normalisedScope.ToLowerInvariant()
            )
        }
    }
}
$policyInventory.UncertainScopes = @(
    @($policyInventory.UncertainScopes) +
    @($boundaryUncertainScopes) |
        Sort-Object -Unique
)
if ($policyInventory.IsEvaluated) {
    Write-Host "  Policy assignments:   $($policyInventory.AssignmentCount)"
    Write-Host "  Role-deny rules:      $($policyInventory.RelevantRuleCount)"
    Write-Host "  Active exemptions:   $($policyInventory.ExemptionCount)"
}
else {
    Write-Host '  Live policy discovery disabled.'
}

Write-Host "Assignment subject:    $targetPrincipalScenario"
Write-Host "Evaluating $($roles.Count) role(s)..."
$baseDiscoveryComplete =
    $scopeDiscovery.IsComplete -and
    $scopeLimitComplete -and
    $roleInventory.IsComplete
$matchCache = @{}
$coverageCache = @{}
$availabilityCache = @{}
$policyEvaluationCache = @{}
$results = New-Object System.Collections.Generic.List[object]
$runtimeWarnings = New-Object System.Collections.Generic.List[string]
$analysisContextCount =
    $baselineContextInventory.Contexts.Count +
    $(if ($csvActions.Count -gt 0) { 1 } else { 0 })
$progressState = [pscustomobject]@{
    Processed = 0
    Total = $roles.Count * $analysisContextCount
    NextConsolePercent = 5
    Stopwatch = [System.Diagnostics.Stopwatch]::StartNew()
}
$earlyOutputDir = Split-Path -Parent $OutputCsv
if (
    $earlyOutputDir -and
    -not (Test-Path -LiteralPath $earlyOutputDir)
) {
    New-Item `
        -ItemType Directory `
        -Path $earlyOutputDir `
        -Force |
        Out-Null
}
$partialOutputCsv = "$OutputCsv.partial"
$coverageOutputCsv = Get-RadarCoverageCsvPath -MatchCsvPath $OutputCsv
$scopeMapOutputCsv = Get-RadarScopeMapCsvPath -MatchCsvPath $OutputCsv
$principalGapOutputCsv =
    Get-RadarPrincipalGapCsvPath -MatchCsvPath $OutputCsv
$partialCoverageCsv = "$coverageOutputCsv.partial"

$getMatch = {
    param(
        [object]$Role,
        [string]$Action
    )
    $roleKey = Get-RadarRoleKey -Role $Role
    $key = "$roleKey$([char]31)$($Action.ToLowerInvariant())"
    if (-not $matchCache.ContainsKey($key)) {
        $matchCache[$key] = Get-ActionMatch `
            -Role $Role `
            -Action $Action
    }
    return $matchCache[$key]
}

$getAvailability = {
    param(
        [object]$Role,
        [object[]]$ContextScopes,
        [string]$ContextKey
    )
    $roleKey = Get-RadarRoleKey -Role $Role
    $key = "$ContextKey$([char]31)$roleKey"
    if (-not $availabilityCache.ContainsKey($key)) {
        $availabilityCache[$key] =
            Get-RadarRoleScopesInContext `
                -Role $Role `
                -ContextScopes $ContextScopes `
                -Hierarchy $scopeHierarchy
    }
    return $availabilityCache[$key]
}

$getCoverage = {
    param(
        [object]$Role,
        [object]$Availability,
        [string]$ContextKey,
        [bool]$ContextComplete,
        [object[]]$AssignmentPaths = @()
    )
    $roleKey = Get-RadarRoleKey -Role $Role
    $pathKey = Get-RadarAssignmentPathCacheKey `
        -AssignmentPaths $AssignmentPaths
    $key = "$ContextKey$([char]31)$roleKey$([char]31)$pathKey$([char]31)$ContextComplete"
    if (-not $coverageCache.ContainsKey($key)) {
        $coverage = Get-RadarRoleDenyCoverage `
            -Role $Role `
            -RoleScopes @(
                $Availability.Scopes |
                    ForEach-Object { $_.Id }
            ) `
            -PolicyInventory $policyInventory `
            -DeniedRoleNames $deniedRoleSet `
            -DiscoveryComplete (
                $baseDiscoveryComplete -and
                $ContextComplete -and
                $Availability.IsComplete
            ) `
            -ScopeHierarchy $scopeHierarchy `
            -AssignmentPaths $AssignmentPaths `
            -TargetPrincipalType $TargetPrincipalType `
            -TargetPrincipalId $effectiveTargetPrincipalId `
            -PolicyEvaluationCache $policyEvaluationCache
        $coverageCache[$key] = $coverage
    }
    return $coverageCache[$key]
}

$addResult = {
    param(
        [string]$AnalysisMode,
        [string]$BaselineRoleName,
        [string]$BaselineRoleId,
        [string]$BaselineScope,
        [string]$RestrictionSource,
        [string]$AssignmentPath,
        [object]$Role,
        [string]$Action,
        [object]$Match,
        [object]$Coverage,
        [string[]]$AdditionalWarnings = @()
    )

    $roleId = [string](
        Get-RadarPropertyValue `
            -InputObject $Role `
            -Name 'Id'
    )
    $exportCoverageKey = Get-RadarCoverageKey `
        -AnalysisMode $AnalysisMode `
        -BaselineRoleId $BaselineRoleId `
        -BaselineScope $BaselineScope `
        -RoleId $roleId `
        -AssignmentPath $AssignmentPath `
        -AdditionalWarnings $AdditionalWarnings

    [void]$results.Add([pscustomobject]@{
        AnalysisMode = $AnalysisMode
        BaselineRoleName = $BaselineRoleName
        BaselineRoleId = $BaselineRoleId
        BaselineScope = $BaselineScope
        RestrictionSource = $RestrictionSource
        AssignmentPath = $AssignmentPath
        RoleName = Get-RadarPropertyValue `
            -InputObject $Role `
            -Name 'Name'
        RoleId = $roleId
        IsCustom = [bool](
            Get-RadarPropertyValue `
                -InputObject $Role `
                -Name 'IsCustom'
        )
        RestrictedAction = $Action
        MatchedPattern = $Match.MatchedPattern
        CoverageKey = $exportCoverageKey
        IsAlreadyDenied = $Coverage.IsAlreadyDenied
        DenyCoverage = $Coverage.Status
        DeniedScopeCount = $Coverage.DeniedScopeCount
        EvaluatedScopeCount = $Coverage.ScopeCount
        BlockingPolicyCount = @($Coverage.BlockingPolicies).Count
        UnblockedScopeCount = @($Coverage.UnblockedScopes).Count
        UnblockedAssignmentPathCount =
            @($Coverage.UnblockedAssignmentPaths).Count
        CoverageWarningCount = @(
            @($Coverage.UnknownReasons) +
            @($AdditionalWarnings) |
                Where-Object {
                    -not [string]::IsNullOrWhiteSpace($_)
                } |
                Sort-Object -Unique
        ).Count
        BlockingPolicies = $Coverage.BlockingPolicies -join '; '
        DeniedScopes = $Coverage.DeniedScopes -join '; '
        UnblockedScopes = $Coverage.UnblockedScopes -join '; '
        UnblockedAssignmentPaths =
            $Coverage.UnblockedAssignmentPaths -join '; '
        CoverageWarnings = @(
            @($Coverage.UnknownReasons) +
            @($AdditionalWarnings) |
                Where-Object {
                    -not [string]::IsNullOrWhiteSpace($_)
                } |
                Sort-Object -Unique
        ) -join '; '
        ScopeEvaluations = @(
            Get-RadarPropertyValue `
                -InputObject $Coverage `
                -Name 'ScopeEvaluations'
        )
    })
}

# Baseline-specific analysis: each source role keeps its own NotActions and
# subtree. Roles and policy coverage are intersected with that subtree before
# any summary is calculated.
foreach ($baselineContext in $baselineContextInventory.Contexts) {
    $contextKey =
        "subtree:$($baselineContext.BaselineScope.ToLowerInvariant())"
    foreach ($role in $roles) {
        $matchedActions =
            New-Object System.Collections.Generic.List[object]
        foreach ($action in $baselineContext.RestrictedActions) {
            $match = & $getMatch $role $action
            if ($null -ne $match) {
                [void]$matchedActions.Add([pscustomobject]@{
                    Action = $action
                    Match = $match
                })
            }
        }
        if ($matchedActions.Count -eq 0) {
            Update-RadarAnalysisProgress `
                -State $progressState `
                -CurrentContext $baselineContext.BaselineRoleName
            continue
        }

        $availability = & $getAvailability `
            $role `
            $baselineContext.EvaluationScopes `
            $contextKey
        foreach ($warning in $availability.Warnings) {
            [void]$runtimeWarnings.Add(
                "$($baselineContext.BaselineRoleName) at $($baselineContext.BaselineScope): $warning"
            )
        }
        if (@($availability.Scopes).Count -eq 0) {
            Update-RadarAnalysisProgress `
                -State $progressState `
                -CurrentContext $baselineContext.BaselineRoleName
            continue
        }

        $coverage = & $getCoverage `
            $role `
            $availability `
            $contextKey `
            $baselineContext.IsComplete `
            $baselineContext.AssignmentPaths
        foreach ($matchedAction in $matchedActions) {
            & $addResult `
                'BaselineNotActions' `
                $baselineContext.BaselineRoleName `
                $baselineContext.BaselineRoleId `
                $baselineContext.BaselineScope `
                'Baseline role NotActions' `
                $baselineContext.AssignmentPath `
                $role `
                $matchedAction.Action `
                $matchedAction.Match `
                $coverage `
                $baselineContext.RestrictionWarnings
        }
        Update-RadarAnalysisProgress `
            -State $progressState `
            -CurrentContext $baselineContext.BaselineRoleName
    }

    if ($results.Count -gt 0) {
        $checkpointResults = @(
            $results.ToArray() |
                Sort-Object `
                AnalysisMode,
                BaselineRoleName,
                BaselineScope,
                RoleName,
                RestrictedAction
        )
        Export-RadarCsvReports `
            -Results $checkpointResults `
            -MatchCsvPath $partialOutputCsv `
            -CoverageCsvPath $partialCoverageCsv
        Write-Host "  Partial checkpoints:  $partialOutputCsv"
        Write-Host "                        $partialCoverageCsv"
    }
}

# The CSV remains an independent estate-wide safety audit. It is not injected
# into baseline contexts, which would incorrectly attribute global restrictions
# to a particular customer role.
if ($csvActions.Count -gt 0) {
    $globalContextKey = 'csv:accessible-estate'
    foreach ($role in $roles) {
        $matchedActions =
            New-Object System.Collections.Generic.List[object]
        foreach ($action in $csvActions) {
            $match = & $getMatch $role $action
            if ($null -ne $match) {
                [void]$matchedActions.Add([pscustomobject]@{
                    Action = $action
                    Match = $match
                })
            }
        }
        if ($matchedActions.Count -eq 0) {
            Update-RadarAnalysisProgress `
                -State $progressState `
                -CurrentContext 'CSV safety baseline'
            continue
        }

        $availability = & $getAvailability `
            $role `
            $knownScopes `
            $globalContextKey
        foreach ($warning in $availability.Warnings) {
            [void]$runtimeWarnings.Add(
                "CSV safety baseline: $warning"
            )
        }
        if (@($availability.Scopes).Count -eq 0) {
            Update-RadarAnalysisProgress `
                -State $progressState `
                -CurrentContext 'CSV safety baseline'
            continue
        }
        $coverage = & $getCoverage `
            $role `
            $availability `
            $globalContextKey `
            $true `
            @()
        foreach ($matchedAction in $matchedActions) {
            & $addResult `
                'GlobalCsv' `
                'CSV safety baseline' `
                '' `
                'Accessible estate' `
                'Input CSV' `
                'Depends on the applicable assignment path' `
                $role `
                $matchedAction.Action `
                $matchedAction.Match `
                $coverage `
                @()
        }
        Update-RadarAnalysisProgress `
            -State $progressState `
            -CurrentContext 'CSV safety baseline'
    }

    if ($results.Count -gt 0) {
        $checkpointResults = @(
            $results.ToArray() |
                Sort-Object `
                AnalysisMode,
                BaselineRoleName,
                BaselineScope,
                RoleName,
                RestrictedAction
        )
        Export-RadarCsvReports `
            -Results $checkpointResults `
            -MatchCsvPath $partialOutputCsv `
            -CoverageCsvPath $partialCoverageCsv
        Write-Host "  Partial checkpoints:  $partialOutputCsv"
        Write-Host "                        $partialCoverageCsv"
    }
}

$progressState.Stopwatch.Stop()
Write-Progress `
    -Activity 'RADAR role/action gap evaluation' `
    -Completed

$sortedResults = @(
    $results.ToArray() |
        Sort-Object `
            AnalysisMode,
            BaselineRoleName,
            BaselineScope,
            RoleName,
            RestrictedAction
)
$principalPolicyCache = @{}
$existingAccessCache = @{}
$principalGaps = @(
    if (-not $NoPrincipalCorrelation) {
        Get-RadarPrincipalGap `
            -Results $sortedResults `
            -BaselineContexts $baselineContextInventory.Contexts `
            -BaselineAssignmentInventory $baselineAssignmentInventory `
            -DirectoryEvidence $principalDirectoryEvidence `
            -PrincipalAssignmentInventory $principalAssignmentInventory `
            -Roles $roles `
            -Hierarchy $scopeHierarchy `
            -PolicyInventory $policyInventory `
            -DeniedRoleNames $deniedRoleSet `
            -DiscoveryComplete (
                $baseDiscoveryComplete -and
                $policyInventory.IsComplete
            ) `
            -PolicyEvaluationCache $policyEvaluationCache `
            -PrincipalPolicyCache $principalPolicyCache `
            -ExistingAccessCache $existingAccessCache
    }
)
$exactControlGapMap = @(
    Get-RadarControlGapMap `
        -Results $sortedResults `
        -ScopeById $knownScopeById `
        -Hierarchy $scopeHierarchy `
        -BaselineAssignmentEvidence $baselineAssignmentEvidence `
        -IncludeSubtreeControlEvidence
)
$subtreeControlGapMap = @(
    Add-RadarSubtreeControlPosture `
        -Rows $exactControlGapMap
)
$controlGapMap = @(
    Add-RadarPrincipalGapSummary `
        -Rows $subtreeControlGapMap `
        -PrincipalGaps $principalGaps
)
$baselineSummaries =
    New-Object System.Collections.Generic.List[object]
foreach ($baselineContext in $baselineContextInventory.Contexts) {
    $contextRows = @(
        $sortedResults |
            Where-Object {
                $_.AnalysisMode -eq 'BaselineNotActions' -and
                [string]::Equals(
                    [string]$_.BaselineRoleId,
                    [string]$baselineContext.BaselineRoleId,
                    [System.StringComparison]::OrdinalIgnoreCase
                ) -and
                [string]::Equals(
                    [string]$_.BaselineScope,
                    [string]$baselineContext.BaselineScope,
                    [System.StringComparison]::OrdinalIgnoreCase
                )
            }
    )
    $contextObtainableActions = @(
        $contextRows |
            Where-Object { -not $_.IsAlreadyDenied } |
            Select-Object -ExpandProperty RestrictedAction -Unique |
            Sort-Object
    )
    [void]$baselineSummaries.Add([pscustomobject]@{
        BaselineRoleName = $baselineContext.BaselineRoleName
        BaselineScope = $baselineContext.BaselineScope
        RestrictedActionCount =
            @($baselineContext.RestrictedActions).Count
        ObtainableActionCount = $contextObtainableActions.Count
        ObtainableActions = $contextObtainableActions
        GapRoleCount = @(
            $contextRows |
                Where-Object { -not $_.IsAlreadyDenied } |
                Select-Object -ExpandProperty RoleId -Unique
        ).Count
    })
}
if ($csvActions.Count -gt 0) {
    $csvRows = @(
        $sortedResults |
            Where-Object { $_.AnalysisMode -eq 'GlobalCsv' }
    )
    $csvObtainableActions = @(
        $csvRows |
            Where-Object { -not $_.IsAlreadyDenied } |
            Select-Object -ExpandProperty RestrictedAction -Unique |
            Sort-Object
    )
    [void]$baselineSummaries.Add([pscustomobject]@{
        BaselineRoleName = 'CSV safety baseline'
        BaselineScope = 'Accessible estate'
        RestrictedActionCount = @($csvActions | Sort-Object -Unique).Count
        ObtainableActionCount = $csvObtainableActions.Count
        ObtainableActions = $csvObtainableActions
        GapRoleCount = @(
            $csvRows |
                Where-Object { -not $_.IsAlreadyDenied } |
                Select-Object -ExpandProperty RoleId -Unique
        ).Count
    })
}
$reportHealthWarning = Get-RadarReportHealthWarning `
    -Results $sortedResults
if ($reportHealthWarning) {
    [void]$runtimeWarnings.Add($reportHealthWarning)
}
$discoveryWarnings = @(
    @($scopeDiscovery.Warnings) +
    @($policyBoundaryInventory.Warnings) +
    @($scopeHierarchy.Warnings) +
    @($roleInventory.Warnings) +
    @($baselineContextInventory.Warnings) +
    @($baselineAssignmentInventory.Warnings) +
    @($principalDirectoryEvidence.Warnings) +
    @($principalAssignmentInventory.Warnings) +
    @($scopeLimitWarnings) +
    @($policyInventory.Warnings) +
    @($runtimeWarnings)
) | Sort-Object -Unique
$discoveryComplete =
    $scopeDiscovery.IsComplete -and
    $scopeLimitComplete -and
    $policyBoundaryInventory.IsComplete -and
    $scopeHierarchy.IsComplete -and
    $roleInventory.IsComplete -and
    $baselineContextInventory.IsComplete -and
    $policyInventory.IsComplete -and
    (
        $baselineContextInventory.Contexts.Count -eq 0 -or
        (
            $baselineAssignmentInventory.IsComplete -and
            $principalDirectoryEvidence.IsComplete -and
            $principalAssignmentInventory.IsComplete
        )
    )

$outputDir = Split-Path -Parent $OutputCsv
if ($outputDir -and -not (Test-Path -LiteralPath $outputDir)) {
    New-Item -ItemType Directory -Path $outputDir -Force | Out-Null
}

Export-RadarCsvReports `
    -Results $sortedResults `
    -MatchCsvPath $OutputCsv `
    -CoverageCsvPath $coverageOutputCsv
Export-RadarControlGapMap `
    -Rows $controlGapMap `
    -Path $scopeMapOutputCsv
Export-RadarPrincipalGap `
    -Rows $principalGaps `
    -Path $principalGapOutputCsv
Remove-RadarCsvReportSet `
    -MatchCsvPath $partialOutputCsv `
    -CoverageCsvPath $partialCoverageCsv

$scopeMapOutputHtml = $null
if ($OutputHtml) {

    $htmlDir = Split-Path -Parent $OutputHtml
    if ($htmlDir -and -not (Test-Path -LiteralPath $htmlDir)) {
        New-Item -ItemType Directory -Path $htmlDir -Force | Out-Null
    }

    $effectiveScope = "$($scanScopes.Count) discovered Azure scope(s)"
    $denyCoverageEvaluated =
        $policyInventory.IsEvaluated -or
        $deniedRoleSet.Count -gt 0

    $html = ConvertTo-RadarHtmlReport `
        -Results $sortedResults `
        -RestrictedActions $restrictedActions `
        -RolesScanned $roles.Count `
        -BuiltInScanned $builtInRoles.Count `
        -CustomScanned $customRoles.Count `
        -IncludeCustomRoles ([bool]$IncludeCustomRoles) `
        -CustomScope $effectiveScope `
        -DeniedListProvided ([bool]$denyCoverageEvaluated) `
        -SourceRoleNames $dynamicSourceRoleNames `
        -ScopeCount $policyScopes.Count `
        -BaselineContextCount $baselineContextInventory.Contexts.Count `
        -BaselineAssignmentCount (
            $relevantBaselineAssignmentCount
        ) `
        -BaselineSummaries $baselineSummaries.ToArray() `
        -ControlGapMap $controlGapMap `
        -PrincipalGaps $principalGaps `
        -PolicyAssignmentCount $policyInventory.AssignmentCount `
        -RoleDenyRuleCount $policyInventory.RelevantRuleCount `
        -PolicyExemptionCount $policyInventory.ExemptionCount `
        -DiscoveryComplete $discoveryComplete `
        -DiscoveryWarnings $discoveryWarnings `
        -PrincipalScenario $targetPrincipalScenario

    Set-Content -LiteralPath $OutputHtml -Value $html -Encoding UTF8

    $scopeMapOutputHtml = Get-RadarScopeMapHtmlPath `
        -ReportHtmlPath $OutputHtml
    $scopeMapHtml = ConvertTo-RadarHtmlReport `
        -Results @() `
        -RestrictedActions $restrictedActions `
        -RolesScanned $roles.Count `
        -BuiltInScanned $builtInRoles.Count `
        -CustomScanned $customRoles.Count `
        -IncludeCustomRoles ([bool]$IncludeCustomRoles) `
        -CustomScope $effectiveScope `
        -DeniedListProvided ([bool]$denyCoverageEvaluated) `
        -SourceRoleNames $dynamicSourceRoleNames `
        -ScopeCount $policyScopes.Count `
        -BaselineContextCount $baselineContextInventory.Contexts.Count `
        -BaselineAssignmentCount (
            $relevantBaselineAssignmentCount
        ) `
        -ControlGapMap $controlGapMap `
        -PrincipalGaps $principalGaps `
        -PolicyAssignmentCount $policyInventory.AssignmentCount `
        -RoleDenyRuleCount $policyInventory.RelevantRuleCount `
        -PolicyExemptionCount $policyInventory.ExemptionCount `
        -DiscoveryComplete $discoveryComplete `
        -DiscoveryWarnings $discoveryWarnings `
        -PrincipalScenario $targetPrincipalScenario `
        -MapOnly
    Set-Content `
        -LiteralPath $scopeMapOutputHtml `
        -Value $scopeMapHtml `
        -Encoding UTF8
}

$customMatches = @($sortedResults | Where-Object { $_.IsCustom }).Count
$builtInMatches = $sortedResults.Count - $customMatches
$affectedRoles = @(
    $sortedResults |
        Select-Object -ExpandProperty RoleId -Unique
)
$gapTargets = @(
    $sortedResults |
        Group-Object {
            "$($_.AnalysisMode)$([char]31)$($_.BaselineRoleId)$([char]31)$($_.BaselineScope)$([char]31)$($_.RoleId)"
        } |
        ForEach-Object { $_.Group[0] }
)
$fullyDenied = @(
    $gapTargets |
        Where-Object { $_.DenyCoverage -eq 'Full' }
)
$partiallyDenied = @(
    $gapTargets |
        Where-Object { $_.DenyCoverage -eq 'Partial' }
)
$unknownCoverage = @(
    $gapTargets |
        Where-Object { $_.DenyCoverage -in @('Unknown', 'NotEvaluated') }
)
$obtainableActions = @(
    $sortedResults |
        Where-Object { -not $_.IsAlreadyDenied } |
        Select-Object -ExpandProperty RestrictedAction -Unique
)
$directAssignedGapScopes = @(
    $controlGapMap |
        Where-Object {
            $_.BaselineAccessStatus -eq
                'DirectAssignmentObserved'
        } |
        Select-Object -ExpandProperty EvaluationScope -Unique
)
$latentCapabilityScopes = @(
    $controlGapMap |
        Where-Object {
            $_.BaselineAccessStatus -eq 'BaselineCapable'
        } |
        Select-Object -ExpandProperty EvaluationScope -Unique
)
$assignmentUnknownScopes = @(
    $controlGapMap |
        Where-Object {
            $_.BaselineAccessStatus -eq 'AssignmentUnknown'
        } |
        Select-Object -ExpandProperty EvaluationScope -Unique
)
$subtreeRemediationGapScopes = @(
    $controlGapMap |
        Where-Object {
            $_.SubtreeControlStatus -eq 'Gap'
        } |
        Select-Object -ExpandProperty EvaluationScope -Unique
)
$netNewPrincipalGapRows = @(
    $principalGaps |
        Where-Object {
            $_.NetNewGapStatus -eq 'NetNewGap'
        }
)
$netNewPrincipalGapActions = @(
    $netNewPrincipalGapRows |
        Select-Object -ExpandProperty RestrictedAction -Unique
)
$netNewPrincipalGapPrincipals = @(
    $netNewPrincipalGapRows |
        Select-Object -ExpandProperty PrincipalId -Unique
)

Write-Host ""
Write-Host "RADAR scan complete."
Write-Host "  Roles scanned:        $($roles.Count) (built-in: $($builtInRoles.Count), custom: $($customRoles.Count))"
Write-Host "  Matches found:        $($sortedResults.Count) (built-in: $builtInMatches, custom: $customMatches)"
Write-Host "  Roles affected:       $($affectedRoles.Count)"
Write-Host "  Baseline/role pairs:  $($gapTargets.Count)"
if ($baselineContextInventory.Contexts.Count -gt 0) {
    Write-Host "  Net-new gap actions:          $($netNewPrincipalGapActions.Count)"
    Write-Host "  Net-new gap principals:       $($netNewPrincipalGapPrincipals.Count)"
    Write-Host "  Net-new principal-gap rows:   $($netNewPrincipalGapRows.Count)"
    Write-Host "  Subtree posture gap scopes:   $($subtreeRemediationGapScopes.Count)"
    Write-Host "  Direct baseline assignments: $relevantBaselineAssignmentCount"
    Write-Host "  Direct-assigned gap scopes:   $($directAssignedGapScopes.Count)"
    Write-Host "  Latent-capability scopes:     $($latentCapabilityScopes.Count)"
    Write-Host "  Assignment-unknown scopes:    $($assignmentUnknownScopes.Count)"
}
if ($policyInventory.IsEvaluated -or $deniedRoleSet.Count -gt 0) {
    Write-Host "  Fully denied pairs:   $($fullyDenied.Count)"
    Write-Host "  Partially denied:     $($partiallyDenied.Count)"
    Write-Host "  Coverage uncertain:   $($unknownCoverage.Count)"
    Write-Host "  Secondary estate-wide candidate-action union: $($obtainableActions.Count) of $($restrictedActions.Count)"
    if ($baselineSummaries.Count -gt 0) {
        Write-Host '  Secondary per-baseline candidate actions:'
        foreach (
            $baselineSummary in @(
                $baselineSummaries |
                    Sort-Object BaselineRoleName, BaselineScope
            )
        ) {
            Write-Host "    - $($baselineSummary.BaselineRoleName) @ $($baselineSummary.BaselineScope): $($baselineSummary.ObtainableActionCount) of $($baselineSummary.RestrictedActionCount) potentially obtainable"
        }
    }
    $rolesStillObtainable = @(
        $gapTargets |
            Where-Object { -not $_.IsAlreadyDenied }
    )
    if ($rolesStillObtainable.Count -gt 0) {
        Write-Host '  Secondary baseline/role candidate paths:'
        foreach (
            $roleResult in @(
                $rolesStillObtainable |
                    Sort-Object BaselineRoleName, BaselineScope, RoleName
            )
        ) {
            Write-Host "    - $($roleResult.BaselineRoleName) @ $($roleResult.BaselineScope) -> $($roleResult.RoleName) [$($roleResult.DenyCoverage)]"
        }
    }
}
Write-Host "  CSV report:           $OutputCsv"
Write-Host "  Coverage detail:      $coverageOutputCsv"
Write-Host "  Scope control map:    $scopeMapOutputCsv"
Write-Host "  Principal gaps:       $principalGapOutputCsv"
if ($OutputHtml) {
    Write-Host "  HTML report:          $OutputHtml"
    Write-Host "  Visual scope map:     $scopeMapOutputHtml"
}

foreach ($warningMessage in $discoveryWarnings) {
    Write-Warning $warningMessage
}
if (-not $discoveryComplete) {
    Write-Warning 'The scan completed with incomplete discovery. Treat every non-Full deny status as a potential path, not proven current exposure, and review the warnings above.'
}
