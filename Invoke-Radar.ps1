<#
.SYNOPSIS
    RADAR - Restricted Action Detector for Azure Roles.

.DESCRIPTION
    Compares restricted Azure RBAC actions against built-in and custom role
    definitions across the accessible Azure estate. It discovers Azure Policy
    assignments that deny role assignments and reports the restricted actions
    that remain obtainable through roles not denied at every scanned scope.

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
    When omitted, RADAR selects the broadest custom wildcard roles with Owner
    or Contributor in the name. Supply patterns to override auto-detection.

.PARAMETER NoPolicyDiscovery
    Disables live discovery of Azure Policy assignments that deny roles.

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

    [switch]$NoPolicyDiscovery
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

# Suppress noisy "Upcoming breaking changes" warnings emitted by Az.Resources cmdlets.
$env:SuppressAzurePowerShellBreakingChangeWarnings = 'true'
$scriptDir = Split-Path -Parent $PSCommandPath
$defaultInputCsv = Join-Path $scriptDir 'restricted-actions.csv'

# Interactive menu when launched with no scoping parameters.
$invokedWithArgs =
    $InputCsv -or
    $OutputCsv -or
    $OutputHtml -or
    $Scope -or
    $ManagementGroup -or
    $CurrentSubscriptionOnly -or
    $BuiltInOnly -or
    $DynamicRestrictedActions
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
            Write-Host '  Baseline roles:    automatic (broadest Owner/Contributor wildcard roles)'
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
        Write-Host 'Dynamic derivation will auto-detect the broadest Owner/Contributor wildcard roles.'
    }
}

function Test-RadarAzSession {
    $context = Get-AzContext -ErrorAction SilentlyContinue
    if (-not $context -or -not $context.Account) { return $false }
    try {
        $null = Get-AzAccessToken `
            -ErrorAction Stop `
            -WarningAction SilentlyContinue
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
    elseif ($normalisedId -like '/subscriptions/*') {
        'Subscription'
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
        try {
            foreach ($group in @(Get-AzManagementGroup -ErrorAction Stop)) {
                $groupId = Get-RadarPropertyValue `
                    -InputObject $group `
                    -Name 'Id'
                $groupName = Get-RadarPropertyValue `
                    -InputObject $group `
                    -Name 'Name'
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
            $tenantId = Get-RadarPropertyValue `
                -InputObject $context.Tenant `
                -Name 'Id'
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

        [int]$PolicyAssignmentCount = 0,

        [int]$RoleDenyRuleCount = 0,

        [int]$PolicyExemptionCount = 0,

        [bool]$DiscoveryComplete = $true,

        [string[]]$DiscoveryWarnings = @()
    )

    $generated = (Get-Date).ToString('u')
    $resultArray = @($Results)
    $discoveryWarningArray = @($DiscoveryWarnings)
    $sourceRoleNameArray = @($SourceRoleNames)
    $totalMatches = $resultArray.Count
    $rolesAffected = (
        $resultArray |
            Select-Object -ExpandProperty RoleId -Unique |
            Measure-Object
    ).Count
    $actionsTriggered = ($resultArray | Select-Object -ExpandProperty RestrictedAction -Unique | Measure-Object).Count

    # Group by role for a collapsible per-role section.
    $grouped = @(
        $resultArray |
            Group-Object -Property RoleId |
            Sort-Object {
                $_.Group[0].RoleName
            }
    )

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

    if (-not $DiscoveryComplete -or $discoveryWarningArray.Count -gt 0) {
        [void]$sb.AppendLine('<section class="warning"><strong>Discovery warning:</strong> deny coverage may be incomplete. Any role not marked Fully Denied is treated as obtainable.')
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

    $customMatches  = @(@($Results) | Where-Object { $_.IsCustom }).Count
    $builtInMatches = $totalMatches - $customMatches

    # Compute scope-aware deny coverage across affected roles.
    $affectedRoles = @($Results) | Group-Object -Property RoleId
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
        [void]$sb.AppendLine('  <h2>Deny-policy coverage</h2>')
        [void]$sb.AppendLine('  <p>Share of affected roles blocked at every evaluated scope. Partial and unknown coverage remains obtainable and is never counted as safe.</p>')
        [void]$sb.AppendLine('  <div class="nums">')
        [void]$sb.AppendLine('    <div class="num"><b>' + $rolesAffected + '</b>roles affected</div>')
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
    [void]$sb.AppendLine("<div class=`"card`"><div class=`"label`">Built-in Scanned</div><div class=`"value accent`">$BuiltInScanned</div></div>")
    if ($IncludeCustomRoles) {
        [void]$sb.AppendLine("<div class=`"card`"><div class=`"label`">Custom Scanned</div><div class=`"value accent`">$CustomScanned</div></div>")
    }
    if ($ScopeCount -gt 0) {
        [void]$sb.AppendLine("<div class=`"card`"><div class=`"label`">Scopes Evaluated</div><div class=`"value accent`">$ScopeCount</div></div>")
    }
    if ($DeniedListProvided) {
        [void]$sb.AppendLine("<div class=`"card`"><div class=`"label`">Policy Assignments</div><div class=`"value`">$PolicyAssignmentCount</div></div>")
        [void]$sb.AppendLine("<div class=`"card`"><div class=`"label`">Role-Deny Rules</div><div class=`"value`">$RoleDenyRuleCount</div></div>")
        [void]$sb.AppendLine("<div class=`"card`"><div class=`"label`">Active Exemptions</div><div class=`"value`">$PolicyExemptionCount</div></div>")
    }
    [void]$sb.AppendLine("<div class=`"card`"><div class=`"label`">Restricted Actions</div><div class=`"value`">$($RestrictedActions.Count)</div></div>")
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
            $items = $g.Group | Sort-Object RestrictedAction
            $first = $items | Select-Object -First 1
            $roleName = $first.RoleName
            $isCustom = $first.IsCustom
            $roleId = $first.RoleId
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
            [void]$sb.AppendLine('<summary><span class="chev">&#9656;</span><span class="name">' + (ConvertTo-HtmlSafe $roleName) + '</span> ' + $badge + $denyBadge + ' <span class="role-id" title="' + (ConvertTo-HtmlSafe $roleId) + '">' + (ConvertTo-HtmlSafe $roleId) + '</span><span class="count">' + $items.Count + ' ' + $matchWord + '</span></summary>')
            if ($DeniedListProvided) {
                $scopeCoverage = "$($first.DeniedScopeCount) of $($first.EvaluatedScopeCount) role-availability scopes denied"
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
                    # Fail open: an unproven exclusion must remain obtainable.
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

    foreach ($permission in @(Get-RolePermissionBlock -Role $Role)) {
        $notActions = @($permission.NotActions)
        foreach (
            $matchedAction in @(
                @($permission.Actions) |
                    Where-Object {
                        Test-PermissionMatch -Pattern $_ -Action $Action
                    }
            )
        ) {
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
    authoritative. Auto-detection chooses the wildcard role with the fewest
    NotActions in each Owner and Contributor name family, which favours broad
    platform roles over narrow roles that claw back most Azure operations.
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
        foreach ($family in @('owner', 'contributor')) {
            $familyCandidates = @(
                $candidates |
                    Where-Object {
                        $_.Name -match
                            "(?i)(^|[^a-z0-9])$family([^a-z0-9]|$)"
                    } |
                    Sort-Object NotActionCount, Name
            )
            if ($familyCandidates.Count -eq 0) { continue }

            $minimumExclusions = $familyCandidates[0].NotActionCount
            foreach (
                $candidate in @(
                    $familyCandidates |
                        Where-Object {
                            $_.NotActionCount -eq $minimumExclusions
                        }
                )
            ) {
                & $addSelection $candidate
            }
        }
        $mode = 'Automatic'
    }

    [pscustomobject]@{
        Roles = $selected.ToArray()
        Candidates = $candidates
        SelectionMode = $mode
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

function Test-RadarPolicyCondition {
    param(
        [object]$Condition,
        [object]$Role,
        [hashtable]$Parameters = @{}
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
                -Parameters $Parameters
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
                -Parameters $Parameters
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
            -Parameters $Parameters
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
            $actual = 'Microsoft.Authorization/roleAssignments'
        }
        elseif ($field -match '(?i)/roleDefinitionId$') {
            $actual = Get-RadarPropertyValue -InputObject $Role -Name 'Id'
            $isRoleDefinitionField = $true
        }
        else {
            return New-RadarPolicyEvaluation `
                -State 'Unknown' `
                -Reason "Unsupported policy field '$field'."
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
            $actual = Get-RadarRoleDefinitionGuid -RoleOrId $Role
            $isRoleDefinitionField = $true
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

function Test-RadarPolicyRuleForRole {
    param(
        [object]$PolicyRule,
        [object]$Role,
        [hashtable]$Parameters = @{}
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
        -Parameters $Parameters
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
            $PolicySetCache[$key] = Get-AzPolicySetDefinition @parameters
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
        $DefinitionCache[$key] = Get-AzPolicyDefinition @parameters
    }
    return $DefinitionCache[$key]
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

        $targetEvidence = [pscustomobject]@{
            Rule = $policyRule
            Parameters = $Parameters
        } | ConvertTo-Json -Depth 100 -Compress
        $classificationWarning = $null
        if (
            $targetEvidence -notmatch
            '(?i)Microsoft\.Authorization/roleAssignments'
        ) {
            $probeRole = [pscustomobject]@{
                Id = '/providers/Microsoft.Authorization/roleDefinitions/00000000-0000-0000-0000-000000000000'
            }
            $probe = Test-RadarPolicyRuleForRole `
                -PolicyRule $policyRule `
                -Role $probeRole `
                -Parameters $Parameters
            if ($probe.State -eq 'NotBlocked') { return }
            if ($probe.State -eq 'Unknown') {
                $classificationWarning =
                    "Policy targeting could not be ruled out safely: $($probe.Reason)"
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
            Warnings = @()
        }
    }

    $definitionCache = @{}
    $policySetCache = @{}
    $resolvedAssignmentCache = @{}
    $assignmentIds = New-Object System.Collections.Generic.HashSet[string] (
        [StringComparer]::OrdinalIgnoreCase
    )
    $exemptionIds = New-Object System.Collections.Generic.HashSet[string] (
        [StringComparer]::OrdinalIgnoreCase
    )
    $warnings = New-Object System.Collections.Generic.List[string]
    $isComplete = $true

    foreach ($scope in $Scopes) {
        try {
            $assignmentParameters = @{
                Scope = $scope.Id
                ErrorAction = 'Stop'
                WarningAction = 'SilentlyContinue'
            }
            $assignments = @(
                Get-AzPolicyAssignment @assignmentParameters
            )
        }
        catch {
            $isComplete = $false
            [void]$warnings.Add(
                "Policy-assignment discovery failed at $($scope.Id): $($_.Exception.Message)"
            )
            continue
        }

        $scopeRules = New-Object System.Collections.Generic.List[object]
        foreach ($assignment in $assignments) {
            $version = Get-RadarDefinitionVersion -InputObject $assignment
            $assignmentId = [string](
                Get-RadarPolicyProperty `
                    -InputObject $assignment `
                    -Name 'Id'
            )
            $assignmentCommand = Get-Command Get-AzPolicyAssignment
            if (
                $version.Warning -and
                $assignmentId -and
                $assignmentCommand.Parameters.ContainsKey('Expand')
            ) {
                try {
                    $assignment = Get-AzPolicyAssignment `
                        -Id $assignmentId `
                        -Expand 'EffectiveDefinitionVersion' `
                        -ErrorAction Stop `
                        -WarningAction SilentlyContinue
                }
                catch {
                    [void]$warnings.Add(
                        "Could not resolve the effective definition version for assignment '$assignmentId': $($_.Exception.Message)"
                    )
                }
            }

            $assignmentKey = Get-RadarPolicyAssignmentKey `
                -Assignment $assignment
            [void]$assignmentIds.Add($assignmentKey)
            if (-not $resolvedAssignmentCache.ContainsKey($assignmentKey)) {
                $resolved = Resolve-RadarPolicyAssignment `
                    -Assignment $assignment `
                    -DefinitionCache $definitionCache `
                    -PolicySetCache $policySetCache
                $resolvedAssignmentCache[$assignmentKey] = $resolved
                foreach ($warning in $resolved.Warnings) {
                    $isComplete = $false
                    [void]$warnings.Add($warning)
                }
            }
            foreach (
                $resolvedRule in @(
                    $resolvedAssignmentCache[$assignmentKey].Rules
                )
            ) {
                [void]$scopeRules.Add($resolvedRule)
            }
        }
        $rulesByScope[$scope.Id.ToLowerInvariant()] = $scopeRules.ToArray()

        try {
            $activeExemptions = New-Object System.Collections.Generic.List[object]
            $exemptionParameters = @{
                Scope = $scope.Id
                ErrorAction = 'Stop'
                WarningAction = 'SilentlyContinue'
            }
            if (
                $scope.Type -ne 'ManagementGroup' -and
                (Get-Command Get-AzPolicyExemption).Parameters.ContainsKey(
                    'IncludeDescendent'
                )
            ) {
                $exemptionParameters.IncludeDescendent = $true
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
                        $isComplete = $false
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
            $isComplete = $false
            [void]$warnings.Add(
                "Policy-exemption discovery failed at $($scope.Id): $($_.Exception.Message)"
            )
        }
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
        IsComplete = $isComplete
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
        [string]$Scope
    )

    foreach ($notScope in @($Rule.NotScopes)) {
        if ([string]::IsNullOrWhiteSpace([string]$notScope)) { continue }
        $normalisedNotScope = ([string]$notScope).TrimEnd('/')
        $normalisedScope = $Scope.TrimEnd('/')
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

        if (
            $normalisedNotScope.StartsWith(
                "$normalisedScope/",
                [System.StringComparison]::OrdinalIgnoreCase
            )
        ) {
            return [pscustomobject]@{
                State = 'Unknown'
                Reason = "The assignment excludes descendant scope '$notScope', so estate-wide coverage is not complete."
            }
        }

        if (
            $normalisedScope -like
                '/providers/Microsoft.Management/managementGroups/*'
        ) {
            return [pscustomobject]@{
                State = 'Unknown'
                Reason = "The assignment has notScopes entries whose management-group relationship cannot be proven from resource IDs."
            }
        }

        if (
            $normalisedNotScope -like
                '/providers/Microsoft.Management/managementGroups/*' -and
            $normalisedScope -like '/subscriptions/*'
        ) {
            return [pscustomobject]@{
                State = 'Unknown'
                Reason = "Could not determine whether subscription scope is below excluded management group '$notScope'."
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

        [bool]$DiscoveryComplete = $true
    )

    $roleName = [string](
        Get-RadarPropertyValue -InputObject $Role -Name 'Name'
    )
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
            UnblockedScopes = @()
            UnknownReasons = @()
        }
    }

    if (-not $PolicyInventory.IsEvaluated) {
        return [pscustomobject]@{
            Status = 'NotEvaluated'
            IsAlreadyDenied = $false
            DeniedScopeCount = 0
            ScopeCount = @($RoleScopes).Count
            BlockingPolicies = @()
            UnblockedScopes = @($RoleScopes)
            UnknownReasons = @('Live policy discovery was disabled.')
        }
    }

    $blockedScopeCount = 0
    $blockingPolicies =
        New-Object System.Collections.Generic.HashSet[string] (
            [StringComparer]::OrdinalIgnoreCase
        )
    $unblockedScopes = New-Object System.Collections.Generic.List[string]
    $unknownReasons = New-Object System.Collections.Generic.List[string]

    foreach ($roleScope in @($RoleScopes | Sort-Object -Unique)) {
        $scopeBlocked = $false
        $scopeUnknown = $false
        $scopeKey = $roleScope.TrimEnd('/').ToLowerInvariant()
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

        foreach ($rule in $rules) {
            if (
                Test-RadarPolicyRuleExempted `
                    -Rule $rule `
                    -Exemptions $exemptions
            ) {
                continue
            }
            if ($rule.UnsupportedReason) {
                $scopeUnknown = $true
                [void]$unknownReasons.Add(
                    "$($rule.AssignmentName): $($rule.UnsupportedReason)"
                )
                continue
            }

            $applicability = Get-RadarPolicyScopeApplicability `
                -Rule $rule `
                -Scope $roleScope
            if ($applicability.State -eq 'Excluded') { continue }
            if ($applicability.State -eq 'Unknown') {
                $scopeUnknown = $true
                [void]$unknownReasons.Add(
                    "$($rule.AssignmentName): $($applicability.Reason)"
                )
                continue
            }

            $evaluation = Test-RadarPolicyRuleForRole `
                -PolicyRule $rule.PolicyRule `
                -Role $Role `
                -Parameters $rule.Parameters
            if ($evaluation.State -eq 'Blocked') {
                $scopeBlocked = $true
                [void]$blockingPolicies.Add($rule.AssignmentName)
            }
            elseif ($evaluation.State -eq 'Unknown') {
                $scopeUnknown = $true
                [void]$unknownReasons.Add(
                    "$($rule.AssignmentName): $($evaluation.Reason)"
                )
            }
        }

        if ($scopeBlocked) {
            $blockedScopeCount++
        }
        else {
            [void]$unblockedScopes.Add($roleScope)
            if ($scopeUnknown) {
                [void]$unknownReasons.Add(
                    "Deny coverage at '$roleScope' is uncertain."
                )
            }
        }
    }

    $scopeCount = @($RoleScopes | Sort-Object -Unique).Count
    $policyInventoryComplete = Get-RadarPropertyValue `
        -InputObject $PolicyInventory `
        -Name 'IsComplete'
    if ($null -ne $policyInventoryComplete) {
        $DiscoveryComplete =
            $DiscoveryComplete -and [bool]$policyInventoryComplete
    }
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
        [void]$unknownReasons.Add(
            'Discovery was incomplete, so full deny coverage cannot be proven.'
        )
    }

    [pscustomobject]@{
        Status = $status
        IsAlreadyDenied = ($status -eq 'Full')
        DeniedScopeCount = $blockedScopeCount
        ScopeCount = $scopeCount
        BlockingPolicies = @($blockingPolicies | Sort-Object)
        UnblockedScopes = @($unblockedScopes | Sort-Object -Unique)
        UnknownReasons = @($unknownReasons | Sort-Object -Unique)
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

# Derive restricted actions from broad wildcard roles discovered anywhere in
# the selected estate.
$dynamicActions = @()
$dynamicSourceRoleNames = @()
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

    $naSet = New-Object System.Collections.Generic.HashSet[string] ([StringComparer]::OrdinalIgnoreCase)
    foreach ($sr in $sourceRoles) {
        foreach ($na in @(Get-RoleProperty -Role $sr -Name 'NotActions')) {
            if (-not [string]::IsNullOrWhiteSpace($na)) { [void]$naSet.Add($na.Trim()) }
        }
    }
    $dynamicActions = @($naSet | Sort-Object)

    if ($sourceRoles.Count -eq 0) {
        if ($BaselineRolePattern.Count -gt 0) {
            Write-Warning "Dynamic mode: no custom wildcard roles matched the explicit baseline pattern(s): $($BaselineRolePattern -join ', ')."
        }
        else {
            Write-Warning 'Dynamic mode: no usable Owner/Contributor wildcard baseline roles were auto-detected.'
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
        Write-Host "  Derived $($dynamicActions.Count) restricted action(s) from $($sourceRoles.Count) $selectionLabel wildcard role(s): $($dynamicSourceRoleNames -join ', ')"
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

# Final restricted-action set: CSV actions and/or dynamically derived NotActions.
$restrictedActions = @(@($csvActions) + @($dynamicActions) |
    Where-Object { -not [string]::IsNullOrWhiteSpace($_) } |
    ForEach-Object { $_.Trim() } |
    Sort-Object -Unique)

if ($restrictedActions.Count -eq 0) {
    throw 'No restricted actions to evaluate. Provide -InputCsv, broaden -BaselineRolePattern, or ensure an Owner/Contributor wildcard baseline role is visible.'
}

Write-Host "Total restricted actions to evaluate: $($restrictedActions.Count)"

# Policy coverage is evaluated at every role-availability scope. Resource Graph
# can surface resource-group-scoped custom roles that were not in the initial
# management-group/subscription discovery set, so include those scopes here.
$policyScopeById = @{}
foreach ($scanScope in $scanScopes) {
    $policyScopeById[$scanScope.Id.ToLowerInvariant()] = $scanScope
}
foreach ($roleScopeList in $roleInventory.RoleScopes.Values) {
    foreach ($roleScope in @($roleScopeList)) {
        if ([string]::IsNullOrWhiteSpace([string]$roleScope)) { continue }
        $normalisedScope = ([string]$roleScope).TrimEnd('/')
        $key = $normalisedScope.ToLowerInvariant()
        if (-not $policyScopeById.ContainsKey($key)) {
            $policyScopeById[$key] = New-RadarScope -Id $normalisedScope
        }
    }
}
$policyScopes = @($policyScopeById.Values | Sort-Object Type, Id)

Write-Host "Discovering effective deny policies across $($policyScopes.Count) role-availability scope(s)..."
$policyInventory = Get-RadarPolicyInventory `
    -Scopes $policyScopes `
    -NoPolicyDiscovery:$NoPolicyDiscovery
if ($policyInventory.IsEvaluated) {
    Write-Host "  Policy assignments:   $($policyInventory.AssignmentCount)"
    Write-Host "  Role-deny rules:      $($policyInventory.RelevantRuleCount)"
    Write-Host "  Active exemptions:   $($policyInventory.ExemptionCount)"
}
else {
    Write-Host '  Live policy discovery disabled.'
}

Write-Host "Evaluating $($roles.Count) role(s)..."
$coverageDiscoveryComplete =
    $scopeDiscovery.IsComplete -and
    $roleInventory.IsComplete -and
    $policyInventory.IsComplete
$coverageByRole = @{}
foreach ($role in $roles) {
    $roleKey = Get-RadarRoleKey -Role $role
    $roleScopes = if ($roleInventory.RoleScopes.ContainsKey($roleKey)) {
        @($roleInventory.RoleScopes[$roleKey])
    }
    else {
        @($scanScopes | ForEach-Object { $_.Id })
    }
    $coverageByRole[$roleKey] = Get-RadarRoleDenyCoverage `
        -Role $role `
        -RoleScopes $roleScopes `
        -PolicyInventory $policyInventory `
        -DeniedRoleNames $deniedRoleSet `
        -DiscoveryComplete $coverageDiscoveryComplete
}

$results = New-Object System.Collections.Generic.List[object]

foreach ($role in $roles) {
    $roleKey = Get-RadarRoleKey -Role $role
    $coverage = $coverageByRole[$roleKey]
    foreach ($action in $restrictedActions) {
        $match = Get-ActionMatch -Role $role -Action $action
        if ($null -ne $match) {
            $results.Add([pscustomobject]@{
                RoleName         = Get-RadarPropertyValue -InputObject $role -Name 'Name'
                RoleId           = Get-RadarPropertyValue -InputObject $role -Name 'Id'
                IsCustom         = [bool](Get-RadarPropertyValue -InputObject $role -Name 'IsCustom')
                RestrictedAction = $action
                MatchedPattern   = $match.MatchedPattern
                IsAlreadyDenied  = $coverage.IsAlreadyDenied
                DenyCoverage     = $coverage.Status
                DeniedScopeCount = $coverage.DeniedScopeCount
                EvaluatedScopeCount = $coverage.ScopeCount
                BlockingPolicies = $coverage.BlockingPolicies -join '; '
                UnblockedScopes  = $coverage.UnblockedScopes -join '; '
                CoverageWarnings = $coverage.UnknownReasons -join '; '
            }) | Out-Null
        }
    }
}

$sortedResults = @(
    $results.ToArray() |
        Sort-Object RoleName, RestrictedAction
)
$discoveryWarnings = @(
    @($scopeDiscovery.Warnings) +
    @($roleInventory.Warnings) +
    @($policyInventory.Warnings)
) | Sort-Object -Unique
$discoveryComplete =
    $scopeDiscovery.IsComplete -and
    $roleInventory.IsComplete -and
    $policyInventory.IsComplete

$outputDir = Split-Path -Parent $OutputCsv
if ($outputDir -and -not (Test-Path -LiteralPath $outputDir)) {
    New-Item -ItemType Directory -Path $outputDir -Force | Out-Null
}

if ($sortedResults.Count -gt 0) {
    $sortedResults |
        Export-Csv -LiteralPath $OutputCsv -NoTypeInformation
}
else {
    Set-Content `
        -LiteralPath $OutputCsv `
        -Encoding UTF8 `
        -Value '"RoleName","RoleId","IsCustom","RestrictedAction","MatchedPattern","IsAlreadyDenied","DenyCoverage","DeniedScopeCount","EvaluatedScopeCount","BlockingPolicies","UnblockedScopes","CoverageWarnings"'
}

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
        -PolicyAssignmentCount $policyInventory.AssignmentCount `
        -RoleDenyRuleCount $policyInventory.RelevantRuleCount `
        -PolicyExemptionCount $policyInventory.ExemptionCount `
        -DiscoveryComplete $discoveryComplete `
        -DiscoveryWarnings $discoveryWarnings

    Set-Content -LiteralPath $OutputHtml -Value $html -Encoding UTF8
}

$customMatches = @($sortedResults | Where-Object { $_.IsCustom }).Count
$builtInMatches = $sortedResults.Count - $customMatches
$affectedRoles = @(
    $sortedResults |
        Group-Object RoleId |
        ForEach-Object { $_.Group[0] }
)
$fullyDenied = @(
    $affectedRoles |
        Where-Object { $_.DenyCoverage -eq 'Full' }
)
$partiallyDenied = @(
    $affectedRoles |
        Where-Object { $_.DenyCoverage -eq 'Partial' }
)
$unknownCoverage = @(
    $affectedRoles |
        Where-Object { $_.DenyCoverage -in @('Unknown', 'NotEvaluated') }
)
$obtainableActions = @(
    $sortedResults |
        Where-Object { -not $_.IsAlreadyDenied } |
        Select-Object -ExpandProperty RestrictedAction -Unique
)

Write-Host ""
Write-Host "RADAR scan complete."
Write-Host "  Roles scanned:        $($roles.Count) (built-in: $($builtInRoles.Count), custom: $($customRoles.Count))"
Write-Host "  Matches found:        $($sortedResults.Count) (built-in: $builtInMatches, custom: $customMatches)"
Write-Host "  Roles affected:       $($affectedRoles.Count)"
if ($policyInventory.IsEvaluated -or $deniedRoleSet.Count -gt 0) {
    Write-Host "  Fully denied roles:   $($fullyDenied.Count)"
    Write-Host "  Partially denied:     $($partiallyDenied.Count)"
    Write-Host "  Coverage uncertain:   $($unknownCoverage.Count)"
    Write-Host "  Obtainable actions:   $($obtainableActions.Count) of $($restrictedActions.Count)"
    $rolesStillObtainable = @(
        $affectedRoles |
            Where-Object { -not $_.IsAlreadyDenied }
    )
    if ($rolesStillObtainable.Count -gt 0) {
        Write-Host '  Roles still obtainable at one or more scopes:'
        foreach ($roleResult in ($rolesStillObtainable | Sort-Object RoleName)) {
            Write-Host "    - $($roleResult.RoleName) [$($roleResult.DenyCoverage)]"
        }
    }
}
Write-Host "  CSV report:           $OutputCsv"
if ($OutputHtml) {
    Write-Host "  HTML report:          $OutputHtml"
}

foreach ($warningMessage in $discoveryWarnings) {
    Write-Warning $warningMessage
}
if (-not $discoveryComplete) {
    Write-Warning 'The scan completed with incomplete discovery. Treat every non-Full deny status as obtainable and review the warnings above.'
}
