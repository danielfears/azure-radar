#Requires -Modules Pester

BeforeAll {
    $scriptPath = Join-Path $PSScriptRoot 'Invoke-Radar.ps1'
    $source = Get-Content -LiteralPath $scriptPath -Raw
    $start = $source.IndexOf('function Test-RadarAzSession')
    $end = $source.IndexOf('# --- Main')
    if ($start -lt 0 -or $end -le $start) {
        throw "Could not locate the helper functions in $scriptPath."
    }
    . ([ScriptBlock]::Create($source.Substring($start, $end - $start)))
}

Describe 'Test-PermissionMatch' {
    It 'matches exact permissions case-insensitively' {
        Test-PermissionMatch `
            -Pattern 'microsoft.keyvault/VAULTS/delete' `
            -Action 'Microsoft.KeyVault/vaults/DELETE' | Should -BeTrue
    }

    It 'detects overlap when both sides contain wildcards' {
        Test-PermissionMatch `
            -Pattern 'Microsoft.Authorization/policyAssignments/*' `
            -Action 'Microsoft.Authorization/*/Write' | Should -BeTrue
    }

    It 'rejects non-overlapping wildcard permissions' {
        Test-PermissionMatch `
            -Pattern 'Microsoft.Storage/*/read' `
            -Action '*/write' | Should -BeFalse
    }
}

Describe 'Test-RadarAzSession' {
    It 'accepts a context only when a token can be acquired' {
        Mock Get-AzContext {
            [pscustomobject]@{
                Account = [pscustomobject]@{ Id = 'test@example.invalid' }
            }
        }
        Mock Get-AzAccessToken {
            [pscustomobject]@{ Token = 'test' }
        }

        Test-RadarAzSession | Should -BeTrue
    }

    It 'rejects a stale context' {
        Mock Get-AzContext {
            [pscustomobject]@{
                Account = [pscustomobject]@{ Id = 'test@example.invalid' }
            }
        }
        Mock Get-AzAccessToken { throw 'interaction required' }

        Test-RadarAzSession | Should -BeFalse
    }
}

Describe 'Get-ActionMatch' {
    It 'supports legacy flattened role permissions' {
        $role = [pscustomobject]@{
            Actions = @('Microsoft.Authorization/*')
            NotActions = @('Microsoft.Authorization/policyAssignments/write')
        }

        Get-ActionMatch `
            -Role $role `
            -Action 'Microsoft.Authorization/policyAssignments/write' |
            Should -BeNullOrEmpty

        $match = Get-ActionMatch `
            -Role $role `
            -Action 'Microsoft.Authorization/roleAssignments/write'
        $match.MatchedPattern | Should -Be 'Microsoft.Authorization/*'
    }

    It 'supports Az.Resources 10 Permissions arrays' {
        $role = [pscustomobject]@{
            Permissions = @(
                [pscustomobject]@{
                    Actions = @('Microsoft.Authorization/*')
                    NotActions = @('Microsoft.Authorization/policyAssignments/write')
                }
            )
        }

        Get-ActionMatch `
            -Role $role `
            -Action 'Microsoft.Authorization/policyAssignments/write' |
            Should -BeNullOrEmpty

        $match = Get-ActionMatch `
            -Role $role `
            -Action 'Microsoft.Authorization/roleAssignments/write'
        $match.MatchedPattern | Should -Be 'Microsoft.Authorization/*'
    }

    It 'does not let one permission block suppress another block grant' {
        $role = [pscustomobject]@{
            Permissions = @(
                [pscustomobject]@{
                    Actions = @('Microsoft.Authorization/*')
                    NotActions = @('Microsoft.Authorization/roleAssignments/write')
                },
                [pscustomobject]@{
                    Actions = @('Microsoft.Authorization/roleAssignments/write')
                    NotActions = @()
                }
            )
        }

        $match = Get-ActionMatch `
            -Role $role `
            -Action 'Microsoft.Authorization/roleAssignments/write'
        $match.MatchedPattern |
            Should -Be 'Microsoft.Authorization/roleAssignments/write'
    }

    It 'keeps wildcard grants when NotActions excludes only part of the match' {
        $role = [pscustomobject]@{
            Permissions = @(
                [pscustomobject]@{
                    Actions = @(
                        'Microsoft.AzureActiveDirectory/b2cDirectories/*'
                    )
                    NotActions = @(
                        'Microsoft.AzureActiveDirectory/b2cDirectories/delete'
                    )
                }
            )
        }

        Get-ActionMatch `
            -Role $role `
            -Action 'Microsoft.AzureActiveDirectory/b2cDirectories/*' |
            Should -Not -BeNullOrEmpty
    }

    It 'removes wildcard grants when NotActions covers the full match' {
        $role = [pscustomobject]@{
            Permissions = @(
                [pscustomobject]@{
                    Actions = @(
                        'Microsoft.AzureActiveDirectory/b2cDirectories/*'
                    )
                    NotActions = @(
                        'Microsoft.AzureActiveDirectory/b2cDirectories/*'
                    )
                }
            )
        }

        Get-ActionMatch `
            -Role $role `
            -Action 'Microsoft.AzureActiveDirectory/b2cDirectories/*' |
            Should -BeNullOrEmpty
    }

    It 'checks later Action patterns when an earlier grant is excluded' {
        $role = [pscustomobject]@{
            Permissions = @(
                [pscustomobject]@{
                    Actions = @(
                        'Microsoft.Network/virtualNetworks/*',
                        '*/read'
                    )
                    NotActions = @(
                        'Microsoft.Network/virtualNetworks/*'
                    )
                }
            )
        }

        $match = Get-ActionMatch `
            -Role $role `
            -Action 'Microsoft.Network/*'
        $match.MatchedPattern | Should -Be '*/read'
    }

    It 'removes a wildcard overlap covered by a different exclusion glob' {
        $role = [pscustomobject]@{
            Permissions = @(
                [pscustomobject]@{
                    Actions = @('Microsoft.Network/*/read')
                    NotActions = @(
                        'Microsoft.Network/virtualNetworks/*'
                    )
                }
            )
        }

        Get-ActionMatch `
            -Role $role `
            -Action 'Microsoft.Network/virtualNetworks/*/read' |
            Should -BeNullOrEmpty
    }
}

Describe 'Get-RadarScanScope' {
    BeforeEach {
        Mock Get-AzContext {
            [pscustomobject]@{
                Tenant = [pscustomobject]@{ Id = 'tenant-1' }
                Subscription = [pscustomobject]@{
                    Id = 'sub-current'
                    Name = 'Current'
                }
            }
        }
        Mock Get-AzManagementGroup {
            @(
                [pscustomobject]@{
                    Id = '/providers/Microsoft.Management/managementGroups/root'
                    Name = 'root'
                    DisplayName = 'Root'
                },
                [pscustomobject]@{
                    Id = '/providers/Microsoft.Management/managementGroups/child'
                    Name = 'child'
                    DisplayName = 'Child'
                }
            )
        }
        Mock Get-AzSubscription {
            @(
                [pscustomobject]@{
                    Id = 'sub-current'
                    Name = 'Current'
                    State = 'Enabled'
                    TenantId = 'tenant-1'
                },
                [pscustomobject]@{
                    Id = 'sub-disabled'
                    Name = 'Disabled'
                    State = 'Disabled'
                    TenantId = 'tenant-1'
                }
            )
        }
    }

    It 'discovers accessible management groups and enabled subscriptions' {
        $result = Get-RadarScanScope

        $result.IsComplete | Should -BeTrue
        $result.Scopes.Id | Should -Contain (
            '/providers/Microsoft.Management/managementGroups/root'
        )
        $result.Scopes.Id | Should -Contain '/subscriptions/sub-current'
        $result.Scopes.Id | Should -Not -Contain '/subscriptions/sub-disabled'
    }

    It 'uses explicit scope IDs without estate discovery' {
        $result = Get-RadarScanScope -ExplicitScope @('/subscriptions/sub-1')

        $result.Scopes.Id | Should -Be '/subscriptions/sub-1'
        Should -Invoke Get-AzManagementGroup -Times 0
        Should -Invoke Get-AzSubscription -Times 0
    }

    It 'limits discovery to the current subscription when requested' {
        $result = Get-RadarScanScope -CurrentSubscriptionOnly

        $result.Scopes.Id | Should -Be '/subscriptions/sub-current'
        Should -Invoke Get-AzManagementGroup -Times 0
        Should -Invoke Get-AzSubscription -Times 0
    }

    It 'marks a management-group-only scan incomplete for descendants' {
        $result = Get-RadarScanScope -ManagementGroup 'root'

        $result.IsComplete | Should -BeFalse
        $result.Warnings |
            Should -Match 'descendant exemption'
    }

    It 'marks an explicit management-group Scope incomplete' {
        $result = Get-RadarScanScope -ExplicitScope @(
            '/providers/Microsoft.Management/managementGroups/root'
        )

        $result.IsComplete | Should -BeFalse
        $result.Warnings |
            Should -Match 'descendant exemptions'
    }
}

Describe 'Get-RadarRoleInventory' {
    It 'uses Resource Graph for estate-wide custom-role discovery' {
        Mock Get-AzRoleDefinition {
            @(
                [pscustomobject]@{
                    Name = 'Reader'
                    Id = '/providers/Microsoft.Authorization/roleDefinitions/acdd72a7-3385-48ef-bd42-f606fba81ae7'
                    IsCustom = $false
                    Permissions = @(
                        [pscustomobject]@{
                            Actions = @('*/read')
                            NotActions = @()
                        }
                    )
                }
            )
        }
        Mock Search-AzGraph {
            [pscustomobject]@{
                Data = @(
                    [pscustomobject]@{
                        Id = '/providers/Microsoft.Authorization/roleDefinitions/11111111-1111-1111-1111-111111111111'
                        RoleName = 'Customer Operator'
                        Description = 'Customer role'
                        AssignableScopes = @(
                            '/providers/Microsoft.Management/managementGroups/root'
                        )
                        Permissions = @(
                            [pscustomobject]@{
                                actions = @('Microsoft.Resources/*')
                                notActions = @()
                                dataActions = @()
                                notDataActions = @()
                            }
                        )
                    }
                )
                SkipToken = $null
                Count = 1
            }
        }
        $scopes = @(
            (New-RadarScope -Id '/subscriptions/sub-1')
            (New-RadarScope -Id '/subscriptions/sub-2')
        )

        $inventory = Get-RadarRoleInventory `
            -Scopes $scopes `
            -UseTenantDiscovery

        $inventory.Warnings | Should -BeNullOrEmpty
        $inventory.Roles.Count | Should -Be 2
        $inventory.CustomRoles.Name | Should -Be 'Customer Operator'
        $customKey = Get-RadarRoleKey -Role $inventory.CustomRoles[0]
        $inventory.RoleScopes[$customKey] |
            Should -Contain '/subscriptions/sub-1'
        $inventory.RoleScopes[$customKey] |
            Should -Contain '/subscriptions/sub-2'
        $inventory.CustomRoleSource |
            Should -Be 'Azure Resource Graph'
    }

    It 'finds roles scoped below an explicit subscription' {
        Mock Get-AzRoleDefinition {
            @(
                [pscustomobject]@{
                    Name = 'Reader'
                    Id = '/providers/Microsoft.Authorization/roleDefinitions/acdd72a7-3385-48ef-bd42-f606fba81ae7'
                    IsCustom = $false
                    Permissions = @(
                        [pscustomobject]@{
                            Actions = @('*/read')
                            NotActions = @()
                        }
                    )
                }
            )
        }
        Mock Search-AzGraph {
            [pscustomobject]@{
                Data = @(
                    [pscustomobject]@{
                        Id = '/subscriptions/sub-1/providers/Microsoft.Authorization/roleDefinitions/22222222-2222-2222-2222-222222222222'
                        RoleName = 'Resource Group Operator'
                        AssignableScopes = @(
                            '/subscriptions/sub-1/resourceGroups/workload'
                        )
                        Permissions = @(
                            [pscustomobject]@{
                                actions = @('Microsoft.Resources/*')
                                notActions = @()
                            }
                        )
                    }
                )
                SkipToken = $null
            }
        }

        $inventory = Get-RadarRoleInventory `
            -Scopes @(
                (New-RadarScope -Id '/subscriptions/sub-1')
            )

        $inventory.CustomRoles.Name |
            Should -Be 'Resource Group Operator'
        $customKey = Get-RadarRoleKey -Role $inventory.CustomRoles[0]
        $inventory.RoleScopes[$customKey] |
            Should -Be '/subscriptions/sub-1/resourceGroups/workload'
        Should -Invoke Search-AzGraph -ParameterFilter {
            $Subscription -contains 'sub-1' -and -not $UseTenantScope
        }
    }
}

Describe 'Test-RadarPolicyRuleForRole' {
    BeforeAll {
        $script:ownerRole = [pscustomobject]@{
            Id = '/providers/Microsoft.Authorization/roleDefinitions/8e3af657-a8ff-443c-a75c-2fe8c4bcb635'
        }
        $script:readerRole = [pscustomobject]@{
            Id = '/providers/Microsoft.Authorization/roleDefinitions/acdd72a7-3385-48ef-bd42-f606fba81ae7'
        }
    }

    It 'recognises a parameterised role deny-list' {
        $rule = @{
            if = @{
                allOf = @(
                    @{
                        field = 'type'
                        equals = 'Microsoft.Authorization/roleAssignments'
                    },
                    @{
                        field = 'Microsoft.Authorization/roleAssignments/roleDefinitionId'
                        in = "[parameters('deniedRoleIds')]"
                    }
                )
            }
            then = @{ effect = "[parameters('effect')]" }
        }
        $parameters = @{
            deniedRoleIds = @($ownerRole.Id)
            effect = 'Deny'
        }

        (
            Test-RadarPolicyRuleForRole `
                -PolicyRule $rule `
                -Role $ownerRole `
                -Parameters $parameters
        ).State | Should -Be 'Blocked'
        (
            Test-RadarPolicyRuleForRole `
                -PolicyRule $rule `
                -Role $readerRole `
                -Parameters $parameters
        ).State | Should -Be 'NotBlocked'
    }

    It 'does not mistake an allow-list for a deny-list' {
        $rule = @{
            if = @{
                allOf = @(
                    @{
                        field = 'type'
                        equals = 'Microsoft.Authorization/roleAssignments'
                    },
                    @{
                        not = @{
                            field = 'Microsoft.Authorization/roleAssignments/roleDefinitionId'
                            in = "[parameters('allowedRoleIds')]"
                        }
                    }
                )
            }
            then = @{ effect = 'deny' }
        }
        $parameters = @{ allowedRoleIds = @($readerRole.Id) }

        (
            Test-RadarPolicyRuleForRole `
                -PolicyRule $rule `
                -Role $readerRole `
                -Parameters $parameters
        ).State | Should -Be 'NotBlocked'
        (
            Test-RadarPolicyRuleForRole `
                -PolicyRule $rule `
                -Role $ownerRole `
                -Parameters $parameters
        ).State | Should -Be 'Blocked'
    }

    It 'supports the PIM role GUID value-expression pattern' {
        $rule = @{
            if = @{
                allOf = @(
                    @{
                        field = 'type'
                        equals = 'Microsoft.Authorization/roleAssignments'
                    },
                    @{
                        value = "[toLower(last(split(field('Microsoft.Authorization/roleAssignments/roleDefinitionId'), '/')))]"
                        notIn = "[parameters('exemptRoleIds')]"
                    }
                )
            }
            then = @{ effect = 'Deny' }
        }
        $parameters = @{
            exemptRoleIds = @(
                'acdd72a7-3385-48ef-bd42-f606fba81ae7'
            )
        }

        (
            Test-RadarPolicyRuleForRole `
                -PolicyRule $rule `
                -Role $readerRole `
                -Parameters $parameters
        ).State | Should -Be 'NotBlocked'
        (
            Test-RadarPolicyRuleForRole `
                -PolicyRule $rule `
                -Role $ownerRole `
                -Parameters $parameters
        ).State | Should -Be 'Blocked'
    }

    It 'does not count a disabled effect as blocking' {
        $rule = @{
            if = @{
                field = 'Microsoft.Authorization/roleAssignments/roleDefinitionId'
                in = "[parameters('deniedRoleIds')]"
            }
            then = @{ effect = "[parameters('effect')]" }
        }

        (
            Test-RadarPolicyRuleForRole `
                -PolicyRule $rule `
                -Role $ownerRole `
                -Parameters @{
                    deniedRoleIds = @($ownerRole.Id)
                    effect = 'Disabled'
                }
        ).State | Should -Be 'NotBlocked'
    }

    It 'surfaces conditions that depend on unsupported runtime fields' {
        $rule = @{
            if = @{
                allOf = @(
                    @{
                        field = 'type'
                        equals = 'Microsoft.Authorization/roleAssignments'
                    },
                    @{
                        field = 'Microsoft.Authorization/roleAssignments/principalType'
                        equals = 'User'
                    }
                )
            }
            then = @{ effect = 'deny' }
        }

        (
            Test-RadarPolicyRuleForRole `
                -PolicyRule $rule `
                -Role $ownerRole
        ).State | Should -Be 'Unknown'
    }
}

Describe 'Resolve-RadarPolicyAssignment' {
    BeforeEach {
        Mock Get-AzPolicyDefinition {
            if ($Id -like '*/indexed-target') {
                return [pscustomobject]@{
                    Id = $Id
                    Name = 'indexed-target'
                    DisplayName = 'Indexed authorization deny'
                    Mode = 'Indexed'
                    Parameter = [pscustomobject]@{}
                    PolicyRule = @{
                        if = @{
                            field = 'type'
                            equals = 'Microsoft.Authorization/roleAssignments'
                        }
                        then = @{ effect = 'Deny' }
                    }
                }
            }
            if ($Id -like '*/wildcard-target') {
                return [pscustomobject]@{
                    Id = $Id
                    Name = 'wildcard-target'
                    DisplayName = 'Authorization deny'
                    Mode = 'All'
                    Parameter = [pscustomobject]@{}
                    PolicyRule = @{
                        if = @{
                            field = 'type'
                            like = 'Microsoft.Authorization/*'
                        }
                        then = @{ effect = 'Deny' }
                    }
                }
            }
            if ($Id -like '*/parameter-target') {
                return [pscustomobject]@{
                    Id = $Id
                    Name = 'parameter-target'
                    DisplayName = 'Parameter-targeted deny'
                    Mode = 'All'
                    Parameter = [pscustomobject]@{
                        blockedTypes = [pscustomobject]@{
                            defaultValue = @()
                        }
                    }
                    PolicyRule = @{
                        if = @{
                            field = 'type'
                            in = "[parameters('blockedTypes')]"
                        }
                        then = @{ effect = 'Deny' }
                    }
                }
            }
            [pscustomobject]@{
                Id = $Id
                Name = 'deny-roles'
                DisplayName = 'Deny selected roles'
                Mode = 'All'
                Parameter = [pscustomobject]@{
                    roleIds = [pscustomobject]@{
                        defaultValue = @()
                    }
                    effect = [pscustomobject]@{
                        defaultValue = 'Deny'
                    }
                }
                PolicyRule = @{
                    if = @{
                        allOf = @(
                            @{
                                field = 'type'
                                equals = 'Microsoft.Authorization/roleAssignments'
                            },
                            @{
                                field = 'Microsoft.Authorization/roleAssignments/roleDefinitionId'
                                in = "[parameters('roleIds')]"
                            }
                        )
                    }
                    then = @{ effect = "[parameters('effect')]" }
                }
            }
        }
        Mock Get-AzPolicySetDefinition {
            [pscustomobject]@{
                Id = $Id
                Name = 'role-initiative'
                DisplayName = 'Role controls'
                Parameter = [pscustomobject]@{
                    blockedRoles = [pscustomobject]@{
                        defaultValue = @()
                    }
                }
                PolicyDefinition = @(
                    [pscustomobject]@{
                        PolicyDefinitionId = '/providers/Microsoft.Authorization/policyDefinitions/deny-roles'
                        PolicyDefinitionReferenceId = 'denyRoleRef'
                        Parameters = [pscustomobject]@{
                            roleIds = [pscustomobject]@{
                                value = "[parameters('blockedRoles')]"
                            }
                        }
                    }
                )
            }
        }
    }

    It 'resolves a direct policy assignment and its parameters' {
        $assignment = [pscustomobject]@{
            Id = '/subscriptions/sub-1/providers/Microsoft.Authorization/policyAssignments/deny'
            Name = 'deny'
            DisplayName = 'Deny roles'
            Scope = '/subscriptions/sub-1'
            PolicyDefinitionId = '/providers/Microsoft.Authorization/policyDefinitions/deny-roles'
            EnforcementMode = 'Default'
            Parameter = [pscustomobject]@{
                roleIds = [pscustomobject]@{
                    value = @($ownerRole.Id)
                }
            }
        }

        $resolved = Resolve-RadarPolicyAssignment `
            -Assignment $assignment `
            -DefinitionCache @{} `
            -PolicySetCache @{}

        $resolved.Rules.Count | Should -Be 1
        (
            Test-RadarPolicyRuleForRole `
                -PolicyRule $resolved.Rules[0].PolicyRule `
                -Role $ownerRole `
                -Parameters $resolved.Rules[0].Parameters
        ).State | Should -Be 'Blocked'
    }

    It 'resolves initiative parameters into a member policy' {
        $assignment = [pscustomobject]@{
            Id = '/subscriptions/sub-1/providers/Microsoft.Authorization/policyAssignments/initiative'
            Name = 'initiative'
            Scope = '/subscriptions/sub-1'
            PolicyDefinitionId = '/providers/Microsoft.Authorization/policySetDefinitions/role-controls'
            EnforcementMode = 'Default'
            Parameter = [pscustomobject]@{
                blockedRoles = [pscustomobject]@{
                    value = @($ownerRole.Id)
                }
            }
        }

        $resolved = Resolve-RadarPolicyAssignment `
            -Assignment $assignment `
            -DefinitionCache @{} `
            -PolicySetCache @{}

        $resolved.Rules.Count | Should -Be 1
        $resolved.Rules[0].ReferenceId | Should -Be 'denyRoleRef'
        (
            Test-RadarPolicyRuleForRole `
                -PolicyRule $resolved.Rules[0].PolicyRule `
                -Role $ownerRole `
                -Parameters $resolved.Rules[0].Parameters
        ).State | Should -Be 'Blocked'
    }

    It 'keeps policies that target role assignments through parameters' {
        $assignment = [pscustomobject]@{
            Id = '/subscriptions/sub-1/providers/Microsoft.Authorization/policyAssignments/parameter-target'
            Name = 'parameter-target'
            Scope = '/subscriptions/sub-1'
            PolicyDefinitionId = '/providers/Microsoft.Authorization/policyDefinitions/parameter-target'
            EnforcementMode = 'Default'
            Parameter = [pscustomobject]@{
                blockedTypes = [pscustomobject]@{
                    value = @(
                        'Microsoft.Authorization/roleAssignments'
                    )
                }
            }
        }

        $resolved = Resolve-RadarPolicyAssignment `
            -Assignment $assignment `
            -DefinitionCache @{} `
            -PolicySetCache @{}

        $resolved.Rules.Count | Should -Be 1
        (
            Test-RadarPolicyRuleForRole `
                -PolicyRule $resolved.Rules[0].PolicyRule `
                -Role $ownerRole `
                -Parameters $resolved.Rules[0].Parameters
        ).State | Should -Be 'Blocked'
    }

    It 'keeps generic policies that can match role assignments' {
        $assignment = [pscustomobject]@{
            Id = '/subscriptions/sub-1/providers/Microsoft.Authorization/policyAssignments/wildcard-target'
            Name = 'wildcard-target'
            Scope = '/subscriptions/sub-1'
            PolicyDefinitionId = '/providers/Microsoft.Authorization/policyDefinitions/wildcard-target'
            EnforcementMode = 'Default'
            Parameter = [pscustomobject]@{}
        }

        $resolved = Resolve-RadarPolicyAssignment `
            -Assignment $assignment `
            -DefinitionCache @{} `
            -PolicySetCache @{}

        $resolved.Rules.Count | Should -Be 1
        (
            Test-RadarPolicyRuleForRole `
                -PolicyRule $resolved.Rules[0].PolicyRule `
                -Role $ownerRole
        ).State | Should -Be 'Blocked'
    }

    It 'ignores Indexed policies that cannot evaluate role assignments' {
        $assignment = [pscustomobject]@{
            Id = '/subscriptions/sub-1/providers/Microsoft.Authorization/policyAssignments/indexed-target'
            Name = 'indexed-target'
            Scope = '/subscriptions/sub-1'
            PolicyDefinitionId = '/providers/Microsoft.Authorization/policyDefinitions/indexed-target'
            EnforcementMode = 'Default'
            Parameter = [pscustomobject]@{}
        }

        $resolved = Resolve-RadarPolicyAssignment `
            -Assignment $assignment `
            -DefinitionCache @{} `
            -PolicySetCache @{}

        $resolved.Rules | Should -BeNullOrEmpty
    }

    It 'marks resource-selector assignments as unsupported' {
        $assignment = [pscustomobject]@{
            Id = '/subscriptions/sub-1/providers/Microsoft.Authorization/policyAssignments/selector'
            Name = 'selector'
            Scope = '/subscriptions/sub-1'
            PolicyDefinitionId = '/providers/Microsoft.Authorization/policyDefinitions/deny-roles'
            EnforcementMode = 'Default'
            Parameter = [pscustomobject]@{
                roleIds = [pscustomobject]@{
                    value = @($ownerRole.Id)
                }
            }
            ResourceSelector = @(
                [pscustomobject]@{
                    Name = 'vm-only'
                    Selector = @(
                        [pscustomobject]@{
                            Kind = 'resourceType'
                            In = @('Microsoft.Compute/virtualMachines')
                        }
                    )
                }
            )
        }

        $resolved = Resolve-RadarPolicyAssignment `
            -Assignment $assignment `
            -DefinitionCache @{} `
            -PolicySetCache @{}

        $resolved.Rules[0].UnsupportedReason |
            Should -Match 'resource selectors'
    }

    It 'retrieves the definition version pinned by the assignment' {
        $assignment = [pscustomobject]@{
            Id = '/subscriptions/sub-1/providers/Microsoft.Authorization/policyAssignments/versioned'
            Name = 'versioned'
            Scope = '/subscriptions/sub-1'
            PolicyDefinitionId = '/providers/Microsoft.Authorization/policyDefinitions/deny-roles'
            DefinitionVersion = '1.2.3'
            EnforcementMode = 'Default'
            Parameter = [pscustomobject]@{}
        }

        $null = Resolve-RadarPolicyAssignment `
            -Assignment $assignment `
            -DefinitionCache @{} `
            -PolicySetCache @{}

        Should -Invoke Get-AzPolicyDefinition `
            -ParameterFilter { $Version -eq '1.2.3' }
    }

    It 'marks unresolved version ranges as unsupported' {
        $assignment = [pscustomobject]@{
            Id = '/subscriptions/sub-1/providers/Microsoft.Authorization/policyAssignments/versioned'
            Name = 'versioned'
            Scope = '/subscriptions/sub-1'
            PolicyDefinitionId = '/providers/Microsoft.Authorization/policyDefinitions/deny-roles'
            DefinitionVersion = '1.*.*'
            EnforcementMode = 'Default'
            Parameter = [pscustomobject]@{
                roleIds = [pscustomobject]@{
                    value = @($ownerRole.Id)
                }
            }
        }

        $resolved = Resolve-RadarPolicyAssignment `
            -Assignment $assignment `
            -DefinitionCache @{} `
            -PolicySetCache @{}

        $resolved.Rules[0].UnsupportedReason |
            Should -Match 'effective version'
    }
}

Describe 'Get-RadarRoleDenyCoverage' {
    BeforeAll {
        $script:denyRule = @{
            if = @{
                field = 'Microsoft.Authorization/roleAssignments/roleDefinitionId'
                in = @($ownerRole.Id)
            }
            then = @{ effect = 'Deny' }
        }
    }

    It 'treats a role denied at only some scopes as still obtainable' {
        $assignmentRule = [pscustomobject]@{
            AssignmentId = '/subscriptions/sub-1/providers/Microsoft.Authorization/policyAssignments/deny'
            AssignmentName = 'Deny Owner'
            AssignmentScope = '/subscriptions/sub-1'
            NotScopes = @()
            DefinitionName = 'Deny Owner'
            ReferenceId = $null
            PolicyRule = $denyRule
            Parameters = @{}
            UnsupportedReason = $null
        }
        $inventory = [pscustomobject]@{
            IsEvaluated = $true
            RulesByScope = @{
                '/subscriptions/sub-1' = @($assignmentRule)
                '/subscriptions/sub-2' = @()
            }
            ExemptionsByScope = @{
                '/subscriptions/sub-1' = @()
                '/subscriptions/sub-2' = @()
            }
        }

        $coverage = Get-RadarRoleDenyCoverage `
            -Role $ownerRole `
            -RoleScopes @(
                '/subscriptions/sub-1',
                '/subscriptions/sub-2'
            ) `
            -PolicyInventory $inventory

        $coverage.Status | Should -Be 'Partial'
        $coverage.IsAlreadyDenied | Should -BeFalse
        $coverage.UnblockedScopes |
            Should -Contain '/subscriptions/sub-2'
    }

    It 'honours an active whole-assignment exemption' {
        $rule = [pscustomobject]@{
            AssignmentId = '/subscriptions/sub-1/providers/Microsoft.Authorization/policyAssignments/deny'
            AssignmentName = 'Deny Owner'
            AssignmentScope = '/subscriptions/sub-1'
            NotScopes = @()
            DefinitionName = 'Deny Owner'
            ReferenceId = $null
            PolicyRule = $denyRule
            Parameters = @{}
            UnsupportedReason = $null
        }
        $inventory = [pscustomobject]@{
            IsEvaluated = $true
            RulesByScope = @{
                '/subscriptions/sub-1' = @($rule)
            }
            ExemptionsByScope = @{
                '/subscriptions/sub-1' = @(
                    [pscustomobject]@{
                        PolicyAssignmentId = $rule.AssignmentId
                        PolicyDefinitionReferenceId = @()
                    }
                )
            }
        }

        $coverage = Get-RadarRoleDenyCoverage `
            -Role $ownerRole `
            -RoleScopes @('/subscriptions/sub-1') `
            -PolicyInventory $inventory

        $coverage.Status | Should -Be 'None'
        $coverage.IsAlreadyDenied | Should -BeFalse
    }

    It 'does not claim full coverage when a descendant scope is excluded' {
        $rule = [pscustomobject]@{
            AssignmentId = '/subscriptions/sub-1/providers/Microsoft.Authorization/policyAssignments/deny'
            AssignmentName = 'Deny Owner'
            AssignmentScope = '/subscriptions/sub-1'
            NotScopes = @(
                '/subscriptions/sub-1/resourceGroups/excluded'
            )
            DefinitionName = 'Deny Owner'
            ReferenceId = $null
            PolicyRule = $denyRule
            Parameters = @{}
            UnsupportedReason = $null
        }
        $inventory = [pscustomobject]@{
            IsEvaluated = $true
            RulesByScope = @{
                '/subscriptions/sub-1' = @($rule)
            }
            ExemptionsByScope = @{
                '/subscriptions/sub-1' = @()
            }
        }

        $coverage = Get-RadarRoleDenyCoverage `
            -Role $ownerRole `
            -RoleScopes @('/subscriptions/sub-1') `
            -PolicyInventory $inventory

        $coverage.Status | Should -Be 'Unknown'
        $coverage.IsAlreadyDenied | Should -BeFalse
    }

    It 'does not claim full coverage after incomplete discovery' {
        $rule = [pscustomobject]@{
            AssignmentId = '/subscriptions/sub-1/providers/Microsoft.Authorization/policyAssignments/deny'
            AssignmentName = 'Deny Owner'
            AssignmentScope = '/subscriptions/sub-1'
            NotScopes = @()
            DefinitionName = 'Deny Owner'
            ReferenceId = $null
            PolicyRule = $denyRule
            Parameters = @{}
            UnsupportedReason = $null
        }
        $inventory = [pscustomobject]@{
            IsEvaluated = $true
            IsComplete = $false
            RulesByScope = @{
                '/subscriptions/sub-1' = @($rule)
            }
            ExemptionsByScope = @{
                '/subscriptions/sub-1' = @()
            }
        }

        $coverage = Get-RadarRoleDenyCoverage `
            -Role $ownerRole `
            -RoleScopes @('/subscriptions/sub-1') `
            -PolicyInventory $inventory

        $coverage.Status | Should -Be 'Unknown'
        $coverage.IsAlreadyDenied | Should -BeFalse
    }
}

Describe 'ConvertTo-RadarHtmlReport' {
    It 'renders a valid empty report' {
        $html = ConvertTo-RadarHtmlReport `
            -Results @() `
            -RestrictedActions @('Microsoft.Authorization/roleAssignments/write') `
            -RolesScanned 1 `
            -IncludeCustomRoles $false

        $html | Should -Match '<!DOCTYPE html>'
        $html | Should -Match 'No matches found'
    }
}

Describe 'Invoke-Radar end-to-end empty result' {
    BeforeEach {
        Mock Get-AzContext {
            [pscustomobject]@{
                Account = [pscustomobject]@{ Id = 'test@example.invalid' }
                Tenant = [pscustomobject]@{ Id = 'tenant-1' }
                Subscription = [pscustomobject]@{
                    Id = 'sub-1'
                    Name = 'Test'
                }
            }
        }
        Mock Get-AzAccessToken {
            [pscustomobject]@{ Token = 'test' }
        }
        Mock Get-AzRoleDefinition {
            if ($Custom) { return @() }
            @(
                [pscustomobject]@{
                    Name = 'Reader'
                    Id = '/providers/Microsoft.Authorization/roleDefinitions/acdd72a7-3385-48ef-bd42-f606fba81ae7'
                    IsCustom = $false
                    AssignableScopes = @('/')
                    Permissions = @(
                        [pscustomobject]@{
                            Actions = @('*/read')
                            NotActions = @()
                        }
                    )
                }
            )
        }
        Mock Get-AzPolicyExemption { @() }
    }

    It 'writes valid empty CSV and HTML reports without a binding error' {
        $inputCsv = Join-Path $TestDrive 'restricted.csv'
        $outputCsv = Join-Path $TestDrive 'radar.csv'
        $outputHtml = Join-Path $TestDrive 'radar.html'
        Set-Content `
            -LiteralPath $inputCsv `
            -Value @(
                'Action',
                'Microsoft.Authorization/roleAssignments/write'
            )

        & $scriptPath `
            -NoMenu `
            -CurrentSubscriptionOnly `
            -BuiltInOnly `
            -NoPolicyDiscovery `
            -InputCsv $inputCsv `
            -OutputCsv $outputCsv `
            -OutputHtml $outputHtml

        Test-Path -LiteralPath $outputCsv | Should -BeTrue
        (Get-Content -LiteralPath $outputCsv -Raw) |
            Should -Match '"DenyCoverage"'
        Test-Path -LiteralPath $outputHtml | Should -BeTrue
        (Get-Content -LiteralPath $outputHtml -Raw) |
            Should -Match 'No matches found'
    }

    It 'derives full deny coverage from a live policy assignment' {
        $inputCsv = Join-Path $TestDrive 'restricted.csv'
        $outputCsv = Join-Path $TestDrive 'radar.csv'
        Set-Content `
            -LiteralPath $inputCsv `
            -Value @(
                'Action',
                'Microsoft.Resources/subscriptions/read'
            )

        Mock Get-AzPolicyAssignment {
            @(
                [pscustomobject]@{
                    Id = '/subscriptions/sub-1/providers/Microsoft.Authorization/policyAssignments/deny-reader'
                    Name = 'deny-reader'
                    DisplayName = 'Deny Reader'
                    Scope = '/subscriptions/sub-1'
                    PolicyDefinitionId = '/providers/Microsoft.Authorization/policyDefinitions/deny-reader'
                    EnforcementMode = 'Default'
                    Parameter = [pscustomobject]@{
                        roleIds = [pscustomobject]@{
                            value = @(
                                '/providers/Microsoft.Authorization/roleDefinitions/acdd72a7-3385-48ef-bd42-f606fba81ae7'
                            )
                        }
                    }
                    NotScope = @()
                }
            )
        }
        Mock Get-AzPolicyDefinition {
            [pscustomobject]@{
                Id = $Id
                Name = 'deny-reader'
                DisplayName = 'Deny Reader'
                Mode = 'All'
                Parameter = [pscustomobject]@{}
                PolicyRule = @{
                    if = @{
                        allOf = @(
                            @{
                                field = 'type'
                                equals = 'Microsoft.Authorization/roleAssignments'
                            },
                            @{
                                field = 'Microsoft.Authorization/roleAssignments/roleDefinitionId'
                                in = "[parameters('roleIds')]"
                            }
                        )
                    }
                    then = @{ effect = 'Deny' }
                }
            }
        }

        & $scriptPath `
            -NoMenu `
            -CurrentSubscriptionOnly `
            -BuiltInOnly `
            -InputCsv $inputCsv `
            -OutputCsv $outputCsv

        $result = Import-Csv -LiteralPath $outputCsv
        $result.RoleName | Should -Be 'Reader'
        $result.CoverageWarnings | Should -BeNullOrEmpty
        $result.DenyCoverage | Should -Be 'Full'
        $result.IsAlreadyDenied | Should -Be 'True'
        $result.BlockingPolicies | Should -Be 'Deny Reader'
    }
}
