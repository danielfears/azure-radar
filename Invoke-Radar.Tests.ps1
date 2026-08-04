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

    It 'rejects an expired token returned without an error' {
        Mock Get-AzContext {
            [pscustomobject]@{
                Account = [pscustomobject]@{ Id = 'test@example.invalid' }
            }
        }
        Mock Get-AzAccessToken {
            [pscustomobject]@{
                Token = 'test'
                ExpiresOn = [DateTimeOffset]::UtcNow.AddMinutes(-5)
            }
        }

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

    It 'uses the direct exclusion path for concrete restricted actions' {
        $role = [pscustomobject]@{
            Permissions = @(
                [pscustomobject]@{
                    Actions = @('Microsoft.Authorization/*')
                    NotActions = @(
                        'Microsoft.Authorization/policyAssignments/write'
                    )
                }
            )
        }
        Mock Test-RadarGlobDifferenceExists {
            throw 'The wildcard automaton should not be used.'
        }

        $match = Get-ActionMatch `
            -Role $role `
            -Action 'Microsoft.Authorization/roleAssignments/write'

        $match.MatchedPattern | Should -Be 'Microsoft.Authorization/*'
        Should -Invoke Test-RadarGlobDifferenceExists -Times 0
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

Describe 'Get-RadarBaselineRole' {
    BeforeAll {
        function New-TestWildcardRole {
            param(
                [string]$Name,
                [string]$Id,
                [string[]]$NotActions
            )

            [pscustomobject]@{
                Name = $Name
                Id = "/providers/Microsoft.Authorization/roleDefinitions/$Id"
                IsCustom = $true
                Permissions = @(
                    [pscustomobject]@{
                        Actions = @('*')
                        NotActions = $NotActions
                    }
                )
            }
        }
    }
    Mock Get-AzPolicyAssignment {
        throw 'Fallback must not run for a valid final REST page.'
    }

    It 'auto-selects every substantial Owner, Contributor, and Baseline role' {
        $roles = @(
            (New-TestWildcardRole `
                -Name 'Customer-Platform-Owner' `
                -Id '11111111-1111-1111-1111-111111111111' `
                -NotActions @('restricted/a', 'restricted/b')),
            (New-TestWildcardRole `
                -Name 'Workload-Storage-Owner' `
                -Id '22222222-2222-2222-2222-222222222222' `
                -NotActions @(
                    'restricted/a',
                    'restricted/b',
                    'Microsoft.Sql/*',
                    'Microsoft.Network/*'
                )),
            (New-TestWildcardRole `
                -Name 'Customer-Platform-Contributor' `
                -Id '33333333-3333-3333-3333-333333333333' `
                -NotActions @(
                    'restricted/a',
                    'restricted/b',
                    'restricted/c'
                )),
            (New-TestWildcardRole `
                -Name 'Peering Operator' `
                -Id '44444444-4444-4444-4444-444444444444' `
                -NotActions @('Microsoft.Sql/*'))
        )

        $selection = Get-RadarBaselineRole -Roles $roles

        $selection.SelectionMode | Should -Be 'Automatic'
        $selection.Roles.Name |
            Should -Contain 'Customer-Platform-Owner'
        $selection.Roles.Name |
            Should -Contain 'Customer-Platform-Contributor'
        $selection.Roles.Name |
            Should -Contain 'Workload-Storage-Owner'
        $selection.Roles.Name |
            Should -Not -Contain 'Peering Operator'
    }

    It 'uses explicit patterns instead of automatic name families' {
        $roles = @(
            (New-TestWildcardRole `
                -Name 'Customer-Platform-Owner' `
                -Id '11111111-1111-1111-1111-111111111111' `
                -NotActions @('restricted/a')),
            (New-TestWildcardRole `
                -Name 'Platform Baseline Admin' `
                -Id '22222222-2222-2222-2222-222222222222' `
                -NotActions @('restricted/b'))
        )

        $selection = Get-RadarBaselineRole `
            -Roles $roles `
            -Pattern '*Baseline Admin'

        $selection.SelectionMode | Should -Be 'ExplicitPattern'
        $selection.Roles.Name | Should -Be 'Platform Baseline Admin'
    }

    It 'returns no automatic selection when no safe name family is visible' {
        $selection = Get-RadarBaselineRole -Roles @(
            (New-TestWildcardRole `
                -Name 'Peering Operator' `
                -Id '44444444-4444-4444-4444-444444444444' `
                -NotActions @('Microsoft.Sql/*'))
        )

        $selection.Roles | Should -BeNullOrEmpty
    }
}

Describe 'Scoped baseline contexts' {
    BeforeEach {
        Mock Get-AzContext {
            [pscustomobject]@{
                Tenant = [pscustomobject]@{ Id = 'tenant-root' }
            }
        }
        Mock Get-AzManagementGroup {
            [pscustomobject]@{
                Id = '/providers/Microsoft.Management/managementGroups/tenant-root'
                Name = 'tenant-root'
                DisplayName = 'Tenant root'
                Children = @(
                    [pscustomobject]@{
                        Id = '/providers/Microsoft.Management/managementGroups/work'
                        Name = 'work'
                        DisplayName = 'Work'
                        Children = @(
                            [pscustomobject]@{
                                Id = '/subscriptions/sub-1'
                                Name = 'sub-1'
                                DisplayName = 'Subscription 1'
                                Children = @()
                            }
                        )
                    },
                    [pscustomobject]@{
                        Id = '/providers/Microsoft.Management/managementGroups/other'
                        Name = 'other'
                        DisplayName = 'Other'
                        Children = @(
                            [pscustomobject]@{
                                Id = '/subscriptions/sub-2'
                                Name = 'sub-2'
                                DisplayName = 'Subscription 2'
                                Children = @()
                            }
                        )
                    }
                )
            }
        }
    }

    It 'expands a management-group baseline only through its own subtree' {
        $knownScopes = @(
            (New-RadarScope `
                -Id '/providers/Microsoft.Management/managementGroups/work'),
            (New-RadarScope -Id '/subscriptions/sub-1'),
            (New-RadarScope `
                -Id '/subscriptions/sub-1/resourceGroups/workload'),
            (New-RadarScope -Id '/subscriptions/sub-2')
        )
        $hierarchy = Get-RadarScopeHierarchy -KnownScopes $knownScopes

        $subtree = Get-RadarSubtreeScope `
            -RootScope '/providers/Microsoft.Management/managementGroups/work' `
            -Scopes $hierarchy.Scopes `
            -Hierarchy $hierarchy

        $subtree.Scopes.Id | Should -Contain '/subscriptions/sub-1'
        $subtree.Scopes.Id |
            Should -Contain '/subscriptions/sub-1/resourceGroups/workload'
        $subtree.Scopes.Id | Should -Not -Contain '/subscriptions/sub-2'
    }

    It 'keeps baseline roles at the same scope as separate contexts' {
        $knownScopes = @(
            (New-RadarScope -Id '/subscriptions/sub-1')
        )
        $hierarchy = Get-RadarScopeHierarchy -KnownScopes $knownScopes
        $roles = @(
            [pscustomobject]@{
                Name = 'Customer-Platform-Owner'
                Id = '/providers/Microsoft.Authorization/roleDefinitions/11111111-1111-1111-1111-111111111111'
                IsCustom = $true
                AssignableScopes = @('/subscriptions/sub-1')
                Permissions = @(
                    [pscustomobject]@{
                        Actions = @('*')
                        NotActions = @(
                            'restricted/owner-only',
                            'restricted/shared',
                            'restricted/third'
                        )
                    }
                )
            },
            [pscustomobject]@{
                Name = 'Customer-Platform-Contributor'
                Id = '/providers/Microsoft.Authorization/roleDefinitions/22222222-2222-2222-2222-222222222222'
                IsCustom = $true
                AssignableScopes = @('/subscriptions/sub-1')
                Permissions = @(
                    [pscustomobject]@{
                        Actions = @('*')
                        NotActions = @(
                            'restricted/contributor-only',
                            'restricted/shared',
                            'restricted/third'
                        )
                    }
                )
            }
        )

        $result = Get-RadarBaselineContext `
            -BaselineRoles $roles `
            -KnownScopes $knownScopes `
            -Hierarchy $hierarchy

        $result.Contexts.Count | Should -Be 2
        (
            $result.Contexts |
                Where-Object {
                    $_.BaselineRoleName -eq 'Customer-Platform-Owner'
                }
        ).RestrictedActions |
            Should -Contain 'restricted/owner-only'
        (
            $result.Contexts |
                Where-Object {
                    $_.BaselineRoleName -eq 'Customer-Platform-Contributor'
                }
        ).RestrictedActions |
            Should -Not -Contain 'restricted/owner-only'
    }

    It 'omits a baseline AssignableScope outside the requested universe' {
        $knownScopes = @(
            (New-RadarScope -Id '/subscriptions/sub-1')
        )
        $hierarchy = Get-RadarScopeHierarchy -KnownScopes $knownScopes
        $role = [pscustomobject]@{
            Name = 'Customer-Platform-Owner'
            Id = '/providers/Microsoft.Authorization/roleDefinitions/11111111-1111-1111-1111-111111111111'
            IsCustom = $true
            AssignableScopes = @(
                '/subscriptions/sub-1',
                '/subscriptions/sub-2'
            )
            Permissions = @(
                [pscustomobject]@{
                    Actions = @('*')
                    NotActions = @(
                        'restricted/a',
                        'restricted/b',
                        'restricted/c'
                    )
                }
            )
        }

        $result = Get-RadarBaselineContext `
            -BaselineRoles @($role) `
            -KnownScopes $knownScopes `
            -Hierarchy $hierarchy

        $result.Contexts.Count | Should -Be 1
        $result.Contexts[0].BaselineScope |
            Should -Be '/subscriptions/sub-1'
    }

    It 'omits a concrete NotAction re-granted by another permission block' {
        $knownScopes = @(
            (New-RadarScope -Id '/subscriptions/sub-1')
        )
        $hierarchy = Get-RadarScopeHierarchy -KnownScopes $knownScopes
        $role = [pscustomobject]@{
            Name = 'Customer-Platform-Owner'
            Id = '/providers/Microsoft.Authorization/roleDefinitions/11111111-1111-1111-1111-111111111111'
            IsCustom = $true
            AssignableScopes = @('/subscriptions/sub-1')
            Permissions = @(
                [pscustomobject]@{
                    Actions = @('*')
                    NotActions = @(
                        'Dangerous.Provider/write',
                        'Dangerous.Provider/delete'
                    )
                },
                [pscustomobject]@{
                    Actions = @('Dangerous.Provider/write')
                    NotActions = @()
                }
            )
        }

        $result = Get-RadarBaselineContext `
            -BaselineRoles @($role) `
            -KnownScopes $knownScopes `
            -Hierarchy $hierarchy

        $result.Contexts[0].RestrictedActions |
            Should -Not -Contain 'Dangerous.Provider/write'
        $result.Contexts[0].RestrictedActions |
            Should -Contain 'Dangerous.Provider/delete'
    }

    It 'limits a subscription role to scopes below its AssignableScope' {
        $knownScopes = @(
            (New-RadarScope -Id '/subscriptions/sub-1'),
            (New-RadarScope `
                -Id '/subscriptions/sub-1/resourceGroups/workload'),
            (New-RadarScope -Id '/subscriptions/sub-2')
        )
        $hierarchy = Get-RadarScopeHierarchy -KnownScopes $knownScopes
        $role = [pscustomobject]@{
            Name = 'Subscription Operator'
            Id = '/providers/Microsoft.Authorization/roleDefinitions/33333333-3333-3333-3333-333333333333'
            IsCustom = $true
            AssignableScopes = @('/subscriptions/sub-1')
            Permissions = @(
                [pscustomobject]@{
                    Actions = @('Microsoft.Resources/*')
                    NotActions = @()
                }
            )
        }

        $availability = Get-RadarRoleScopesInContext `
            -Role $role `
            -ContextScopes $knownScopes `
            -Hierarchy $hierarchy

        $availability.Scopes.Id | Should -Contain '/subscriptions/sub-1'
        $availability.Scopes.Id |
            Should -Contain '/subscriptions/sub-1/resourceGroups/workload'
        $availability.Scopes.Id | Should -Not -Contain '/subscriptions/sub-2'
    }

    It 'keeps ancestry above an accessible fallback root unresolved' {
        $hierarchy = [pscustomobject]@{
            AncestorsByScope = @{
                '/providers/microsoft.management/managementgroups/child' = @()
            }
            UnresolvedAncestorRoots = @(
                '/providers/microsoft.management/managementgroups/child'
            )
        }

        $relationship = Test-RadarScopeDescendsFrom `
            -Scope '/providers/Microsoft.Management/managementGroups/child' `
            -RootScope '/providers/Microsoft.Management/managementGroups/unreadable-parent' `
            -Hierarchy $hierarchy

        $relationship.State | Should -Be 'Unknown'
    }

    It 'builds descendants from an accessible customer root without tenant-root read' {
        Mock Get-AzManagementGroup {
            if ($GroupName -eq 'tenant-root') {
                throw 'tenant root forbidden'
            }
            [pscustomobject]@{
                Id = '/providers/Microsoft.Management/managementGroups/customer-root'
                Name = 'customer-root'
                DisplayName = 'Customer root'
                ParentId = '/providers/Microsoft.Management/managementGroups/tenant-root'
                Children = @(
                    [pscustomobject]@{
                        Id = '/subscriptions/sub-1'
                        Name = 'sub-1'
                        DisplayName = 'Subscription 1'
                        Children = @()
                    }
                )
            }
        }
        $knownScopes = @(
            (New-RadarScope `
                -Id '/providers/Microsoft.Management/managementGroups/customer-root'),
            (New-RadarScope -Id '/subscriptions/sub-1')
        )

        $hierarchy = Get-RadarScopeHierarchy -KnownScopes $knownScopes
        $insideCustomer = Test-RadarScopeDescendsFrom `
            -Scope '/subscriptions/sub-1' `
            -RootScope '/providers/Microsoft.Management/managementGroups/customer-root' `
            -Hierarchy $hierarchy
        $aboveCustomer = Test-RadarScopeDescendsFrom `
            -Scope '/subscriptions/sub-1' `
            -RootScope '/providers/Microsoft.Management/managementGroups/tenant-root' `
            -Hierarchy $hierarchy

        $insideCustomer.State | Should -Be 'True'
        $aboveCustomer.State | Should -Be 'Unknown'
    }

    It 'does not let an observed external role scope poison required hierarchy completeness' {
        $requiredScopes = @(
            (New-RadarScope `
                -Id '/providers/Microsoft.Management/managementGroups/work'),
            (New-RadarScope -Id '/subscriptions/sub-1')
        )
        $knownScopes = @(
            @($requiredScopes) +
            (New-RadarScope -Id '/subscriptions/external')
        )

        $hierarchy = Get-RadarScopeHierarchy `
            -KnownScopes $knownScopes `
            -RequiredScopes $requiredScopes

        $hierarchy.IsComplete | Should -BeTrue
        $hierarchy.AncestorsByScope.ContainsKey(
            '/subscriptions/sub-1'
        ) | Should -BeTrue
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

    It 'retains roles beneath both roots in a mixed MG and subscription query' {
        Mock Get-AzRoleDefinition { @() }
        Mock Search-AzGraph {
            [pscustomobject]@{
                Data = @(
                    [pscustomobject]@{
                        Id = '/subscriptions/sub-1/providers/Microsoft.Authorization/roleDefinitions/22222222-2222-2222-2222-222222222222'
                        RoleName = 'Customer-Platform-Owner'
                        AssignableScopes = @('/subscriptions/sub-1')
                        Permissions = @(
                            [pscustomobject]@{
                                actions = @('*')
                                notActions = @('Dangerous.Provider/write')
                            }
                        )
                    },
                    [pscustomobject]@{
                        Id = '/subscriptions/unrelated/providers/Microsoft.Authorization/roleDefinitions/33333333-3333-3333-3333-333333333333'
                        RoleName = 'Standalone Workload Role'
                        AssignableScopes = @(
                            '/subscriptions/unrelated/resourceGroups/workload'
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
                (New-RadarScope `
                    -Id '/providers/Microsoft.Management/managementGroups/customer-root'),
                (New-RadarScope -Id '/subscriptions/unrelated')
            )

        $inventory.Warnings | Should -BeNullOrEmpty
        $inventory.CustomRoles.Name |
            Should -Contain 'Customer-Platform-Owner'
        $inventory.CustomRoles.Name |
            Should -Contain 'Standalone Workload Role'
        $mgRole = $inventory.CustomRoles |
            Where-Object { $_.Name -eq 'Customer-Platform-Owner' }
        $roleKey = Get-RadarRoleKey -Role $mgRole
        $inventory.RoleScopes[$roleKey] |
            Should -Contain '/subscriptions/sub-1'
        Should -Invoke Search-AzGraph -ParameterFilter {
            $UseTenantScope -and
            -not $ManagementGroup -and
            -not $Subscription
        }
    }
}

Describe 'New-RadarScope' {
    It 'classifies only exact subscription IDs as subscriptions' {
        (New-RadarScope -Id '/subscriptions/sub-1').Type |
            Should -Be 'Subscription'
        (
            New-RadarScope `
                -Id '/subscriptions/sub-1/resourceGroups/workload'
        ).Type | Should -Be 'ResourceGroup'
        (
            New-RadarScope `
                -Id '/subscriptions/sub-1/resourceGroups/workload/providers/Microsoft.Storage/storageAccounts/test'
        ).Type | Should -Be 'Resource'
    }
}

Describe 'Get-RadarPolicyBoundaryScope' {
    BeforeEach {
        Mock Search-AzGraph {
            [pscustomobject]@{
                Data = @()
                SkipToken = $null
            }
        }
        Mock Get-AzPolicyAssignment {
            @(
                [pscustomobject]@{
                    Id = '/subscriptions/sub-1/providers/Microsoft.Authorization/policyAssignments/deny'
                    Scope = '/subscriptions/sub-1'
                    NotScope = @(
                        '/subscriptions/sub-1/resourceGroups/excluded'
                    )
                }
            )
        }
        Mock Get-AzPolicyExemption {
            @(
                [pscustomobject]@{
                    Id = '/subscriptions/sub-1/resourceGroups/waived/providers/Microsoft.Authorization/policyExemptions/waiver'
                }
            )
        }
    }

    It 'uses live descendant queries to discover notScope and exemption boundaries' {
        $result = Get-RadarPolicyBoundaryScope -Scopes @(
            (New-RadarScope -Id '/subscriptions/sub-1')
        )

        $result.IsComplete | Should -BeTrue
        $result.Scopes.Id |
            Should -Contain '/subscriptions/sub-1/resourceGroups/excluded'
        $result.Scopes.Id |
            Should -Contain '/subscriptions/sub-1/resourceGroups/waived'
        Should -Invoke Get-AzPolicyAssignment -ParameterFilter {
            $IncludeDescendent -and
            $Scope -eq '/subscriptions/sub-1'
        }
        Should -Invoke Get-AzPolicyExemption -ParameterFilter {
            $IncludeDescendent -and
            $Scope -eq '/subscriptions/sub-1'
        }
    }

    It 'keeps exact-scope exemption evaluation separate from boundary discovery' {
        Mock Get-AzPolicyAssignment { @() }
        Mock Get-RadarPolicyAssignmentAtScope { @() }
        Mock Get-AzPolicyExemption { @() }

        $null = Get-RadarPolicyInventory -Scopes @(
            (New-RadarScope -Id '/subscriptions/sub-1')
        )

        Should -Invoke Get-AzPolicyExemption -ParameterFilter {
            -not $IncludeDescendent -and
            $Scope -eq '/subscriptions/sub-1'
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
                        like = 'Microsoft.Authorization/*'
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
                        like = 'Microsoft.Authorization/*'
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

Describe 'Test-RadarPolicyTypeApplicability' {
    It 'rules out an unrelated policy even when another condition is unsupported' {
        $condition = @{
            allOf = @(
                @{
                    field = 'type'
                    equals = 'Microsoft.Consumption/budgets'
                },
                @{
                    field =
                        'Microsoft.Consumption/budgets/notifications[*].contactEmails[*]'
                    notLike = '*@example.invalid'
                }
            )
        }

        Test-RadarPolicyTypeApplicability `
            -Condition $condition `
            -ResourceTypes @(
                'Microsoft.Authorization/roleAssignments',
                'Microsoft.Authorization/roleAssignmentScheduleRequests'
            ) |
            Should -Be 'False'
    }

    It 'retains a parameterised policy that can target role assignments' {
        $condition = @{
            field = 'type'
            in = "[parameters('targetTypes')]"
        }

        Test-RadarPolicyTypeApplicability `
            -Condition $condition `
            -Parameters @{
                targetTypes = @(
                    'Microsoft.Authorization/roleAssignments'
                )
            } `
            -ResourceTypes @(
                'Microsoft.Authorization/roleAssignments'
            ) |
            Should -Be 'True'
    }

    It 'evaluates a negated type condition per assignment resource type' {
        $condition = @{
            not = @{
                field = 'type'
                equals = 'Microsoft.Authorization/roleAssignments'
            }
        }

        Test-RadarPolicyTypeApplicability `
            -Condition $condition `
            -ResourceTypes @(
                'Microsoft.Authorization/roleAssignments',
                'Microsoft.Authorization/roleAssignmentScheduleRequests'
            ) |
            Should -Be 'True'
    }

    It 'does not exclude a negated composite with unconstrained conditions' {
        $condition = @{
            not = @{
                allOf = @(
                    @{
                        field = 'type'
                        like = 'Microsoft.Authorization/*'
                    },
                    @{
                        field = 'name'
                        equals = 'allowed'
                    }
                )
            }
        }

        Test-RadarPolicyTypeApplicability `
            -Condition $condition `
            -ResourceTypes @(
                'Microsoft.Authorization/roleAssignments'
            ) |
            Should -Be 'True'
    }
}

Describe 'Resolve-RadarPolicyAssignmentVersion' {
    It 'populates effective version through the available expansion path' {
        $assignment = [pscustomobject]@{
            Id = '/subscriptions/sub-1/providers/Microsoft.Authorization/policyAssignments/versioned'
            DefinitionVersion = '1.*.*'
        }

        if (
            (Get-Command Get-AzPolicyAssignment).Parameters.ContainsKey(
                'Expand'
            )
        ) {
            Mock Get-AzPolicyAssignment {
                [pscustomobject]@{
                    Id = $Id
                    DefinitionVersion = '1.*.*'
                    EffectiveDefinitionVersion = '1.2.3'
                }
            }
        }
        else {
            Mock Invoke-AzRestMethod {
                [pscustomobject]@{
                    Content = '{"properties":{"effectiveDefinitionVersion":"1.2.3"}}'
                }
            }
        }

        $expanded = Resolve-RadarPolicyAssignmentVersion `
            -Assignment $assignment

        $expanded.EffectiveDefinitionVersion |
            Should -Be '1.2.3'
    }
}

Describe 'Get-RadarPolicyAssignmentAtScope' {
    It 'lists assignments with effective versions expanded in one request' {
        Set-StrictMode -Version Latest
        Mock Invoke-AzRestMethod {
            [pscustomobject]@{
                Content = @'
{
  "value": [
    {
      "id": "/subscriptions/sub-1/providers/Microsoft.Authorization/policyAssignments/versioned",
      "properties": {
        "definitionVersion": "1.*.*",
        "effectiveDefinitionVersion": "1.2.3"
      }
    }
  ]
}
'@
            }
        }
        Mock Get-AzPolicyAssignment {
            throw 'Fallback must not run for a valid final REST page.'
        }

        $assignments = @(
            Get-RadarPolicyAssignmentAtScope `
                -Scope '/subscriptions/sub-1'
        )

        $assignments.Count | Should -Be 1
        $assignments[0].properties.effectiveDefinitionVersion |
            Should -Be '1.2.3'
        Should -Invoke Invoke-AzRestMethod -Times 1 -ParameterFilter {
            $Path -match '\$filter=atScope\(\)' -and
            $Path -match '\$expand=EffectiveDefinitionVersion'
        }
        Should -Invoke Get-AzPolicyAssignment -Times 0
    }
}

Describe 'Get-RadarPolicyDefinitionCached' {
    It 'falls back to REST when versioned Az.Resources output has no rule' {
        Mock Get-AzPolicyDefinition { $null }
        Mock Invoke-AzRestMethod {
            [pscustomobject]@{
                Content = @'
{
  "name": "1.2.3",
  "properties": {
    "displayName": "Deny selected roles",
    "policyType": "Custom",
    "mode": "All",
    "parameters": {},
    "policyRule": {
      "if": {
        "field": "type",
        "equals": "Microsoft.Authorization/roleAssignments"
      },
      "then": {
        "effect": "deny"
      }
    }
  }
}
'@
            }
        }

        $definition = Get-RadarPolicyDefinitionCached `
            -Id '/providers/Microsoft.Authorization/policyDefinitions/deny-roles' `
            -DefinitionCache @{} `
            -PolicySetCache @{} `
            -Version '1.2.3'

        $definition.Mode | Should -Be 'All'
        $definition.PolicyRule.then.effect | Should -Be 'deny'
        Should -Invoke Invoke-AzRestMethod -ParameterFilter {
            $Path -match '/versions/1\.2\.3\?api-version='
        }
    }

    It 'uses expanded REST output when initiative members remain ranged' {
        Mock Get-AzPolicySetDefinition {
            [pscustomobject]@{
                Id = $Id
                PolicyDefinition = @(
                    [pscustomobject]@{
                        PolicyDefinitionId =
                            '/providers/Microsoft.Authorization/policyDefinitions/member'
                        DefinitionVersion = '1.*.*'
                    }
                )
            }
        }
        Mock Invoke-AzRestMethod {
            [pscustomobject]@{
                Content = @'
{
  "name": "2.0.0",
  "properties": {
    "displayName": "Role controls",
    "policyType": "Custom",
    "parameters": {},
    "policyDefinitions": [
      {
        "policyDefinitionId": "/providers/Microsoft.Authorization/policyDefinitions/member",
        "definitionVersion": "1.*.*",
        "effectiveDefinitionVersion": "1.4.2"
      }
    ]
  }
}
'@
            }
        }

        $set = Get-RadarPolicyDefinitionCached `
            -Id '/providers/Microsoft.Authorization/policySetDefinitions/role-controls' `
            -DefinitionCache @{} `
            -PolicySetCache @{} `
            -Version '2.0.0'

        $set.PolicyDefinition[0].effectiveDefinitionVersion |
            Should -Be '1.4.2'
        Should -Invoke Invoke-AzRestMethod -ParameterFilter {
            $Path -match '\$expand=EffectiveDefinitionVersion'
        }
    }

    It 'rejects REST initiative output with unresolved member ranges' {
        Mock Get-AzPolicySetDefinition { $null }
        Mock Invoke-AzRestMethod {
            [pscustomobject]@{
                Content = @'
{
  "name": "2.0.0",
  "properties": {
    "displayName": "Role controls",
    "policyType": "Custom",
    "parameters": {},
    "policyDefinitions": [
      {
        "policyDefinitionId": "/providers/Microsoft.Authorization/policyDefinitions/member",
        "definitionVersion": "1.*.*"
      }
    ]
  }
}
'@
            }
        }

        {
            Get-RadarPolicyDefinitionCached `
                -Id '/providers/Microsoft.Authorization/policySetDefinitions/role-controls' `
                -DefinitionCache @{} `
                -PolicySetCache @{} `
                -Version '2.0.0'
        } | Should -Throw '*effective versions*'
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
        $script:ownerRole = [pscustomobject]@{
            Id = '/providers/Microsoft.Authorization/roleDefinitions/8e3af657-a8ff-443c-a75c-2fe8c4bcb635'
            Name = 'Owner'
        }
        $script:denyRule = @{
            if = @{
                field = 'Microsoft.Authorization/roleAssignments/roleDefinitionId'
                in = @($ownerRole.Id)
            }
            then = @{ effect = 'Deny' }
        }
        $script:directAssignmentPath = @(
            [pscustomobject]@{
                Name = 'Direct role assignment'
                ResourceType =
                    'Microsoft.Authorization/roleAssignments'
            }
        )
    }

    It 'does not treat a direct-assignment-only deny as covering PIM paths' {
        $directOnlyRule = [pscustomobject]@{
            AssignmentId = '/subscriptions/sub-1/providers/Microsoft.Authorization/policyAssignments/direct-only'
            AssignmentName = 'Deny direct role assignments'
            AssignmentScope = '/subscriptions/sub-1'
            NotScopes = @()
            DefinitionName = 'Deny direct role assignments'
            ReferenceId = $null
            PolicyRule = @{
                if = @{
                    allOf = @(
                        @{
                            field = 'type'
                            equals = 'Microsoft.Authorization/roleAssignments'
                        },
                        @{
                            field = 'Microsoft.Authorization/roleAssignments/roleDefinitionId'
                            in = @($ownerRole.Id)
                        }
                    )
                }
                then = @{ effect = 'Deny' }
            }
            Parameters = @{}
            UnsupportedReason = $null
        }
        $inventory = [pscustomobject]@{
            IsEvaluated = $true
            UncertainScopes = @()
            RulesByScope = @{
                '/subscriptions/sub-1' = @($directOnlyRule)
            }
            ExemptionsByScope = @{
                '/subscriptions/sub-1' = @()
            }
        }

        $coverage = Get-RadarRoleDenyCoverage `
            -Role $ownerRole `
            -RoleScopes @('/subscriptions/sub-1') `
            -PolicyInventory $inventory

        $coverage.Status | Should -Be 'None'
        $coverage.IsAlreadyDenied | Should -BeFalse
        $coverage.UnblockedAssignmentPaths |
            Should -Contain (
                '/subscriptions/sub-1 :: PIM active assignment request'
            )
    }

    It 'does not let a direct roleDefinitionId alias block PIM paths' {
        $aliasOnlyRule = [pscustomobject]@{
            AssignmentId = '/subscriptions/sub-1/providers/Microsoft.Authorization/policyAssignments/direct-alias'
            AssignmentName = 'Deny direct role alias'
            AssignmentScope = '/subscriptions/sub-1'
            NotScopes = @()
            DefinitionName = 'Deny direct role alias'
            ReferenceId = $null
            PolicyRule = @{
                if = @{
                    field =
                        'Microsoft.Authorization/roleAssignments/roleDefinitionId'
                    in = @($ownerRole.Id)
                }
                then = @{ effect = 'Deny' }
            }
            Parameters = @{}
            UnsupportedReason = $null
        }
        $inventory = [pscustomobject]@{
            IsEvaluated = $true
            UncertainScopes = @()
            RulesByScope = @{
                '/subscriptions/sub-1' = @($aliasOnlyRule)
            }
            ExemptionsByScope = @{
                '/subscriptions/sub-1' = @()
            }
        }

        $coverage = Get-RadarRoleDenyCoverage `
            -Role $ownerRole `
            -RoleScopes @('/subscriptions/sub-1') `
            -PolicyInventory $inventory

        $coverage.Status | Should -Be 'None'
        $coverage.UnblockedAssignmentPaths |
            Should -Contain (
                '/subscriptions/sub-1 :: PIM eligible assignment request'
            )
    }

    It 'does not let an unrelated Authorization alias block assignment paths' {
        $unrelatedAliasRule = [pscustomobject]@{
            AssignmentId = '/subscriptions/sub-1/providers/Microsoft.Authorization/policyAssignments/schedule-instance'
            AssignmentName = 'Deny schedule instance'
            AssignmentScope = '/subscriptions/sub-1'
            NotScopes = @()
            DefinitionName = 'Deny schedule instance'
            ReferenceId = $null
            PolicyRule = @{
                if = @{
                    field =
                        'Microsoft.Authorization/roleAssignmentScheduleInstances/roleDefinitionId'
                    in = @($ownerRole.Id)
                }
                then = @{ effect = 'Deny' }
            }
            Parameters = @{}
            UnsupportedReason = $null
        }
        $inventory = [pscustomobject]@{
            IsEvaluated = $true
            UncertainScopes = @()
            RulesByScope = @{
                '/subscriptions/sub-1' = @($unrelatedAliasRule)
            }
            ExemptionsByScope = @{
                '/subscriptions/sub-1' = @()
            }
        }

        $coverage = Get-RadarRoleDenyCoverage `
            -Role $ownerRole `
            -RoleScopes @('/subscriptions/sub-1') `
            -PolicyInventory $inventory

        $coverage.Status | Should -Be 'None'
        $coverage.IsAlreadyDenied | Should -BeFalse
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
            -PolicyInventory $inventory `
            -AssignmentPaths $directAssignmentPath

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
            -PolicyInventory $inventory `
            -AssignmentPaths $directAssignmentPath

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
                '/subscriptions/sub-1/resourcegroups/excluded' = @($rule)
            }
            ExemptionsByScope = @{
                '/subscriptions/sub-1' = @()
                '/subscriptions/sub-1/resourcegroups/excluded' = @()
            }
        }

        $coverage = Get-RadarRoleDenyCoverage `
            -Role $ownerRole `
            -RoleScopes @(
                '/subscriptions/sub-1',
                '/subscriptions/sub-1/resourceGroups/excluded'
            ) `
            -PolicyInventory $inventory `
            -AssignmentPaths $directAssignmentPath

        $coverage.Status | Should -Be 'Partial'
        $coverage.IsAlreadyDenied | Should -BeFalse
        $coverage.UnblockedScopes |
            Should -Contain '/subscriptions/sub-1/resourceGroups/excluded'
    }

    It 'honours management-group notScopes through the hierarchy' {
        $rule = [pscustomobject]@{
            AssignmentId = '/providers/Microsoft.Management/managementGroups/root/providers/Microsoft.Authorization/policyAssignments/deny'
            AssignmentName = 'Deny Owner'
            AssignmentScope = '/providers/Microsoft.Management/managementGroups/root'
            NotScopes = @(
                '/providers/Microsoft.Management/managementGroups/uat'
            )
            DefinitionName = 'Deny Owner'
            ReferenceId = $null
            PolicyRule = $denyRule
            Parameters = @{}
            UnsupportedReason = $null
        }
        $inventory = [pscustomobject]@{
            IsEvaluated = $true
            UncertainScopes = @()
            RulesByScope = @{
                '/subscriptions/sub-uat' = @($rule)
            }
            ExemptionsByScope = @{
                '/subscriptions/sub-uat' = @()
            }
        }
        $hierarchy = [pscustomobject]@{
            AncestorsByScope = @{
                '/subscriptions/sub-uat' = @(
                    '/providers/Microsoft.Management/managementGroups/root',
                    '/providers/Microsoft.Management/managementGroups/uat'
                )
            }
            UnresolvedAncestorRoots = @()
        }

        $coverage = Get-RadarRoleDenyCoverage `
            -Role $ownerRole `
            -RoleScopes @('/subscriptions/sub-uat') `
            -PolicyInventory $inventory `
            -ScopeHierarchy $hierarchy `
            -AssignmentPaths $directAssignmentPath

        $coverage.Status | Should -Be 'None'
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
            UncertainScopes = @('/subscriptions/sub-1')
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
            -PolicyInventory $inventory `
            -AssignmentPaths $directAssignmentPath

        $coverage.Status | Should -Be 'Unknown'
        $coverage.IsAlreadyDenied | Should -BeFalse
    }

    It 'does not let an unrelated failed policy scope downgrade full coverage' {
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
            UncertainScopes = @('/subscriptions/sub-2')
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
            -PolicyInventory $inventory `
            -AssignmentPaths $directAssignmentPath

        $coverage.Status | Should -Be 'Full'
        $coverage.IsAlreadyDenied | Should -BeTrue
    }

    It 'reuses role-policy evaluation across scopes and coverage calls' {
        $rule = [pscustomobject]@{
            AssignmentId = '/providers/Microsoft.Authorization/policyAssignments/deny-owner'
            AssignmentName = 'Deny Owner'
            AssignmentScope = '/'
            NotScopes = @()
            DefinitionName = 'Deny Owner'
            ReferenceId = $null
            PolicyRule = $denyRule
            Parameters = @{}
            UnsupportedReason = $null
        }
        $inventory = [pscustomobject]@{
            IsEvaluated = $true
            UncertainScopes = @()
            RulesByScope = @{
                '/subscriptions/sub-1' = @($rule)
                '/subscriptions/sub-2' = @($rule)
            }
            ExemptionsByScope = @{
                '/subscriptions/sub-1' = @()
                '/subscriptions/sub-2' = @()
            }
        }
        $evaluationCache = @{}
        Mock Test-RadarPolicyRuleForRole {
            [pscustomobject]@{
                State = 'Blocked'
                Reason = $null
            }
        }

        foreach ($scope in @(
            '/subscriptions/sub-1',
            '/subscriptions/sub-2'
        )) {
            $coverage = Get-RadarRoleDenyCoverage `
                -Role $ownerRole `
                -RoleScopes @($scope) `
                -PolicyInventory $inventory `
                -AssignmentPaths $directAssignmentPath `
                -PolicyEvaluationCache $evaluationCache
            $coverage.Status | Should -Be 'Full'
        }

        Should -Invoke Test-RadarPolicyRuleForRole -Times 1
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

Describe 'Normalised CSV output' {
    It 'gives separate baselines distinct stable coverage keys' {
        $first = Get-RadarCoverageKey `
            -AnalysisMode 'BaselineNotActions' `
            -BaselineRoleId 'baseline-1' `
            -BaselineScope '/subscriptions/sub-1' `
            -RoleId 'role-1' `
            -AssignmentPath 'Direct role assignment'
        $repeat = Get-RadarCoverageKey `
            -AnalysisMode 'BaselineNotActions' `
            -BaselineRoleId 'baseline-1' `
            -BaselineScope '/subscriptions/sub-1' `
            -RoleId 'role-1' `
            -AssignmentPath 'Direct role assignment'
        $second = Get-RadarCoverageKey `
            -AnalysisMode 'BaselineNotActions' `
            -BaselineRoleId 'baseline-2' `
            -BaselineScope '/subscriptions/sub-1' `
            -RoleId 'role-1' `
            -AssignmentPath 'Direct role assignment'

        $first | Should -Be $repeat
        $first | Should -Not -Be $second
    }

    It 'exports match and coverage files with valid joins and no temp files' {
        $matchPath = Join-Path $TestDrive 'matches.csv'
        $coveragePath = Join-Path $TestDrive 'matches-coverage.csv'
        $result = [pscustomobject]@{
            AnalysisMode = 'BaselineNotActions'
            BaselineRoleName = 'Baseline'
            BaselineRoleId = 'baseline-1'
            BaselineScope = '/subscriptions/sub-1'
            RestrictionSource = 'Baseline role NotActions'
            AssignmentPath = 'Direct role assignment'
            RoleName = 'Owner'
            RoleId = 'role-1'
            IsCustom = $false
            RestrictedAction = 'Dangerous.Provider/write'
            MatchedPattern = '*'
            CoverageKey = 'CV-test'
            IsAlreadyDenied = $false
            DenyCoverage = 'None'
            DeniedScopeCount = 0
            EvaluatedScopeCount = 1
            BlockingPolicyCount = 0
            UnblockedScopeCount = 1
            UnblockedAssignmentPathCount = 1
            CoverageWarningCount = 0
            BlockingPolicies = ''
            DeniedScopes = ''
            UnblockedScopes = '/subscriptions/sub-1'
            UnblockedAssignmentPaths =
                '/subscriptions/sub-1 :: Direct role assignment'
            CoverageWarnings = ''
        }

        Export-RadarCsvReports `
            -Results @($result) `
            -MatchCsvPath $matchPath `
            -CoverageCsvPath $coveragePath

        $match = Import-Csv -LiteralPath $matchPath
        $coverage = Import-Csv -LiteralPath $coveragePath
        $match.CoverageKey | Should -Be $coverage.CoverageKey
        $match.PSObject.Properties.Name |
            Should -Not -Contain 'CoverageWarnings'
        $coverage.UnblockedScopes |
            Should -Be '/subscriptions/sub-1'
        @(Get-ChildItem -LiteralPath $TestDrive -Filter '*.tmp.*').Count |
            Should -Be 0
        $manifestPath = "$matchPath.manifest.json"
        Test-Path -LiteralPath $manifestPath | Should -BeTrue
        $manifest = (
            Get-Content -LiteralPath $manifestPath -Raw
        ) | ConvertFrom-Json
        Test-Path -LiteralPath $manifest.MatchCsv | Should -BeTrue
        Test-Path -LiteralPath $manifest.CoverageCsv | Should -BeTrue
        (
            Import-Csv -LiteralPath $manifest.MatchCsv
        ).CoverageKey |
            Should -Be (
                Import-Csv -LiteralPath $manifest.CoverageCsv
            ).CoverageKey
    }

    It 'does not delete paths outside owned report generations' {
        $matchPath = Join-Path $TestDrive 'matches.csv.partial'
        $coveragePath =
            Join-Path $TestDrive 'matches-coverage.csv.partial'
        $victimPath = Join-Path $TestDrive 'keep-me.txt'
        Set-Content -LiteralPath $matchPath -Value 'match'
        Set-Content -LiteralPath $coveragePath -Value 'coverage'
        Set-Content -LiteralPath $victimPath -Value 'important'
        [pscustomobject]@{
            MatchCsv = $victimPath
            CoverageCsv = $victimPath
        } |
            ConvertTo-Json |
            Set-Content `
                -LiteralPath "$matchPath.manifest.json"

        Remove-RadarCsvReportSet `
            -MatchCsvPath $matchPath `
            -CoverageCsvPath $coveragePath

        Test-Path -LiteralPath $victimPath | Should -BeTrue
    }

    It 'uses case-sensitive directory ownership on non-Windows hosts' -Skip:(
        [System.Environment]::OSVersion.Platform -eq
        [System.PlatformID]::Win32NT
    ) {
        $lowerDirectory = Join-Path $TestDrive 'reports'
        $upperDirectory = Join-Path $TestDrive 'Reports'
        New-Item -ItemType Directory -Path $lowerDirectory | Out-Null
        New-Item -ItemType Directory -Path $upperDirectory | Out-Null

        Test-RadarOwnedGenerationPath `
            -CandidatePath (
                Join-Path `
                    $upperDirectory `
                    'matches.csv.generation-test'
            ) `
            -ReportPath (
                Join-Path $lowerDirectory 'matches.csv'
            ) |
            Should -BeFalse
    }

    It 'publishes provider-resolved manifest paths for relative outputs' {
        $originalLocation = Get-Location
        try {
            Set-Location $TestDrive
            $result = [pscustomobject]@{
                AnalysisMode = 'GlobalCsv'
                BaselineRoleName = 'CSV'
                BaselineRoleId = ''
                BaselineScope = 'Estate'
                RestrictionSource = 'Input CSV'
                AssignmentPath = 'Direct'
                RoleName = 'Owner'
                RoleId = 'role-1'
                IsCustom = $false
                RestrictedAction = 'Dangerous/write'
                MatchedPattern = '*'
                CoverageKey = 'CV-relative'
                IsAlreadyDenied = $false
                DenyCoverage = 'None'
                DeniedScopeCount = 0
                EvaluatedScopeCount = 1
                BlockingPolicyCount = 0
                UnblockedScopeCount = 1
                UnblockedAssignmentPathCount = 1
                CoverageWarningCount = 0
                BlockingPolicies = ''
                DeniedScopes = ''
                UnblockedScopes = '/subscriptions/sub-1'
                UnblockedAssignmentPaths = 'Direct'
                CoverageWarnings = ''
            }

            Export-RadarCsvReports `
                -Results @($result) `
                -MatchCsvPath 'relative.csv' `
                -CoverageCsvPath 'relative-coverage.csv'

            $manifest = (
                Get-Content `
                    -LiteralPath 'relative.csv.manifest.json' `
                    -Raw
            ) | ConvertFrom-Json
            $manifest.MatchCsv.StartsWith(
                [string]$TestDrive
            ) | Should -BeTrue
            $manifest.CoverageCsv.StartsWith(
                [string]$TestDrive
            ) | Should -BeTrue
        }
        finally {
            Set-Location $originalLocation
        }
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
        Mock Search-AzGraph {
            [pscustomobject]@{
                Data = @()
                SkipToken = $null
            }
        }
        Mock Get-AzPolicyExemption { @() }
        Mock Get-AzPolicyAssignment { @() }
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
        Test-Path -LiteralPath "$outputCsv.manifest.json" |
            Should -BeTrue
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

        Mock Get-RadarPolicyAssignmentAtScope {
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
                        field = 'type'
                        like = 'Microsoft.Authorization/*'
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
        $coverageResult = Import-Csv -LiteralPath (
            Get-RadarCoverageCsvPath -MatchCsvPath $outputCsv
        ) |
            Where-Object {
                $_.CoverageKey -eq $result.CoverageKey
            }
        $coverageResult.BlockingPolicies |
            Should -Match (
                'Deny Reader \[/subscriptions/sub-1\] via ' +
                'Direct role assignment'
            )
    }

    It 'falls back to the bundled CSV when automatic baseline discovery finds no role' {
        $outputCsv = Join-Path $TestDrive 'dynamic-fallback.csv'
        Mock Search-AzGraph {
            [pscustomobject]@{
                Data = @(
                    [pscustomobject]@{
                        Id = '/subscriptions/sub-1/providers/Microsoft.Authorization/roleDefinitions/44444444-4444-4444-4444-444444444444'
                        RoleName = 'Peering Operator'
                        AssignableScopes = @('/subscriptions/sub-1')
                        Permissions = @(
                            [pscustomobject]@{
                                actions = @('*')
                                notActions = @('Microsoft.Sql/*')
                            }
                        )
                    }
                )
                SkipToken = $null
            }
        }

        {
            & $scriptPath `
                -NoMenu `
                -CurrentSubscriptionOnly `
                -DynamicRestrictedActions `
                -NoPolicyDiscovery `
                -OutputCsv $outputCsv
        } | Should -Not -Throw

        Test-Path -LiteralPath $outputCsv | Should -BeTrue
        (Get-Content -LiteralPath $outputCsv -Raw) |
            Should -Match '"RestrictedAction"'
    }
}

Describe 'Invoke-Radar scoped baseline gap model' {
    BeforeEach {
        Mock Get-AzContext {
            [pscustomobject]@{
                Account = [pscustomobject]@{
                    Id = 'test@example.invalid'
                }
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
        Mock Get-AzPolicyAssignment { @() }
        Mock Get-AzRoleDefinition {
            @(
                [pscustomobject]@{
                    Name = 'Dangerous Built-in'
                    Id = '/providers/Microsoft.Authorization/roleDefinitions/aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa'
                    IsCustom = $false
                    AssignableScopes = @('/')
                    Permissions = @(
                        [pscustomobject]@{
                            Actions = @('Dangerous.Provider/*')
                            NotActions = @()
                        }
                    )
                }
            )
        }
        Mock Search-AzGraph {
            if ($Query -match 'roledefinitions') {
                return [pscustomobject]@{
                    Data = @(
                        [pscustomobject]@{
                            Id = '/subscriptions/sub-1/providers/Microsoft.Authorization/roleDefinitions/11111111-1111-1111-1111-111111111111'
                            RoleName = 'Customer-Platform-Owner'
                            AssignableScopes = @('/subscriptions/sub-1')
                            Permissions = @(
                                [pscustomobject]@{
                                    actions = @('*')
                                    notActions = @(
                                        'Dangerous.Provider/write',
                                        'Dangerous.Provider/delete',
                                        'Dangerous.Provider/action',
                                        'Microsoft.Authorization/roleAssignmentScheduleRequests/write',
                                        'Microsoft.Authorization/roleEligibilityScheduleRequests/write'
                                    )
                                }
                            )
                        },
                        [pscustomobject]@{
                            Id = '/subscriptions/sub-2/providers/Microsoft.Authorization/roleDefinitions/22222222-2222-2222-2222-222222222222'
                            RoleName = 'Customer-Platform-Owner-UAT'
                            AssignableScopes = @('/subscriptions/sub-2')
                            Permissions = @(
                                [pscustomobject]@{
                                    actions = @('*')
                                    notActions = @(
                                        'Dangerous.Provider/write',
                                        'Dangerous.Provider/delete',
                                        'Dangerous.Provider/action',
                                        'Microsoft.Authorization/roleAssignmentScheduleRequests/write',
                                        'Microsoft.Authorization/roleEligibilityScheduleRequests/write'
                                    )
                                }
                            )
                        }
                    )
                    SkipToken = $null
                }
            }

            return [pscustomobject]@{
                Data = @()
                SkipToken = $null
            }
        }
        Mock Get-RadarPolicyAssignmentAtScope {
            if ($Scope -ieq '/subscriptions/sub-1') {
                return @(
                    [pscustomobject]@{
                        Id = '/subscriptions/sub-1/providers/Microsoft.Authorization/policyAssignments/deny-danger'
                        Name = 'deny-danger'
                        DisplayName = 'Deny Dangerous Built-in'
                        Scope = '/subscriptions/sub-1'
                        PolicyDefinitionId = '/providers/Microsoft.Authorization/policyDefinitions/deny-danger'
                        EnforcementMode = 'Default'
                        Parameter = [pscustomobject]@{
                            roleIds = [pscustomobject]@{
                                value = @(
                                    '/providers/Microsoft.Authorization/roleDefinitions/aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa'
                                )
                            }
                        }
                        NotScope = @()
                    }
                )
            }
            return @()
        }
        Mock Get-AzPolicyDefinition {
            [pscustomobject]@{
                Id = $Id
                Name = 'deny-danger'
                DisplayName = 'Deny Dangerous Built-in'
                Mode = 'All'
                Parameter = [pscustomobject]@{}
                PolicyRule = @{
                    if = @{
                        allOf = @(
                            @{
                                field = 'type'
                                like = 'Microsoft.Authorization/*'
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
        Mock Get-AzPolicyExemption { @() }
    }

    It 'keeps customer-style baselines separate and exposes the unblocked scope' {
        $outputCsv = Join-Path $TestDrive 'scoped-gaps.csv'

        & $scriptPath `
            -NoMenu `
            -Scope '/subscriptions/sub-1','/subscriptions/sub-2' `
            -DynamicRestrictedActions `
            -BaselineRolePattern 'Customer-Platform-*' `
            -OutputCsv $outputCsv

        $results = @(Import-Csv -LiteralPath $outputCsv)
        $production = @(
            $results |
                Where-Object {
                    $_.AnalysisMode -eq 'BaselineNotActions' -and
                    $_.BaselineRoleName -eq 'Customer-Platform-Owner' -and
                    $_.RoleName -eq 'Dangerous Built-in' -and
                    $_.RestrictedAction -eq 'Dangerous.Provider/write'
                }
        )
        $uat = @(
            $results |
                Where-Object {
                    $_.AnalysisMode -eq 'BaselineNotActions' -and
                    $_.BaselineRoleName -eq 'Customer-Platform-Owner-UAT' -and
                    $_.RoleName -eq 'Dangerous Built-in' -and
                    $_.RestrictedAction -eq 'Dangerous.Provider/write'
                }
        )

        $production.Count | Should -Be 1
        $production[0].BaselineScope |
            Should -Be '/subscriptions/sub-1'
        $production[0].DenyCoverage | Should -Be 'Full'
        $uat.Count | Should -Be 1
        $uat[0].BaselineScope | Should -Be '/subscriptions/sub-2'
        $uat[0].DenyCoverage | Should -Be 'None'
        $uat[0].UnblockedScopeCount | Should -Be '1'
        $coverageResult = Import-Csv -LiteralPath (
            Get-RadarCoverageCsvPath -MatchCsvPath $outputCsv
        ) |
            Where-Object {
                $_.CoverageKey -eq $uat[0].CoverageKey
            }
        $coverageResult.UnblockedScopes |
            Should -Be '/subscriptions/sub-2'
        Test-Path -LiteralPath "$outputCsv.partial" |
            Should -BeFalse
        Test-Path -LiteralPath "$(
            Get-RadarCoverageCsvPath -MatchCsvPath $outputCsv
        ).partial" | Should -BeFalse
        Test-Path -LiteralPath "$outputCsv.partial.manifest.json" |
            Should -BeFalse
        @(
            Get-ChildItem `
                -LiteralPath $TestDrive `
                -Filter 'scoped-gaps*.partial.generation-*'
        ).Count | Should -Be 0
    }
}
