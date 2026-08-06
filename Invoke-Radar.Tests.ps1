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
            IsComplete = $true
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

    It 'proves separately mapped fallback roots are not nested' {
        $firstRoot =
            '/providers/Microsoft.Management/managementGroups/first'
        $secondRoot =
            '/providers/Microsoft.Management/managementGroups/second'
        $hierarchy = [pscustomobject]@{
            AncestorsByScope = @{
                $firstRoot.ToLowerInvariant() = @()
                $secondRoot.ToLowerInvariant() = @()
                '/subscriptions/sub-2' = @($secondRoot)
            }
            UnresolvedAncestorRoots = @(
                $firstRoot,
                $secondRoot
            )
        }

        $relationship = Test-RadarScopeDescendsFrom `
            -Scope '/subscriptions/sub-2' `
            -RootScope $firstRoot `
            -Hierarchy $hierarchy

        $relationship.State | Should -Be 'False'
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

    It 'fills an unplaced subscription ancestry from Resource Graph' {
        Mock Get-AzManagementGroup {
            if ($GroupName -eq 'tenant-root') {
                throw 'tenant root forbidden'
            }
            [pscustomobject]@{
                Id = '/providers/Microsoft.Management/managementGroups/customer-root'
                Name = 'customer-root'
                DisplayName = 'Customer root'
                ParentId = '/providers/Microsoft.Management/managementGroups/tenant-root'
                Children = @()
            }
        }
        Mock Search-AzGraph {
            [pscustomobject]@{
                SubscriptionId = 'sub-unplaced'
                ManagementGroupAncestorsChain = @(
                    [pscustomobject]@{
                        Name = 'leaf'
                    },
                    [pscustomobject]@{
                        Name = 'middle'
                    },
                    [pscustomobject]@{
                        Name = 'tenant-root'
                    }
                )
            }
        }
        $knownScopes = @(
            (New-RadarScope `
                -Id '/providers/Microsoft.Management/managementGroups/customer-root'),
            (New-RadarScope -Id '/subscriptions/sub-unplaced')
        )

        $hierarchy = Get-RadarScopeHierarchy `
            -KnownScopes $knownScopes `
            -RequiredScopes $knownScopes

        $hierarchy.IsComplete | Should -BeTrue
        $hierarchy.AncestorsByScope[
            '/subscriptions/sub-unplaced'
        ] | Should -Be @(
            '/providers/Microsoft.Management/managementGroups/tenant-root',
            '/providers/Microsoft.Management/managementGroups/middle',
            '/providers/Microsoft.Management/managementGroups/leaf'
        )
        $map = @(
            Get-RadarControlGapMap `
                -Results @(
                    [pscustomobject]@{
                        AnalysisMode = 'BaselineNotActions'
                        BaselineRoleName =
                            'Customer-Platform-Owner'
                        BaselineRoleId = 'baseline-1'
                        BaselineScope =
                            '/providers/Microsoft.Management/managementGroups/leaf'
                        RestrictedAction =
                            'Dangerous.Provider/write'
                        RoleName = 'Contributor'
                        RoleId = 'role-1'
                        ScopeEvaluations = @(
                            [pscustomobject]@{
                                Scope =
                                    '/subscriptions/sub-unplaced'
                                GapStatus = 'Gap'
                                BlockingPolicies = @()
                                UnblockedAssignmentPaths = @(
                                    'Direct role assignment'
                                )
                                BaselineAssignablePaths = @(
                                    'Direct role assignment'
                                )
                                ExternalAssignmentPaths = @()
                                UnknownReasons = @()
                            }
                        )
                    }
                ) `
                -ScopeById $hierarchy.ScopeById `
                -Hierarchy $hierarchy
        )
        $map[0].ParentScope | Should -Be (
            '/providers/Microsoft.Management/managementGroups/leaf'
        )
        $map[0].AncestorScopes | Should -Be (
            @(
                '/providers/Microsoft.Management/managementGroups/tenant-root',
                '/providers/Microsoft.Management/managementGroups/middle',
                '/providers/Microsoft.Management/managementGroups/leaf'
            ) -join '; '
        )
        Should -Invoke Search-AzGraph -Times 1
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

    It 'omits the Tenant Root Group from automatic estate scopes' {
        Mock Get-AzManagementGroup {
            @(
                [pscustomobject]@{
                    Id = '/providers/Microsoft.Management/managementGroups/tenant-1'
                    Name = 'tenant-1'
                    DisplayName = 'Tenant Root Group'
                },
                [pscustomobject]@{
                    Id = '/providers/Microsoft.Management/managementGroups/customer-root'
                    Name = 'customer-root'
                    DisplayName = 'Customer root'
                }
            )
        }

        $result = Get-RadarScanScope

        $result.Scopes.Id | Should -Not -Contain (
            '/providers/Microsoft.Management/managementGroups/tenant-1'
        )
        $result.Scopes.Id | Should -Contain (
            '/providers/Microsoft.Management/managementGroups/customer-root'
        )
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

Describe 'Get-RadarBaselineRoleAssignmentInventory' {
    It 'loads relevant direct assignments in one filtered graph query' {
        Mock Search-AzGraph {
            [pscustomobject]@{
                Data = @(
                    [pscustomobject]@{
                        AssignmentId =
                            '/subscriptions/sub-1/providers/Microsoft.Authorization/roleAssignments/assignment-1'
                        AssignmentScope = '/subscriptions/sub-1'
                        PrincipalId = 'principal-1'
                        PrincipalType = 'User'
                        RoleDefinitionId =
                            '/providers/Microsoft.Authorization/roleDefinitions/11111111-1111-1111-1111-111111111111'
                        RoleDefinitionGuid =
                            '11111111-1111-1111-1111-111111111111'
                    }
                )
                SkipToken = $null
            }
        }
        $context = [pscustomobject]@{
            BaselineRoleId =
                '/providers/Microsoft.Authorization/roleDefinitions/11111111-1111-1111-1111-111111111111'
        }

        $inventory =
            Get-RadarBaselineRoleAssignmentInventory `
                -BaselineContexts @($context)

        $inventory.IsComplete | Should -BeTrue
        $inventory.AssignmentCount | Should -Be 1
        $inventory.Assignments[0].AssignmentScope |
            Should -Be '/subscriptions/sub-1'
        Should -Invoke Search-AzGraph -Times 1 -ParameterFilter {
            $Query -match
                'microsoft\.authorization/roleassignments' -and
            $Query -match
                '11111111-1111-1111-1111-111111111111' -and
            $UseTenantScope -and
            -not $Subscription -and
            -not $ManagementGroup
        }
    }

    It 'retains the id column and follows graph skip tokens' {
        Mock Search-AzGraph {
            $suffix = if ($SkipToken) { '2' } else { '1' }
            [pscustomobject]@{
                Data = @(
                    [pscustomobject]@{
                        Id = "assignment-$suffix"
                        AssignmentId = "assignment-$suffix"
                        AssignmentScope = '/subscriptions/sub-1'
                        PrincipalId = "principal-$suffix"
                        PrincipalType = 'User'
                        RoleDefinitionId =
                            '/providers/Microsoft.Authorization/roleDefinitions/11111111-1111-1111-1111-111111111111'
                        RoleDefinitionGuid =
                            '11111111-1111-1111-1111-111111111111'
                    }
                )
                SkipToken = if ($SkipToken) { $null } else { 'next' }
            }
        }

        $inventory =
            Get-RadarBaselineRoleAssignmentInventory `
                -BaselineContexts @(
                    [pscustomobject]@{
                        BaselineRoleId =
                            '/providers/Microsoft.Authorization/roleDefinitions/11111111-1111-1111-1111-111111111111'
                    }
                )

        $inventory.AssignmentCount | Should -Be 2
        Should -Invoke Search-AzGraph -Times 2
        Should -Invoke Search-AzGraph -Times 1 -ParameterFilter {
            $SkipToken -eq 'next'
        }
        Should -Invoke Search-AzGraph -ParameterFilter {
            $Query -match '(?s)\| project\s+id,'
        }
    }

    It 'reports assignment exposure unknown when graph is disabled' {
        $inventory =
            Get-RadarBaselineRoleAssignmentInventory `
                -BaselineContexts @(
                    [pscustomobject]@{
                        BaselineRoleId =
                            '/providers/Microsoft.Authorization/roleDefinitions/11111111-1111-1111-1111-111111111111'
                    }
                ) `
                -NoAssignmentDiscovery

        $inventory.IsComplete | Should -BeFalse
        $inventory.IsEvaluated | Should -BeFalse
    }
}

Describe 'Get-RadarPrincipalDirectoryEvidence' {
    It 'batches enabled-state and paged transitive-group requests' {
        Mock Get-AzAccessToken {
            [pscustomobject]@{ Token = 'test-token' }
        }
        $script:directoryBatchSizes = @()
        $script:directoryAuthorizations = @()
        Mock Invoke-RestMethod {
            $payload = $Body | ConvertFrom-Json
            $script:directoryBatchSizes +=
                @($payload.requests).Count
            $script:directoryAuthorizations +=
                [string]$Headers.Authorization
            $responses = @(
                foreach ($request in @($payload.requests)) {
                    if ($request.url -match 'transitiveMemberOf') {
                        $principalId = (
                            $request.url -split '/'
                        )[2]
                        $pageTwo =
                            $request.url -match 'page=2'
                        $body = [ordered]@{
                            value = @(
                                [pscustomobject]@{
                                    id = if ($pageTwo) {
                                        "$principalId-group-2"
                                    }
                                    else {
                                        "$principalId-group-1"
                                    }
                                }
                            )
                        }
                        if (-not $pageTwo) {
                            $body['@odata.nextLink'] =
                                "https://graph.microsoft.com/v1.0/users/$principalId/transitiveMemberOf/microsoft.graph.group?page=2"
                        }
                        [pscustomobject]@{
                            id = $request.id
                            status = 200
                            body = [pscustomobject]$body
                        }
                    }
                    else {
                        [pscustomobject]@{
                            id = $request.id
                            status = 200
                            body = [pscustomobject]@{
                                id = (
                                    $request.url -split '/'
                                )[2]
                                accountEnabled = $true
                            }
                        }
                    }
                }
            )
            [pscustomobject]@{ responses = $responses }
        }
        $assignments = @(
            foreach ($index in 1..11) {
                [pscustomobject]@{
                    PrincipalId =
                        ('00000000-0000-0000-0000-{0:D12}' -f $index)
                    PrincipalType = 'User'
                }
            }
        )
        $baselineInventory = [pscustomobject]@{
            IsEvaluated = $true
            IsComplete = $true
            Warnings = @()
            Assignments = $assignments
        }

        $evidence = Get-RadarPrincipalDirectoryEvidence `
            -BaselineAssignmentInventory $baselineInventory

        $evidence.IsComplete | Should -BeTrue
        $evidence.EvidenceByPrincipal.Count | Should -Be 11
        $evidence.GroupIds.Count | Should -Be 22
        ($script:directoryBatchSizes | Measure-Object -Maximum).
            Maximum | Should -BeLessOrEqual 20
        @($script:directoryAuthorizations | Sort-Object -Unique) |
            Should -Be @('Bearer test-token')
        Should -Invoke Invoke-RestMethod -Times 3
    }

    It 'keeps principal IDs out of global Graph warnings' {
        Mock Get-AzAccessToken {
            [pscustomobject]@{ Token = 'test-token' }
        }
        Mock Invoke-RestMethod {
            $payload = $Body | ConvertFrom-Json
            [pscustomobject]@{
                responses = @(
                    foreach ($request in @($payload.requests)) {
                        [pscustomobject]@{
                            id = $request.id
                            status = 403
                            body = [pscustomobject]@{}
                        }
                    }
                )
            }
        }
        $principalId = '33333333-3333-3333-3333-333333333333'
        $baselineInventory = [pscustomobject]@{
            IsEvaluated = $true
            IsComplete = $true
            Warnings = @()
            Assignments = @(
                [pscustomobject]@{
                    PrincipalId = $principalId
                    PrincipalType = 'User'
                }
            )
        }

        $evidence = Get-RadarPrincipalDirectoryEvidence `
            -BaselineAssignmentInventory $baselineInventory

        $evidence.IsComplete | Should -BeFalse
        ($evidence.Warnings -join ' ') | Should -Not -Match $principalId
        (
            $evidence.EvidenceByPrincipal[
                $principalId
            ].Warnings -join ' '
        ) | Should -Match 'HTTP 403'
    }

    It 'fails closed to incomplete evidence when Graph is unavailable' {
        Mock Get-AzAccessToken { throw 'consent required' }
        $baselineInventory = [pscustomobject]@{
            IsEvaluated = $true
            IsComplete = $true
            Warnings = @()
            Assignments = @(
                [pscustomobject]@{
                    PrincipalId =
                        '33333333-3333-3333-3333-333333333333'
                    PrincipalType = 'User'
                }
            )
        }

        $evidence = Get-RadarPrincipalDirectoryEvidence `
            -BaselineAssignmentInventory $baselineInventory

        $evidence.IsComplete | Should -BeFalse
        $evidence.Warnings |
            Should -Match 'unavailable'
    }
}

Describe 'Get-RadarPrincipalRoleAssignmentInventory' {
    It 'uses one tenant-scoped principal-filtered paged query' {
        Mock Search-AzGraph {
            $suffix = if ($SkipToken) { '2' } else { '1' }
            [pscustomobject]@{
                Data = @(
                    [pscustomobject]@{
                        Id = "assignment-$suffix"
                        AssignmentId = "assignment-$suffix"
                        AssignmentScope = '/subscriptions/sub-1'
                        PrincipalId =
                            '33333333-3333-3333-3333-333333333333'
                        PrincipalType = 'User'
                        RoleDefinitionId =
                            '/providers/Microsoft.Authorization/roleDefinitions/aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa'
                        RoleDefinitionGuid =
                            'aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa'
                    }
                )
                SkipToken = if ($SkipToken) { $null } else { 'next' }
            }

        }
        $baselineInventory = [pscustomobject]@{
            IsEvaluated = $true
            IsComplete = $true
            Warnings = @()
            Assignments = @(
                [pscustomobject]@{
                    AssignmentId = 'source-assignment'
                    AssignmentScope = '/subscriptions/sub-1'
                    PrincipalId =
                        '33333333-3333-3333-3333-333333333333'
                    PrincipalType = 'User'
                }
            )
        }

        $inventory =
            Get-RadarPrincipalRoleAssignmentInventory `
                -BaselineAssignmentInventory $baselineInventory

        $inventory.AssignmentCount | Should -Be 2
        $inventory.AssignmentsByPrincipalAndScope.Count |
            Should -Be 1
        Should -Invoke Search-AzGraph -Times 2
        Should -Invoke Search-AzGraph -Times 1 -ParameterFilter {
            $SkipToken -eq 'next'
        }
        Should -Invoke Search-AzGraph -ParameterFilter {
            $UseTenantScope -and
            -not $Subscription -and
            -not $ManagementGroup -and
            $Query -match 'PrincipalId in~' -and
            $Query -match '(?s)\| project\s+id,'
        }
    }

    It 'does not attach another principal directory warning to all assignments' {
        Mock Search-AzGraph {
            [pscustomobject]@{
                Data = @()
                SkipToken = $null
            }
        }
        $baselineInventory = [pscustomobject]@{
            IsEvaluated = $true
            IsComplete = $true
            Warnings = @()
            Assignments = @(
                [pscustomobject]@{
                    PrincipalId =
                        '33333333-3333-3333-3333-333333333333'
                    PrincipalType = 'User'
                }
            )
        }
        $directoryEvidence = [pscustomobject]@{
            IsComplete = $false
            GroupIds = @()
            Warnings = @(
                'Another directory object returned HTTP 404.'
            )
        }

        $inventory =
            Get-RadarPrincipalRoleAssignmentInventory `
                -BaselineAssignmentInventory $baselineInventory `
                -DirectoryEvidence $directoryEvidence

        $inventory.Warnings |
            Should -Not -Contain (
                'Another directory object returned HTTP 404.'
            )
    }

    It 'splits large principal and group filters into bounded queries' {
        Mock Search-AzGraph {
            [pscustomobject]@{
                Data = @()
                SkipToken = $null
            }
        }
        $assignments = @(
            foreach ($index in 1..300) {
                [pscustomobject]@{
                    PrincipalId =
                        ('00000000-0000-0000-0000-{0:D12}' -f $index)
                    PrincipalType = 'User'
                }
            }
        )
        $baselineInventory = [pscustomobject]@{
            IsEvaluated = $true
            IsComplete = $true
            Warnings = @()
            Assignments = $assignments
        }
        $directoryEvidence = [pscustomobject]@{
            IsComplete = $true
            GroupIds = @(
                '99999999-9999-9999-9999-999999999999'
            )
            Warnings = @()
        }

        $null = Get-RadarPrincipalRoleAssignmentInventory `
            -BaselineAssignmentInventory $baselineInventory `
            -DirectoryEvidence $directoryEvidence

        Should -Invoke Search-AzGraph -Times 2
        Should -Invoke Search-AzGraph -ParameterFilter {
            $UseTenantScope -and
            $Query.Length -lt 50000
        }
    }
}

Describe 'Get-RadarPrincipalGap' {
    BeforeAll {
        $baselineRoleId =
            '/providers/Microsoft.Authorization/roleDefinitions/11111111-1111-1111-1111-111111111111'
        $grantingRoleId =
            '/providers/Microsoft.Authorization/roleDefinitions/aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa'
        $ownerRoleId =
            '/providers/Microsoft.Authorization/roleDefinitions/bbbbbbbb-bbbb-bbbb-bbbb-bbbbbbbbbbbb'
        $principalId =
            '33333333-3333-3333-3333-333333333333'
        $subscription = '/subscriptions/sub-1'
        $managementGroup =
            '/providers/Microsoft.Management/managementGroups/root'
        $action = 'Dangerous.Provider/write'
        $baselineRole = [pscustomobject]@{
            Name = 'Baseline Owner'
            Id = $baselineRoleId
            IsCustom = $true
            Permissions = @(
                [pscustomobject]@{
                    Actions = @('*')
                    NotActions = @($action)
                }
            )
        }
        $grantingRole = [pscustomobject]@{
            Name = 'Dangerous Operator'
            Id = $grantingRoleId
            IsCustom = $false
            Permissions = @(
                [pscustomobject]@{
                    Actions = @('Dangerous.Provider/*')
                    NotActions = @()
                }
            )
        }
        $ownerRole = [pscustomobject]@{
            Name = 'Owner'
            Id = $ownerRoleId
            IsCustom = $false
            Permissions = @(
                [pscustomobject]@{
                    Actions = @('*')
                    NotActions = @()
                }
            )
        }
        $assignmentPath = [pscustomobject]@{
            Name = 'Direct role assignment'
            ResourceType =
                'Microsoft.Authorization/roleAssignments'
            Reachability =
                'Baseline role can create direct role assignments'
        }
        $externalPath = [pscustomobject]@{
            Name = 'Direct role assignment'
            ResourceType =
                'Microsoft.Authorization/roleAssignments'
            Reachability =
                'Requires another principal or assignment process'
        }
        $policyInventory = [pscustomobject]@{
            IsEvaluated = $true
            IsComplete = $true
            RulesByScope = @{
                $subscription = @()
                $managementGroup.ToLowerInvariant() = @()
            }
            ExemptionsByScope = @{
                $subscription = @()
                $managementGroup.ToLowerInvariant() = @()
            }
            UncertainScopes = @()
        }
        $hierarchy = [pscustomobject]@{
            IsComplete = $true
            AncestorsByScope = @{
                $managementGroup.ToLowerInvariant() = @()
                $subscription.ToLowerInvariant() = @(
                    $managementGroup
                )
            }
            UnresolvedAncestorRoots = @()
        }
    }

    BeforeEach {
        $context = [pscustomobject]@{
            BaselineRoleName = 'Baseline Owner'
            BaselineRoleId = $baselineRoleId
            BaselineScope = $subscription
            AssignmentPaths = @($assignmentPath)
        }
        $result = [pscustomobject]@{
            AnalysisMode = 'BaselineNotActions'
            BaselineRoleName = 'Baseline Owner'
            BaselineRoleId = $baselineRoleId
            BaselineScope = $subscription
            RestrictedAction = $action
            RoleName = 'Dangerous Operator'
            RoleId = $grantingRoleId
            ScopeEvaluations = @(
                [pscustomobject]@{
                    Scope = $subscription
                }
            )
        }
        $sourceAssignment = [pscustomobject]@{
            AssignmentId = 'source-assignment'
            AssignmentScope = $subscription
            RoleDefinitionGuid =
                '11111111-1111-1111-1111-111111111111'
            PrincipalId = $principalId
            PrincipalType = 'User'
            Condition = ''
        }
        $baselineInventory = [pscustomobject]@{
            IsEvaluated = $true
            IsComplete = $true
            Warnings = @()
            Assignments = @($sourceAssignment)
        }
        $principalInventory = [pscustomobject]@{
            IsEvaluated = $true
            IsComplete = $true
            Warnings = @()
            Assignments = @($sourceAssignment)
            AssignmentsByPrincipalAndScope =
                New-RadarPrincipalScopeAssignmentIndex `
                    -Assignments @($sourceAssignment)
        }
        $directoryEvidenceItem = [pscustomobject]@{
            PrincipalId = $principalId
            PrincipalType = 'User'
            AccountEnabled = $true
            GroupIds =
                New-Object System.Collections.Generic.HashSet[string] (
                    [StringComparer]::OrdinalIgnoreCase
                )
            IsComplete = $true
            Warnings = @()
        }
        $directoryEvidence = [pscustomobject]@{
            IsEvaluated = $true
            IsComplete = $true
            EvidenceByPrincipal = @{
                $principalId.ToLowerInvariant() =
                    $directoryEvidenceItem
            }
            GroupIds = @()
            Warnings = @()
        }
        $deniedRoles =
            New-Object System.Collections.Generic.HashSet[string] (
                [StringComparer]::OrdinalIgnoreCase
            )
    }

    It 'reports a holder without the action as a net-new gap' {
        $gaps = @(
            Get-RadarPrincipalGap `
                -Results @($result) `
                -BaselineContexts @($context) `
                -BaselineAssignmentInventory $baselineInventory `
                -DirectoryEvidence $directoryEvidence `
                -PrincipalAssignmentInventory $principalInventory `
                -Roles @(
                    $baselineRole,
                    $grantingRole,
                    $ownerRole
                ) `
                -Hierarchy $hierarchy `
                -PolicyInventory $policyInventory `
                -DeniedRoleNames $deniedRoles
        )

        $gaps.Count | Should -Be 1
        $gaps[0].ExistingAccessStatus |
            Should -Be 'NoExistingAction'
        $gaps[0].AssignmentPolicyStatus |
            Should -Be 'Permitted'
        $gaps[0].NetNewGapStatus | Should -Be 'NetNewGap'
    }

    It 'keeps a single transitive group as an array under strict mode' {
        [void]$directoryEvidenceItem.GroupIds.Add(
            '44444444-4444-4444-4444-444444444444'
        )

        $gap = & {
            Set-StrictMode -Version Latest
            Get-RadarPrincipalGap `
                -Results @($result) `
                -BaselineContexts @($context) `
                -BaselineAssignmentInventory $baselineInventory `
                -DirectoryEvidence $directoryEvidence `
                -PrincipalAssignmentInventory $principalInventory `
                -Roles @(
                    $baselineRole,
                    $grantingRole,
                    $ownerRole
                ) `
                -Hierarchy $hierarchy `
                -PolicyInventory $policyInventory `
                -DeniedRoleNames $deniedRoles
        }

        $gap.TransitiveGroupCount | Should -Be 1
    }

    It 'caches effective existing-access evidence across candidate roles' {
        $secondGrantingRole = [pscustomobject]@{
            Name = 'Dangerous Operator Two'
            Id =
                '/providers/Microsoft.Authorization/roleDefinitions/eeeeeeee-eeee-eeee-eeee-eeeeeeeeeeee'
            IsCustom = $false
            Permissions = @(
                [pscustomobject]@{
                    Actions = @('Dangerous.Provider/write')
                    NotActions = @()
                }
            )
        }
        $secondResult = $result.PSObject.Copy()
        $secondResult.RoleName = $secondGrantingRole.Name
        $secondResult.RoleId = $secondGrantingRole.Id
        Mock Get-RadarEffectivePrincipalAssignments {
            [pscustomobject]@{
                IsComplete = $true
                Assignments = @()
                Warnings = @()
            }
        }

        $gaps = @(
            Get-RadarPrincipalGap `
                -Results @($result, $secondResult) `
                -BaselineContexts @($context) `
                -BaselineAssignmentInventory $baselineInventory `
                -DirectoryEvidence $directoryEvidence `
                -PrincipalAssignmentInventory $principalInventory `
                -Roles @(
                    $baselineRole,
                    $grantingRole,
                    $secondGrantingRole
                ) `
                -Hierarchy $hierarchy `
                -PolicyInventory $policyInventory `
                -DeniedRoleNames $deniedRoles `
                -ExistingAccessCache @{}
        )

        $gaps.Count | Should -Be 2
        $gaps.NetNewGapStatus |
            Should -Not -Contain 'Unknown'
        Should -Invoke `
            Get-RadarEffectivePrincipalAssignments `
            -Times 1
    }

    It 'classifies an inherited existing action as AlreadyHasAction' {
        $context.BaselineScope = $managementGroup
        $result.BaselineScope = $managementGroup
        $sourceAssignment.AssignmentScope = $managementGroup
        $ownerAssignment = [pscustomobject]@{
            AssignmentId = 'owner-assignment'
            AssignmentScope = $managementGroup
            RoleDefinitionGuid =
                'bbbbbbbb-bbbb-bbbb-bbbb-bbbbbbbbbbbb'
            PrincipalId = $principalId
            PrincipalType = 'User'
            Condition = ''
        }
        $principalInventory.Assignments = @(
            $sourceAssignment,
            $ownerAssignment
        )
        $principalInventory.AssignmentsByPrincipalAndScope =
            New-RadarPrincipalScopeAssignmentIndex `
                -Assignments $principalInventory.Assignments

        $gap = Get-RadarPrincipalGap `
            -Results @($result) `
            -BaselineContexts @($context) `
            -BaselineAssignmentInventory $baselineInventory `
            -DirectoryEvidence $directoryEvidence `
            -PrincipalAssignmentInventory $principalInventory `
            -Roles @($baselineRole, $grantingRole, $ownerRole) `
            -Hierarchy $hierarchy `
            -PolicyInventory $policyInventory `
            -DeniedRoleNames $deniedRoles

        $gap.ExistingAccessStatus |
            Should -Be 'AlreadyHasAction'
        $gap.NetNewGapStatus |
            Should -Be 'AlreadyHasAction'
    }

    It 'includes inherited assignments from transitive groups' {
        $groupId =
            '44444444-4444-4444-4444-444444444444'
        [void]$directoryEvidenceItem.GroupIds.Add($groupId)
        $directoryEvidence.GroupIds = @($groupId)
        $groupOwnerAssignment = [pscustomobject]@{
            AssignmentId = 'group-owner-assignment'
            AssignmentScope = $subscription
            RoleDefinitionGuid =
                'bbbbbbbb-bbbb-bbbb-bbbb-bbbbbbbbbbbb'
            PrincipalId = $groupId
            PrincipalType = 'Group'
            Condition = ''
        }
        $principalInventory.Assignments = @(
            $sourceAssignment,
            $groupOwnerAssignment
        )
        $principalInventory.AssignmentsByPrincipalAndScope =
            New-RadarPrincipalScopeAssignmentIndex `
                -Assignments $principalInventory.Assignments

        $gap = Get-RadarPrincipalGap `
            -Results @($result) `
            -BaselineContexts @($context) `
            -BaselineAssignmentInventory $baselineInventory `
            -DirectoryEvidence $directoryEvidence `
            -PrincipalAssignmentInventory $principalInventory `
            -Roles @($baselineRole, $grantingRole, $ownerRole) `
            -Hierarchy $hierarchy `
            -PolicyInventory $policyInventory `
            -DeniedRoleNames $deniedRoles

        $gap.ExistingAccessStatus |
            Should -Be 'AlreadyHasAction'
        $gap.TransitiveGroupCount | Should -Be 1
        $gap.NetNewGapStatus |
            Should -Be 'AlreadyHasAction'
    }

    It 'keeps disabled and incomplete directory principals non-actionable' {
        $directoryEvidenceItem.AccountEnabled = $false
        $disabledGap = Get-RadarPrincipalGap `
            -Results @($result) `
            -BaselineContexts @($context) `
            -BaselineAssignmentInventory $baselineInventory `
            -DirectoryEvidence $directoryEvidence `
            -PrincipalAssignmentInventory $principalInventory `
            -Roles @($baselineRole, $grantingRole) `
            -Hierarchy $hierarchy `
            -PolicyInventory $policyInventory `
            -DeniedRoleNames $deniedRoles
        $disabledGap.NetNewGapStatus |
            Should -Be 'PrincipalDisabled'

        $directoryEvidenceItem.AccountEnabled = $true
        $directoryEvidenceItem.IsComplete = $false
        $incompleteGap = Get-RadarPrincipalGap `
            -Results @($result) `
            -BaselineContexts @($context) `
            -BaselineAssignmentInventory $baselineInventory `
            -DirectoryEvidence $directoryEvidence `
            -PrincipalAssignmentInventory $principalInventory `
            -Roles @($baselineRole, $grantingRole) `
            -Hierarchy $hierarchy `
            -PolicyInventory $policyInventory `
            -DeniedRoleNames $deniedRoles
        $incompleteGap.NetNewGapStatus |
            Should -Be 'Unknown'
    }

    It 'keeps a wildcard write residual actionable after an existing read grant' {
        $storageRestrictedAction =
            'Microsoft.Storage/storageAccounts/*'
        $storageGrantingRole = [pscustomobject]@{
            Name = 'Storage Writer'
            Id =
                '/providers/Microsoft.Authorization/roleDefinitions/cccccccc-cccc-cccc-cccc-cccccccccccc'
            IsCustom = $false
            Permissions = @(
                [pscustomobject]@{
                    Actions = @(
                        'Microsoft.Storage/storageAccounts/*'
                    )
                    NotActions = @()
                }
            )
        }
        $storageBaselineRole = [pscustomobject]@{
            Name = 'Baseline Owner'
            Id = $baselineRoleId
            IsCustom = $true
            Permissions = @(
                [pscustomobject]@{
                    Actions = @('*')
                    NotActions = @($storageRestrictedAction)
                }
            )
        }
        $storageReaderRole = [pscustomobject]@{
            Name = 'Storage Reader'
            Id =
                '/providers/Microsoft.Authorization/roleDefinitions/dddddddd-dddd-dddd-dddd-dddddddddddd'
            IsCustom = $false
            Permissions = @(
                [pscustomobject]@{
                    Actions = @(
                        'Microsoft.Storage/storageAccounts/read'
                    )
                    NotActions = @()
                }
            )
        }
        $result.RestrictedAction = $storageRestrictedAction
        $result.RoleName = 'Storage Writer'
        $result.RoleId = $storageGrantingRole.Id
        $readAssignment = [pscustomobject]@{
            AssignmentId = 'storage-read-assignment'
            AssignmentScope = $subscription
            RoleDefinitionGuid =
                'dddddddd-dddd-dddd-dddd-dddddddddddd'
            PrincipalId = $principalId
            PrincipalType = 'User'
            Condition = ''
        }
        $principalInventory.Assignments = @(
            $sourceAssignment,
            $readAssignment
        )
        $principalInventory.AssignmentsByPrincipalAndScope =
            New-RadarPrincipalScopeAssignmentIndex `
                -Assignments $principalInventory.Assignments

        $gap = Get-RadarPrincipalGap `
            -Results @($result) `
            -BaselineContexts @($context) `
            -BaselineAssignmentInventory $baselineInventory `
            -DirectoryEvidence $directoryEvidence `
            -PrincipalAssignmentInventory $principalInventory `
            -Roles @(
                $storageBaselineRole,
                $storageGrantingRole,
                $storageReaderRole
            ) `
            -Hierarchy $hierarchy `
            -PolicyInventory $policyInventory `
            -DeniedRoleNames $deniedRoles

        $gap.ExistingAccessStatus |
            Should -Be 'NetNewDelta'
        $gap.NetNewGapStatus | Should -Be 'NetNewGap'
    }

    It 'classifies collective unconditioned coverage as AlreadyHasAction' {
        $result.RestrictedAction = 'Dangerous.Provider/*'
        $grantingRole.Permissions = @(
            [pscustomobject]@{
                Actions = @(
                    'Dangerous.Provider/read',
                    'Dangerous.Provider/write'
                )
                NotActions = @()
            }
        )
        $readerRole = [pscustomobject]@{
            Name = 'Dangerous Reader'
            Id =
                '/providers/Microsoft.Authorization/roleDefinitions/cccccccc-cccc-cccc-cccc-cccccccccccc'
            IsCustom = $false
            Permissions = @(
                [pscustomobject]@{
                    Actions = @('Dangerous.Provider/read')
                    NotActions = @()
                }
            )
        }
        $writerRole = [pscustomobject]@{
            Name = 'Dangerous Writer'
            Id =
                '/providers/Microsoft.Authorization/roleDefinitions/dddddddd-dddd-dddd-dddd-dddddddddddd'
            IsCustom = $false
            Permissions = @(
                [pscustomobject]@{
                    Actions = @('Dangerous.Provider/write')
                    NotActions = @()
                }
            )
        }
        $principalInventory.Assignments = @(
            $sourceAssignment,
            [pscustomobject]@{
                AssignmentId = 'reader-assignment'
                AssignmentScope = $subscription
                RoleDefinitionGuid =
                    'cccccccc-cccc-cccc-cccc-cccccccccccc'
                PrincipalId = $principalId
                PrincipalType = 'User'
                Condition = ''
            },
            [pscustomobject]@{
                AssignmentId = 'writer-assignment'
                AssignmentScope = $subscription
                RoleDefinitionGuid =
                    'dddddddd-dddd-dddd-dddd-dddddddddddd'
                PrincipalId = $principalId
                PrincipalType = 'User'
                Condition = ''
            }
        )
        $principalInventory.AssignmentsByPrincipalAndScope =
            New-RadarPrincipalScopeAssignmentIndex `
                -Assignments $principalInventory.Assignments

        $gap = Get-RadarPrincipalGap `
            -Results @($result) `
            -BaselineContexts @($context) `
            -BaselineAssignmentInventory $baselineInventory `
            -DirectoryEvidence $directoryEvidence `
            -PrincipalAssignmentInventory $principalInventory `
            -Roles @(
                $baselineRole,
                $grantingRole,
                $readerRole,
                $writerRole
            ) `
            -Hierarchy $hierarchy `
            -PolicyInventory $policyInventory `
            -DeniedRoleNames $deniedRoles

        $gap.ExistingAccessStatus |
            Should -Be 'AlreadyHasAction'
        $gap.NetNewGapStatus |
            Should -Be 'AlreadyHasAction'
    }

    It 'honours NotActions while allowing another block to regrant' {
        $candidateRole = [pscustomobject]@{
            Name = 'Candidate wildcard'
            Permissions = @(
                [pscustomobject]@{
                    Actions = @('Dangerous.Provider/*')
                    NotActions = @()
                }
            )
        }
        $roleWithExclusion = [pscustomobject]@{
            Name = 'Wildcard except write'
            Permissions = @(
                [pscustomobject]@{
                    Actions = @('Dangerous.Provider/*')
                    NotActions = @('Dangerous.Provider/write')
                }
            )
        }
        $writeRegrant = [pscustomobject]@{
            Name = 'Write regrant'
            Permissions = @(
                [pscustomobject]@{
                    Actions = @('Dangerous.Provider/write')
                    NotActions = @()
                }
            )
        }

        (
            Get-RadarExistingCapabilityCoverage `
                -CandidateRole $candidateRole `
                -RestrictedAction 'Dangerous.Provider/*' `
                -ExistingRoles @($roleWithExclusion)
        ).State | Should -Be 'NetNewDelta'
        (
            Get-RadarExistingCapabilityCoverage `
                -CandidateRole $candidateRole `
                -RestrictedAction 'Dangerous.Provider/*' `
                -ExistingRoles @(
                    $roleWithExclusion,
                    $writeRegrant
                )
        ).State | Should -Be 'Full'
    }

    It 'emits no principal gap when no source-role holder exists' {
        $baselineInventory.Assignments = @()

        @(
            Get-RadarPrincipalGap `
                -Results @($result) `
                -BaselineContexts @($context) `
                -BaselineAssignmentInventory $baselineInventory `
                -DirectoryEvidence $directoryEvidence `
                -PrincipalAssignmentInventory $principalInventory `
                -Roles @($baselineRole, $grantingRole) `
                -Hierarchy $hierarchy `
                -PolicyInventory $policyInventory `
                -DeniedRoleNames $deniedRoles
        ).Count | Should -Be 0
    }

    It 'keeps group, missing, conditioned and incomplete evidence unknown' {
        $sourceAssignment.PrincipalType = 'Group'
        $groupGap = Get-RadarPrincipalGap `
            -Results @($result) `
            -BaselineContexts @($context) `
            -BaselineAssignmentInventory $baselineInventory `
            -DirectoryEvidence $directoryEvidence `
            -PrincipalAssignmentInventory $principalInventory `
            -Roles @($baselineRole, $grantingRole) `
            -Hierarchy $hierarchy `
            -PolicyInventory $policyInventory `
            -DeniedRoleNames $deniedRoles
        $groupGap.NetNewGapStatus | Should -Be 'Unknown'

        $sourceAssignment.PrincipalType = ''
        $missingTypeGap = Get-RadarPrincipalGap `
            -Results @($result) `
            -BaselineContexts @($context) `
            -BaselineAssignmentInventory $baselineInventory `
            -DirectoryEvidence $directoryEvidence `
            -PrincipalAssignmentInventory $principalInventory `
            -Roles @($baselineRole, $grantingRole) `
            -Hierarchy $hierarchy `
            -PolicyInventory $policyInventory `
            -DeniedRoleNames $deniedRoles
        $missingTypeGap.NetNewGapStatus | Should -Be 'Unknown'

        $sourceAssignment.PrincipalType = 'User'
        $sourceAssignment.Condition = '@Resource[example] StringEquals true'
        $conditionedGap = Get-RadarPrincipalGap `
            -Results @($result) `
            -BaselineContexts @($context) `
            -BaselineAssignmentInventory $baselineInventory `
            -DirectoryEvidence $directoryEvidence `
            -PrincipalAssignmentInventory $principalInventory `
            -Roles @($baselineRole, $grantingRole) `
            -Hierarchy $hierarchy `
            -PolicyInventory $policyInventory `
            -DeniedRoleNames $deniedRoles
        $conditionedGap.NetNewGapStatus | Should -Be 'Unknown'

        $sourceAssignment.Condition = ''
        $principalInventory.IsComplete = $false
        $incompleteGap = Get-RadarPrincipalGap `
            -Results @($result) `
            -BaselineContexts @($context) `
            -BaselineAssignmentInventory $baselineInventory `
            -DirectoryEvidence $directoryEvidence `
            -PrincipalAssignmentInventory $principalInventory `
            -Roles @($baselineRole, $grantingRole) `
            -Hierarchy $hierarchy `
            -PolicyInventory $policyInventory `
            -DeniedRoleNames $deniedRoles
        $incompleteGap.NetNewGapStatus | Should -Be 'Unknown'
    }

    It 'keeps a conditioned existing grant unknown' {
        $conditionedAssignment = [pscustomobject]@{
            AssignmentId = 'conditioned-assignment'
            AssignmentScope = $subscription
            RoleDefinitionGuid =
                'bbbbbbbb-bbbb-bbbb-bbbb-bbbbbbbbbbbb'
            PrincipalId = $principalId
            PrincipalType = 'User'
            Condition = '@Resource[example] StringEquals true'
        }
        $principalInventory.Assignments = @(
            $sourceAssignment,
            $conditionedAssignment
        )
        $principalInventory.AssignmentsByPrincipalAndScope =
            New-RadarPrincipalScopeAssignmentIndex `
                -Assignments $principalInventory.Assignments

        $gap = Get-RadarPrincipalGap `
            -Results @($result) `
            -BaselineContexts @($context) `
            -BaselineAssignmentInventory $baselineInventory `
            -DirectoryEvidence $directoryEvidence `
            -PrincipalAssignmentInventory $principalInventory `
            -Roles @($baselineRole, $grantingRole, $ownerRole) `
            -Hierarchy $hierarchy `
            -PolicyInventory $policyInventory `
            -DeniedRoleNames $deniedRoles

        $gap.ExistingAccessStatus | Should -Be 'Unknown'
        $gap.NetNewGapStatus | Should -Be 'Unknown'
    }

    It 'keeps unavailable existing role evidence unknown' {
        $unsupportedAssignment = [pscustomobject]@{
            AssignmentId = 'unsupported-assignment'
            AssignmentScope = $subscription
            RoleDefinitionGuid =
                'cccccccc-cccc-cccc-cccc-cccccccccccc'
            PrincipalId = $principalId
            PrincipalType = 'User'
            Condition = ''
        }
        $principalInventory.Assignments = @(
            $sourceAssignment,
            $unsupportedAssignment
        )
        $principalInventory.AssignmentsByPrincipalAndScope =
            New-RadarPrincipalScopeAssignmentIndex `
                -Assignments $principalInventory.Assignments

        $gap = Get-RadarPrincipalGap `
            -Results @($result) `
            -BaselineContexts @($context) `
            -BaselineAssignmentInventory $baselineInventory `
            -DirectoryEvidence $directoryEvidence `
            -PrincipalAssignmentInventory $principalInventory `
            -Roles @($baselineRole, $grantingRole) `
            -Hierarchy $hierarchy `
            -PolicyInventory $policyInventory `
            -DeniedRoleNames $deniedRoles

        $gap.ExistingAccessStatus | Should -Be 'Unknown'
        $gap.Warnings | Should -Match 'unavailable role definition'
    }

    It 'does not report a gap when assignment policy blocks the role' {
        [void]$deniedRoles.Add('Dangerous Operator')

        $gap = Get-RadarPrincipalGap `
            -Results @($result) `
            -BaselineContexts @($context) `
            -BaselineAssignmentInventory $baselineInventory `
            -DirectoryEvidence $directoryEvidence `
            -PrincipalAssignmentInventory $principalInventory `
            -Roles @($baselineRole, $grantingRole) `
            -Hierarchy $hierarchy `
            -PolicyInventory $policyInventory `
            -DeniedRoleNames $deniedRoles

        $gap.AssignmentPolicyStatus | Should -Be 'Blocked'
        $gap.NetNewGapStatus | Should -Be 'PolicyBlocked'
    }

    It 'keeps exact-scope policy discovery uncertainty non-actionable' {
        $policyInventory.UncertainScopes = @(
            $subscription.ToLowerInvariant()
        )

        $gap = Get-RadarPrincipalGap `
            -Results @($result) `
            -BaselineContexts @($context) `
            -BaselineAssignmentInventory $baselineInventory `
            -DirectoryEvidence $directoryEvidence `
            -PrincipalAssignmentInventory $principalInventory `
            -Roles @($baselineRole, $grantingRole) `
            -Hierarchy $hierarchy `
            -PolicyInventory $policyInventory `
            -DeniedRoleNames $deniedRoles

        $gap.AssignmentPolicyStatus | Should -Be 'Unknown'
        $gap.NetNewGapStatus | Should -Be 'Unknown'
        $gap.Warnings |
            Should -Match 'discovery was incomplete'
    }

    It 'does not treat an external-only assignment path as actionable' {
        $context.AssignmentPaths = @($externalPath)
        Mock Get-RadarPrincipalExistingAccess {
            throw 'Existing access should not be evaluated without a reachable path.'
        }

        $gap = Get-RadarPrincipalGap `
            -Results @($result) `
            -BaselineContexts @($context) `
            -BaselineAssignmentInventory $baselineInventory `
            -DirectoryEvidence $directoryEvidence `
            -PrincipalAssignmentInventory $principalInventory `
            -Roles @($baselineRole, $grantingRole) `
            -Hierarchy $hierarchy `
            -PolicyInventory $policyInventory `
            -DeniedRoleNames $deniedRoles

        $gap.AssignmentPolicyStatus |
            Should -Be 'NoBaselineReachablePath'
        $gap.NetNewGapStatus |
            Should -Be 'NoBaselineReachablePath'
        Should -Invoke Get-RadarPrincipalExistingAccess -Times 0
    }
}

Describe 'Principal-gap reporting' {
    It 'skips principal correlation and exports only headers when disabled' {
        $mainSource =
            Get-Content -LiteralPath $scriptPath -Raw
        $assignmentStart =
            $mainSource.IndexOf('$principalGaps = @(')
        $assignmentEnd =
            $mainSource.IndexOf(
                '$exactControlGapMap = @(',
                $assignmentStart
            )
        $assignmentStart | Should -BeGreaterOrEqual 0
        $assignmentEnd | Should -BeGreaterThan $assignmentStart
        $principalAssignment = $mainSource.Substring(
            $assignmentStart,
            $assignmentEnd - $assignmentStart
        )
        Mock Get-RadarPrincipalGap {
            throw 'Principal correlation should have been skipped.'
        }
        $NoPrincipalCorrelation = $true

        . ([ScriptBlock]::Create($principalAssignment))

        @($principalGaps).Count | Should -Be 0
        Should -Invoke Get-RadarPrincipalGap -Times 0
        $path = Join-Path $TestDrive 'disabled-principal-gaps.csv'
        Export-RadarPrincipalGap -Rows $principalGaps -Path $path
        $content = Get-Content -LiteralPath $path -Raw
        $content | Should -Match '"PrincipalId"'
        @($content.Trim() -split "`n").Count | Should -Be 1
    }

    It 'exports an empty atomic report with headers' {
        $path = Join-Path $TestDrive 'radar-principal-gaps.csv'

        Export-RadarPrincipalGap -Rows @() -Path $path

        Test-Path -LiteralPath $path | Should -BeTrue
        (Get-Content -LiteralPath $path -Raw) |
            Should -Match '"NetNewGapStatus"'
        @(
            Get-ChildItem `
                -LiteralPath $TestDrive `
                -Filter '*.tmp.*'
        ).Count | Should -Be 0
    }

    It 'adds net-new counts and roles to scope-map rows' {
        $row = [pscustomobject]@{
            BaselineRoleId = 'baseline-role'
            BaselineScope = '/subscriptions/sub-1'
            EvaluationScope = '/subscriptions/sub-1'
            RestrictedAction = 'Dangerous.Provider/write'
            BaselineAssignmentState = 'DirectAssignmentObserved'
        }
        $principalGap = [pscustomobject]@{
            PrincipalId = 'principal-placeholder'
            PrincipalType = 'User'
            BaselineRoleId = 'baseline-role'
            BaselineScope = '/subscriptions/sub-1'
            EvaluationScope = '/subscriptions/sub-1'
            RestrictedAction = 'Dangerous.Provider/write'
            GrantingRoleName = 'Dangerous Operator'
            GrantingRoleId = 'granting-role'
            NetNewGapStatus = 'NetNewGap'
            Warnings = ''
        }

        $summary = Add-RadarPrincipalGapSummary `
            -Rows @($row) `
            -PrincipalGaps @(
                $principalGap,
                [pscustomobject]@{
                    PrincipalId = ''
                    PrincipalType = ''
                    BaselineRoleId = 'baseline-role'
                    BaselineScope = '/subscriptions/sub-1'
                    EvaluationScope = '/subscriptions/sub-1'
                    RestrictedAction =
                        'Dangerous.Provider/write'
                    GrantingRoleName = 'Unknown Operator'
                    GrantingRoleId = 'unknown-role'
                    NetNewGapStatus = 'Unknown'
                    Warnings =
                        'Principal identity is unreadable.'
                }
            )

        $summary.PrincipalGapStatus | Should -Be 'NetNewGap'
        $summary.NetNewGapActionCount | Should -Be 1
        $summary.NetNewGapPrincipalCount | Should -Be 1
        $summary.NetNewGapPrincipals |
            Should -Be 'principal-placeholder [User]'
        $summary.NetNewGapRoleCount | Should -Be 1
        $summary.NetNewGapRoles |
            Should -Match 'Dangerous Operator'
        $summary.UnknownPrincipalCount | Should -Be 0
        $summary.UnknownPrincipalRowCount | Should -Be 1
        $summary.PrincipalGapWarnings |
            Should -Match 'Principal identity is unreadable'
    }

    It 'marks a complete no-holder scope as dormant rather than a gap' {
        $row = [pscustomobject]@{
            BaselineRoleId = 'baseline-role'
            BaselineScope = '/subscriptions/sub-1'
            EvaluationScope = '/subscriptions/sub-1'
            RestrictedAction = 'Dangerous.Provider/write'
            BaselineAssignmentState = 'NoDirectAssignment'
        }

        $summary = Add-RadarPrincipalGapSummary `
            -Rows @($row) `
            -PrincipalGaps @()

        $summary.PrincipalGapStatus |
            Should -Be 'NoObservedHolder'
        $summary.NetNewGapActionCount | Should -Be 0
        $summary.NetNewGapPrincipalCount | Should -Be 0
    }
}

Describe 'Get-RadarBaselineAssignmentEvidenceMap' {
    It 'applies an assignment downwards but never upwards' {
        $root =
            '/providers/Microsoft.Management/managementGroups/customer'
        $subscription = '/subscriptions/sub-1'
        $resourceGroup =
            '/subscriptions/sub-1/resourceGroups/workload'
        $context = [pscustomobject]@{
            BaselineRoleId =
                '/providers/Microsoft.Authorization/roleDefinitions/11111111-1111-1111-1111-111111111111'
            BaselineScope = $root
            EvaluationScopes = @(
                (New-RadarScope -Id $root),
                (New-RadarScope -Id $subscription),
                (New-RadarScope -Id $resourceGroup)
            )
        }
        $inventory = [pscustomobject]@{
            IsComplete = $true
            Warnings = @()
            Assignments = @(
                [pscustomobject]@{
                    AssignmentId = 'assignment-1'
                    AssignmentScope = $subscription
                    RoleDefinitionGuid =
                        '11111111-1111-1111-1111-111111111111'
                    PrincipalType = 'User'
                }
            )
        }
        $hierarchy = [pscustomobject]@{
            AncestorsByScope = @{
                $root.ToLowerInvariant() = @()
                $subscription.ToLowerInvariant() = @($root)
            }
            UnresolvedAncestorRoots = @()
        }

        $evidence =
            Get-RadarBaselineAssignmentEvidenceMap `
                -BaselineContexts @($context) `
                -AssignmentInventory $inventory `
                -Hierarchy $hierarchy
        $rootKey = Get-RadarBaselineAssignmentEvidenceKey `
            -BaselineRoleId $context.BaselineRoleId `
            -BaselineScope $root `
            -EvaluationScope $root
        $subscriptionKey =
            Get-RadarBaselineAssignmentEvidenceKey `
                -BaselineRoleId $context.BaselineRoleId `
                -BaselineScope $root `
                -EvaluationScope $subscription

        $evidence[$rootKey].State |
            Should -Be 'NoDirectAssignment'
        $evidence[$subscriptionKey].State |
            Should -Be 'DirectAssignmentObserved'
        Get-RadarRelevantBaselineAssignmentCount `
            -EvidenceByKey $evidence |
            Should -Be 1
    }

    It 'keeps conditioned baseline assignments uncertain' {
        $subscription = '/subscriptions/sub-1'
        $context = [pscustomobject]@{
            BaselineRoleId =
                '/providers/Microsoft.Authorization/roleDefinitions/11111111-1111-1111-1111-111111111111'
            BaselineScope = $subscription
            EvaluationScopes = @(
                (New-RadarScope -Id $subscription)
            )
        }
        $inventory = [pscustomobject]@{
            IsComplete = $true
            Warnings = @()
            Assignments = @(
                [pscustomobject]@{
                    AssignmentId = 'assignment-1'
                    AssignmentScope = $subscription
                    RoleDefinitionGuid =
                        '11111111-1111-1111-1111-111111111111'
                    PrincipalType = 'User'
                    Condition =
                        "@Resource[Microsoft.Authorization/roleAssignments:RoleDefinitionId] StringEqualsIgnoreCase 'allowed-role'"
                }
            )
        }
        $hierarchy = [pscustomobject]@{
            IsComplete = $true
            AncestorsByScope = @{
                $subscription.ToLowerInvariant() = @()
            }
            UnresolvedAncestorRoots = @()
        }

        $evidence =
            Get-RadarBaselineAssignmentEvidenceMap `
                -BaselineContexts @($context) `
                -AssignmentInventory $inventory `
                -Hierarchy $hierarchy
        $key = Get-RadarBaselineAssignmentEvidenceKey `
            -BaselineRoleId $context.BaselineRoleId `
            -BaselineScope $subscription `
            -EvaluationScope $subscription

        $evidence[$key].State |
            Should -Be 'AssignmentUnknown'
        $evidence[$key].Warnings |
            Should -Match 'conditions'
    }

    It 'uses the scope index when hierarchy is complete' {
        Mock Test-RadarScopeDescendsFrom {
            throw 'The complete-hierarchy fast path should not probe pairs.'
        }
        $root =
            '/providers/Microsoft.Management/managementGroups/customer'
        $subscription = '/subscriptions/sub-1'
        $context = [pscustomobject]@{
            BaselineRoleId =
                '/providers/Microsoft.Authorization/roleDefinitions/11111111-1111-1111-1111-111111111111'
            BaselineScope = $root
            EvaluationScopes = @(
                (New-RadarScope -Id $root),
                (New-RadarScope -Id $subscription)
            )
        }
        $inventory = [pscustomobject]@{
            IsComplete = $true
            Warnings = @()
            Assignments = @(
                [pscustomobject]@{
                    AssignmentId = 'assignment-1'
                    AssignmentScope = $root
                    RoleDefinitionGuid =
                        '11111111-1111-1111-1111-111111111111'
                    PrincipalType = 'User'
                    Condition = ''
                }
            )
        }
        $hierarchy = [pscustomobject]@{
            IsComplete = $true
            AncestorsByScope = @{
                $root.ToLowerInvariant() = @()
                $subscription.ToLowerInvariant() = @($root)
            }
            UnresolvedAncestorRoots = @()
        }

        $null = Get-RadarBaselineAssignmentEvidenceMap `
            -BaselineContexts @($context) `
            -AssignmentInventory $inventory `
            -Hierarchy $hierarchy

        Should -Invoke Test-RadarScopeDescendsFrom -Times 0
    }

    It 'keeps assignments above an unresolved ancestor uncertain' {
        $customerRoot =
            '/providers/Microsoft.Management/managementGroups/customer'
        $unreadableParent =
            '/providers/Microsoft.Management/managementGroups/parent'
        $context = [pscustomobject]@{
            BaselineRoleId =
                '/providers/Microsoft.Authorization/roleDefinitions/11111111-1111-1111-1111-111111111111'
            BaselineScope = $customerRoot
            EvaluationScopes = @(
                (New-RadarScope -Id $customerRoot)
            )
        }
        $inventory = [pscustomobject]@{
            IsComplete = $true
            Warnings = @()
            Assignments = @(
                [pscustomobject]@{
                    AssignmentId = 'assignment-1'
                    AssignmentScope = $unreadableParent
                    RoleDefinitionGuid =
                        '11111111-1111-1111-1111-111111111111'
                    PrincipalType = 'User'
                    Condition = ''
                }
            )
        }
        $hierarchy = [pscustomobject]@{
            IsComplete = $true
            AncestorsByScope = @{
                $customerRoot.ToLowerInvariant() = @()
            }
            UnresolvedAncestorRoots = @($customerRoot)
        }

        $evidence =
            Get-RadarBaselineAssignmentEvidenceMap `
                -BaselineContexts @($context) `
                -AssignmentInventory $inventory `
                -Hierarchy $hierarchy
        $key = Get-RadarBaselineAssignmentEvidenceKey `
            -BaselineRoleId $context.BaselineRoleId `
            -BaselineScope $customerRoot `
            -EvaluationScope $customerRoot

        $evidence[$key].State |
            Should -Be 'AssignmentUnknown'
        $evidence[$key].Warnings |
            Should -Match 'could not be placed'
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

    It 'omits the Tenant Root Group as an estate boundary' {
        Mock Get-AzContext {
            [pscustomobject]@{
                Tenant = [pscustomobject]@{ Id = 'tenant-1' }
            }
        }
        Mock Search-AzGraph {
            [pscustomobject]@{
                Data = @(
                    [pscustomobject]@{
                        Id = '/providers/Microsoft.Management/managementGroups/tenant-1/providers/Microsoft.Authorization/policyAssignments/root-deny'
                        Type =
                            'microsoft.authorization/policyassignments'
                        Scope =
                            '/providers/Microsoft.Management/managementGroups/tenant-1'
                        NotScopes = @(
                            '/subscriptions/sub-1/resourceGroups/excluded'
                        )
                    }
                )
                SkipToken = $null
            }
        }
        Mock Get-AzPolicyAssignment { @() }
        Mock Get-AzPolicyExemption { @() }

        $result = Get-RadarPolicyBoundaryScope `
            -Scopes @(
                (New-RadarScope -Id '/subscriptions/sub-1')
            ) `
            -UseTenantDiscovery

        $result.Scopes.Id | Should -Not -Contain (
            '/providers/Microsoft.Management/managementGroups/tenant-1'
        )
        $result.Scopes.Id | Should -Contain (
            '/subscriptions/sub-1/resourceGroups/excluded'
        )
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

    It 'evaluates policy conditions for a known assignment subject' {
        $rule = @{
            if = @{
                allOf = @(
                    @{
                        field = 'type'
                        equals =
                            'Microsoft.Authorization/roleAssignments'
                    },
                    @{
                        field =
                            'Microsoft.Authorization/roleAssignments/principalType'
                        equals = 'User'
                    },
                    @{
                        not = @{
                            field =
                                'Microsoft.Authorization/roleAssignments/principalId'
                            in = "[parameters('allowedPrincipalIds')]"
                        }
                    }
                )
            }
            then = @{ effect = 'deny' }
        }
        $parameters = @{
            allowedPrincipalIds = @('allowed-principal')
        }

        (
            Test-RadarPolicyRuleForRole `
                -PolicyRule $rule `
                -Role $ownerRole `
                -Parameters $parameters `
                -TargetPrincipalType 'User' `
                -TargetPrincipalId 'ordinary-principal'
        ).State | Should -Be 'Blocked'
        (
            Test-RadarPolicyRuleForRole `
                -PolicyRule $rule `
                -Role $ownerRole `
                -Parameters $parameters `
                -TargetPrincipalType 'User' `
                -TargetPrincipalId 'allowed-principal'
        ).State | Should -Be 'NotBlocked'
    }

    It 'rules out a value expression for an unrelated resource alias' {
        $rule = @{
                if = @{
                    value =
                        "[string(field('Microsoft.Consumption/budgets/notifications'))]"
                    contains = '.com'
                }
                then = @{ effect = 'deny' }
        }

        (
                Test-RadarPolicyRuleForRole `
                    -PolicyRule $rule `
                    -Role $ownerRole
        ).State | Should -Be 'NotBlocked'
    }

    It 'treats an alias for another assignment path as absent' {
        $rule = @{
                if = @{
                    field =
                        'Microsoft.Authorization/roleAssignmentScheduleRequests/principalType'
                    equals = 'ServicePrincipal'
                }
                then = @{ effect = 'deny' }
        }

        (
                Test-RadarPolicyRuleForRole `
                    -PolicyRule $rule `
                    -Role $ownerRole `
                    -AssignmentResourceType (
                        'Microsoft.Authorization/roleAssignments'
                    )
        ).State | Should -Be 'NotBlocked'
    }

    It 'evaluates the assignment scope alias when scope is known' {
        $rule = @{
                if = @{
                    field =
                        'Microsoft.Authorization/roleAssignments/scope'
                    equals = '/subscriptions/sub-1'
                }
                then = @{ effect = 'deny' }
        }

        (
                Test-RadarPolicyRuleForRole `
                    -PolicyRule $rule `
                    -Role $ownerRole `
                    -AssignmentScope '/subscriptions/sub-1'
        ).State | Should -Be 'Blocked'
    }

    It 'rules out unrelated name and alias branches' {
        $rule = @{
            if = @{
                allOf = @(
                    @{
                        field = 'id'
                        contains = '/privateDnsZones/example/'
                    },
                    @{
                        anyOf = @(
                            @{
                                field = 'type'
                                equals =
                                    'Microsoft.Network/privateDnsZones/A'
                            },
                            @{
                                allOf = @(
                                    @{
                                        field = 'name'
                                        equals = 'gitlab.tooling'
                                    },
                                    @{
                                        field =
                                            'Microsoft.Network/privateDnsZones/A/aRecords[*].ipv4Address'
                                        notEquals = '10.0.0.1'
                                    }
                                )
                            }
                        )
                    }
                )
            }
            then = @{ effect = 'deny' }
        }

        (
            Test-RadarPolicyRuleForRole `
                -PolicyRule $rule `
                -Role $ownerRole
        ).State | Should -Be 'NotBlocked'
    }

    It 'keeps direct and PIM branches isolated in a customer-shaped deny rule' {
        $rule = @{
            if = @{
                anyOf = @(
                    @{
                        allOf = @(
                            @{
                                field = 'type'
                                equals =
                                    'Microsoft.Authorization/roleAssignments'
                            },
                            @{
                                field =
                                    'Microsoft.Authorization/roleAssignments/roleDefinitionId'
                                in = "[parameters('roleDefinitionIds')]"
                            },
                            @{
                                not = @{
                                    field =
                                        'Microsoft.Authorization/roleAssignments/principalId'
                                    in =
                                        "[parameters('allowedPrincipalIds')]"
                                }
                            }
                        )
                    },
                    @{
                        anyOf = @(
                            @{
                                allOf = @(
                                    @{
                                        field = 'type'
                                        equals =
                                            'Microsoft.Authorization/roleAssignmentScheduleRequests'
                                    },
                                    @{
                                        field =
                                            'Microsoft.Authorization/roleAssignmentScheduleRequests/roleDefinitionId'
                                        in =
                                            "[parameters('roleDefinitionIds')]"
                                    },
                                    @{
                                        not = @{
                                            field =
                                                'Microsoft.Authorization/roleAssignmentScheduleRequests/principalId'
                                            in =
                                                "[parameters('allowedPrincipalIds')]"
                                        }
                                    }
                                )
                            },
                            @{
                                allOf = @(
                                    @{
                                        field =
                                            'Microsoft.Authorization/roleAssignmentScheduleRequests/principalType'
                                        equals = 'ServicePrincipal'
                                    },
                                    @{
                                        value =
                                            "[last(split(field('Microsoft.Authorization/roleAssignmentScheduleRequests/roleDefinitionId'),'/'))]"
                                        in =
                                            "[parameters('roleDefinitionIds')]"
                                    }
                                )
                            }
                        )
                    }
                )
            }
            then = @{ effect = 'deny' }
        }
        $parameters = @{
            roleDefinitionIds = @(
                Get-RadarRoleDefinitionGuid -RoleOrId $ownerRole
            )
            allowedPrincipalIds = @()
        }

        foreach ($resourceType in @(
            'Microsoft.Authorization/roleAssignments',
            'Microsoft.Authorization/roleAssignmentScheduleRequests'
        )) {
            (
                Test-RadarPolicyRuleForRole `
                    -PolicyRule $rule `
                    -Role $readerRole `
                    -Parameters $parameters `
                    -AssignmentResourceType $resourceType
            ).State | Should -Be 'NotBlocked'
        }
        (
            Test-RadarPolicyRuleForRole `
                -PolicyRule $rule `
                -Role $ownerRole `
                -Parameters $parameters `
                -AssignmentResourceType (
                    'Microsoft.Authorization/roleAssignments'
                )
        ).State | Should -Be 'Unknown'
        (
            Test-RadarPolicyRuleForRole `
                -PolicyRule $rule `
                -Role $ownerRole `
                -Parameters $parameters `
                -AssignmentResourceType (
                    'Microsoft.Authorization/roleAssignmentScheduleRequests'
                )
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
    It 'handles omitted optional REST properties under strict mode' {
        Mock Get-AzPolicyDefinition { $null }
        Mock Invoke-AzRestMethod {
            [pscustomobject]@{
                Content = @'
{
  "name": "1.0.0",
  "properties": {
    "displayName": "Audit unrelated resources",
    "policyRule": {
      "if": {
        "field": "type",
        "equals": "Microsoft.Storage/storageAccounts"
      },
      "then": {
        "effect": "audit"
      }
    }
  }
}
'@
            }
        }

        $definition = & {
            Set-StrictMode -Version Latest
            Get-RadarPolicyDefinitionCached `
                -Id '/providers/Microsoft.Authorization/policyDefinitions/audit-storage' `
                -DefinitionCache @{} `
                -PolicySetCache @{} `
                -Version '1.0.0'
        }

        $definition.Mode | Should -BeNullOrEmpty
        $definition.Parameter | Should -BeNullOrEmpty
        $definition.PolicyRule.then.effect | Should -Be 'audit'
    }

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

Describe 'Import-RadarPolicyDefinitionGraphCache' {
    It 'preloads assigned definitions and initiative members by exact version' {
        $directId =
            '/providers/Microsoft.Authorization/policyDefinitions/direct'
        $setId =
            '/providers/Microsoft.Authorization/policySetDefinitions/set'
        $memberId =
            '/providers/Microsoft.Authorization/policyDefinitions/member'
        $assignments = @(
            [pscustomobject]@{
                PolicyDefinitionId = $directId
                EffectiveDefinitionVersion = '1.2.3'
            },
            [pscustomobject]@{
                PolicyDefinitionId = $setId
                EffectiveDefinitionVersion = '2.0.0'
            }
        )
        Mock Search-AzGraph {
            if ($Query -match '/member/versions/1\.4\.2') {
                return [pscustomobject]@{
                    Data = @(
                        [pscustomobject]@{
                            Id = "$memberId/versions/1.4.2"
                            Name = '1.4.2'
                            Type =
                                'microsoft.authorization/policydefinitions/versions'
                            Properties = [pscustomobject]@{
                                DisplayName = 'Member'
                                Mode = 'All'
                                Parameters = [pscustomobject]@{}
                                PolicyRule = [pscustomobject]@{
                                    if = [pscustomobject]@{
                                        field = 'type'
                                        equals =
                                            'Microsoft.Authorization/roleAssignments'
                                    }
                                    then = [pscustomobject]@{
                                        effect = 'deny'
                                    }
                                }
                            }
                        }
                    )
                }
            }
            [pscustomobject]@{
                Data = @(
                    [pscustomobject]@{
                        Id = "$directId/versions/1.2.3"
                        Name = '1.2.3'
                        Type =
                            'microsoft.authorization/policydefinitions/versions'
                        Properties = [pscustomobject]@{
                            DisplayName = 'Direct'
                            Mode = 'All'
                            Parameters = [pscustomobject]@{}
                            PolicyRule = [pscustomobject]@{
                                if = [pscustomobject]@{
                                    field = 'type'
                                    equals =
                                        'Microsoft.Authorization/roleAssignments'
                                }
                                then = [pscustomobject]@{
                                    effect = 'deny'
                                }
                            }
                        }
                    },
                    [pscustomobject]@{
                        Id = "$setId/versions/2.0.0"
                        Name = '2.0.0'
                        Type =
                            'microsoft.authorization/policysetdefinitions/versions'
                        Properties = [pscustomobject]@{
                            DisplayName = 'Set'
                            Parameters = [pscustomobject]@{}
                            PolicyDefinitions = @(
                                [pscustomobject]@{
                                    PolicyDefinitionId = $memberId
                                    DefinitionVersion = '1.*.*'
                                    EffectiveDefinitionVersion = '1.4.2'
                                    Parameters = [pscustomobject]@{}
                                }
                            )
                        }
                    }
                )
            }
        }
        $definitionCache = @{}
        $policySetCache = @{}

        Import-RadarPolicyDefinitionGraphCache `
            -Assignments $assignments `
            -DefinitionCache $definitionCache `
            -PolicySetCache $policySetCache

        $definitionCache.ContainsKey(
            "$($directId.ToLowerInvariant())::1.2.3"
        ) | Should -BeTrue
        $policySetCache.ContainsKey(
            "$($setId.ToLowerInvariant())::2.0.0"
        ) | Should -BeTrue
        $definitionCache.ContainsKey(
            "$($memberId.ToLowerInvariant())::1.4.2"
        ) | Should -BeTrue
        Should -Invoke Search-AzGraph -Times 2
    }
}

Describe 'Get-RadarPolicyInventory large-estate path' {
    It 'bulk-loads one exact definition before resolving many scopes' {
        $definitionId =
            '/providers/Microsoft.Authorization/policyDefinitions/deny-role'
        $roleId =
            '/providers/Microsoft.Authorization/roleDefinitions/8e3af657-a8ff-443c-a75c-2fe8c4bcb635'
        $assignment = [pscustomobject]@{
            Id = '/subscriptions/root/providers/Microsoft.Authorization/policyAssignments/deny-role'
            Name = 'deny-role'
            DisplayName = 'Deny role'
            Scope = '/subscriptions/root'
            PolicyDefinitionId = $definitionId
            EffectiveDefinitionVersion = '1.0.0'
            Parameter = [pscustomobject]@{
                roleIds = [pscustomobject]@{
                    value = @($roleId)
                }
            }
            NotScope = @()
        }
        Mock Get-RadarPolicyAssignmentAtScope {
            @($assignment)
        }
        Mock Get-AzPolicyExemption { @() }
        Mock Search-AzGraph {
            [pscustomobject]@{
                Data = @(
                    [pscustomobject]@{
                        Id = "$definitionId/versions/1.0.0"
                        Name = '1.0.0'
                        Type =
                            'microsoft.authorization/policydefinitions/versions'
                        Properties = [pscustomobject]@{
                            DisplayName = 'Deny role'
                            Mode = 'All'
                            Parameters = [pscustomobject]@{
                                roleIds = [pscustomobject]@{
                                    defaultValue = @()
                                }
                            }
                            PolicyRule = [pscustomobject]@{
                                if = [pscustomobject]@{
                                    field =
                                        'Microsoft.Authorization/roleAssignments/roleDefinitionId'
                                    in = "[parameters('roleIds')]"
                                }
                                then = [pscustomobject]@{
                                    effect = 'deny'
                                }
                            }
                        }
                    }
                )
            }
        }
        Mock Get-AzPolicyDefinition {
            throw 'Per-definition ARM fallback should not run.'
        }
        Mock Invoke-AzRestMethod {
            throw 'Per-definition REST fallback should not run.'
        }
        $scopes = @(
            1..20 |
                ForEach-Object {
                    New-RadarScope -Id "/subscriptions/sub-$_"
                }
        )

        $inventory = Get-RadarPolicyInventory -Scopes $scopes

        $inventory.IsComplete | Should -BeTrue
        $inventory.AssignmentCount | Should -Be 1
        $inventory.RelevantRuleCount | Should -Be 1
        foreach ($scope in $scopes) {
            @(
                $inventory.RulesByScope[
                    $scope.Id.ToLowerInvariant()
                ]
            ).Count | Should -Be 1
        }
        Should -Invoke Search-AzGraph -Times 1
        Should -Invoke Get-AzPolicyDefinition -Times 0
        Should -Invoke Invoke-AzRestMethod -Times 0
    }

    It 'keeps a failed assignment scope as an empty uncertain scope' {
        Mock Get-RadarPolicyAssignmentAtScope {
            if ($Scope -eq '/subscriptions/sub-2') {
                throw 'assignment read denied'
            }
            @()
        }
        Mock Get-AzPolicyExemption { @() }
        $scopes = @(
            (New-RadarScope -Id '/subscriptions/sub-1'),
            (New-RadarScope -Id '/subscriptions/sub-2')
        )

        $inventory = Get-RadarPolicyInventory -Scopes $scopes

        $inventory.IsComplete | Should -BeFalse
        $inventory.UncertainScopes |
            Should -Contain '/subscriptions/sub-2'
        @(
            $inventory.RulesByScope['/subscriptions/sub-2']
        ).Count | Should -Be 0
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
            if ($Id -like '*/unrelated-value-target') {
                return [pscustomobject]@{
                    Id = $Id
                    Name = 'unrelated-value-target'
                    DisplayName = 'Budget notification deny'
                    Mode = 'All'
                    Parameter = [pscustomobject]@{}
                    PolicyRule = @{
                        if = @{
                            value =
                                "[string(field('Microsoft.Consumption/budgets/notifications'))]"
                            contains = '.com'
                        }
                        then = @{ effect = 'Deny' }
                    }
                }
            }
            if ($Id -like '*/ambiguous-generic-target') {
                return [pscustomobject]@{
                    Id = $Id
                    Name = 'ambiguous-generic-target'
                    DisplayName = 'Allowed locations from provided scopes'
                    Mode = 'All'
                    Parameter = [pscustomobject]@{
                        includedScopes = [pscustomobject]@{
                            defaultValue = @()
                        }
                        allowedLocations = [pscustomobject]@{
                            defaultValue = @()
                        }
                    }
                    PolicyRule = @{
                        if = @{
                            allOf = @(
                                @{
                                    count = @{
                                        name = 'scope'
                                        value =
                                            "[parameters('includedScopes')]"
                                        where = @{
                                            field = 'id'
                                            like = "[current('scope')]"
                                        }
                                    }
                                    greater = 0
                                },
                                @{
                                    field = 'location'
                                    notIn =
                                        "[parameters('allowedLocations')]"
                                }
                            )
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

    It 'drops policies whose value aliases are unrelated to assignments' {
        $assignment = [pscustomobject]@{
            Id = '/subscriptions/sub-1/providers/Microsoft.Authorization/policyAssignments/unrelated-value-target'
            Name = 'unrelated-value-target'
            Scope = '/subscriptions/sub-1'
            PolicyDefinitionId =
                '/providers/Microsoft.Authorization/policyDefinitions/unrelated-value-target'
            Parameter = [pscustomobject]@{}
            NotScope = @()
        }

        $resolved = Resolve-RadarPolicyAssignment `
            -Assignment $assignment `
            -DefinitionCache @{} `
            -PolicySetCache @{}

        $resolved.Rules | Should -BeNullOrEmpty
        $resolved.Warnings | Should -BeNullOrEmpty
    }

    It 'keeps ambiguous generic policies uncertain' {
        $assignment = [pscustomobject]@{
            Id = '/subscriptions/sub-1/providers/Microsoft.Authorization/policyAssignments/ambiguous-generic-target'
            Name = 'ambiguous-generic-target'
            Scope = '/subscriptions/sub-1'
            PolicyDefinitionId =
                '/providers/Microsoft.Authorization/policyDefinitions/ambiguous-generic-target'
            Parameter = [pscustomobject]@{
                includedScopes = [pscustomobject]@{
                    value = @('/subscriptions/sub-1')
                }
                allowedLocations = [pscustomobject]@{
                    value = @('uksouth')
                }
            }
            NotScope = @()
        }

        $resolved = Resolve-RadarPolicyAssignment `
            -Assignment $assignment `
            -DefinitionCache @{} `
            -PolicySetCache @{}

        $resolved.Rules.Count | Should -Be 1
        $resolved.Rules[0].UnsupportedReason |
            Should -Match 'targeting could not be ruled out'
        $resolved.Rules[0].ScopeSensitive | Should -BeTrue
        $resolved.Warnings | Should -BeNullOrEmpty
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
        (
            $coverage.ScopeEvaluations |
                Where-Object {
                    $_.Scope -eq '/subscriptions/sub-1'
                }
        ).GapStatus | Should -Be 'Covered'
        (
            $coverage.ScopeEvaluations |
                Where-Object {
                    $_.Scope -eq '/subscriptions/sub-1'
                }
        ).BlockingPolicies |
            Should -Match 'Deny Owner'
        (
            $coverage.ScopeEvaluations |
                Where-Object {
                    $_.Scope -eq '/subscriptions/sub-2'
                }
        ).GapStatus | Should -Be 'Gap'
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
        $coverage.ScopeEvaluations[0].GapStatus |
            Should -Be 'Unknown'
        ($coverage.ScopeEvaluations[0].UnknownReasons -join '; ') |
            Should -Match 'discovery was incomplete'
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

    It 'reuses a conclusive probe for scope-sensitive policies' {
        $rule = [pscustomobject]@{
            AssignmentId = '/providers/Microsoft.Authorization/policyAssignments/scoped'
            AssignmentName = 'Scoped deny'
            AssignmentScope = '/'
            NotScopes = @()
            DefinitionName = 'Scoped deny'
            ReferenceId = $null
            PolicyRule = $denyRule
            Parameters = @{}
            ScopeSensitive = $true
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
        Mock Test-RadarPolicyRuleForRole {
            [pscustomobject]@{
                State = 'NotBlocked'
                Reason = $null
            }
        }

        $coverage = Get-RadarRoleDenyCoverage `
            -Role $ownerRole `
            -RoleScopes @(
                '/subscriptions/sub-1',
                '/subscriptions/sub-2'
            ) `
            -PolicyInventory $inventory `
            -AssignmentPaths $directAssignmentPath `
            -PolicyEvaluationCache @{}

        $coverage.Status | Should -Be 'None'
        Should -Invoke Test-RadarPolicyRuleForRole -Times 1
    }

    It 'evaluates each scope when the scope probe is inconclusive' {
        $rule = [pscustomobject]@{
            AssignmentId = '/providers/Microsoft.Authorization/policyAssignments/scoped'
            AssignmentName = 'Scoped deny'
            AssignmentScope = '/'
            NotScopes = @()
            DefinitionName = 'Scoped deny'
            ReferenceId = $null
            PolicyRule = $denyRule
            Parameters = @{}
            ScopeSensitive = $true
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
        Mock Test-RadarPolicyRuleForRole {
            [pscustomobject]@{
                State = if ($AssignmentScope) {
                    'Blocked'
                }
                else {
                    'Unknown'
                }
                Reason = $null
            }
        }

        $coverage = Get-RadarRoleDenyCoverage `
            -Role $ownerRole `
            -RoleScopes @(
                '/subscriptions/sub-1',
                '/subscriptions/sub-2'
            ) `
            -PolicyInventory $inventory `
            -AssignmentPaths $directAssignmentPath `
            -PolicyEvaluationCache @{}

        $coverage.Status | Should -Be 'Full'
        Should -Invoke Test-RadarPolicyRuleForRole -Times 3
    }

    It 'does not reuse an id-sensitive verdict across scopes' {
        $rule = [pscustomobject]@{
            AssignmentId = '/providers/Microsoft.Authorization/policyAssignments/id-scoped'
            AssignmentName = 'ID-scoped deny'
            AssignmentScope = '/'
            NotScopes = @()
            DefinitionName = 'ID-scoped deny'
            ReferenceId = $null
            PolicyRule = @{
                if = @{
                    field = 'id'
                    like = '/subscriptions/sub-1/*'
                }
                then = @{ effect = 'deny' }
            }
            Parameters = @{}
            ScopeSensitive = $true
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

        $first = Get-RadarRoleDenyCoverage `
            -Role $ownerRole `
            -RoleScopes @('/subscriptions/sub-1') `
            -PolicyInventory $inventory `
            -AssignmentPaths $directAssignmentPath `
            -PolicyEvaluationCache $evaluationCache
        $second = Get-RadarRoleDenyCoverage `
            -Role $ownerRole `
            -RoleScopes @('/subscriptions/sub-2') `
            -PolicyInventory $inventory `
            -AssignmentPaths $directAssignmentPath `
            -PolicyEvaluationCache $evaluationCache

        $first.Status | Should -Be 'Full'
        $second.Status | Should -Be 'None'
    }

    It 'does not reuse policy verdicts across target principals' {
        $rule = [pscustomobject]@{
            AssignmentId =
                '/subscriptions/sub-1/providers/Microsoft.Authorization/policyAssignments/principal-aware'
            AssignmentName = 'Principal-aware deny'
            AssignmentScope = '/subscriptions/sub-1'
            NotScopes = @()
            DefinitionName = 'Principal-aware deny'
            ReferenceId = $null
            PolicyRule = @{
                if = @{
                    allOf = @(
                        @{
                            field =
                                'Microsoft.Authorization/roleAssignments/roleDefinitionId'
                            in = @($ownerRole.Id)
                        },
                        @{
                            not = @{
                                field =
                                    'Microsoft.Authorization/roleAssignments/principalId'
                                in = @('allowed-principal')
                            }
                        }
                    )
                }
                then = @{ effect = 'deny' }
            }
            Parameters = @{}
            ScopeSensitive = $false
            UnsupportedReason = $null
        }
        $inventory = [pscustomobject]@{
            IsEvaluated = $true
            UncertainScopes = @()
            RulesByScope = @{
                '/subscriptions/sub-1' = @($rule)
            }
            ExemptionsByScope = @{
                '/subscriptions/sub-1' = @()
            }
        }
        $evaluationCache = @{}

        $ordinary = Get-RadarRoleDenyCoverage `
            -Role $ownerRole `
            -RoleScopes @('/subscriptions/sub-1') `
            -PolicyInventory $inventory `
            -AssignmentPaths $directAssignmentPath `
            -TargetPrincipalId 'ordinary-principal' `
            -PolicyEvaluationCache $evaluationCache
        $allowed = Get-RadarRoleDenyCoverage `
            -Role $ownerRole `
            -RoleScopes @('/subscriptions/sub-1') `
            -PolicyInventory $inventory `
            -AssignmentPaths $directAssignmentPath `
            -TargetPrincipalId 'allowed-principal' `
            -PolicyEvaluationCache $evaluationCache

        $ordinary.Status | Should -Be 'Full'
        $allowed.Status | Should -Be 'None'
    }
}

Describe 'Control-gap scope map' {
    It 'groups exact scope intent, gaps, unknowns, and covered roles' {
        $base = @{
            AnalysisMode = 'BaselineNotActions'
            BaselineRoleName = 'Customer-Platform-Owner'
            BaselineRoleId = 'baseline-1'
            BaselineScope =
                '/providers/Microsoft.Management/managementGroups/customer'
            RestrictedAction = 'Dangerous.Provider/write'
        }
        $results = @(
            [pscustomobject]($base + @{
                RoleName = 'Self-assignable role'
                RoleId = 'role-1'
                AssignmentPath =
                    'Direct role assignment: Baseline role can create direct role assignments'
                ScopeEvaluations = @(
                    [pscustomobject]@{
                        Scope = '/subscriptions/sub-1'
                        GapStatus = 'Gap'
                        BlockingPolicies = @()
                        UnblockedAssignmentPaths = @(
                            'Direct role assignment'
                        )
                        BaselineAssignablePaths = @(
                            'Direct role assignment'
                        )
                        ExternalAssignmentPaths = @()
                        UnknownReasons = @()
                    },
                    [pscustomobject]@{
                        Scope =
                            '/subscriptions/sub-1/resourceGroups/workload'
                        GapStatus = 'Gap'
                        BlockingPolicies = @()
                        UnblockedAssignmentPaths = @(
                            'Direct role assignment'
                        )
                        BaselineAssignablePaths = @(
                            'Direct role assignment'
                        )
                        ExternalAssignmentPaths = @()
                        UnknownReasons = @()
                    }
                )
            }),
            [pscustomobject]($base + @{
                RoleName = 'Delivery role'
                RoleId = 'role-2'
                AssignmentPath =
                    'Direct role assignment: Requires another principal or assignment process'
                ScopeEvaluations = @(
                    [pscustomobject]@{
                        Scope = '/subscriptions/sub-1'
                        GapStatus = 'Gap'
                        BlockingPolicies = @()
                        UnblockedAssignmentPaths = @(
                            'Direct role assignment'
                        )
                        BaselineAssignablePaths = @()
                        ExternalAssignmentPaths = @(
                            'Direct role assignment'
                        )
                        UnknownReasons = @()
                    }
                )
            }),
            [pscustomobject]($base + @{
                RoleName = 'Uncertain role'
                RoleId = 'role-3'
                AssignmentPath =
                    'Direct role assignment: Requires another principal or assignment process'
                ScopeEvaluations = @(
                    [pscustomobject]@{
                        Scope = '/subscriptions/sub-1'
                        GapStatus = 'Unknown'
                        BlockingPolicies = @()
                        UnblockedAssignmentPaths = @()
                        BaselineAssignablePaths = @()
                        ExternalAssignmentPaths = @()
                        UnknownReasons = @(
                            'Principal type is unknown.'
                        )
                    }
                )
            }),
            [pscustomobject]($base + @{
                RoleName = 'Covered role'
                RoleId = 'role-4'
                AssignmentPath =
                    'Direct role assignment: Baseline role can create direct role assignments'
                ScopeEvaluations = @(
                    [pscustomobject]@{
                        Scope = '/subscriptions/sub-1'
                        GapStatus = 'Covered'
                        BlockingPolicies = @(
                            'Deny covered role [/subscriptions/sub-1]'
                        )
                        UnblockedAssignmentPaths = @()
                        BaselineAssignablePaths = @()
                        ExternalAssignmentPaths = @()
                        UnknownReasons = @()
                    }
                )
            })
        )
        $scopeById = @{
            '/subscriptions/sub-1' = [pscustomobject]@{
                Id = '/subscriptions/sub-1'
                Type = 'Subscription'
                DisplayName = 'Workload subscription'
            }
            '/providers/microsoft.management/managementgroups/customer' =
                [pscustomobject]@{
                    Id =
                        '/providers/Microsoft.Management/managementGroups/customer'
                    Type = 'ManagementGroup'
                    DisplayName = 'Customer root'
                }
        }
        $hierarchy = [pscustomobject]@{
            AncestorsByScope = @{
                '/subscriptions/sub-1' = @(
                    '/providers/Microsoft.Management/managementGroups/customer'
                )
            }
        }
        $assignmentEvidence = @{}
        $assignmentEvidenceKey =
            Get-RadarBaselineAssignmentEvidenceKey `
                -BaselineRoleId 'baseline-1' `
                -BaselineScope (
                    '/providers/Microsoft.Management/managementGroups/customer'
                ) `
                -EvaluationScope '/subscriptions/sub-1'
        $assignmentEvidence[$assignmentEvidenceKey] =
            [pscustomobject]@{
                State = 'DirectAssignmentObserved'
                EffectiveDirectAssignmentCount = 1
                PrincipalTypes = @('User')
                AssignmentScopes = @('/subscriptions/sub-1')
                Warnings = @()
            }

        $map = @(
            Get-RadarControlGapMap `
                -Results $results `
                -ScopeById $scopeById `
                -Hierarchy $hierarchy `
                -BaselineAssignmentEvidence $assignmentEvidence
        )

        $map.Count | Should -Be 1
        $map[0].EvaluationScopeType |
            Should -Be 'Subscription'
        $map[0].EvaluationScopeName |
            Should -Be 'Workload subscription'
        $map[0].ParentScope |
            Should -Be (
                '/providers/Microsoft.Management/managementGroups/customer'
            )
        $map[0].AncestorScopes |
            Should -Be (
                '/providers/Microsoft.Management/managementGroups/customer'
            )
        $map[0].GapStatus | Should -Be 'Gap'
        $map[0].BaselineAccessStatus |
            Should -Be 'DirectAssignmentObserved'
        $map[0].EffectiveDirectAssignmentCount | Should -Be 1
        $map[0].ConfirmedGapRoleCount | Should -Be 2
        $map[0].BaselineAssignableRoleCount | Should -Be 1
        $map[0].ExternalAssignmentRoleCount | Should -Be 1
        $map[0].UnknownRoleCount | Should -Be 1
        $map[0].CoveredRoleCount | Should -Be 1
        $map[0].BlockingPolicies |
            Should -Match 'Deny covered role'
        $map[0].CoverageWarnings |
            Should -Match 'Principal type is unknown'
    }

    It 'exports a normalised scope map atomically' {
        $path = Join-Path $TestDrive 'radar-scope-map.csv'
        $row = [pscustomobject]@{
            EvaluationScopeType = 'Subscription'
            EvaluationScopeName = 'Workload'
            EvaluationScope = '/subscriptions/sub-1'
            ParentScopeName = ''
            ParentScope = ''
            AncestorScopes = ''
            BaselineRoleName = 'Customer-Platform-Owner'
            BaselineRoleId = 'baseline-1'
            BaselineScope = '/subscriptions/sub-1'
            RestrictedAction = 'Dangerous.Provider/write'
            IntentSource =
                'Customer-Platform-Owner NotActions'
            GapStatus = 'Gap'
            BaselineAccessStatus = 'BaselineCapable'
            ConfirmedGapRoleCount = 1
            ConfirmedGapRoles = 'Owner [role-1]'
            BaselineAssignableRoleCount = 1
            BaselineAssignableRoles = 'Owner [role-1]'
            ExternalAssignmentRoleCount = 0
            ExternalAssignmentRoles = ''
            UnknownRoleCount = 0
            UnknownRoles = ''
            CoveredRoleCount = 0
            CoveredRoles = ''
            BlockingPolicies = ''
            UnblockedAssignmentPaths =
                'Direct role assignment'
            CoverageWarnings = ''
        }

        Export-RadarControlGapMap -Rows @($row) -Path $path

        $exported = Import-Csv -LiteralPath $path
        $exported.GapStatus | Should -Be 'Gap'
        $exported.BaselineAccessStatus |
            Should -Be 'BaselineCapable'
        $exported.EvaluationScope |
            Should -Be '/subscriptions/sub-1'
        @(
            Get-ChildItem `
                -LiteralPath $TestDrive `
                -Filter '*.tmp.*'
        ).Count | Should -Be 0
    }

    It 'classifies reachability from the actual unblocked path' {
        $result = [pscustomobject]@{
            AnalysisMode = 'BaselineNotActions'
            BaselineRoleName = 'Customer-Platform-Owner'
            BaselineRoleId = 'baseline-1'
            BaselineScope = '/subscriptions/sub-1'
            RestrictedAction = 'Dangerous.Provider/write'
            RoleName = 'Contributor'
            RoleId = 'role-1'
            AssignmentPath = @(
                'Direct role assignment: Requires another principal or assignment process',
                'PIM eligible assignment request: Baseline role can create this PIM request'
            ) -join '; '
            ScopeEvaluations = @(
                [pscustomobject]@{
                    Scope = '/subscriptions/sub-1'
                    GapStatus = 'Gap'
                    BlockingPolicies = @(
                        'Deny PIM via PIM eligible assignment request'
                    )
                    BlockedAssignmentPaths = @(
                        'PIM eligible assignment request'
                    )
                    UnblockedAssignmentPaths = @(
                        'Direct role assignment'
                    )
                    BaselineAssignablePaths = @()
                    ExternalAssignmentPaths = @(
                        'Direct role assignment'
                    )
                    UnknownReasons = @()
                }
            )
        }

        $map = @(
            Get-RadarControlGapMap -Results @($result)
        )

        $map[0].BaselineAssignableRoleCount | Should -Be 0
        $map[0].ExternalAssignmentRoleCount | Should -Be 1
        $map[0].BaselineAccessStatus | Should -Be 'ExternalOnly'
        $map[0].PolicyControlledRoleCount | Should -Be 1
        $map[0].ExternalAssignmentRoles |
            Should -Match 'Contributor'
    }

    It 'keeps baseline access unknown when its route is uncertain' {
        $result = [pscustomobject]@{
            AnalysisMode = 'BaselineNotActions'
            BaselineRoleName = 'Customer-Platform-Owner'
            BaselineRoleId = 'baseline-1'
            BaselineScope = '/subscriptions/sub-1'
            RestrictedAction = 'Dangerous.Provider/write'
            RoleName = 'Contributor'
            RoleId = 'role-1'
            AssignmentPath = 'Mixed paths'
            ScopeEvaluations = @(
                [pscustomobject]@{
                    Scope = '/subscriptions/sub-1'
                    GapStatus = 'Gap'
                    BlockingPolicies = @()
                    BlockedAssignmentPaths = @()
                    UnblockedAssignmentPaths = @(
                        'Direct role assignment'
                    )
                    BaselineAssignablePaths = @()
                    ExternalAssignmentPaths = @(
                        'Direct role assignment'
                    )
                    UnknownBaselineAssignablePaths = @(
                        'PIM eligible assignment request'
                    )
                    UnknownExternalAssignmentPaths = @()
                    UnknownReasons = @(
                        'PIM policy outcome is unknown.'
                    )
                }
            )
        }

        $evidence = @{}
        $key = Get-RadarBaselineAssignmentEvidenceKey `
            -BaselineRoleId 'baseline-1' `
            -BaselineScope '/subscriptions/sub-1' `
            -EvaluationScope '/subscriptions/sub-1'
        $evidence[$key] = [pscustomobject]@{
            State = 'NoDirectAssignment'
            EffectiveDirectAssignmentCount = 0
            PrincipalTypes = @()
            AssignmentScopes = @()
            Warnings = @()
        }
        $map = @(
            Get-RadarControlGapMap `
                -Results @($result) `
                -BaselineAssignmentEvidence $evidence
        )

        $map[0].GapStatus | Should -Be 'Gap'
        $map[0].BaselineAccessStatus | Should -Be 'Unknown'
        $map[0].UnknownBaselineAssignableRoleCount |
            Should -Be 1
    }

    It 'lists a role in both reachability groups when both paths are open' {
        $result = [pscustomobject]@{
            AnalysisMode = 'BaselineNotActions'
            BaselineRoleName = 'Customer-Platform-Owner'
            BaselineRoleId = 'baseline-1'
            BaselineScope = '/subscriptions/sub-1'
            RestrictedAction = 'Dangerous.Provider/write'
            RoleName = 'Contributor'
            RoleId = 'role-1'
            AssignmentPath = 'Mixed paths'
            ScopeEvaluations = @(
                [pscustomobject]@{
                    Scope = '/subscriptions/sub-1'
                    GapStatus = 'Gap'
                    BlockingPolicies = @()
                    BlockedAssignmentPaths = @()
                    UnblockedAssignmentPaths = @(
                        'Direct role assignment',
                        'PIM eligible assignment request'
                    )
                    BaselineAssignablePaths = @(
                        'PIM eligible assignment request'
                    )
                    ExternalAssignmentPaths = @(
                        'Direct role assignment'
                    )
                    UnknownReasons = @()
                }
            )
        }

        $evidence = @{}
        $key = Get-RadarBaselineAssignmentEvidenceKey `
            -BaselineRoleId 'baseline-1' `
            -BaselineScope '/subscriptions/sub-1' `
            -EvaluationScope '/subscriptions/sub-1'
        $evidence[$key] = [pscustomobject]@{
            State = 'NoDirectAssignment'
            EffectiveDirectAssignmentCount = 0
            PrincipalTypes = @()
            AssignmentScopes = @()
            Warnings = @()
        }
        $map = @(
            Get-RadarControlGapMap `
                -Results @($result) `
                -BaselineAssignmentEvidence $evidence
        )

        $map[0].BaselineAssignableRoleCount | Should -Be 1
        $map[0].ExternalAssignmentRoleCount | Should -Be 1
        $map[0].BaselineAccessStatus | Should -Be 'BaselineCapable'
    }
}

Describe 'Add-RadarSubtreeControlPosture' {
    It 'reproduces descendant deny-list posture at each parent scope' {
        $root =
            '/providers/Microsoft.Management/managementGroups/customer'
        $subscription = '/subscriptions/sub-1'
        $common = @{
            BaselineRoleName = 'Customer-Platform-Owner'
            BaselineRoleId = 'baseline-1'
            BaselineScope = $root
            RestrictedAction = 'Dangerous.Provider/write'
            IntentSource = 'Customer-Platform-Owner NotActions'
            GapStatus = 'Gap'
            ConfirmedGapRoles = 'Role A [role-a]; Role B [role-b]'
            UnknownRoles = ''
            CoveredRoles = ''
        }
        $rows = @(
            [pscustomobject]($common + @{
                EvaluationScopeType = 'ManagementGroup'
                EvaluationScopeName = 'Customer'
                EvaluationScope = $root
                ParentScopeName = ''
                ParentScope = ''
                AncestorScopes = ''
                PolicyControlledRoles = ''
            }),
            [pscustomobject]($common + @{
                EvaluationScopeType = 'Subscription'
                EvaluationScopeName = 'Workload'
                EvaluationScope = $subscription
                ParentScopeName = 'Customer'
                ParentScope = $root
                AncestorScopes = $root
                PolicyControlledRoles = 'Role A [role-a]'
            })
        )

        $posture = @(
            Add-RadarSubtreeControlPosture -Rows $rows
        )
        $rootRow = $posture |
            Where-Object { $_.EvaluationScope -eq $root }
        $subscriptionRow = $posture |
            Where-Object {
                $_.EvaluationScope -eq $subscription
            }

        $rootRow.SubtreeControlStatus | Should -Be 'Gap'
        $rootRow.SubtreeControlledRoles |
            Should -Be 'Role A [role-a]'
        $rootRow.SubtreeGapRoles |
            Should -Be 'Role B [role-b]'
        $subscriptionRow.SubtreeControlledRoles |
            Should -Be 'Role A [role-a]'
        $subscriptionRow.SubtreeGapRoles |
            Should -Be 'Role B [role-b]'
    }

    It 'includes policy controls below a subscription' {
        $subscription = '/subscriptions/sub-1'
        $resourceGroup =
            '/subscriptions/sub-1/resourceGroups/workload'
        $result = [pscustomobject]@{
            AnalysisMode = 'BaselineNotActions'
            BaselineRoleName = 'Customer-Platform-Owner'
            BaselineRoleId = 'baseline-1'
            BaselineScope = $subscription
            RestrictedAction = 'Dangerous.Provider/write'
            RoleName = 'Role A'
            RoleId = 'role-a'
            ScopeEvaluations = @(
                [pscustomobject]@{
                    Scope = $subscription
                    GapStatus = 'Gap'
                    BlockingPolicies = @()
                    BlockedAssignmentPaths = @()
                    UnblockedAssignmentPaths = @(
                        'Direct role assignment'
                    )
                    BaselineAssignablePaths = @(
                        'Direct role assignment'
                    )
                    ExternalAssignmentPaths = @()
                    UnknownReasons = @()
                },
                [pscustomobject]@{
                    Scope = $resourceGroup
                    GapStatus = 'Covered'
                    BlockingPolicies = @(
                        'Deny role assignment'
                    )
                    BlockedAssignmentPaths = @(
                        'Direct role assignment'
                    )
                    UnblockedAssignmentPaths = @()
                    BaselineAssignablePaths = @()
                    ExternalAssignmentPaths = @()
                    UnknownReasons = @()
                }
            )
        }
        $hierarchy = [pscustomobject]@{
            AncestorsByScope = @{
                $subscription.ToLowerInvariant() = @()
            }
        }

        $exactAndEvidence = @(
            Get-RadarControlGapMap `
                -Results @($result) `
                -Hierarchy $hierarchy `
                -IncludeSubtreeControlEvidence
        )
        $posture = @(
            Add-RadarSubtreeControlPosture `
                -Rows $exactAndEvidence
        )

        $posture.Count | Should -Be 1
        $posture[0].EvaluationScope |
            Should -Be $subscription
        $posture[0].SubtreeControlStatus |
            Should -Be 'Covered'
        $posture[0].SubtreeControlledRoles |
            Should -Match 'Role A'
    }
}

Describe 'Get-RadarAssignmentPathCacheKey' {
    It 'distinguishes identical resource types with different reachability' {
        $baselineAssignable = @(
            [pscustomobject]@{
                Name = 'Direct role assignment'
                ResourceType =
                    'Microsoft.Authorization/roleAssignments'
                Reachability =
                    'Baseline role can create direct role assignments'
            }
        )
        $external = @(
            [pscustomobject]@{
                Name = 'Direct role assignment'
                ResourceType =
                    'Microsoft.Authorization/roleAssignments'
                Reachability =
                    'Requires another principal or assignment process'
            }
        )

        Get-RadarAssignmentPathCacheKey $baselineAssignable |
            Should -Not -Be (
                Get-RadarAssignmentPathCacheKey $external
            )
        Get-RadarAssignmentPathCacheKey $baselineAssignable |
            Should -Be (
                Get-RadarAssignmentPathCacheKey $baselineAssignable
            )
    }
}

Describe 'Get-RadarReportHealthWarning' {
    It 'flags a report whose every pair is uncertain' {
        $results = @(
            [pscustomobject]@{
                AnalysisMode = 'BaselineNotActions'
                BaselineRoleId = 'baseline-1'
                BaselineScope = '/subscriptions/sub-1'
                RoleId = 'role-1'
                DenyCoverage = 'Unknown'
            },
            [pscustomobject]@{
                AnalysisMode = 'BaselineNotActions'
                BaselineRoleId = 'baseline-1'
                BaselineScope = '/subscriptions/sub-1'
                RoleId = 'role-2'
                DenyCoverage = 'NotEvaluated'
            }
        )

        Get-RadarReportHealthWarning -Results $results |
            Should -Match 'not operationally actionable'
    }

    It 'accepts a report with at least one conclusive pair' {
        $results = @(
            [pscustomobject]@{
                AnalysisMode = 'BaselineNotActions'
                BaselineRoleId = 'baseline-1'
                BaselineScope = '/subscriptions/sub-1'
                RoleId = 'role-1'
                DenyCoverage = 'Unknown'
            },
            [pscustomobject]@{
                AnalysisMode = 'BaselineNotActions'
                BaselineRoleId = 'baseline-1'
                BaselineScope = '/subscriptions/sub-1'
                RoleId = 'role-2'
                DenyCoverage = 'None'
            }
        )

        Get-RadarReportHealthWarning -Results $results |
            Should -BeNullOrEmpty
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

    It 'renders the MG and subscription control-gap map' {
        $controlGapMap = @(
                [pscustomobject]@{
                    EvaluationScopeType = 'ManagementGroup'
                    EvaluationScopeName = 'Customer root'
                    EvaluationScope =
                        '/providers/Microsoft.Management/managementGroups/customer'
                    ParentScopeName = ''
                    ParentScope = ''
                    BaselineRoleName =
                        'Customer-Platform-Owner'
                    BaselineRoleId = 'baseline-1'
                    RestrictedAction =
                        'Dangerous.Provider/write'
                    GapStatus = 'Unknown'
                    BaselineAssignableRoles = ''
                    ExternalAssignmentRoles = ''
                    BlockingPolicies = ''
                },
                [pscustomobject]@{
                    EvaluationScopeType = 'Subscription'
                    EvaluationScopeName = 'Workload'
                    EvaluationScope = '/subscriptions/sub-1'
                    ParentScopeName = 'Landing zone'
                    ParentScope =
                        '/providers/Microsoft.Management/managementGroups/landing-zone'
                    AncestorScopes = @(
                        '/providers/Microsoft.Management/managementGroups/customer',
                        '/providers/Microsoft.Management/managementGroups/landing-zone'
                    ) -join '; '
                    BaselineRoleName =
                        'Customer-Platform-Owner'
                    BaselineRoleId = 'baseline-1'
                    RestrictedAction =
                        'Dangerous.Provider/write'
                    GapStatus = 'Gap'
                    BaselineAssignableRoles =
                        'Owner [role-1]'
                    ExternalAssignmentRoles = ''
                    BlockingPolicies = ''
                }
            )
        $html = & {
            Set-StrictMode -Version Latest
            ConvertTo-RadarHtmlReport `
                -Results @() `
                -RestrictedActions @(
                    'Dangerous.Provider/write'
                ) `
                -RolesScanned 1 `
                -IncludeCustomRoles $true `
                -ControlGapMap $controlGapMap
        }

        $html | Should -Match 'control-gap map'
        $html | Should -Match 'scope-tree'
        $html | Should -Not -Match 'Flat scope summary table'
        $html | Should -Match 'Workload'
        $html | Should -Match 'Dangerous.Provider/write'
        $html | Should -Match 'Owner \[role-1\]'
        $html | Should -Match 'baseline-capable'
        $html | Should -Match 'remain latent'
        $html | Should -Match 'external-route'
        $html | Should -Match (
            'data-scope-id="/subscriptions/sub-1" ' +
            'data-parent-scope="/providers/Microsoft.Management/managementGroups/customer"'
        )
        $html.IndexOf('Customer root') |
            Should -BeLessThan $html.IndexOf('Workload')
        $childStart = $html.IndexOf(
            'data-scope-id="/subscriptions/sub-1"'
        )
        $childStart | Should -BeGreaterThan $html.IndexOf(
            'data-scope-id="/providers/Microsoft.Management/managementGroups/customer"'
        )
        $html | Should -Match 'baseline-metrics'
    }

    It 'renders a dedicated map without legacy role-report sections' {
        $controlGapMap = @(
            [pscustomobject]@{
                EvaluationScopeType = 'Subscription'
                EvaluationScopeName = 'Workload'
                EvaluationScope = '/subscriptions/sub-1'
                ParentScopeName = ''
                ParentScope = ''
                AncestorScopes = ''
                BaselineRoleName = 'Customer-Platform-Owner'
                BaselineRoleId = 'baseline-1'
                BaselineScope = '/subscriptions/sub-1'
                RestrictedAction = 'Dangerous.Provider/write'
                GapStatus = 'Gap'
                BaselineAccessStatus = 'DirectAssignmentObserved'
                EffectiveDirectAssignmentCount = 1
                BaselinePrincipalTypes = 'User'
                BaselineAssignmentScopes = '/subscriptions/sub-1'
                AssignmentWarnings = ''
                PrincipalGapStatus = 'NetNewGap'
                NetNewGapRoles = 'Owner [role-1]'
                NetNewGapPrincipals =
                    'principal-placeholder [User]'
                UnknownPrincipalCount = 1
                UnknownPrincipals =
                    'review-placeholder [ServicePrincipal]'
                PrincipalGapWarnings =
                    'One principal requires directory review.'
                BaselineAssignableRoles = 'Owner [role-1]'
                ExternalAssignmentRoles = 'Owner [role-1]'
                SubtreeControlStatus = 'Gap'
                SubtreeGapRoles = 'Owner [role-1]'
                SubtreeControlledRoles = ''
                BlockingPolicies = ''
            }
        )

        $html = & {
            Set-StrictMode -Version Latest
            ConvertTo-RadarHtmlReport `
                -Results @() `
                -RestrictedActions @(
                    'Dangerous.Provider/write'
                ) `
                -RolesScanned 1 `
                -IncludeCustomRoles $true `
                -BaselineContextCount 1 `
                -ControlGapMap $controlGapMap `
                -PrincipalGaps @(
                    [pscustomobject]@{
                        PrincipalId = 'principal-placeholder'
                        RestrictedAction =
                            'Dangerous.Provider/write'
                        NetNewGapStatus = 'NetNewGap'
                    }
                ) `
                -MapOnly
        }

        $html |
            Should -Match '<title>RADAR Scope Control-Gap Map</title>'
        $html | Should -Match 'scope-node'
        $html | Should -Match 'baseline-metrics'
        $html | Should -Not -Match 'No matches found'
        $html | Should -Not -Match 'id="filter"'
        $html | Should -Match '1 direct-assigned'
        $html | Should -Match '1 net-new gaps'
        $html | Should -Match 'Actionable \(1\)'
        $html | Should -Match 'Needs review \(1\)'
        $html | Should -Match 'All diagnostics \(1\)'
        $html | Should -Match 'data-mode="actionable"'
        $html | Should -Match 'id="map-search"'
        $html | Should -Match 'id="map-scope-type"'
        $html | Should -Match 'applyMapFilters'
        $html | Should -Match 'scopeOrAncestorMatchesSearch'
        $html | Should -Match 'if \(scopeType === ''all''\)'
        $html | Should -Match 'map-ancestor-only'
        $html | Should -Match 'map-status-actionable'
        $html | Should -Match 'map-status-review-secondary'
        $html | Should -Match 'review-placeholder \[ServicePrincipal\]'
        $html |
            Should -Match 'One principal requires directory review'
        $html | Should -Not -Match 'scopeType !== ''all'''
        (
            [regex]::Matches(
                $html,
                '<button type="button" class="map-tab"'
            ).Count
        ) | Should -Be 3
        $html |
            Should -Match 'principal-placeholder \[User\]'
        $html | Should -Match '1 remediation gaps'
        $html | Should -Match 'roles missing from subtree controls'
        $html |
            Should -Match 'actions with a direct baseline assignment'
        $html | Should -Match 'direct baseline assignment scopes'
        $html |
            Should -Not -Match 'external-process gap actions'
    }

    It 'renders principal identities and reasons in Needs review' {
        $row = [pscustomobject]@{
            EvaluationScopeType = 'Subscription'
            EvaluationScopeName = 'Workload'
            EvaluationScope = '/subscriptions/sub-1'
            ParentScopeName = ''
            ParentScope = ''
            AncestorScopes = ''
            BaselineRoleName = 'Customer-Platform-Owner'
            BaselineRoleId = 'baseline-1'
            BaselineScope = '/subscriptions/sub-1'
            RestrictedAction = 'Dangerous.Provider/write'
            PrincipalGapStatus = 'Unknown'
            UnknownPrincipals =
                'principal-placeholder [ServicePrincipal]'
            PrincipalGapWarnings =
                'Directory evidence is incomplete.'
            GapStatus = 'Unknown'
            BaselineAccessStatus = 'Unknown'
            BaselineAssignableRoles = ''
            ExternalAssignmentRoles = ''
            BlockingPolicies = ''
        }

        $html = ConvertTo-RadarHtmlReport `
            -Results @() `
            -RestrictedActions @('Dangerous.Provider/write') `
            -RolesScanned 1 `
            -IncludeCustomRoles $true `
            -BaselineContextCount 1 `
            -ControlGapMap @($row) `
            -MapOnly

        $html | Should -Match 'Actionable \(0\)'
        $html | Should -Match 'Needs review \(1\)'
        $html | Should -Match 'data-mode="review"'
        $html |
            Should -Match 'principal-placeholder \[ServicePrincipal\]'
        $html | Should -Match 'Directory evidence is incomplete'
        $html | Should -Match 'principals requiring review'
        $html | Should -Match 'why principal evidence is unknown'
        $html | Should -Match 'map-status-review'
    }

    It 'keeps distinct baseline scopes separate in the map' {
        $rows = @(
            foreach ($baselineScope in @(
                '/subscriptions/sub-1',
                '/subscriptions/sub-2'
            )) {
                [pscustomobject]@{
                    EvaluationScopeType = 'Subscription'
                    EvaluationScopeName = 'Workload'
                    EvaluationScope = '/subscriptions/sub-1'
                    ParentScopeName = ''
                    ParentScope = ''
                    AncestorScopes = ''
                    BaselineRoleName = 'Customer-Platform-Owner'
                    BaselineRoleId = 'baseline-1'
                    BaselineScope = $baselineScope
                    RestrictedAction = 'Dangerous.Provider/write'
                    GapStatus = 'Gap'
                    BaselineAccessStatus = 'BaselineCapable'
                    BaselineAssignableRoles = 'Owner [role-1]'
                    ExternalAssignmentRoles = ''
                    BlockingPolicies = ''
                }
            }
        )

        $html = ConvertTo-RadarHtmlReport `
            -Results @() `
            -RestrictedActions @('Dangerous.Provider/write') `
            -RolesScanned 1 `
            -IncludeCustomRoles $true `
            -ControlGapMap $rows `
            -MapOnly

        (
            [regex]::Matches(
                $html,
                'class="baseline-summary"'
            ).Count
        ) | Should -Be 2
        $html | Should -Match '@ /subscriptions/sub-1'
        $html | Should -Match '@ /subscriptions/sub-2'
        $html | Should -Match 'No actionable gaps'
        $html | Should -Not -Match '<strong>0</strong>'
    }

    It 'derives the dedicated map path from the requested report path' {
        Get-RadarScopeMapHtmlPath `
            -ReportHtmlPath '/tmp/radar-report.html' |
            Should -Be '/tmp/radar-report-scope-map.html'
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
        $principalGapPath =
            Get-RadarPrincipalGapCsvPath `
                -MatchCsvPath $outputCsv
        Test-Path -LiteralPath $principalGapPath |
            Should -BeTrue
        (Get-Content -LiteralPath $principalGapPath -Raw) |
            Should -Match '"NetNewGapStatus"'
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

    It 'keeps customer baseline contexts separate and exposes the unblocked scope' {
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
        $scopeMap = Import-Csv -LiteralPath (
            Get-RadarScopeMapCsvPath -MatchCsvPath $outputCsv
        )
        $coveredMapRow = $scopeMap |
            Where-Object {
                $_.EvaluationScope -eq '/subscriptions/sub-1' -and
                $_.BaselineRoleName -eq
                    'Customer-Platform-Owner' -and
                $_.RestrictedAction -eq
                    'Dangerous.Provider/write'
            }
        $coveredMapRow.GapStatus | Should -Be 'Covered'
        $coveredMapRow.CoveredRoles |
            Should -Match 'Dangerous Built-in'
        $gapMapRow = $scopeMap |
            Where-Object {
                $_.EvaluationScope -eq '/subscriptions/sub-2' -and
                $_.BaselineRoleName -eq
                    'Customer-Platform-Owner-UAT' -and
                $_.RestrictedAction -eq
                    'Dangerous.Provider/write'
            }
        $gapMapRow.GapStatus | Should -Be 'Gap'
        $gapMapRow.ConfirmedGapRoles |
            Should -Match 'Dangerous Built-in'
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
