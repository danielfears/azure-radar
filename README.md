# RADAR - Restricted Action Detector for Azure Roles

RADAR is a PowerShell tool that identifies which **Azure RBAC roles** grant access to a defined list of **restricted actions**, the actions a team does not want any of their users to be able to perform.

It takes a CSV of Azure RBAC actions to restrict and compares each one against the permissions of every built-in role (and optionally custom roles defined at a specific management group), honouring `Actions` and `NotActions`. The output is a CSV and a self-contained HTML report listing every role that grants any of the restricted actions, with the matched permission pattern shown alongside.

When a list of roles already blocked by the deny policy is supplied, RADAR cross-references the matches against it and flags the roles that still need to be added, so the gap between RBAC reality and policy is visible in one place.

## How it works

```mermaid
%%{init: {'theme':'base','themeVariables':{
  'fontFamily':'Inter, ui-sans-serif, -apple-system, BlinkMacSystemFont, "Segoe UI Variable", "Segoe UI", system-ui, Roboto, "Helvetica Neue", Arial, sans-serif',
  'fontSize':'15px',
  'primaryColor':'#0f172a','primaryTextColor':'#e2e8f0','primaryBorderColor':'#334155',
  'lineColor':'#64748b','clusterBkg':'#0b1220','clusterBorder':'#1e293b'
}}}%%
flowchart LR
    A(["<b>restricted-actions.csv</b><br/><sub>actions to restrict</sub>"]):::input
    B(["<b>Azure tenant</b><br/><sub>all built-in roles<br/>+ custom roles in scope</sub>"]):::input
    P(["<b>denied-roles.csv</b><br/><sub>roles already denied by policy<br/>(optional)</sub>"]):::input

    M{{"<b>Match permissions</b><br/><sub>wildcard-aware<br/>respects NotActions</sub>"}}:::proc
    X{{"<b>Cross-reference</b><br/><sub>flag roles missing<br/>from deny policy</sub>"}}:::proc

    R[("<b>Roles granting</b><br/><b>restricted actions</b>")]:::data
    H[/"<b>CSV + HTML report</b><br/><sub>red badges = gap to close</sub>"/]:::output

    A --> M
    B --> M
    M --> R
    R --> X
    P -.-> X
    X --> H

    classDef input  fill:#0369a1,stroke:#38bdf8,color:#f0f9ff,stroke-width:1.5px;
    classDef proc   fill:#b45309,stroke:#facc15,color:#fefce8,stroke-width:1.5px;
    classDef data   fill:#15803d,stroke:#86efac,color:#f0fdf4,stroke-width:1.5px;
    classDef output fill:#166534,stroke:#4ade80,color:#f0fdf4,stroke-width:2px;
```

The two CSV inputs converge through the tenant's role data into a single annotated report. Every matched role is listed; matches not yet covered by the deny policy are highlighted in red.

## Why RADAR?

Azure exposes hundreds of built-in roles, each granting dozens or hundreds of permissions, frequently via wildcards. Auditing them by hand to determine which expose sensitive operations such as `Microsoft.Authorization/roleAssignments/write` or `Microsoft.KeyVault/vaults/delete` is slow and error-prone. RADAR automates that audit:

- Detects exact and wildcard matches against the restricted-actions list (matching is bidirectional, so `Microsoft.Foo/*` in either the input or the role definition resolves correctly).
- Honours `NotActions` exclusions, so a role is not flagged for a permission it explicitly removes.
- Surfaces the delta between matched roles and the existing deny-policy coverage.
- Emits a CSV for pipeline consumption and a self-contained HTML report for review and sharing.

## Requirements

- PowerShell 7+ (or Windows PowerShell 5.1)
- [`Az.Resources`](https://learn.microsoft.com/powershell/module/az.resources/) PowerShell module
- An authenticated Azure context (`Connect-AzAccount`)
- Read access to role definitions in the tenant

## Repository layout

```
radar/
├── README.md                  # This file
├── Invoke-Radar.ps1           # Main script
├── restricted-actions.csv     # Input: actions to restrict
├── denied-roles.csv           # Optional: roles already denied by policy
└── output/                    # Generated reports (created at runtime)
```

## Input format

`restricted-actions.csv` is a single-column CSV listing the actions to flag:

```csv
Action
Microsoft.Authorization/roleAssignments/write
Microsoft.Authorization/roleAssignments/delete
Microsoft.KeyVault/vaults/delete
Microsoft.Storage/storageAccounts/listKeys/action
```

`denied-roles.csv` (optional) is a single-column CSV of role names already blocked by the deny policy:

```csv
RoleName
Owner
Contributor
User Access Administrator
```

## Usage

The simplest invocation accepts all defaults and presents an interactive menu when no scoping arguments are passed:

```powershell
Connect-AzAccount
./Invoke-Radar.ps1
```

The menu offers built-in only, or built-in plus a management group entered at the prompt. Pass `-NoMenu` to skip it. To run non-interactively with explicit paths:

```powershell
./Invoke-Radar.ps1 -InputCsv ./restricted-actions.csv `
                   -OutputCsv ./output/radar-report.csv `
                   -OutputHtml ./output/radar-report.html
```

`-OutputHtml` is optional; supply it to generate the styled HTML report alongside the CSV.

### Including custom roles

By default RADAR scans only built-in Azure roles. To also include custom roles defined at a specific management group, pass `-ManagementGroup`:

| Switch | Behaviour |
| --- | --- |
| `-ManagementGroup <name>` | In addition to built-in roles, scan custom role definitions whose `AssignableScopes` is exactly the named management group. Roles inherited from a parent scope are excluded. |

```powershell
# Built-in roles only
./Invoke-Radar.ps1 -InputCsv ./restricted-actions.csv `
                   -OutputCsv ./output/radar-report.csv `
                   -OutputHtml ./output/radar-report.html

# Built-in plus custom roles defined at a management group
./Invoke-Radar.ps1 -InputCsv ./restricted-actions.csv `
                   -OutputCsv ./output/radar-report.csv `
                   -OutputHtml ./output/radar-report.html `
                   -ManagementGroup my-management-group
```

Custom roles are visually distinguished in both reports: the CSV `IsCustom` column is `True`, and the HTML report renders an orange `Custom` badge with a left-edge accent bar plus dedicated "Custom Scanned" and "Custom Matches" summary cards.

### Cross-referencing against the deny policy

When the team already maintains a list of role names blocked by Azure Policy or another deny mechanism, RADAR can flag any matched role that is not yet on it.

| Switch | Behaviour |
| --- | --- |
| `-DeniedRolesCsv <path>` | CSV with a single `RoleName` column. Each matched role is checked against this set; the report flags those not yet denied. If `denied-roles.csv` is present next to the script it is picked up automatically. |

```powershell
./Invoke-Radar.ps1 -InputCsv ./restricted-actions.csv `
                   -OutputCsv ./output/radar-report.csv `
                   -OutputHtml ./output/radar-report.html `
                   -ManagementGroup my-management-group `
                   -DeniedRolesCsv ./denied-roles.csv
```

When supplied:

- The CSV gains an `IsAlreadyDenied` column (`True`/`False`) per row.
- The HTML report adds **Already Denied** (green) and **Not Yet Denied** (red) summary cards, a green `Denied` or red `Not Denied` pill on each role section, and a red left-edge accent bar on roles still to be denied.
- The console summary prints the role names that are not yet on the deny list, ready to be pasted into the policy.

## Output

The **CSV report** has one row per matched role-and-action pairing:

- `RoleName`, `RoleId`
- `IsCustom`
- `RestrictedAction`: the input action that triggered the match
- `MatchedPattern`: the permission entry on the role responsible for the match
- `IsAlreadyDenied`: populated when `-DeniedRolesCsv` is supplied

The **HTML report** is a self-contained dashboard with summary cards, a collapsible per-role breakdown, custom-role and denied-role badges, and a client-side search filter for narrowing by role name, action, or matched pattern.

## Roadmap

- [x] Wildcard matching with `NotActions` exclusion
- [x] HTML report
- [x] Optional scan of custom roles in a management group
- [x] Cross-reference against an existing denied-roles list
- [ ] Markdown report format
- [ ] CI-friendly exit codes for pipeline use

## License

TBD
