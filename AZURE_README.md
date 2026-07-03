# Azure cloud review

Pentester-focused **Entra ID + Azure resource** automation aligned to `Draft_Methodology_Azure_FINAL.xlsx` (~91 workbook rows, 35 sections; ~57 script checks). For AD DS domains (including Azure-hosted DCs) use [AD_README.md](AD_README.md). For Windows OS hardening use [WINBUILD_README.md](WINBUILD_README.md). Pack overview: [README.md](README.md).

| Item | Value |
|------|--------|
| Script | `AzureCloudReviewv1.ps1` (**v1.0.1**) |
| Shared | `AzureCloudReview.Common.ps1` |
| Installer | `Install-AzureReviewTools.ps1` |
| Lab | `Deploy-AzureReviewLab.ps1`, `Destroy-AzureReviewLab.ps1` (**v1.0.2** destroy) |
| ROADrecon auth | `Start-RoadreconAuth.ps1` → `.roadtools_auth` |
| ROADrecon gather | `Invoke-RoadreconGather.ps1` → `roadrecon.db` (streams output; flags HTTP 4xx/5xx; verifies DB was written) |
| ROADrecon GUI | `Start-RoadreconGui.ps1` → http://127.0.0.1:5000 |
| AzureHound auth | `Get-AzureHoundRefreshToken.ps1` → `./tools/azurehound.refresh` |
| AzureHound collect | `Invoke-AzureHoundList.ps1` → `./tools/azurehound.json` (clear pass/fail; dims expected lab-tenant warnings) |
| Workbook | `Draft_Methodology_Azure_FINAL.xlsx` |

**Scope:** Entra ID, Azure resources, RBAC, CIS-aligned misconfigs, identity attack-path hints. Read-only via **Azure CLI** and Graph REST. Does **not** require Python for the core review script.

Methodology workbook: shared **13-column** header row (see [README.md](README.md#repository-layout)); generic **`Policy`** column is intentionally empty.

**Workbook vs runner:** the workbook has granular CIS rows per section; the script often emits **one bundled triage row per section** (e.g. §34 Virtual Machines: one CSV line covering several workbook controls). Optional `-RunProwler` adds CIS L1 depth. Triage by **Title → column F** — not row index. See [README.md — Workbook vs runner](README.md#workbook-vs-runner-all-tracks).

---

## Requirements

- PowerShell **5.1+** (Windows) or **7+ (`pwsh`)** on Linux/macOS — see [Linux / Kali](#linux--kali) for install
- **Azure CLI** (`az login`); Reader+ on in-scope subscriptions
- Optional Python **3.10–3.12** for Prowler; **3.10+** for ROADrecon

| Role | Enough for review? |
|------|-------------------|
| **Reader** on subscription | Yes for most `az` reads |
| **Global Reader** (Entra) | Better for Graph policy checks |
| **Contributor** | Required for `Deploy-AzureReviewLab.ps1` only |

---

## Quick start

**Windows:**

```powershell
cd C:\path\to\AD_WIN_AZURE_methandscripts
.\Install-AzureReviewTools.ps1 -InstallAll -AddToolsToUserPath
az login
.\AzureCloudReviewv1.ps1
.\AzureCloudReviewv1.ps1 -SubscriptionId "<guid>" -RunProwler
```

**Linux / Kali:** install `pwsh` first, then see [Linux / Kali](#linux--kali) for full commands (`pwsh ./Install-AzureReviewTools.ps1`, `pwsh ./AzureCloudReviewv1.ps1`, AzureHound via `./tools/azurehound`).

**Minimum (no Python):**

```powershell
winget install Microsoft.AzureCLI
az login
.\AzureCloudReviewv1.ps1
```

Service-specific sections **SKIP** when that resource type is not deployed.

### Demo

Tool installer check (`Install-AzureReviewTools.ps1`):

![Install Azure review tools (az, Prowler, ROADrecon, AzureHound)](AzureTools.gif)

Cloud review run (`AzureCloudReviewv1.ps1`; example uses `-RunProwler`):

![Run AzureCloudReviewv1.ps1 against a subscription](AzureRun.gif)

---

## Parameters (`AzureCloudReviewv1.ps1`)

| Parameter | Description |
|-----------|-------------|
| `-SubscriptionId` | One or more GUIDs (default: all enabled subs) |
| `-OutputPath` | Report directory |
| `-RunProwler` | Run Prowler CIS 5.0 L1 if `prowler` in PATH |
| `-SkipIdentityTools` | Skip ROADrecon / AzureHound hint rows |

---

## Outputs

| File | Content |
|------|---------|
| `AzureCloudReview-<timestamp>.txt` | Full log |
| `AzureCloudReview-<timestamp>.csv` | Structured results |
| `AzureCloudReview-<timestamp>.html` | Summary table |
| `prowler-<sub>-<timestamp>/` | If `-RunProwler` (CSV, HTML, compliance CSV) |

**Prowler notes:** Scan completes with **INFO** in the review script even when findings FAIL (Prowler exit code 3 is normal). Use Python **3.10–3.12**, not 3.14. On Windows Server, Prowler **5.31+** can crash with `UnicodeEncodeError` (banner uses `│` / U+2502) when the console is **cp1252** — `-RunProwler` sets `PYTHONUTF8=1` for you.

Standalone Prowler:

```powershell
$env:PYTHONUTF8 = '1'
prowler azure --az-cli-auth --subscription-ids <id> --compliance cis_5.0_azure `
  -M csv html -o ./prowler-output --ignore-exit-code-3
```

---

## Tool installer (`Install-AzureReviewTools.ps1`)

```powershell
.\Install-AzureReviewTools.ps1                    # check only (Windows)
pwsh ./Install-AzureReviewTools.ps1               # check only (Linux/macOS)
.\Install-AzureReviewTools.ps1 -InstallAll -AddToolsToUserPath
```

| Switch | Action |
|--------|--------|
| `-InstallAzCli` | **Windows:** Azure CLI via winget · **Linux:** `apt` package or Microsoft `InstallAzureCLIDeb` script (may need `sudo`) |
| `-InstallPythonTools` | `pip install prowler roadrecon` (skips if already installed unless `-Upgrade`) |
| `-InstallAzureHound` | Download AzureHound into `./tools` (Windows `.exe` or Linux/macOS binary matched to CPU arch) |
| `-Upgrade` | `pip --upgrade` with `-InstallPythonTools`; AzureHound update when missing, tag unknown, or newer (skips if at latest) |
| `-InstallAll` | All three |
| `-AddToolsToUserPath` | Append `./tools` + Python scripts dir; sets user **`PYTHONUNBUFFERED=1`** (ROADrecon device code / cleaner Python CLI on Windows Server) |

Shared download folder: **`./tools`** (AzureHound, `azurehound.refresh`, `azurehound.json`).

AzureHound auth helper: **`Get-AzureHoundRefreshToken.ps1`** (device code → `./tools/azurehound.refresh`). Collection is a **separate** `azurehound list` step — see [AzureHound (attack paths)](#azurehound-attack-paths). **Do not** reuse ROADrecon’s `.roadtools_auth` token for AzureHound.

**Platforms:** Windows PowerShell **5.1+** or **PowerShell 7+** (`pwsh`) on Windows, Linux, and macOS. On Linux/macOS use **`pwsh ./Install-AzureReviewTools.ps1`** (see [Linux / Kali](#linux--kali)).

---

## Identity tools (manual — methodology section 35)

These steps are **manual** after `AzureCloudReviewv1.ps1`. They do not replace the script; they deepen **Entra ID** and **attack-path** analysis. Use **`-SkipIdentityTools`** to omit ROADrecon / AzureHound hint rows in section 35.

### Split of responsibilities

| Tool | Best for |
|------|----------|
| `AzureCloudReviewv1.ps1` | Subscription RBAC, resource misconfigs, some Entra signals via `az` / Graph REST |
| **ROADrecon** | Entra object inventory: users, roles, apps, service principals, CA policies |
| **AzureHound + BloodHound CE** | Privilege-escalation **paths** (who can reach Owner / GA / UAA) |

BloodHound CE setup: [README.md](README.md#bloodhound-ce-ad-and-azure-collectors).

---

### ROADrecon

ROADrecon **enumerates** Entra ID into a local SQLite DB (`roadrecon.db`). It does not emit PASS/FAIL like Prowler; you review in the **GUI** or **plugins**.

#### 1. Target tenant

Use the same tenant as `az login`:

```powershell
az account show --query "{tenantId:tenantId, tenantDomain:tenantDefaultDomain}" -o table
```

Sign in with an identity that has **read access in that tenant** (Global Reader, Security Reader, or Global Administrator). A personal Microsoft account with no role in the lab tenant will not produce useful data.

#### 2. Authenticate (device code)

Use **`Start-RoadreconAuth.ps1`** (recommended). It applies the correct **tenant** + **Azure CLI client**, sets **`PYTHONUNBUFFERED=1`** so the device code appears immediately in PowerShell on Windows Server (plain `roadrecon auth` may show nothing until Ctrl+C), and writes `.roadtools_auth` in the current directory.

```powershell
.\Start-RoadreconAuth.ps1
# or: .\Start-RoadreconAuth.ps1 -Tenant contoso.onmicrosoft.com -ForceReauth
```

Tenant defaults from `az account show` if omitted.

**Do not** use plain `roadrecon auth --device-code` alone on current tenants — it often lands on the **Microsoft Services** tenant (`f8cdef31-…`) or uses a client blocked for legacy **AAD Graph** (`graph.windows.net` → HTTP 403). The helper uses `-t` (not `-d`) and client `04b07795-…` (see [ROADtools issue #147](https://github.com/dirkjanm/ROADtools/issues/147)).

| Item | Value |
|------|--------|
| Helper | `Start-RoadreconAuth.ps1` |
| OAuth client | `04b07795-…` (**Azure CLI**) |
| Token file | `.roadtools_auth` (cwd) |

`Install-AzureReviewTools.ps1 -InstallPythonTools` also sets user **`PYTHONUNBUFFERED=1`** so manual `roadrecon` / `prowler` invocations behave better in new shells.

Default ROADrecon client (`1b730954-…`, Azure AD PowerShell) is often blocked for directory enumeration.

#### 3. Gather and explore

Use **`Invoke-RoadreconGather.ps1`** (recommended). It streams `roadrecon gather`'s output live (no
buffering, so it never appears to "hang"), highlights `Error 40x/5xx` lines instead of letting them
scroll past unnoticed, and verifies the database file was actually created/updated before reporting
success — plain `roadrecon gather` returning exit code 0 doesn't by itself confirm useful data landed.

```powershell
.\Invoke-RoadreconGather.ps1
# or, for per-user MFA method details (requires Global Reader/Security Reader/Auth Admin+):
.\Invoke-RoadreconGather.ps1 -Mfa
.\Start-RoadreconGui.ps1
```

Plain `roadrecon gather` still works if you prefer it (`-d`/`-f`/`-t`/`--mfa`/`--skip-azure`/`--evade`/`--skip-first-phase` are the real upstream flags).

Open **http://127.0.0.1:5000** in a browser on the **same machine** (e.g. RDP session on the DC). Plain `roadrecon gui` often works too, but PowerShell may show Flask’s Werkzeug **“development server”** stderr line as a red `NativeCommandError` — that is **not** a failure; the GUI is still running. Use `Start-RoadreconGui.ps1` to avoid the scary red line.

**Success:** no `Error 40x/5xx` lines during gather; hundreds of HTTP requests (not ~19); GUI shows users, apps, roles, etc.

If gather still hits AAD Graph 403s after upgrading (`python -m pip install --upgrade roadrecon roadtx`) and confirming the auth client (`Start-RoadreconAuth.ps1` already uses the Azure CLI client — see step 2), treat it as a **permission/role gap** on the signed-in account (needs Global Reader / Security Reader or above) first. The mainline `pip install roadrecon` build only talks to the legacy `graph.windows.net` API — it has **no built-in Microsoft Graph mode**; `--msgraph` is not a real flag on PyPI `roadrecon` (verified against the current `gather.py` argparse). A Microsoft Graph fork exists (`roadrecon gather --msgraph` / `roadrecon gui --msgraph`) from an unmerged pull request — [dirkjanm/ROADtools#125](https://github.com/dirkjanm/ROADtools/pull/125) — but it must be installed from that fork/branch manually; `Install-AzureReviewTools.ps1` does not install it.

#### 4. Built-in analysis commands

```powershell
roadrecon plugin -h
```

| Command | Purpose |
|---------|---------|
| `roadrecon gui` | Browse directory objects, role assignments, app permissions |
| `roadrecon plugin policies -f caps.html -p` | Export **Conditional Access** policies to HTML (+ console summary) |
| `roadrecon plugin bloodhound -h` | Export Entra data for BloodHound (custom ingest) |
| `roadrecon dump -h` | Dump DB to files (options vary by version) |

Optional extra collectors (if your `roadrecon -h` lists them): `pimgather`, `azgather`, etc. — only needed for PIM or Azure RBAC detail beyond core `gather`.

#### 5. What to look for (section 35)

| Area | Examples |
|------|----------|
| **Privileged roles** | Global Administrator, Privileged Role Administrator, permanent vs eligible assignments |
| **Service principals / apps** | High Graph permissions, **client secrets/certs**, dangerous API permissions, app **owners** |
| **Consent & delegation** | OAuth2 permission grants, over-broad delegated admin consent |
| **Guests** | `#EXT#` users in privileged roles |
| **Conditional Access** | Gaps for admins, legacy auth, incomplete coverage — use `plugin policies` |
| **Tenant policy** | Guest invite settings, default user role permissions, authorization policy |

ROADrecon does **not** replace subscription CIS checks (storage, KV, NSG, etc.) — those stay in `AzureCloudReviewv1.ps1` and Prowler.

---

### AzureHound (attack paths)

**AzureHound v2+** (e.g. **v2.12.2**): `start` is for **BloodHound Enterprise** only. For **BloodHound CE**, use **`list`** and write **JSON** (ingest in the CE UI — not `.zip`).

**Do not** pass a Graph-only JWT from `az account get-access-token --resource https://graph.microsoft.com` — AzureHound also calls **Azure Resource Manager** (`management.azure.com`). A Graph token causes `invalid audience` on subscription/tenant steps (Entra + ARM collection still partially completes).

#### Recommended: two-step workflow (auth, then collect)

**Do not reuse ROADrecon’s `.roadtools_auth` refresh token.** ROADrecon auth uses the **Azure CLI** client (`04b07795-8ddb-461a-bbee-02f9e1bf7b46`). AzureHound exchanges refresh tokens as the **Azure PowerShell** public client (`1950a258-227b-4e31-a9cf-717495945fc2`). Passing the ROADrecon token (even with `-a 04b07795-…`) usually returns **`AADSTS70000: Provided grant is invalid or malformed`**.

**AzureHound does not accept `-r file`** (that magic string is ROADtools-only).

Keep **token acquisition** and **AzureHound collection** as separate steps (same pattern as ROADrecon: `auth` then `gather`).

**Step 1 — acquire refresh token** (`Get-AzureHoundRefreshToken.ps1` writes `./tools/azurehound.refresh`; on Linux use `pwsh ./Get-AzureHoundRefreshToken.ps1`):

```powershell
cd C:\path\to\AD_WIN_AZURE_methandscripts   # or /path/to/... on Linux
.\Get-AzureHoundRefreshToken.ps1              # Windows
# pwsh ./Get-AzureHoundRefreshToken.ps1     # Linux / macOS
```

Sign in at https://microsoft.com/devicelogin when prompted.

**Step 2 — run AzureHound**:

Recommended: **`Invoke-AzureHoundList.ps1`** (Windows and Linux/macOS via `pwsh`). It reads
`./tools/azurehound.refresh`, auto-detects the tenant the same way step 1 does, and runs
AzureHound via a controlled process instead of a plain native-command call — so harmless
AzureHound log lines (missing `config.json`, missing Entra P1/P2 premium license, missing
PIM/RoleManagement read scopes, a built-in role template absent from this tenant) are shown
dimmed instead of as scary red PowerShell `NativeCommandError` blocks. It ends with a clear
`COLLECTION SUCCEEDED` / `COLLECTION FAILED` verdict based on AzureHound's actual exit code
and whether the output file was written — not on whether AzureHound printed anything to stderr.

```powershell
.\Invoke-AzureHoundList.ps1                       # Windows
# pwsh ./Invoke-AzureHoundList.ps1                # Linux / macOS
```

Optional — limit to one subscription:

```powershell
.\Invoke-AzureHoundList.ps1 -SubscriptionId (az account show --query id -o tsv)
```

Manual/fallback equivalent (same two flags AzureHound actually needs — `-r` **must** be the
token *value*, never the file path/name; passing the filename produces `AADSTS9002313`):

```powershell
$tenant = (az account show --query tenantDefaultDomain -o tsv)
$rt = Get-Content ./tools/azurehound.refresh -Raw
azurehound list -r $rt -t $tenant -o ./tools/azurehound.json
```

Bash equivalent (if `azurehound` is not in PATH, use `./tools/azurehound` — installer sets
executable bit):

```bash
tenant=$(az account show --query tenantDefaultDomain -o tsv)
rt=$(cat ./tools/azurehound.refresh)
./tools/azurehound list -r "$rt" -t "$tenant" -o ./tools/azurehound.json
```

Ingest **`azurehound.json`** in **BloodHound CE** — Docker must use **Linux containers** ([README.md](README.md#bloodhound-ce-ad-and-azure-collectors)). Pathfinding steps below.

#### BloodHound CE — Azure pathfinding

After ingest, use the graph to find **privilege-escalation chains** (who can reach Global Administrator, subscription Owner, User Access Administrator, etc.). ROADrecon covers Entra inventory and policies; BloodHound maps **permission edges** between identities and high-value targets.

1. Open **http://localhost:8080/ui/login** → **Administration** → **File Ingest** → upload `./tools/azurehound.json`.
2. Confirm Azure node counts (service principals, roles, subscriptions) are non-zero.

**Prebuilt queries (fastest)**

1. **Explore** → **Cypher** search bar → **folder icon** (prebuilt searches).
2. Filter **Platform → Azure**.
3. Run useful starting queries:

| Prebuilt query (typical name) | Purpose |
|-------------------------------|---------|
| All Global Administrators | Who holds GA |
| All Privileged Role Administrators | PRA holders |
| Shortest paths to high value roles | Escalation chains to GA / UAA / app admin roles |
| Service principals with high privileges | Abusable SP starting points |

Results render as a graph: **nodes** = users, groups, service principals, roles, subscriptions, key vaults, etc.; **edges** = abuse relationships (`AZOwner`, `AZUserAccessAdministrator`, role membership, …). Click an edge to read what each hop means.

**Pathfinding from a known starting point**

1. **Search** for your compromised principal (user, group, or `AZServicePrincipal`).
2. Select the node → **Set as Starting Node** (or right-click pathfinding options).
3. Search for a target (e.g. **Global Administrator** role, or your subscription).
4. **Set as Ending Node** → run **Pathfinding**.

Optional: right-click a node → **Mark as Owned**, then use owned-principal path queries where available.

**Custom Cypher examples**

Shortest path to Global Administrator:

```cypher
MATCH (n:AZRole {displayname: 'Global Administrator'}), (m),
      p = shortestPath((m)-[r*1..]->(n))
WHERE NOT m = n
RETURN p
```

Paths toward subscription control (adjust subscription name/id from Search):

```cypher
MATCH (sub:AZSubscription), (m),
      p = shortestPath((m)-[r*1..]->(sub))
WHERE NOT m = sub
RETURN p
LIMIT 25
```

From a named service principal:

```cypher
MATCH (sp:AZServicePrincipal {displayname: 'YourAppName'}),
      (target:AZRole {displayname: 'Global Administrator'}),
      p = shortestPath((sp)-[r*1..]->(target))
RETURN p
```

**Reading escalation edges**

| Edge (examples) | Meaning |
|-----------------|--------|
| `AZGlobalAdmin` / role membership | Entra privileged role |
| `AZOwner` | Full control of subscription or resource |
| `AZUserAccessAdministrator` | Can grant RBAC → path to Owner |
| `AZAddSecret` / app role assignments | Control of an app/SP with further rights |
| Key vault / managed identity edges | Resource → identity abuse chains |

Walk each path start → end; every arrow is one step an attacker would execute.

**Lab tenant note (free / no Entra P1/P2)**

AzureHound may skip **user** detail (`Authentication_RequestFromNonPremiumTenantOrB2CTenant`). You still get service principals, roles, RBAC, key vaults, and web apps — enough for lab path analysis. Cross-check identities and CA policy in **ROADrecon**; use BloodHound for **Owner / UAA / GA chains** via SPs and role assignments.

**Suggested pathfinding order (section 35)**

1. Prebuilt → **All Global Administrators**
2. Prebuilt → **Shortest paths to high value roles**
3. Pathfind from your assessment account → **Global Administrator**
4. Pathfind to **subscription Owner** on the lab subscription
5. Expand high-value nodes (key vaults, web apps, privileged SPs)

More: [BloodHound Cypher search](https://bloodhound.specterops.io/analyze-data/explore/cypher-search) · [AzureHound CE collection](https://bloodhound.specterops.io/collect-data/ce-collection/azurehound)

#### Expected errors on free / lab tenants (often OK)

| Log line | Meaning |
|----------|---------|
| `invalid audience` (with `--jwt`) | Graph JWT used where ARM token needed — use refresh token auth instead |
| `AADSTS9002313` / `invalid_grant` with `-r file` | AzureHound does not support `-r file`; use `Get-AzureHoundRefreshToken.ps1` instead |
| `AADSTS70000` / `invalid_grant` with ROADrecon `$rt` | Wrong client — ROADrecon token is Azure CLI; AzureHound needs Azure PowerShell device-code token |
| `Authentication_RequestFromNonPremiumTenantOrB2CTenant` | User detail APIs need Entra ID P1/P2 — users may be missing; other objects still collect |
| `PermissionScopeNotGranted` (RoleManagement / PIM) | No PIM read scopes — normal without Global Reader + PIM licensing |
| `Request_ResourceNotFound` on a `roleDefinitionId` | A built-in Entra role template referenced by the tenant's role-assignment data doesn't exist in this tenant's role catalog — benign, other role assignments still collect |
| `No configuration file located at ...\.config\azurehound\config.json` (shown as a red `NativeCommandError`) | Informational only — this workflow deliberately never creates a config file and passes `-r`/`-t`/`-o` as flags instead; AzureHound falls back to those flags and continues normally. Use `Invoke-AzureHoundList.ps1` to avoid PowerShell displaying this as a scary red error block. |
| `Resource 'a0b1b346-…' does not exist` | Benign on small tenants (default User role template) |

`collection completed` with hundreds of service principals / role assignments is usually **enough for lab path analysis**.

**Service principal count (~100–200 on a small tenant) is normal.** AzureHound lists every **enterprise application** service principal in Entra, mostly **Microsoft first-party** identities (Portal, Graph, ARM, Office, etc.) created when the tenant and subscription are used — not by `Deploy-AzureReviewLab.ps1` (that script does not modify Entra). Custom **app registrations** are usually far fewer (often 1–5); managed identities from lab resources add only a handful. For section 35, focus on **privileged or path-relevant** SPs in BloodHound/ROADrecon, not the total count.

```powershell
azurehound list --help
```

See [AzureHound CE docs](https://bloodhound.specterops.io/collect-data/ce-collection/azurehound).

---

### Suggested section 35 workflow

1. Run `AzureCloudReviewv1.ps1` (and `-RunProwler` if in scope).
2. ROADrecon: auth → gather → `plugin policies` → GUI review.
3. AzureHound → BloodHound CE pathfinding (prebuilt Azure queries + pathfinding; see **BloodHound CE — Azure pathfinding** above).
4. Triage **MANUAL** / **REVIEW** rows in section 35 of `Draft_Methodology_Azure_FINAL.xlsx` against the above.

---

## Tier 2 lab (optional)

Intentionally weak resources for testing FAIL/REVIEW rows in `AzureCloudReviewv1.ps1`.

**First deploy:** Resource providers (`Microsoft.KeyVault`, `Microsoft.Sql`, etc.) register automatically (1–3 minutes each).

**Re-run / add flags:** Safe to re-run on existing `rg-cloudreview-lab` (e.g. add `-IncludeExtendedLab`). Existing resources log `[i] … already exists` and lab misconfigurations are re-applied.

**SQL:** Some subscriptions block new SQL in `eastus` — script tries fallback regions or `-SqlLocation westus2`. Use `-SkipSql` to omit SQL.

**Compute quota:** App Service (F1) and `-IncludeVm` need regional quota. Script tries `-Location` then fallbacks (`eastus`, `westus2`, …). Pin with `-ComputeLocation eastus`.

**Extended lab (`-IncludeExtendedLab`):** ACR Basic, Service Bus Basic, Cognitive **F0** (tries several kinds if quota blocks paid SKUs), Cosmos serverless — public access by design. Modest extra cost while running.

**Regions:** CLI uses lowercase slugs. **UK South** = `uksouth`. App Service / VM may land in a different region than storage (e.g. westus2) when quota requires it.

```powershell
.\Deploy-AzureReviewLab.ps1 -Location uksouth -SqlLocation uksouth -IncludeVm -IncludeExtendedLab
.\AzureCloudReviewv1.ps1 -SubscriptionId "<guid-from-manifest>" -RunProwler
.\Destroy-AzureReviewLab.ps1 -Force
```

### Deploy parameters

| Parameter | Description |
|-----------|-------------|
| `-ResourceGroupName` | Default: `rg-cloudreview-lab` |
| `-Location` | Region for storage, network, KV, extended lab. Default: `eastus` |
| `-SqlLocation` | SQL only; auto-fallback if blocked |
| `-ComputeLocation` | App Service + VM; auto-fallback on zero quota |
| `-SkipSql` | Skip SQL server |
| `-SkipAppService` | Skip App Service |
| `-SubscriptionId` | Target subscription |
| `-Prefix` | Resource name prefix (default: `crlab`) |
| `-IncludeVm` | Linux VM (B1s) with public IP |
| `-IncludeExtendedLab` | ACR, Service Bus, Cognitive, Cosmos (sections 4, 6, 15, 30) |

### Destroy parameters

| Parameter | Description |
|-----------|-------------|
| `-Force` | Skip confirmation |
| `-KeepManifest` | Keep `AzureReviewLab-manifest.json` |
| `-WaitTimeoutMinutes` | RG delete wait (default: 20) |

Destroy deletes the **entire resource group** (core + extended lab), purges soft-deleted Key Vaults and Cognitive Services accounts, and sweeps resources tagged `Purpose=CloudReviewLab`. Does **not** remove `NetworkWatcherRG` unless lab-tagged.

| Tier | Setup | What you exercise |
|------|-------|-------------------|
| 1 | Free account, no deploy | Entra, governance; many service sections SKIP |
| 2 | `Deploy-AzureReviewLab.ps1` | Storage, NSG, KV, SQL, App Service; `-IncludeVm`; `-IncludeExtendedLab` |
| 3 | Full engagement | AKS, Cosmos, etc.; Prowler as CIS baseline |

---

## Linux / Kali

Use **PowerShell 7+** (`pwsh`) for the review scripts and installers. Core review: **`AzureCloudReviewv1.ps1`** + **`az login`**. AD and WinBuild tracks remain Windows-only.

### Install PowerShell 7 (`pwsh`)

**Kali / Debian / Ubuntu** (if `powershell` is in your repos):

```bash
sudo apt update
sudo apt install -y powershell
pwsh --version
```

If the package is missing, use the [Microsoft PowerShell install guide for Linux](https://learn.microsoft.com/powershell/scripting/install/install-debian) (Debian/Ubuntu `.deb` repo, or direct `.tar.gz`).

### Install review tools

From the repo root:

```bash
cd /path/to/AD_WIN_AZURE_methandscripts
pwsh ./Install-AzureReviewTools.ps1 -InstallAll -AddToolsToUserPath
```

This checks or installs **`az`** (via `apt` or Microsoft script — may prompt for `sudo`), **`prowler`** / **`roadrecon`** (pip), and **`./tools/azurehound`** (Linux amd64/arm64 zip from GitHub). Re-open the shell or `export PATH="$PATH:$HOME/.local/bin:./tools"` if commands are not found.

Alternative: `sudo apt install azure-cli azurehound` on Kali when packages are available; ROADrecon/Prowler still via pip.

### Run the cloud review

```bash
az login
pwsh ./AzureCloudReviewv1.ps1
pwsh ./AzureCloudReviewv1.ps1 -SubscriptionId "<guid>" -RunProwler
```

Lab deploy/destroy: `pwsh ./Deploy-AzureReviewLab.ps1` · `pwsh ./Destroy-AzureReviewLab.ps1 -Force`

### AzureHound on Linux (section 35)

Auth and collection stay **two separate steps** — same OAuth client rules as Windows ([AzureHound (attack paths)](#azurehound-attack-paths)).

```bash
az login
pwsh ./Get-AzureHoundRefreshToken.ps1
# Complete device code at https://microsoft.com/devicelogin

pwsh ./Invoke-AzureHoundList.ps1
```

Optional single subscription: `pwsh ./Invoke-AzureHoundList.ps1 -SubscriptionId "$(az account show --query id -o tsv)"`.

Manual/fallback equivalent:

```bash
tenant=$(az account show --query tenantDefaultDomain -o tsv)
rt=$(cat ./tools/azurehound.refresh)
./tools/azurehound list -r "$rt" -t "$tenant" -o ./tools/azurehound.json
```

Ingest `./tools/azurehound.json` in **BloodHound CE** (Docker with Linux containers). ROADrecon: `pwsh ./Start-RoadreconAuth.ps1` then `pwsh ./Invoke-RoadreconGather.ps1` — separate auth from AzureHound.

---

## v1 limitations

Many checks are heuristic `REVIEW`; legacy `az ad` MFA signals may be incomplete; Front Door / ML / Synapse rows are inventory-heavy. Section bundles do not replace every granular workbook row — complete **MANUAL** items and use **Prowler CIS L1** as the authoritative CSPM baseline when in scope.

---

## Check statuses

Same definitions as the pack overview: [README.md — Check result statuses](README.md#check-result-statuses-all-scripts). Azure-specific: **`SKIP`** = resource type not deployed; **`INFO`** includes a successful Prowler run.

---

## Appendix A: methodology v7 — all 35 sections

Source: `Draft_Methodology_Azure_FINAL.xlsx`.

| # | Section |
|---|---------|
| 1 | Automation / Scanning / Tool Setup |
| 2 | Azure Entra ID |
| 3 | Azure Storage Accounts |
| 4 | AI Services |
| 5 | Azure Functions |
| 6 | Azure Cosmos DB |
| 7 | Network |
| 8 | AKS |
| 9 | API Management |
| 10 | Access Control |
| 11 | Activity Log |
| 12 | Advisor |
| 13 | App Service |
| 14 | Container Apps |
| 15 | Container Registry |
| 16 | Databricks |
| 17 | Front Door |
| 18 | Key Vault |
| 19 | Locks |
| 20 | Machine Learning |
| 21 | Monitor |
| 22 | MySQL |
| 23 | Policy |
| 24 | PostgreSQL |
| 25 | Recovery Services |
| 26 | Redis Cache |
| 27 | Resources |
| 28 | Search |
| 29 | Defender |
| 30 | Service Bus |
| 31 | SQL |
| 32 | Subscriptions |
| 33 | Synapse |
| 34 | Virtual Machines |
| 35 | Identity & Attack Path |

---

## Appendix B: script automation coverage by section

| # | Section | `AzureCloudReviewv1.ps1` coverage |
|---|---------|-----------------------------------|
| 1 | Automation | Optional **Prowler CIS 5.0 L1** with `-RunProwler` |
| 2 | Entra ID | Guests, security defaults, MFA, app registration, consent via Graph / `az rest` |
| 3 | Storage | HTTPS, public blob, network restrictions, Entra default auth |
| 4 | AI Services | Cognitive public network access |
| 5 | Functions | Remote debugging, HTTPS, managed identity |
| 6 | Cosmos DB | Public network access |
| 7 | Network | Permissive NSG, Network Watcher, NIC IP forwarding |
| 8 | AKS | Private cluster, Entra RBAC, public FQDN |
| 9 | API Management | Public network access |
| 10 | Access Control | Custom Owner-like roles |
| 11 | Activity Log | Activity alerts, service health alerts |
| 12 | Advisor | Security recommendation count |
| 13 | App Service | Remote debugging, auth, Key Vault refs |
| 14 | Container Apps | Public access, managed identity |
| 15 | Container Registry | Public access, private endpoints |
| 16 | Databricks | VNet injection (**REVIEW**) |
| 17 | Front Door | Profile inventory (**REVIEW**) |
| 18 | Key Vault | Soft delete, purge protection, RBAC, network ACLs |
| 19 | Locks | Subscription resource locks |
| 20 | Machine Learning | CMK signal (**REVIEW**) |
| 21 | Monitor | Diagnostic / activity log export |
| 22 | MySQL | In-transit encryption |
| 23 | Policy | Policy assignments |
| 24 | PostgreSQL | Entra admin, TLS / firewall |
| 25 | Recovery Services | Backup alerts |
| 26 | Redis Cache | In-transit encryption |
| 27 | Resources | Tagging |
| 28 | Search | Public access, managed identity |
| 29 | Defender | Assessments, alerts, external write roles |
| 30 | Service Bus | Public network access |
| 31 | SQL | TLS, Entra admin, firewall, auditing |
| 32 | Subscriptions | Owner count, UAA, budgets, policies |
| 33 | Synapse | TDE (**REVIEW**) |
| 34 | Virtual Machines | Public IPs, VMSS, JIT |
| 35 | Identity & Attack Path | Script: RBAC / SP counts via `az`. **Manual:** ROADrecon (Entra inventory + CA export), AzureHound → BloodHound (attack paths) |
