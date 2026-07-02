# AD, Windows Build, and Azure Cloud Review Pack

Pentester-focused assessment pack with **three separate tracks**. Each track has a finalized Excel methodology workbook and a PowerShell runner. The tracks are **deliberately scoped apart** so AD object review, host OS hardening, and cloud controls are not mixed.

**Track documentation:**

| Track | README |
|-------|--------|
| Active Directory | **[AD_README.md](AD_README.md)** |
| Windows build / host OS | **[WINBUILD_README.md](WINBUILD_README.md)** |
| Azure / Entra cloud | **[AZURE_README.md](AZURE_README.md)** |

---

## Choose your track

| Track | Script | Methodology workbook | Version | Scope |
|-------|--------|----------------------|---------|--------|
| **Active Directory** | `ADReviewv1.ps1` | `Draft_AD_Methodology_FINAL.xlsx` | 1.0.5 | AD objects, domain/forest policy, trusts, delegation, ADCS posture, hybrid Entra |
| **Windows build / host** | `WinBuildReview.ps1` | `Draft_Windows-Build-Review-Methodology_FINAL.xlsx` | 2.0.6 | OS services, patching, SMB, firewall, Defender, local GPO, local privesc |
| **Azure / Entra cloud** | `AzureCloudReviewv1.ps1` | `Draft_Methodology_Azure_FINAL.xlsx` | 1.0.0 | Entra ID, Azure resources, RBAC, CIS-aligned cloud misconfigs |

| Track | Out of scope (use another track) |
|-------|----------------------------------|
| AD | DC OS hardening, SMB, patching, Nessus CIS OS scans |
| WinBuild | AD objects, trusts, delegation, Azure resources |
| Azure | Cloud / Entra subscription review — use **AD track** for AD DS domains (including DCs on Azure VMs); use **WinBuild** for server OS on Azure VMs |

---

## External tools (summary)

| Tool | AD | WinBuild | Azure | Installed by |
|------|:--:|:--------:|:-----:|--------------|
| RSAT ActiveDirectory | Required | - | - | Windows feature |
| Azure CLI (`az`) | - | - | Required | winget / MSI (Windows) · apt / Microsoft script (Linux) |
| SharpHound | Optional | - | - | `Install-ADReviewTools.ps1` |
| PingCastle | Optional | - | - | `Install-ADReviewTools.ps1` |
| Purple Knight | Optional | - | - | Manual (Semperis) |
| winPEAS | - | Optional | - | `Install-WinBuildReviewTools.ps1` |
| Prowler | - | - | Optional | `Install-AzureReviewTools.ps1` |
| ROADrecon / AzureHound | - | - | Optional | `Install-AzureReviewTools.ps1` |
| BloodHound CE | Manual | - | Manual | Docker + bloodhound-cli |
| Microsoft Graph | Optional (`-IncludeEntra`) | - | Via `az rest` | AD: `-InstallGraphModule` |

**WinBuild has no third-party tools required** — CIS checks use native PowerShell; optional **winPEAS** via `Install-WinBuildReviewTools.ps1`.

**WinBuild optional tools:** winPEAS + PEASS parsers (`Install-WinBuildReviewTools.ps1 -InstallAll`) — native script checks cover common privesc signals without them.

| Tool | Auto-run flag |
|------|---------------|
| SharpHound (AD) | `-RunSharpHound` |
| PingCastle (AD) | `-RunPingCastle` |
| Purple Knight (AD) | `-RunPurpleKnight` |
| winPEAS (WinBuild) | `-RunWinPeas` |
| Prowler (Azure) | `-RunProwler` |

Without `-Run*`, AD and Azure scripts **detect** tools and emit **MANUAL** guidance. WinBuild emits **MANUAL** for winPEAS unless `-RunWinPeas`. Use `-SkipExternalTools` (AD/WinBuild) or `-SkipIdentityTools` (Azure) to skip those rows.

**Tool upgrades:** `-Upgrade` on each track installer skips re-download when the release tag already matches GitHub latest — **winPEAS** (`Install-WinBuildReviewTools.ps1 -Upgrade`; first install `-InstallAll`); **SharpHound/PingCastle** (`Install-ADReviewTools.ps1 -InstallAll -Upgrade`); **Azure** pip via `-InstallPythonTools -Upgrade`, **AzureHound** via `-InstallAzureHound -Upgrade` (release tag in `.\tools\azurehound.release`).

Details: [AD_README.md — external tools](AD_README.md#external-tools) · [AZURE_README.md — installer & identity tools](AZURE_README.md#identity-tools-manual--methodology-section-35)

---

## Requirements at a glance

| Script | Python? | PowerShell | Typical host |
|--------|---------|------------|--------------|
| `ADReviewv1.ps1` | No | 5.1+ | Domain-joined workstation with RSAT, or DC |
| `WinBuildReview.ps1` | No | 5.1+ | Each in-scope server/DC (elevated recommended) |
| `AzureCloudReviewv1.ps1` | No for core review | 5.1+ or 7 on Linux | Host with `az login` |
| `Install-ADReviewTools.ps1` | No | 5.1+ | Windows with internet |
| `Install-AzureReviewTools.ps1` | Installs pip tools | 5.1+ (Windows) or **7+ pwsh** (Linux/macOS) | Windows, Linux, or macOS with network |
| `Deploy-AzureReviewLab.ps1`, `Destroy-AzureReviewLab.ps1` | No | 5.1+ / pwsh | Same as Azure review |

**Prowler:** Python **3.10–3.12** only (not 3.14). **ROADrecon:** 3.10+.

Server **2008 / 2008 R2** are not WinBuild targets. ADReview can assess a legacy **domain** from a modern RSAT jump host.

---

## Repository layout

| File | Track |
|------|-------|
| `ADReviewv1.ps1`, `ADReview.Common.ps1`, `Install-ADReviewTools.ps1` | AD |
| `Draft_AD_Methodology_FINAL.xlsx` | AD |
| `WinBuildReview.ps1`, `WinBuildReview.Common.ps1`, `WinBuildReview.CisProfiles.ps1`, `WinBuildReview.PrivEscDeep.ps1` | Build |
| `Install-WinBuildReviewTools.ps1` | Build (optional winPEAS) |
| `Draft_Windows-Build-Review-Methodology_FINAL.xlsx` | Build |
| `AzureCloudReviewv1.ps1`, `AzureCloudReview.Common.ps1`, `Install-AzureReviewTools.ps1` | Azure |
| `Deploy-AzureReviewLab.ps1`, `Destroy-AzureReviewLab.ps1` | Azure |
| `Get-AzureHoundRefreshToken.ps1` | Azure (AzureHound auth helper) |
| `Draft_Methodology_Azure_FINAL.xlsx` | Azure |
| `tools/` | Shared binaries (SharpHound, PingCastle, AzureHound — `.exe` on Windows, plain binary on Linux) |
| `README.md` | This overview |
| `AD_README.md`, `WINBUILD_README.md`, `AZURE_README.md` | Per-track docs (each embeds a demo `.gif`) |
| `ADTools.gif`, `ADrun.gif` | AD track demos → [AD_README.md](AD_README.md) |
| `WinBuildInstall.gif`, `WinBuildRun.gif`, `WinBuildRun2.gif` | Build track demos → [WINBUILD_README.md](WINBUILD_README.md) |
| `AzureTools.gif`, `AzureRun.gif` | Azure track demos → [AZURE_README.md](AZURE_README.md) |

**Methodology workbooks** (`Draft_*_FINAL.xlsx`) share one header row (bold): Type, Scope, Executor, Executed, Comments, Title, Description, Tooling, Commands/Guidance, Mitre Technique, **Policy** (empty in generic files), Written Issues, Notes. Client-specific methodology copies (gitignored) may use a separate policy column when populated.

### Workbook vs runner (all tracks)

The **`.xlsx` is the full engagement checklist** (every control + MITRE column J). Each **PowerShell runner** produces a passive first pass (`PASS` / `FAIL` / `REVIEW` / `MANUAL` / `SKIP`) — triage output, not a row-for-row substitute for sign-off.

| Track | Workbook rows (approx.) | Script titles emitted (approx.) | Notes |
|-------|-------------------------|----------------------------------|-------|
| AD | ~129 (~110 in-scope in workbook) | ~50 | Many ADCS / GPO / Entra rows stay MANUAL; match CSV **Title** → column F |
| WinBuild | ~67 | ~61 | Closest alignment; finish CIS PDF gaps from workbook |
| Azure | ~91 | ~57 | Workbook = granular CIS rows; script often **bundles by section** (e.g. §34 VMs); optional `-RunProwler` for CIS L1 depth |

**Triage:** map each CSV row to the workbook by **Title (column F)**, then MITRE — not by row number. Title strings often differ from the workbook; workbook-only rows are expected.

---

## Quick start

```powershell
cd C:\path\to\AD_WIN_AZURE_methandscripts

# AD
.\ADReviewv1.ps1

# Windows build (auto-detects Server 2012–2025 profile)
.\WinBuildReview.ps1

# Azure (after az login — Windows or pwsh on Linux)
.\AzureCloudReviewv1.ps1
# Linux: pwsh ./AzureCloudReviewv1.ps1  (see AZURE_README.md)
```

Install optional tooling:

```powershell
.\Install-ADReviewTools.ps1 -InstallAll -AddToolsToUserPath
.\Install-AzureReviewTools.ps1 -InstallAll -AddToolsToUserPath   # Windows
# pwsh ./Install-AzureReviewTools.ps1 -InstallAll -AddToolsToUserPath   # Linux/macOS
az login
```

With external tools:

```powershell
.\ADReviewv1.ps1 -RunSharpHound -RunPingCastle
.\AzureCloudReviewv1.ps1 -SubscriptionId "<guid>" -RunProwler
```

Full parameter lists and lab deploy: see track READMEs above.

---

## Check result statuses (all scripts)

| Status | Meaning |
|--------|---------|
| `PASS` | Automated signal looks compliant |
| `FAIL` | Automated signal indicates misconfiguration |
| `REVIEW` | Data captured; analyst judgement required |
| `SKIP` | Precondition not met (wrong role, service not deployed, OS control N/A) |
| `MANUAL` | External tool or portal step documented |
| `ERROR` | Command or permission failure |
| `INFO` | Informational only |

Treat output as **triage**, not a final audit verdict.

---

## BloodHound CE (AD and Azure collectors)

BloodHound **CE** is not installed by either installer and is **not used by WinBuildReview**. It is the **analysis GUI** for SharpHound (AD) or AzureHound (Azure) collector zips.

Install: [Community Edition quickstart](https://bloodhound.specterops.io/get-started/quickstart/community-edition-quickstart) — **Docker Desktop** (must use **Linux containers**, not Windows containers) + **[bloodhound-cli](https://github.com/SpecterOps/bloodhound-cli/releases/latest)**.

```powershell
.\bloodhound-cli install
# UI: http://localhost:8080/ui/login
```

If install fails with `no matching manifest for windows(...)/amd64`, switch Docker Desktop to Linux containers (tray icon → **Switch to Linux containers…**), then retry.

Collectors: SharpHound (AD) or AzureHound (Azure) — see track READMEs. Azure auth is **two steps**: `Get-AzureHoundRefreshToken.ps1` (Azure PowerShell client token), then `azurehound list` — **do not** reuse ROADrecon’s `.roadtools_auth` ([AZURE_README.md](AZURE_README.md#azurehound-attack-paths)).

---

## Supported platforms

| Scenario | ADReview | WinBuildReview | AzureCloudReview |
|----------|----------|----------------|------------------|
| Server 2025 DC | Yes (RSAT or on-DC) | Yes (profile 2025) | Yes (with az) |
| Server 2012 DC | Query from jump host | Yes (WMF 5.1 on 2012) | Use modern OS for az/Prowler |
| AD DS on **Azure VMs** | Yes (RSAT/jump with DC reachability) | Yes (on each VM/DC) | Yes (subscription + Entra) |
| Server 2008 R2 host | Not recommended as runner | **Not supported** | **Not supported** |
| Legacy 2008 domain as **target** | Yes from modern RSAT host | N/A | N/A |
| **Linux / Kali** | **No** (RSAT Windows-only) | **No** | **Yes** (`pwsh` + `az`) — [AZURE_README.md — Linux / Kali](AZURE_README.md#linux--kali) |

### Deployment model (which tracks to run)

| Deployment | Run |
|------------|-----|
| **Cloud-first** (Entra + Azure; no AD DS domain) | Azure (+ WinBuild on Azure IaaS VMs if OS review in scope) |
| **Cloud with AD DS** (e.g. DCs on Azure VMs) | AD + WinBuild on those hosts **and** Azure subscription review |
| **On-prem only** (no Azure in scope) | AD + WinBuild — **no** `AzureCloudReviewv1.ps1` |
| **Hybrid** | All three per scope; AD `-IncludeEntra`; Azure §35 ROADrecon + AzureHound (separate auth) |

---

## Recommended engagement workflow

1. **Scope** forests, hosts, subscriptions, hybrid Entra, ADCS.
2. **AD:** [AD_README.md](AD_README.md) — RSAT workstation; `-RunPingCastle` / `-RunSharpHound`; BloodHound CE for paths.
3. **Build:** [WINBUILD_README.md](WINBUILD_README.md) — on each server/DC; complete remaining CIS PDF controls manually.
4. **Azure:** [AZURE_README.md](AZURE_README.md) — `az login` → review (optional `-RunProwler`); section 35: ROADrecon + AzureHound/BloodHound (separate auth steps).
5. **Triage** CSV rows against the matching workbook — match **Title** to column F (+ MITRE); complete **MANUAL** rows (portal, CIS PDF, BloodHound ingest, §35 tools).

---

## Version history

| Component | Version | Notes |
|-----------|---------|--------|
| AD methodology | **FINAL** (`Draft_AD_Methodology_FINAL.xlsx`) | ~129 workbook rows (~110 in-scope); ~50 script checks |
| `ADReviewv1.ps1` | **1.0.5** | SharpHound, PingCastle, Purple Knight, `-PingCastleServer` |
| `Install-ADReviewTools.ps1` | **1.0.0** | SharpHound + PingCastle (Windows) |
| WinBuild methodology | **FINAL** (`Draft_Windows-Build-Review-Methodology_FINAL.xlsx`) | ~67 workbook rows; ~61 script checks |
| `WinBuildReview.ps1` | **2.0.6** | Native deep privesc checks; optional `-RunWinPeas` → timestamped winpeas `.out` + JSON/HTML/PDF when parsers installed |
| `Install-WinBuildReviewTools.ps1` | **1.1.0** | winPEAS + PEASS parsers (Windows) |
| Azure methodology | **FINAL** (`Draft_Methodology_Azure_FINAL.xlsx`) | ~91 workbook rows, 35 sections; ~57 script checks |
| `AzureCloudReviewv1.ps1` | **1.0.0** | az CLI + optional Prowler |
| `Install-AzureReviewTools.ps1` | **1.0.0** | az, pip tools, AzureHound (Windows; Linux/macOS via `pwsh`) |
| `Get-AzureHoundRefreshToken.ps1` | — | AzureHound device-code auth → `./tools/azurehound.refresh` |
| Lab deploy | **1.0.0** | Tier 2 lab, `-IncludeExtendedLab` |
| Lab destroy | **1.0.2** | RG delete + KV/Cognitive purge + tag sweep |

---

## Quick reference

```powershell
.\Install-ADReviewTools.ps1 -InstallAll -AddToolsToUserPath
.\ADReviewv1.ps1 -RunSharpHound -RunPingCastle

.\WinBuildReview.ps1 -CisBaselineOnly -StrictCis
.\Install-WinBuildReviewTools.ps1 -InstallAll -AddToolsToUserPath
.\WinBuildReview.ps1 -RunWinPeas

.\Install-AzureReviewTools.ps1 -InstallAll -AddToolsToUserPath
# Linux: pwsh ./Install-AzureReviewTools.ps1 -InstallAll -AddToolsToUserPath
az login
.\Get-AzureHoundRefreshToken.ps1
# Linux: pwsh ./Get-AzureHoundRefreshToken.ps1
# Windows PowerShell — on Linux use bash from AZURE_README.md (Linux / Kali):
azurehound list -r (Get-Content ./tools/azurehound.refresh -Raw) -t (az account show --query tenantDefaultDomain -o tsv) -o ./tools/azurehound.json
.\Deploy-AzureReviewLab.ps1 -IncludeExtendedLab
.\AzureCloudReviewv1.ps1 -SubscriptionId "<guid>" -RunProwler
.\Destroy-AzureReviewLab.ps1 -Force
```

See **[AD_README.md](AD_README.md)**, **[WINBUILD_README.md](WINBUILD_README.md)**, and **[AZURE_README.md](AZURE_README.md)** for full detail.
