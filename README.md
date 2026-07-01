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
| **Windows build / host** | `WinBuildReview.ps1` | `Draft_Windows-Build-Review-Methodology_FINAL.xlsx` | 2.0.3 | OS services, patching, SMB, firewall, Defender, local GPO |
| **Azure / Entra cloud** | `AzureCloudReviewv1.ps1` | `Draft_Methodology_Azure_FINAL.xlsx` | 1.0.0 | Entra ID, Azure resources, RBAC, CIS-aligned cloud misconfigs |

| Track | Out of scope (use another track) |
|-------|----------------------------------|
| AD | DC OS hardening, SMB, patching, Nessus CIS OS scans |
| WinBuild | AD objects, trusts, delegation, Azure resources |
| Azure | On-prem AD object review, Windows Server CIS on the DC OS |

---

## External tools (summary)

| Tool | AD | WinBuild | Azure | Installed by |
|------|:--:|:--------:|:-----:|--------------|
| RSAT ActiveDirectory | Required | - | - | Windows feature |
| Azure CLI (`az`) | - | - | Required | winget / MSI |
| SharpHound | Optional | - | - | `Install-ADReviewTools.ps1` |
| PingCastle | Optional | - | - | `Install-ADReviewTools.ps1` |
| Purple Knight | Optional | - | - | Manual (Semperis) |
| Prowler | - | - | Optional | `Install-AzureReviewTools.ps1` |
| ROADrecon / AzureHound | - | - | Optional | `Install-AzureReviewTools.ps1` |
| BloodHound CE | Manual | - | Manual | Docker + bloodhound-cli |
| Microsoft Graph | Optional (`-IncludeEntra`) | - | Via `az rest` | AD: `-InstallGraphModule` |

**WinBuild has no third-party tools** — only native PowerShell, registry, and WMI.

| Tool | Auto-run flag |
|------|---------------|
| SharpHound (AD) | `-RunSharpHound` |
| PingCastle (AD) | `-RunPingCastle` |
| Purple Knight (AD) | `-RunPurpleKnight` |
| Prowler (Azure) | `-RunProwler` |

Without `-Run*`, AD and Azure scripts **detect** tools and emit **MANUAL** guidance. Use `-SkipExternalTools` (AD) or `-SkipIdentityTools` (Azure) to skip those rows.

Details: [AD_README.md — external tools](AD_README.md#external-tools) · [AZURE_README.md — installer & identity tools](AZURE_README.md#identity-tools-manual--methodology-section-35)

---

## Requirements at a glance

| Script | Python? | PowerShell | Typical host |
|--------|---------|------------|--------------|
| `ADReviewv1.ps1` | No | 5.1+ | Domain-joined workstation with RSAT, or DC |
| `WinBuildReview.ps1` | No | 5.1+ | Each in-scope server/DC (elevated recommended) |
| `AzureCloudReviewv1.ps1` | No for core review | 5.1+ or 7 on Linux | Host with `az login` |
| `Install-ADReviewTools.ps1` | No | 5.1+ | Windows with internet |
| `Install-AzureReviewTools.ps1` | Installs pip tools | 5.1+ | Windows 10/11 or Server 2016+ |
| `Deploy/Destroy-AzureReviewLab.ps1` | No | 5.1+ / pwsh | Same as Azure review |

**Prowler:** Python **3.10–3.12** only (not 3.14). **ROADrecon:** 3.10+.

Server **2008 / 2008 R2** are not WinBuild targets. ADReview can assess a legacy **domain** from a modern RSAT jump host.

---

## Repository layout

| File | Track |
|------|-------|
| `ADReviewv1.ps1`, `ADReview.Common.ps1`, `Install-ADReviewTools.ps1` | AD |
| `Draft_AD_Methodology_FINAL.xlsx` | AD |
| `WinBuildReview.ps1`, `WinBuildReview.Common.ps1`, `WinBuildReview.CisProfiles.ps1` | Build |
| `Draft_Windows-Build-Review-Methodology_FINAL.xlsx` | Build |
| `AzureCloudReviewv1.ps1`, `AzureCloudReview.Common.ps1`, `Install-AzureReviewTools.ps1` | Azure |
| `Deploy-AzureReviewLab.ps1`, `Destroy-AzureReviewLab.ps1` | Azure |
| `Get-AzureHoundRefreshToken.ps1` | Azure (AzureHound auth helper) |
| `Draft_Methodology_Azure_FINAL.xlsx` | Azure |
| `tools/` | Shared binaries (SharpHound, PingCastle, AzureHound) |
| `README.md` | This overview |
| `AD_README.md`, `WINBUILD_README.md`, `AZURE_README.md` | Per-track docs |

---

## Quick start

```powershell
cd C:\path\to\AD_WIN_AZURE_methandscripts

# AD
.\ADReviewv1.ps1

# Windows build (auto-detects Server 2012–2025 profile)
.\WinBuildReview.ps1

# Azure (after az login)
.\AzureCloudReviewv1.ps1
```

Install optional tooling:

```powershell
.\Install-ADReviewTools.ps1 -InstallAll -AddToolsToUserPath
.\Install-AzureReviewTools.ps1 -InstallAll -AddToolsToUserPath
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

Collectors: SharpHound (AD) or AzureHound (Azure) — see track READMEs. Azure auth is **two steps**: `Get-AzureHoundRefreshToken.ps1`, then `azurehound list` ([AZURE_README.md](AZURE_README.md#azurehound-attack-paths)).

---

## Supported platforms

| Scenario | ADReview | WinBuildReview | AzureCloudReview |
|----------|----------|----------------|------------------|
| Server 2025 DC | Yes (RSAT or on-DC) | Yes (profile 2025) | Yes (with az) |
| Server 2012 DC | Query from jump host | Yes (WMF 5.1 on 2012) | Use modern OS for az/Prowler |
| Server 2008 R2 host | Not recommended as runner | **Not supported** | **Not supported** |
| Legacy 2008 domain as **target** | Yes from modern RSAT host | N/A | N/A |

**Recommended split for legacy + cloud:**

| Machine | Run |
|---------|-----|
| 2012 DC | `ADReviewv1.ps1`, `WinBuildReview.ps1` |
| Windows 10/11 or Server 2016+ | `az login`, Azure review, Prowler, lab deploy |

---

## Recommended engagement workflow

1. **Scope** forests, hosts, subscriptions, hybrid Entra, ADCS.
2. **AD:** [AD_README.md](AD_README.md) — RSAT workstation; `-RunPingCastle` / `-RunSharpHound`; BloodHound CE for paths.
3. **Build:** [WINBUILD_README.md](WINBUILD_README.md) — on each server/DC; complete remaining CIS PDF controls manually.
4. **Azure:** [AZURE_README.md](AZURE_README.md) — `az login` → review (optional `-RunProwler`); section 35: ROADrecon + AzureHound/BloodHound (separate auth steps).
5. **Triage** CSV `FAIL` / `REVIEW` rows against the matching methodology workbook.

---

## Version history

| Component | Version | Notes |
|-----------|---------|--------|
| AD methodology | **FINAL** (`Draft_AD_Methodology_FINAL.xlsx`) | AD-only; ~110 checks |
| `ADReviewv1.ps1` | **1.0.5** | SharpHound, PingCastle, Purple Knight, `-PingCastleServer` |
| `Install-ADReviewTools.ps1` | **1.0.0** | SharpHound + PingCastle |
| WinBuild methodology | **FINAL** (`Draft_Windows-Build-Review-Methodology_FINAL.xlsx`) | CIS-oriented, role split |
| `WinBuildReview.ps1` | **2.0.3** | `-CisBaselineOnly`, `-StrictCis` |
| Azure methodology | **FINAL** (`Draft_Methodology_Azure_FINAL.xlsx`) | ~89 checks, 35 sections |
| `AzureCloudReviewv1.ps1` | **1.0.0** | az CLI + optional Prowler |
| `Install-AzureReviewTools.ps1` | **1.0.0** | az, pip tools, AzureHound |
| `Get-AzureHoundRefreshToken.ps1` | — | AzureHound device-code auth (writes `tools\azurehound.refresh`) |
| Lab deploy | **1.0.0** | Tier 2 lab, `-IncludeExtendedLab` |
| Lab destroy | **1.0.2** | RG delete + KV/Cognitive purge + tag sweep |

---

## Quick reference

```powershell
.\Install-ADReviewTools.ps1 -InstallAll -AddToolsToUserPath
.\ADReviewv1.ps1 -RunSharpHound -RunPingCastle

.\WinBuildReview.ps1 -CisBaselineOnly -StrictCis

.\Install-AzureReviewTools.ps1 -InstallAll -AddToolsToUserPath
az login
.\Get-AzureHoundRefreshToken.ps1
azurehound list -r (Get-Content .\tools\azurehound.refresh -Raw) -t (az account show --query tenantDefaultDomain -o tsv) -o .\tools\azurehound.json
.\Deploy-AzureReviewLab.ps1 -IncludeExtendedLab
.\AzureCloudReviewv1.ps1 -SubscriptionId "<guid>" -RunProwler
.\Destroy-AzureReviewLab.ps1 -Force
```

See **[AD_README.md](AD_README.md)**, **[WINBUILD_README.md](WINBUILD_README.md)**, and **[AZURE_README.md](AZURE_README.md)** for full detail.
