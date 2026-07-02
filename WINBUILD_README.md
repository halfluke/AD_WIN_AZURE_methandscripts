# Windows build review

Pentester-focused **local OS hardening** automation aligned to `Draft_Windows-Build-Review-Methodology_FINAL.xlsx` (~67 workbook rows; ~61 script checks; CIS-oriented). For AD object review use [AD_README.md](AD_README.md). For Azure cloud use [AZURE_README.md](AZURE_README.md). Pack overview: [README.md](README.md).

| Item | Value |
|------|--------|
| Script | `WinBuildReview.ps1` (**v2.0.6**) |
| Shared | `WinBuildReview.Common.ps1`, `WinBuildReview.CisProfiles.ps1`, `WinBuildReview.PrivEscDeep.ps1` |
| Installer | `Install-WinBuildReviewTools.ps1` (optional winPEAS) |
| Workbook | `Draft_Windows-Build-Review-Methodology_FINAL.xlsx` |

**Scope:** OS services, patching signals, SMB, firewall, Defender, local GPO on **member servers and DCs** (on-prem or **Azure VMs**). **No** AD object checks, **no** Azure subscription checks. Optional **winPEAS** for deep local privesc enumeration (`-RunWinPeas`).

**Platform:** **Windows only** — run elevated on **each** in-scope host.

Workbook columns match the pack-wide **13-column** schema (see [README.md](README.md#repository-layout)); CIS benchmark versions per OS are preserved in **Notes** (`[CIS Refs]: …`).

**Workbook vs runner:** ~67 workbook rows vs ~61 script checks (closest alignment of the three tracks). Triage by **Title → column F**; complete remaining controls from the CIS PDF where the script emits `REVIEW` / `MANUAL`. See [README.md — Workbook vs runner](README.md#workbook-vs-runner-all-tracks).

---

## Requirements

- PowerShell **5.1+**
- Administrator recommended
- **Supported OS profiles:** 2012, 2012R2, 2016, 2019, 2022, 2025 (CIS-mapped)
- **Not supported:** Server 2008 / 2008 R2 as review targets

| Profile | CIS benchmark (L1 MS unless noted) |
|---------|-------------------------------------|
| 2012 | Windows Server 2012 v3.0.0 |
| 2012R2 | Windows Server 2012 R2 v3.0.0 |
| 2016 | Windows Server 2016 v4.0.0 MS |
| 2019 | Windows Server 2019 v5.0.0 MS |
| 2022 | Windows Server 2022 v5.0.0 MS |
| 2025 | Windows Server 2025 v2.0.0 MS |

---

## Quick start

```powershell
cd C:\path\to\AD_WIN_AZURE_methandscripts
.\Install-WinBuildReviewTools.ps1 -InstallAll -AddToolsToUserPath   # optional winPEAS
.\WinBuildReview.ps1
.\WinBuildReview.ps1 -RunWinPeas
.\WinBuildReview.ps1 -CisBaselineOnly -StrictCis   # lab smoke test (skips privesc/winPEAS blocks)
.\WinBuildReview.ps1 -OsProfile 2025
```

Run **on each in-scope server/DC**, elevated where possible.

![Install WinBuild tools (winPEAS + parsers)](WinBuildInstall.gif)

![Run WinBuildReview.ps1 — build review](WinBuildRun.gif)

![Run WinBuildReview.ps1 with winPEAS (-RunWinPeas)](WinBuildRun2.gif)

---

## Parameters

| Parameter | Description |
|-----------|-------------|
| `-OutputPath` | Report directory |
| `-OsProfile` | Override auto-detect (`2012`, `2012R2`, `2016`, `2019`, `2022`, `2025`) |
| `-CisBaselineOnly` | CIS + role checks only; skip pentest/hygiene REVIEW rows (incl. native deep privesc + winPEAS) |
| `-StrictCis` | Promote ambiguous CIS gaps from REVIEW to FAIL |
| `-RunWinPeas` | Run winPEAS when installed; writes `winpeas-<host>-<timestamp>.out` under `-OutputPath`. **Run from a standard-user session** for realistic privesc triage (see [Deep local privesc](#deep-local-privesc-full-run)). |
| `-WinPeasProfile` | `Focused` (default) or `Full` — both skip slow **eventsinfo** / file crawls |
| `-SkipExternalTools` | Skip winPEAS automation row only |

With `-RunWinPeas`, winPEAS runs with the **quiet** flag (findings + section output; suppresses banner/progress noise), streaming to the **console** and a timestamped **`.out`** file. If PEASS parsers are installed (`-InstallAll`), the script also runs **peas2json**, **json2html**, and **json2pdf** → matching `winpeas-<host>-<timestamp>.json`, `.html`, `.pdf` in `-OutputPath` (PDF has a 10-minute timeout on large reports). Prior runs are kept (no overwrite).

Use `-CisBaselineOnly` for lab CIS runs; add `-StrictCis` for a short smoke test. Use a **full run** (no `-CisBaselineOnly`) for local privesc signal + optional `-RunWinPeas`.

---

## Deep local privesc (full run)

On a default full run (not `-CisBaselineOnly`), the script includes **native deep privesc checks** in **PRIVILEGE ESCALATION**:

| Check | What it looks for |
|-------|-------------------|
| AlwaysInstallElevated | MSI install elevation for low-priv users |
| Token impersonation privileges | Enabled `SeImpersonate`, `SeAssignPrimaryToken`, `SeDebug`, etc. |
| Writable service binaries | Running services whose `.exe` is writable by low-priv principals |
| Service DACL permissions | `sc sdshow` signals for Users/Authenticated Users/Everyone modify rights |
| Writable PATH entries | DLL hijack candidates in Machine/User `PATH` |
| (existing) | Unquoted paths, modifiable service registry keys, weak ACLs, hotfix/CVE correlation |

Optional **winPEAS** (`Install-WinBuildReviewTools.ps1 -InstallAll`, `-RunWinPeas`) adds broader enumeration. Default **Focused** profile skips event-log trawls (e.g. winlogon history) and file crawls; use `-WinPeasProfile Full` for network/browser/cloud modules.

### Running context: admin vs standard user

| Goal | Recommended account |
|------|---------------------|
| CIS / build hardening (most of `WinBuildReview.ps1`) | **Administrator** (elevated) |
| **winPEAS** privesc triage | **Standard user** (non-admin) |

**Yes — for actual privilege-escalation assessment, run winPEAS as a standard user**, not from an elevated admin session. winPEAS reports what the **current token** can see and exploit; as admin you already hold high privileges, so results reflect the wrong attack path and can **miss** vectors that matter to a compromised low-priv account (token privileges, writable paths, service abuse visible only from that context).

**Practical workflow:**

1. Run the full build review **elevated** (CIS, services, firewall, native privesc config checks).
2. Run **winPEAS separately as a standard user** — either a second pass with `-RunWinPeas` only, or invoke winPEAS manually from `.\tools` — and use a distinct `-OutputPath` so reports do not overwrite each other.

```powershell
# 1) Hardening + native privesc config (elevated)
.\WinBuildReview.ps1 -OutputPath C:\Reviews\Build-elevated

# 2) winPEAS privesc triage (standard user — open non-elevated PowerShell)
.\WinBuildReview.ps1 -RunWinPeas -OutputPath C:\Reviews\Build-privesc-user
# or: .\tools\winPEASx64.exe quiet ...  # save console output to winpeas-<host>-<timestamp>.out manually
```

Native **PRIVILEGE ESCALATION** rows in the script still help when run elevated (they flag misconfigurations such as AlwaysInstallElevated or weak service ACLs). winPEAS is the check most sensitive to **session context** — treat elevated vs standard-user runs as complementary, not interchangeable.

```powershell
.\Install-WinBuildReviewTools.ps1 -InstallAll -AddToolsToUserPath
.\WinBuildReview.ps1 -RunWinPeas   # prefer standard-user session; see above
```

This is **host-local privesc triage**, not AD/cloud attack-path mapping (use ADReview + BloodHound or Azure/AzureHound for those).

---

## Tool installer (`Install-WinBuildReviewTools.ps1`)

```powershell
.\Install-WinBuildReviewTools.ps1                         # check vs latest GitHub release
.\Install-WinBuildReviewTools.ps1 -InstallAll -AddToolsToUserPath
.\Install-WinBuildReviewTools.ps1 -Upgrade                # update if newer or tag unknown
```

| Switch | Action |
|--------|--------|
| `-InstallAll` | Download winPEAS + PEASS parsers (`.\tools\parsers`) when missing |
| `-Upgrade` | Download when missing, tag unknown, or newer release available; skips if already at latest |
| `-AddToolsToUserPath` | Append `.\tools` to user PATH |

`-InstallAll` also installs **peas2json.py** / **peas2json.ps1**, **json2html.ps1**, **json2pdf.py** under `.\tools\parsers` and `reportlab` via pip when Python is available (PDF output). JSON conversion prefers **peas2json.py** when Python is present.

Release tags stored in `.\tools\winpeas.release` and `.\tools\parsers\parsers.release`. Check-only mode shows **UPDATE** when a newer release exists.

---

## Outputs

| File | Content |
|------|---------|
| `BuildReview-<host>-<timestamp>.txt` | Evidence log |
| `BuildReview-<host>-<timestamp>.csv` | Includes OsProfile, CisBenchmark, CisRef |
| `BuildReview-<host>-<timestamp>.html` | Summary table |
| `winpeas-<host>-<timestamp>.out` | Raw winPEAS log (with `-RunWinPeas`) |
| `winpeas-<host>-<timestamp>.json` / `.html` / `.pdf` | Parsed winPEAS reports when parsers installed (same timestamp as `.out`) |

---

## Limitations (v2)

Password policy, patch posture, and full CIS PDF pass remain `REVIEW` / `MANUAL` by design. Complete remaining controls from the matching CIS PDF on [CIS Workbench](https://www.cisecurity.org/cis-benchmarks) and triage CSV rows against the workbook by **Title → column F** ([README.md — Workbook vs runner](README.md#workbook-vs-runner-all-tracks)).

---

## Check statuses

Same definitions as the pack overview: [README.md — Check result statuses](README.md#check-result-statuses-all-scripts). WinBuild-specific: **`SKIP`** = control N/A for this OS profile or role.

---
