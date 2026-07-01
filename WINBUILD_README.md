# Windows build review

Pentester-focused **local OS hardening** automation aligned to `Draft_Windows-Build-Review-Methodology_FINAL.xlsx` (CIS-oriented). For AD object review use [AD_README.md](AD_README.md). For Azure cloud use [AZURE_README.md](AZURE_README.md). Pack overview: [README.md](README.md).

| Item | Value |
|------|--------|
| Script | `WinBuildReview.ps1` (**v2.0.3**) |
| Shared | `WinBuildReview.Common.ps1`, `WinBuildReview.CisProfiles.ps1` |
| Workbook | `Draft_Windows-Build-Review-Methodology_FINAL.xlsx` |

**Scope:** OS services, patching signals, SMB, firewall, Defender, local GPO on **member servers and DCs**. **No** AD object checks, **no** Azure checks, **no** external tools.

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
.\WinBuildReview.ps1
.\WinBuildReview.ps1 -CisBaselineOnly -StrictCis   # lab smoke test
.\WinBuildReview.ps1 -OsProfile 2025
```

Run **on each in-scope server/DC**, elevated where possible.

### Demo

![Run WinBuildReview.ps1 on a server](WinBuildRun.gif)

---

## Parameters

| Parameter | Description |
|-----------|-------------|
| `-OutputPath` | Report directory |
| `-OsProfile` | Override auto-detect (`2012`, `2012R2`, `2016`, `2019`, `2022`, `2025`) |
| `-CisBaselineOnly` | CIS + role checks only; skip pentest/hygiene REVIEW rows |
| `-StrictCis` | Promote ambiguous CIS gaps from REVIEW to FAIL |

Use `-CisBaselineOnly` for lab runs; add `-StrictCis` for a short smoke test.

---

## Outputs

| File | Content |
|------|---------|
| `BuildReview-<host>-<timestamp>.txt` | Evidence log |
| `BuildReview-<host>-<timestamp>.csv` | Includes OsProfile, CisBenchmark, CisRef |
| `BuildReview-<host>-<timestamp>.html` | Summary table |

---

## Limitations (v2)

Password policy, patch posture, and full CIS PDF pass remain `REVIEW` / `MANUAL` by design. Complete remaining controls from the matching CIS PDF on [CIS Workbench](https://www.cisecurity.org/cis-benchmarks).

---

## Check statuses

Same definitions as the pack overview: [README.md — Check result statuses](README.md#check-result-statuses-all-scripts). WinBuild-specific: **`SKIP`** = control N/A for this OS profile or role.

---
