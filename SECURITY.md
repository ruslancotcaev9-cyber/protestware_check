# Security Policy

The following policy applies to security vulnerabilities **in protestware-check itself** (including its CLI, parsers, repository ingestion, report generation and update/dependency handling). Findings *about packages being scanned* are not vulnerabilities in the scanner; report those to the affected upstream maintainers through their security channels.

This policy is informed by the coordinated disclosure workflow used in Google's open-source projects, notably [google/capsem](https://github.com/google/capsem/security/policy), but **this project is not affiliated with Google** and uses no Google reporting endpoint or promised Google response times.

## Supported versions

| Version | Security fixes |
| --- | --- |
| Current `main` (development line: 1.3.x, unreleased) | Supported on a best-effort basis |
| Older versions | No guaranteed backports; please upgrade |

The maintainers may change the supported release line as new versions are published. This is a community-maintained project; there is no contractual service-level agreement.

Known detection gaps and dated validation evidence are recorded in the
[technical reference](docs/TECHNICAL_REFERENCE.md) and
[evaluation report](docs/EVALUATION_2026-11-11.md). They do not establish a published
release or complete detection coverage.

## Reporting a vulnerability privately

1. **If private vulnerability reporting has been enabled**, open **[Security → Report a vulnerability](https://github.com/ruslancotcaev9-cyber/protestware_check/security/advisories/new)**. GitHub's private reporting feature must be *explicitly enabled* by repository administrators; the presence of this link or this file alone does not enable it.
2. **Until then, or if the reporting form is unavailable**, ask the maintainers for a private security contact through their GitHub profile or a minimal GitHub issue containing **no vulnerability details, exploit, payload, sensitive path or secret**. Move the report to a mutually agreed private channel before sharing details. For private repository collaborators, a maintainer can initiate a **draft GitHub Security Advisory**.
3. Do **not** open a public issue or pull request containing actionable exploitation details. Do not test vulnerabilities against systems or accounts you do not own or have authorization to assess.

When sending a private report, include (where possible): affected version/commit, prerequisites, impact and potential exploitability, exact safe reproduction steps using inert/minimal input, evidence with sensitive information removed, relevant logs, and any proposed mitigation. Never include real access tokens, personal data or third-party exploit traffic.

## Maintainer response and remediation

These are **best-effort targets, not guarantees**; time may depend on severity, reproducibility, maintainer availability and external dependencies.

| Stage | Intended action | Target |
| --- | --- | --- |
| Acknowledge | Confirm private receipt and establish a follow-up channel | Within 7 calendar days |
| Triage | Reproduce safely, identify affected versions, classify severity and exploitability | Initial assessment within 14 calendar days |
| Containment | Recommend a workaround, feature switch, update or temporary mitigation when feasible | As soon as practical for urgent reports |
| Remediation | Create a private fix, add regression tests, review it and prepare a security release | Plan or mitigation for confirmed high-severity issues ideally within 90 calendar days |
| Coordinated disclosure | Publish a GitHub Security Advisory and release notes when users can reasonably mitigate; request a CVE when appropriate | Coordinated with reporter; no automatic disclosure deadline |

Maintainers should preserve a minimal private investigation record (report, affected commits/versions, severity rationale, fix review, tests and notification decision). Where a reporter consents, the public advisory may credit them. Retest the fix on supported Python versions and supported input formats, and do not execute untrusted sample code as part of verification.

## Threats in scope

Examples include: arbitrary execution caused by scanning source files; uncontrolled deletion/writes outside requested output; SSRF through repository, package or watchlist metadata; path traversal or symlink escape; malicious archive/manifest processing; credential disclosure in reports or logs; denial of service caused by unbounded input; dependency or update integrity compromise; and a security-relevant false-negative bypass supported by a convincing, reproducible attack scenario.

Ordinary inaccuracies in heuristic scores, contentious classifications in third-party lists, and general feature requests should normally be filed as non-security issues unless accompanied by a concrete security impact.

## Security guarantees and operational guidance

The tool is a **static triage analyzer, not a malware sandbox**. It does not run code from scanned repositories. It may connect to explicitly selected GitHub and registry endpoints; use offline modes when required. Keep tokens in secret stores, do not publish reports of private code, and verify external threat-intelligence matches independently.

## Maintainer security configuration

- Enable **Private vulnerability reporting** under GitHub repository Security settings, and verify the reporting form from a non-maintainer account.
- Configure a monitored, private backup contact channel if the form cannot be enabled; replace the fallback wording above with that real channel.
- Confirm who monitors reports and who has permission to create advisories, issue fixes and coordinate disclosures.

---

**Для русскоязычных исследователей:** сообщения об уязвимостях самого сканера передавайте конфиденциально через GitHub Security Advisories после включения private vulnerability reporting. Если канал недоступен, запросите у сопровождающих приватный способ связи **без публикации деталей**. Плановые этапы: подтверждение обращения до 7 дней, первичный анализ до 14 дней и план исправления критичных/высоких рисков по возможности до 90 дней; это целевые ориентиры, не SLA.
