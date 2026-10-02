# Assurance Tool Capability Evidence Ledger

Status: Primary-source research. No Cryptalis execution or independent review

Initial access date: **2026-09-30**, except T-BETTERLEAKS first inspected **2026-10-01**.
T-DSSE, T-GITLEAKS, T-NUCLEI and T-OWASP-ASVS were rechecked **2026-10-01**. All other rows retain
their initial access date.

This ledger owns assurance-tool capability claims used by [assurance research](../security-assurance-suite-research.md).
It also supplies claims for the [canonical assurance contract](../architecture/assurance-evidence.md).
The [prior-art ledger](../prior-art.md) remains owner of protection-product comparisons.

`Documented` means the cited primary page was read on the access date.
It does not mean that a binary was installed, licensed, executed or benchmarked. Rolling documentation cannot establish the latest
binary version or Cryptalis support. Documentation example versions are not release pins.

An actual adapter trial must record the exact binary, edition and image.
It must also record add-on, model, rule, template and feed versions, configuration and digest, and the output schema. Recheck these sources before public comparison.

| ID | Product / edition and version evidence | Documented capability | Boundary / Cryptalis decision | Primary sources |
|---|---|---|---|---|
| T-ZAP | ZAP open-source desktop Automation Framework add-on. Rolling docs. Binary and add-on pins not established | Ordered automation jobs support plan validation, execution, progress and stop. The framework supports all ZAP authentication mechanisms and job tests. Configuration may override default autorun exit states | Baseline DAST adapter. Independently inspect authentication and job completion. Exit 0 and no alerts do not pass field protection. Stop may lag. Documented generic active scanning has logical-flaw limits | [Automation Framework](https://www.zaproxy.org/docs/desktop/addons/automation-framework/), [authentication](https://www.zaproxy.org/docs/desktop/addons/automation-framework/authentication/), [API limits](https://www.zaproxy.org/docs/api/) |
| T-BURP | Burp Suite DAST commercial Cloud or Self-hosted. Source pages updated 2026-09-22. Installed release not established. Do not substitute Community or Professional | CI-driven container scans, dedicated API-user setup, optional correlation ID and JUnit XML output. Trusted extensions, BChecks and BApps | Optional commercial adapter. Never a prerequisite for the open lab. Active testing can damage targets. Record actual licensing, edition, application authentication and scan configuration before an equivalence claim | [DAST overview and warning](https://portswigger.net/burp/documentation/dast), [CI-driven scans](https://portswigger.net/burp/documentation/dast/user-guide/ci-cd/ci-driven-scans/getting-started) |
| T-CODEQL | GitHub CodeQL Python libraries. Modular data-flow API documented since 2.13.0. Actual CLI and query-pack pins not established | Local and global data flow, non-value-preserving taint, and path-query explanations. Configurable sources, sinks, barriers and additional flow | Deep reference and model adapter. Cross-program models have cost and precision limits. Do not call it Python runtime taint. GitHub public-repository access differs from private organization repositories requiring Code Security. Independently verify CLI distribution and license terms for intended redistribution | [Python data flow](https://codeql.github.com/docs/codeql-language-guides/analyzing-data-flow-in-python/), [GitHub access](https://docs.github.com/en/code-security/concepts/code-scanning/codeql/codeql-code-scanning) |
| T-SEMGREP | Semgrep CE compared with commercial Semgrep Code and its cross-file binary. Rolling docs. Versions not pinned | CE supports intraprocedural analysis. Code supports cross-function analysis by default and optional cross-file analysis. Cross-file analysis uses a separate proprietary binary. Docs say cross-file analysis currently does not run on diff-aware scans | Compare equivalent editions and full-scan modes. A clean CE result cannot establish cross-file absence. Generated rules and imported results retain licensing and model provenance | [Semgrep analysis scope](https://docs.semgrep.dev/semgrep-code/semgrep-pro-engine-intro) |
| T-NUCLEI | ProjectDiscovery Nuclei open-source CLI and templates. Rolling docs. Example development and pack numbers are not current release pins | Many target formats and workflows. Code, headless and fuzzing capabilities require explicit selection. Official template signatures and code-template signature restrictions | Explicitly allowlisted packs. Signing is optional for protocols other than code. Signatures include referenced code but exclude payload and helper files from the template digest. Independently hash every pack member and privilege. A signature cannot certify safe behavior | [execution](https://docs.projectdiscovery.io/opensource/nuclei/running), [signing and exclusions](https://docs.projectdiscovery.io/templates/reference/template-signing) |
| T-SQLMAP | sqlmap open-source project usage wiki. Page shows a 2026-07-23 edit. Actual release not pinned | SQL injection detection and extraction with bounded target, request and extraction controls. Risk 2 includes heavy time-based tests. Risk 3 includes OR-based tests. Direct DB access and broad OS, filesystem and SQL features also exist | Separate destructive profile for disposable synthetic columns. Risk 1 does not establish containment. OR-based tests can affect many rows in UPDATE contexts. Disallow general dumps, OS actions, filesystem actions, arbitrary SQL and inherited broad targets | [sqlmap Usage](https://github.com/sqlmapproject/sqlmap/wiki/Usage) |
| T-TRIVY | Aqua Trivy open-source CLI. Rolling latest documentation. Binary, check and feed pins not established | IaC misconfiguration checks include Dockerfile, Kubernetes, Terraform and CloudFormation. Custom checks are supported. Image, fs and repo modes can explicitly select vulnerability, misconfiguration and secret scanners | Import configuration and deployment evidence. The misconfiguration scanner is not the default in image, fs or repo modes. A listed Docker capability is not proof of complete Docker Compose semantics. Report actual recognized files, checks and freshness | [misconfiguration scanner](https://trivy.dev/docs/latest/guide/scanner/misconfiguration/) |
| T-GRYPE | Anchore Grype open-source CLI. Rolling docs. Binary and database pins not established | Severity-based CI failure threshold. Fix-state filtering, ignores and VEX-based exploitability filtering | Preserve filtered and unfiltered policy and VEX provenance. Ignored, non-fixed and unknown data must remain visible. Its documented exit 2 means severity threshold, unlike Cryptalis exits. The adapter must normalize execution separately | [Grype filtering and VEX](https://oss.anchore.com/docs/guides/vulnerability/filter-results/) |
| T-GITLEAKS | Gitleaks open-source v8 module family. Master README. Exact release not pinned. Hook example v8.24.2 is not current-release evidence | Secrets in git, files and stdin. Baselines, configurable redaction, and JSON, CSV, JUnit and SARIF formats | Import findings. A clean secret scan supplies no proof. The README says feature complete and future releases contain security patches only. The maintainer shifts to Betterleaks. This warrants replacement research but does not authorize automatic tool migration | [maintainer README](https://raw.githubusercontent.com/gitleaks/gitleaks/master/README.md) |
| T-BETTERLEAKS | Betterleaks maintainer `main` README. Accessed 2026-10-01. It labels main as v2 development and v1.x as maintenance. It contains conditional stable-v2 packaging text. Exact release not established | Expr filtering. Optional network credential validation and identity analysis, plus explicit revocation. The environment can enable validation or analysis. Scan revocation is separate | Research alternative after the Gitleaks maintenance announcement. No automatic replacement. Pin branch, binary and configuration. Test semantics. Remove inherited environment settings that enable these features. Forbid validation, analysis, revocation and source downloads in passive imports. External credential requests require separately scoped synthetic authorization | [maintainer main README](https://raw.githubusercontent.com/betterleaks/betterleaks/main/README.md) |
| T-NMAP | Nmap official book XML interface. Rolling book. The old sample version is not a binary pin | The book recommends machine-readable extensible XML for programmatic parsing. XML includes host, port and service observations | Exposure and service inventory only. It does not establish encrypted-field protection. Disable external XML entities. Disable imports of remote stylesheets. Active inventory obeys lab authorization | [Nmap XML output](https://nmap.org/book/output-formats-xml-output.html) |
| T-TSHARK | Wireshark and TShark official man page. Rolling docs. Binary not pinned | Live capture and offline PCAP or pcapng reading. Capture and display filters. Structured JSON, EK and field output | Pin decoder fields and version, capture point, filters, drops and snaplen. PCAP is sensitive and untrusted input. Network evidence corroborates explicit assets. It does not prove plaintext absence | [TShark manual](https://www.wireshark.org/docs/man-pages/tshark.html) |
| T-WIRESHARK-TLS | Wireshark official project TLS wiki. Notes a dissector rename since 3.0. No current binary pin | Lab session-key logs support TLS decryption. RSA private keys work only under narrow older-protocol and non-DHE conditions. pcapng may contain embedded session secrets | Ordinary TLS traffic does not expose application or DB plaintext. Quarantine keys and decrypted captures. Destroy them after use. Inspect exported pcapng for embedded secrets | [TLS decryption and pcapng secrets](https://wiki.wireshark.org/TLS) |
| T-ZEEK | Zeek open-source current reference logs. Rolling docs. No binary or script pin | conn.log and ssl.log represent flows and TLS metadata. Zeek does not natively recognize encrypted HTTPS as HTTP | No automatic TLS bypass. Log, drop, capture and script identity matters. Correlate by evidenced UID, flow and run keys. Time alone is insufficient | [ssl.log limits](https://docs.zeek.org/en/current/reference/logs/ssl.html) |
| T-ACRA | Cossack Labs Acra docs display 0.96.0 and last commit 2025-12-05. Edition entitlement for each feature is not established | Encryption, search, masking, tokenization, transport and SQL firewall, key management, and anomaly reactions. Logging, events, cryptographically protected exported audit logging and SIEM concepts | Disproves the broad claim that data-protection competitors stop at encryption. Study SQL policy, honeytokens, reactions and audit. Do not infer that every edition includes every feature. Do not claim Cryptalis equivalence | [Acra controls](https://docs.cossacklabs.com/acra/security-controls/), [logging/events](https://docs.cossacklabs.com/acra/security-controls/security-logging-and-events/) |
| T-IN-TOTO | in-toto Attestation Statement v1 spec. Main repository inspected. This is not an executable toolkit pin | Statement subject digests bind immutable artifacts. predicateType names the meaning | The wrapper binds the bundle manifest to a versioned Cryptalis predicate. It does not prove truthful measurements. Cryptalis requires SHA-256 although statement spec itself does not guarantee digest cryptographic strength | [Statement v1](https://github.com/in-toto/attestation/blob/main/spec/v1/statement.md) |
| T-DSSE | DSSE envelope and protocol version 1.0.2, dated 2024-05-10. Docs inspected. No implementation pin | Authenticates serialized bytes and payload type through PAE. keyid is an unauthenticated hint. Verified bytes must be the same bytes delivered to the application | Use a reviewed implementation, an allowed type and version, and externally trusted key policy. Reparsing or reextracting after verification can violate binding. Envelope format alone proves no provenance truth | [envelope](https://github.com/secure-systems-lab/dsse/blob/master/envelope.md), [protocol](https://raw.githubusercontent.com/secure-systems-lab/dsse/master/protocol.md) |
| T-SIGSTORE | Sigstore Cosign blob signing and verification rolling docs. Binary and bundle versions not pinned | Blob bundles carry signature, certificate and transparency inclusion metadata. Verification can require the expected OIDC issuer and identity or a public key | Exact manifest bytes and explicit trust roots and identity are required. Accepting any signer does not establish authenticity for Cryptalis. Inclusion and time evidence do not establish collector honesty or independence | [blob signing](https://docs.sigstore.dev/cosign/signing/signing_with_blobs/), [verification](https://docs.sigstore.dev/cosign/verifying/verify/) |
| T-OWASP-WSTG | OWASP WSTG stable resolves to v4.2 | Testing catalogue covers identity, authentication, authorization, sessions, configuration, injection, errors, cryptography, business logic and client-side testing | Scenario references pin the version and specific test. A ZAP scan or lab course demonstration is not complete WSTG coverage | [WSTG v4.2 catalogue](https://wstg.owasp.org/v4.2/4-Web_Application_Security_Testing/) |
| T-OWASP-ASVS | OWASP ASVS latest stable source identifies 5.0.0 | Versioned technical security requirements. Explicit guidance for references to IDs that include the version | Read the exact relevant requirements before mapping them. Do not claim ASVS certification or compliance from field-protection evidence | [ASVS project/version guidance](https://owasp.org/www-project-application-security-verification-standard/) |

## Reproduction obligations and unresolved evidence

All rows are `Documented`. None are `Cryptalis-reproduced`, `Cryptalis-benchmarked` or `Independently-reviewed`. Source repository access in the browser is documentation inspection. It does not establish an executed source-code audit.

The pinned tool-output, model and edition compatibility matrix remains pending. Versioned requirements do not imply installed dependencies.

A trial must capture these records:

- Licensed edition and access basis
- Digests for the binary, image, add-ons, rules, templates and feed
- Parser output schema
- Selected and disabled jobs
- Authentication state
- All exclusions, filters and baselines
- Network, file and code privileges
- Data freshness
- Raw redacted output and exit status
- Controls and health
- Cleanup

Tool-native exits, CVSS and alert absence remain separate from Cryptalis assertion outcomes.

The following uncertainty remains intentional:

- Exact latest releases for tools with rolling documentation
- Binary behavior against Cryptalis fixtures
- Complete Trivy Docker Compose coverage
- Acra edition entitlements for each feature
- CodeQL and maintained-rule redistribution terms
- Access and performance for proprietary Semgrep and Burp editions
- Independent value of correlation from field to exposure

Absence from search results does not establish that a competitor lacks a capability. Findings about those uncertainties require further primary evidence
or bounded trials before public claims.

The older Semgrep `semgrep-pro-vs-semgrep-ce` and Burp `/dast/scans` URLs returned not-found during
research. The working scope/CI pages above support the stated claims. No capability was inferred
from those failed fetches.
