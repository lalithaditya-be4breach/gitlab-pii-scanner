# Developer Guidance Report

## Executive Summary

This developer guidance report accompanies the PII scan of https://gitlab.com/be4breach-group/gitlab-private-test.git. It explains, for each detected issue, why it was flagged and how to fix it -- the risk score and pipeline status themselves are decided exclusively by the deterministic risk engine and are reproduced here for reference only.

## Risk Score & Overall Severity

- **Risk score:** 95 (warning >= 20, fail >= 50)
- **Pipeline status:** FAIL
- **Total findings:** 37
- **Overall severity breakdown:**
  - High: 6
  - Medium: 11
  - Low: 20

## Detected Issues, Root Cause & Recommended Fix

### F-000001 - PERSON [HIGH]

- **Location:** README.md:14
- **Category:** Personal Information
- **Detection confidence:** 0.85
- **Root cause:** A real person's name was left in source code, comments, fixtures, or logs instead of a synthetic placeholder.
- **Likely developer mistake:** Using a real customer's or colleague's name in an example, test fixture, or code comment.
- **Security impact:** Real names, especially combined with other findings (email, phone, location), increase re-identification risk.
- **Recommended fix:** Replace real customer/employee names in code, comments, and test fixtures with synthetic test data.
- **Security best practice:** Use synthetic names in code, comments, and test fixtures.
- **OWASP:** OWASP A01:2021 - Broken Access Control
- **CWE:** CWE-359: Exposure of Private Personal Information to an Unauthorized Actor
- **References:** https://owasp.org/Top10/A01_2021-Broken_Access_Control/, https://cwe.mitre.org/data/definitions/359.html

### F-000010 - PERSON [HIGH]

- **Location:** README.md:62
- **Category:** Personal Information
- **Detection confidence:** 0.85
- **Root cause:** A real person's name was left in source code, comments, fixtures, or logs instead of a synthetic placeholder.
- **Likely developer mistake:** Using a real customer's or colleague's name in an example, test fixture, or code comment.
- **Security impact:** Real names, especially combined with other findings (email, phone, location), increase re-identification risk.
- **Recommended fix:** Replace real customer/employee names in code, comments, and test fixtures with synthetic test data.
- **Security best practice:** Use synthetic names in code, comments, and test fixtures.
- **OWASP:** OWASP A01:2021 - Broken Access Control
- **CWE:** CWE-359: Exposure of Private Personal Information to an Unauthorized Actor
- **References:** https://owasp.org/Top10/A01_2021-Broken_Access_Control/, https://cwe.mitre.org/data/definitions/359.html

### F-000011 - PERSON [HIGH]

- **Location:** README.md:65
- **Category:** Personal Information
- **Detection confidence:** 0.85
- **Root cause:** A real person's name was left in source code, comments, fixtures, or logs instead of a synthetic placeholder.
- **Likely developer mistake:** Using a real customer's or colleague's name in an example, test fixture, or code comment.
- **Security impact:** Real names, especially combined with other findings (email, phone, location), increase re-identification risk.
- **Recommended fix:** Replace real customer/employee names in code, comments, and test fixtures with synthetic test data.
- **Security best practice:** Use synthetic names in code, comments, and test fixtures.
- **OWASP:** OWASP A01:2021 - Broken Access Control
- **CWE:** CWE-359: Exposure of Private Personal Information to an Unauthorized Actor
- **References:** https://owasp.org/Top10/A01_2021-Broken_Access_Control/, https://cwe.mitre.org/data/definitions/359.html

### F-000013 - PERSON [HIGH]

- **Location:** README.md:68
- **Category:** Personal Information
- **Detection confidence:** 0.85
- **Root cause:** A real person's name was left in source code, comments, fixtures, or logs instead of a synthetic placeholder.
- **Likely developer mistake:** Using a real customer's or colleague's name in an example, test fixture, or code comment.
- **Security impact:** Real names, especially combined with other findings (email, phone, location), increase re-identification risk.
- **Recommended fix:** Replace real customer/employee names in code, comments, and test fixtures with synthetic test data.
- **Security best practice:** Use synthetic names in code, comments, and test fixtures.
- **OWASP:** OWASP A01:2021 - Broken Access Control
- **CWE:** CWE-359: Exposure of Private Personal Information to an Unauthorized Actor
- **References:** https://owasp.org/Top10/A01_2021-Broken_Access_Control/, https://cwe.mitre.org/data/definitions/359.html

### F-000033 - EMAIL_ADDRESS [HIGH]

- **Location:** sample.py:2
- **Category:** Personal Information
- **Detection confidence:** 1.0
- **Root cause:** A real email address was left in source code, comments, fixtures, or logs instead of a synthetic example address.
- **Likely developer mistake:** Copy-pasting a real user's email address into a test fixture, example, or debug log statement.
- **Security impact:** Exposed email addresses enable targeted phishing and, when combined with other findings, can support account enumeration.
- **Recommended fix:** Replace real email addresses in code, fixtures, and test data with synthetic example addresses (e.g. user@example.com).
- **Security best practice:** Use synthetic example addresses (e.g. user@example.com) in code, fixtures, and documentation.
- **OWASP:** OWASP A01:2021 - Broken Access Control
- **CWE:** CWE-200: Exposure of Sensitive Information to an Unauthorized Actor
- **References:** https://owasp.org/Top10/A01_2021-Broken_Access_Control/, https://cwe.mitre.org/data/definitions/200.html

### F-000034 - PERSON [HIGH]

- **Location:** sample.py:1
- **Category:** Personal Information
- **Detection confidence:** 0.85
- **Root cause:** A real person's name was left in source code, comments, fixtures, or logs instead of a synthetic placeholder.
- **Likely developer mistake:** Using a real customer's or colleague's name in an example, test fixture, or code comment.
- **Security impact:** Real names, especially combined with other findings (email, phone, location), increase re-identification risk.
- **Recommended fix:** Replace real customer/employee names in code, comments, and test fixtures with synthetic test data.
- **Security best practice:** Use synthetic names in code, comments, and test fixtures.
- **OWASP:** OWASP A01:2021 - Broken Access Control
- **CWE:** CWE-359: Exposure of Private Personal Information to an Unauthorized Actor
- **References:** https://owasp.org/Top10/A01_2021-Broken_Access_Control/, https://cwe.mitre.org/data/definitions/359.html

### F-000000 - ORGANIZATION [MEDIUM]

- **Location:** README.md:7
- **Category:** Business Information
- **Detection confidence:** 0.85
- **Root cause:** An organization or company name was detected within repository content. While organization names are often public, they may reveal confidential customers, partners, internal projects, suppliers, or business relationships when committed into source code, documentation, logs, or datasets.
- **Likely developer mistake:** Committing customer datasets, internal business documentation, vendor information, project documentation, exported reports, or test datasets containing real organizations.
- **Security impact:** Organization names can disclose confidential partners or customers, reveal business relationships, expose internal organizational metadata, or provide competitive intelligence.
- **Recommended fix:** Review detected organization names to confirm they are intended to be public. Replace confidential customer, partner, vendor, supplier, or internal project names with synthetic values in source, documentation, logs, and test datasets.
- **Security best practice:** Avoid committing confidential customer, partner, vendor, supplier, or internal project names; use synthetic organization names in source, documentation, logs, and test datasets unless the names are intentionally public.
- **OWASP:** OWASP A01:2021 - Broken Access Control
- **CWE:** CWE-200: Exposure of Sensitive Information to an Unauthorized Actor
- **References:** https://owasp.org/Top10/A01_2021-Broken_Access_Control/, https://cwe.mitre.org/data/definitions/200.html

### F-000002 - ORGANIZATION [MEDIUM]

- **Location:** README.md:18
- **Category:** Business Information
- **Detection confidence:** 0.85
- **Root cause:** An organization or company name was detected within repository content. While organization names are often public, they may reveal confidential customers, partners, internal projects, suppliers, or business relationships when committed into source code, documentation, logs, or datasets.
- **Likely developer mistake:** Committing customer datasets, internal business documentation, vendor information, project documentation, exported reports, or test datasets containing real organizations.
- **Security impact:** Organization names can disclose confidential partners or customers, reveal business relationships, expose internal organizational metadata, or provide competitive intelligence.
- **Recommended fix:** Review detected organization names to confirm they are intended to be public. Replace confidential customer, partner, vendor, supplier, or internal project names with synthetic values in source, documentation, logs, and test datasets.
- **Security best practice:** Avoid committing confidential customer, partner, vendor, supplier, or internal project names; use synthetic organization names in source, documentation, logs, and test datasets unless the names are intentionally public.
- **OWASP:** OWASP A01:2021 - Broken Access Control
- **CWE:** CWE-200: Exposure of Sensitive Information to an Unauthorized Actor
- **References:** https://owasp.org/Top10/A01_2021-Broken_Access_Control/, https://cwe.mitre.org/data/definitions/200.html

### F-000003 - ORGANIZATION [MEDIUM]

- **Location:** README.md:37
- **Category:** Business Information
- **Detection confidence:** 0.85
- **Root cause:** An organization or company name was detected within repository content. While organization names are often public, they may reveal confidential customers, partners, internal projects, suppliers, or business relationships when committed into source code, documentation, logs, or datasets.
- **Likely developer mistake:** Committing customer datasets, internal business documentation, vendor information, project documentation, exported reports, or test datasets containing real organizations.
- **Security impact:** Organization names can disclose confidential partners or customers, reveal business relationships, expose internal organizational metadata, or provide competitive intelligence.
- **Recommended fix:** Review detected organization names to confirm they are intended to be public. Replace confidential customer, partner, vendor, supplier, or internal project names with synthetic values in source, documentation, logs, and test datasets.
- **Security best practice:** Avoid committing confidential customer, partner, vendor, supplier, or internal project names; use synthetic organization names in source, documentation, logs, and test datasets unless the names are intentionally public.
- **OWASP:** OWASP A01:2021 - Broken Access Control
- **CWE:** CWE-200: Exposure of Sensitive Information to an Unauthorized Actor
- **References:** https://owasp.org/Top10/A01_2021-Broken_Access_Control/, https://cwe.mitre.org/data/definitions/200.html

### F-000004 - ORGANIZATION [MEDIUM]

- **Location:** README.md:39
- **Category:** Business Information
- **Detection confidence:** 0.85
- **Root cause:** An organization or company name was detected within repository content. While organization names are often public, they may reveal confidential customers, partners, internal projects, suppliers, or business relationships when committed into source code, documentation, logs, or datasets.
- **Likely developer mistake:** Committing customer datasets, internal business documentation, vendor information, project documentation, exported reports, or test datasets containing real organizations.
- **Security impact:** Organization names can disclose confidential partners or customers, reveal business relationships, expose internal organizational metadata, or provide competitive intelligence.
- **Recommended fix:** Review detected organization names to confirm they are intended to be public. Replace confidential customer, partner, vendor, supplier, or internal project names with synthetic values in source, documentation, logs, and test datasets.
- **Security best practice:** Avoid committing confidential customer, partner, vendor, supplier, or internal project names; use synthetic organization names in source, documentation, logs, and test datasets unless the names are intentionally public.
- **OWASP:** OWASP A01:2021 - Broken Access Control
- **CWE:** CWE-200: Exposure of Sensitive Information to an Unauthorized Actor
- **References:** https://owasp.org/Top10/A01_2021-Broken_Access_Control/, https://cwe.mitre.org/data/definitions/200.html

### F-000005 - ORGANIZATION [MEDIUM]

- **Location:** README.md:40
- **Category:** Business Information
- **Detection confidence:** 0.85
- **Root cause:** An organization or company name was detected within repository content. While organization names are often public, they may reveal confidential customers, partners, internal projects, suppliers, or business relationships when committed into source code, documentation, logs, or datasets.
- **Likely developer mistake:** Committing customer datasets, internal business documentation, vendor information, project documentation, exported reports, or test datasets containing real organizations.
- **Security impact:** Organization names can disclose confidential partners or customers, reveal business relationships, expose internal organizational metadata, or provide competitive intelligence.
- **Recommended fix:** Review detected organization names to confirm they are intended to be public. Replace confidential customer, partner, vendor, supplier, or internal project names with synthetic values in source, documentation, logs, and test datasets.
- **Security best practice:** Avoid committing confidential customer, partner, vendor, supplier, or internal project names; use synthetic organization names in source, documentation, logs, and test datasets unless the names are intentionally public.
- **OWASP:** OWASP A01:2021 - Broken Access Control
- **CWE:** CWE-200: Exposure of Sensitive Information to an Unauthorized Actor
- **References:** https://owasp.org/Top10/A01_2021-Broken_Access_Control/, https://cwe.mitre.org/data/definitions/200.html

### F-000006 - ORGANIZATION [MEDIUM]

- **Location:** README.md:41
- **Category:** Business Information
- **Detection confidence:** 0.85
- **Root cause:** An organization or company name was detected within repository content. While organization names are often public, they may reveal confidential customers, partners, internal projects, suppliers, or business relationships when committed into source code, documentation, logs, or datasets.
- **Likely developer mistake:** Committing customer datasets, internal business documentation, vendor information, project documentation, exported reports, or test datasets containing real organizations.
- **Security impact:** Organization names can disclose confidential partners or customers, reveal business relationships, expose internal organizational metadata, or provide competitive intelligence.
- **Recommended fix:** Review detected organization names to confirm they are intended to be public. Replace confidential customer, partner, vendor, supplier, or internal project names with synthetic values in source, documentation, logs, and test datasets.
- **Security best practice:** Avoid committing confidential customer, partner, vendor, supplier, or internal project names; use synthetic organization names in source, documentation, logs, and test datasets unless the names are intentionally public.
- **OWASP:** OWASP A01:2021 - Broken Access Control
- **CWE:** CWE-200: Exposure of Sensitive Information to an Unauthorized Actor
- **References:** https://owasp.org/Top10/A01_2021-Broken_Access_Control/, https://cwe.mitre.org/data/definitions/200.html

### F-000007 - ORGANIZATION [MEDIUM]

- **Location:** README.md:41
- **Category:** Business Information
- **Detection confidence:** 0.85
- **Root cause:** An organization or company name was detected within repository content. While organization names are often public, they may reveal confidential customers, partners, internal projects, suppliers, or business relationships when committed into source code, documentation, logs, or datasets.
- **Likely developer mistake:** Committing customer datasets, internal business documentation, vendor information, project documentation, exported reports, or test datasets containing real organizations.
- **Security impact:** Organization names can disclose confidential partners or customers, reveal business relationships, expose internal organizational metadata, or provide competitive intelligence.
- **Recommended fix:** Review detected organization names to confirm they are intended to be public. Replace confidential customer, partner, vendor, supplier, or internal project names with synthetic values in source, documentation, logs, and test datasets.
- **Security best practice:** Avoid committing confidential customer, partner, vendor, supplier, or internal project names; use synthetic organization names in source, documentation, logs, and test datasets unless the names are intentionally public.
- **OWASP:** OWASP A01:2021 - Broken Access Control
- **CWE:** CWE-200: Exposure of Sensitive Information to an Unauthorized Actor
- **References:** https://owasp.org/Top10/A01_2021-Broken_Access_Control/, https://cwe.mitre.org/data/definitions/200.html

### F-000008 - ORGANIZATION [MEDIUM]

- **Location:** README.md:41
- **Category:** Business Information
- **Detection confidence:** 0.85
- **Root cause:** An organization or company name was detected within repository content. While organization names are often public, they may reveal confidential customers, partners, internal projects, suppliers, or business relationships when committed into source code, documentation, logs, or datasets.
- **Likely developer mistake:** Committing customer datasets, internal business documentation, vendor information, project documentation, exported reports, or test datasets containing real organizations.
- **Security impact:** Organization names can disclose confidential partners or customers, reveal business relationships, expose internal organizational metadata, or provide competitive intelligence.
- **Recommended fix:** Review detected organization names to confirm they are intended to be public. Replace confidential customer, partner, vendor, supplier, or internal project names with synthetic values in source, documentation, logs, and test datasets.
- **Security best practice:** Avoid committing confidential customer, partner, vendor, supplier, or internal project names; use synthetic organization names in source, documentation, logs, and test datasets unless the names are intentionally public.
- **OWASP:** OWASP A01:2021 - Broken Access Control
- **CWE:** CWE-200: Exposure of Sensitive Information to an Unauthorized Actor
- **References:** https://owasp.org/Top10/A01_2021-Broken_Access_Control/, https://cwe.mitre.org/data/definitions/200.html

### F-000009 - ORGANIZATION [MEDIUM]

- **Location:** README.md:42
- **Category:** Business Information
- **Detection confidence:** 0.85
- **Root cause:** An organization or company name was detected within repository content. While organization names are often public, they may reveal confidential customers, partners, internal projects, suppliers, or business relationships when committed into source code, documentation, logs, or datasets.
- **Likely developer mistake:** Committing customer datasets, internal business documentation, vendor information, project documentation, exported reports, or test datasets containing real organizations.
- **Security impact:** Organization names can disclose confidential partners or customers, reveal business relationships, expose internal organizational metadata, or provide competitive intelligence.
- **Recommended fix:** Review detected organization names to confirm they are intended to be public. Replace confidential customer, partner, vendor, supplier, or internal project names with synthetic values in source, documentation, logs, and test datasets.
- **Security best practice:** Avoid committing confidential customer, partner, vendor, supplier, or internal project names; use synthetic organization names in source, documentation, logs, and test datasets unless the names are intentionally public.
- **OWASP:** OWASP A01:2021 - Broken Access Control
- **CWE:** CWE-200: Exposure of Sensitive Information to an Unauthorized Actor
- **References:** https://owasp.org/Top10/A01_2021-Broken_Access_Control/, https://cwe.mitre.org/data/definitions/200.html

### F-000012 - ORGANIZATION [MEDIUM]

- **Location:** README.md:68
- **Category:** Business Information
- **Detection confidence:** 0.85
- **Root cause:** An organization or company name was detected within repository content. While organization names are often public, they may reveal confidential customers, partners, internal projects, suppliers, or business relationships when committed into source code, documentation, logs, or datasets.
- **Likely developer mistake:** Committing customer datasets, internal business documentation, vendor information, project documentation, exported reports, or test datasets containing real organizations.
- **Security impact:** Organization names can disclose confidential partners or customers, reveal business relationships, expose internal organizational metadata, or provide competitive intelligence.
- **Recommended fix:** Review detected organization names to confirm they are intended to be public. Replace confidential customer, partner, vendor, supplier, or internal project names with synthetic values in source, documentation, logs, and test datasets.
- **Security best practice:** Avoid committing confidential customer, partner, vendor, supplier, or internal project names; use synthetic organization names in source, documentation, logs, and test datasets unless the names are intentionally public.
- **OWASP:** OWASP A01:2021 - Broken Access Control
- **CWE:** CWE-200: Exposure of Sensitive Information to an Unauthorized Actor
- **References:** https://owasp.org/Top10/A01_2021-Broken_Access_Control/, https://cwe.mitre.org/data/definitions/200.html

### F-000014 - ORGANIZATION [MEDIUM]

- **Location:** README.md:68
- **Category:** Business Information
- **Detection confidence:** 0.85
- **Root cause:** An organization or company name was detected within repository content. While organization names are often public, they may reveal confidential customers, partners, internal projects, suppliers, or business relationships when committed into source code, documentation, logs, or datasets.
- **Likely developer mistake:** Committing customer datasets, internal business documentation, vendor information, project documentation, exported reports, or test datasets containing real organizations.
- **Security impact:** Organization names can disclose confidential partners or customers, reveal business relationships, expose internal organizational metadata, or provide competitive intelligence.
- **Recommended fix:** Review detected organization names to confirm they are intended to be public. Replace confidential customer, partner, vendor, supplier, or internal project names with synthetic values in source, documentation, logs, and test datasets.
- **Security best practice:** Avoid committing confidential customer, partner, vendor, supplier, or internal project names; use synthetic organization names in source, documentation, logs, and test datasets unless the names are intentionally public.
- **OWASP:** OWASP A01:2021 - Broken Access Control
- **CWE:** CWE-200: Exposure of Sensitive Information to an Unauthorized Actor
- **References:** https://owasp.org/Top10/A01_2021-Broken_Access_Control/, https://cwe.mitre.org/data/definitions/200.html

### F-000015 - URL [LOW]

- **Location:** README.md:13
- **Category:** Network Information
- **Detection confidence:** 0.6
- **Root cause:** A URL embedded in source or configuration may contain credentials, internal-only hostnames, or other environment-specific detail that does not belong in code.
- **Likely developer mistake:** Hardcoding an environment-specific or credentialed URL instead of building it from configuration/secrets at runtime.
- **Security impact:** URLs containing embedded credentials or internal hostnames can leak access or aid reconnaissance if the repository is exposed.
- **Recommended fix:** Review embedded URLs for credentials or internal-only endpoints; move environment-specific URLs into configuration.
- **Security best practice:** Move environment-specific or credentialed URLs into configuration/secrets rather than hardcoding in source.
- **OWASP:** OWASP A05:2021 - Security Misconfiguration
- **CWE:** CWE-200: Exposure of Sensitive Information to an Unauthorized Actor
- **References:** https://owasp.org/Top10/A05_2021-Security_Misconfiguration/, https://cwe.mitre.org/data/definitions/200.html

### F-000016 - URL [LOW]

- **Location:** README.md:13
- **Category:** Network Information
- **Detection confidence:** 0.6
- **Root cause:** A URL embedded in source or configuration may contain credentials, internal-only hostnames, or other environment-specific detail that does not belong in code.
- **Likely developer mistake:** Hardcoding an environment-specific or credentialed URL instead of building it from configuration/secrets at runtime.
- **Security impact:** URLs containing embedded credentials or internal hostnames can leak access or aid reconnaissance if the repository is exposed.
- **Recommended fix:** Review embedded URLs for credentials or internal-only endpoints; move environment-specific URLs into configuration.
- **Security best practice:** Move environment-specific or credentialed URLs into configuration/secrets rather than hardcoding in source.
- **OWASP:** OWASP A05:2021 - Security Misconfiguration
- **CWE:** CWE-200: Exposure of Sensitive Information to an Unauthorized Actor
- **References:** https://owasp.org/Top10/A05_2021-Security_Misconfiguration/, https://cwe.mitre.org/data/definitions/200.html

### F-000017 - URL [LOW]

- **Location:** README.md:14
- **Category:** Network Information
- **Detection confidence:** 0.6
- **Root cause:** A URL embedded in source or configuration may contain credentials, internal-only hostnames, or other environment-specific detail that does not belong in code.
- **Likely developer mistake:** Hardcoding an environment-specific or credentialed URL instead of building it from configuration/secrets at runtime.
- **Security impact:** URLs containing embedded credentials or internal hostnames can leak access or aid reconnaissance if the repository is exposed.
- **Recommended fix:** Review embedded URLs for credentials or internal-only endpoints; move environment-specific URLs into configuration.
- **Security best practice:** Move environment-specific or credentialed URLs into configuration/secrets rather than hardcoding in source.
- **OWASP:** OWASP A05:2021 - Security Misconfiguration
- **CWE:** CWE-200: Exposure of Sensitive Information to an Unauthorized Actor
- **References:** https://owasp.org/Top10/A05_2021-Security_Misconfiguration/, https://cwe.mitre.org/data/definitions/200.html

...and 17 more finding(s). See `dashboard.json` for category-level aggregates or the full JSON report for every finding.

## Secure Coding Recommendations (by category)

- **PERSON** (HIGH): OWASP A01:2021 - Broken Access Control / CWE-359: Exposure of Private Personal Information to an Unauthorized Actor -- Use synthetic names in code, comments, and test fixtures.
- **EMAIL_ADDRESS** (HIGH): OWASP A01:2021 - Broken Access Control / CWE-200: Exposure of Sensitive Information to an Unauthorized Actor -- Use synthetic example addresses (e.g. user@example.com) in code, fixtures, and documentation.
- **ORGANIZATION** (MEDIUM): OWASP A01:2021 - Broken Access Control / CWE-200: Exposure of Sensitive Information to an Unauthorized Actor -- Avoid committing confidential customer, partner, vendor, supplier, or internal project names; use synthetic organization names in source, documentation, logs, and test datasets unless the names are intentionally public.
- **URL** (LOW): OWASP A05:2021 - Security Misconfiguration / CWE-200: Exposure of Sensitive Information to an Unauthorized Actor -- Move environment-specific or credentialed URLs into configuration/secrets rather than hardcoding in source.
