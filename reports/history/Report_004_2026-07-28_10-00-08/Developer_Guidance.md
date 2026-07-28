# Developer Guidance Report

## Executive Summary

This developer guidance report accompanies the PII scan of https://gitlab.com/morimekta/tiny-server-example.git. It explains, for each detected issue, why it was flagged and how to fix it -- the risk score and pipeline status themselves are decided exclusively by the deterministic risk engine and are reproduced here for reference only.

## Risk Score & Overall Severity

- **Risk score:** 272 (warning >= 20, fail >= 50)
- **Pipeline status:** FAIL
- **Total findings:** 190
- **Overall severity breakdown:**
  - High: 7
  - Medium: 20
  - Low: 163

## Detected Issues, Root Cause & Recommended Fix

### F-000008 - EMAIL_ADDRESS [HIGH]

- **Location:** pom.xml:24
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

### F-000011 - PERSON [HIGH]

- **Location:** pom.xml:2
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

### F-000088 - LOCATION [HIGH]

- **Location:** src\main\java\net\morimekta\tiny\server\example\ExampleApplication.java:46
- **Category:** Personal Information
- **Detection confidence:** 0.85
- **Root cause:** A real, specific location (e.g. a home or office address) tied to an individual was left in source or test data.
- **Likely developer mistake:** Reusing a real customer address in a fixture instead of a synthetic one.
- **Security impact:** Location data tied to a named individual is sensitive PII and can enable physical-safety risks if leaked.
- **Recommended fix:** Replace real addresses/locations tied to individuals with synthetic test data.
- **Security best practice:** Use synthetic addresses/locations in test data instead of real, individual-linked locations.
- **OWASP:** OWASP A01:2021 - Broken Access Control
- **CWE:** CWE-359: Exposure of Private Personal Information to an Unauthorized Actor
- **References:** https://owasp.org/Top10/A01_2021-Broken_Access_Control/, https://cwe.mitre.org/data/definitions/359.html

### F-000089 - PERSON [HIGH]

- **Location:** src\main\java\net\morimekta\tiny\server\example\ExampleApplication.java:54
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

### F-000090 - LOCATION [HIGH]

- **Location:** src\main\java\net\morimekta\tiny\server\example\ExampleApplication.java:55
- **Category:** Personal Information
- **Detection confidence:** 0.85
- **Root cause:** A real, specific location (e.g. a home or office address) tied to an individual was left in source or test data.
- **Likely developer mistake:** Reusing a real customer address in a fixture instead of a synthetic one.
- **Security impact:** Location data tied to a named individual is sensitive PII and can enable physical-safety risks if leaked.
- **Recommended fix:** Replace real addresses/locations tied to individuals with synthetic test data.
- **Security best practice:** Use synthetic addresses/locations in test data instead of real, individual-linked locations.
- **OWASP:** OWASP A01:2021 - Broken Access Control
- **CWE:** CWE-359: Exposure of Private Personal Information to an Unauthorized Actor
- **References:** https://owasp.org/Top10/A01_2021-Broken_Access_Control/, https://cwe.mitre.org/data/definitions/359.html

### F-000134 - PERSON [HIGH]

- **Location:** src\main\java\net\morimekta\tiny\server\example\ExampleServiceImpl.java:23
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

### F-000135 - LOCATION [HIGH]

- **Location:** src\main\java\net\morimekta\tiny\server\example\ExampleServiceImpl.java:29
- **Category:** Personal Information
- **Detection confidence:** 0.85
- **Root cause:** A real, specific location (e.g. a home or office address) tied to an individual was left in source or test data.
- **Likely developer mistake:** Reusing a real customer address in a fixture instead of a synthetic one.
- **Security impact:** Location data tied to a named individual is sensitive PII and can enable physical-safety risks if leaked.
- **Recommended fix:** Replace real addresses/locations tied to individuals with synthetic test data.
- **Security best practice:** Use synthetic addresses/locations in test data instead of real, individual-linked locations.
- **OWASP:** OWASP A01:2021 - Broken Access Control
- **CWE:** CWE-359: Exposure of Private Personal Information to an Unauthorized Actor
- **References:** https://owasp.org/Top10/A01_2021-Broken_Access_Control/, https://cwe.mitre.org/data/definitions/359.html

### F-000013 - ORGANIZATION [MEDIUM]

- **Location:** pom.xml:216
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

- **Location:** pom.xml:217
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

### F-000015 - ORGANIZATION [MEDIUM]

- **Location:** pom.xml:218
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

### F-000016 - ORGANIZATION [MEDIUM]

- **Location:** pom.xml:225
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

### F-000017 - ORGANIZATION [MEDIUM]

- **Location:** pom.xml:226
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

### F-000018 - ORGANIZATION [MEDIUM]

- **Location:** pom.xml:227
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

### F-000019 - ORGANIZATION [MEDIUM]

- **Location:** pom.xml:238
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

### F-000020 - ORGANIZATION [MEDIUM]

- **Location:** pom.xml:245
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

### F-000079 - ORGANIZATION [MEDIUM]

- **Location:** src\main\java\net\morimekta\tiny\server\example\ExampleApplication.java:5
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

### F-000080 - ORGANIZATION [MEDIUM]

- **Location:** src\main\java\net\morimekta\tiny\server\example\ExampleApplication.java:7
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

### F-000081 - ORGANIZATION [MEDIUM]

- **Location:** src\main\java\net\morimekta\tiny\server\example\ExampleApplication.java:9
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

### F-000082 - ORGANIZATION [MEDIUM]

- **Location:** src\main\java\net\morimekta\tiny\server\example\ExampleApplication.java:11
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

### F-000083 - ORGANIZATION [MEDIUM]

- **Location:** src\main\java\net\morimekta\tiny\server\example\ExampleApplication.java:14
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

...and 170 more finding(s). See `dashboard.json` for category-level aggregates or the full JSON report for every finding.

## Secure Coding Recommendations (by category)

- **EMAIL_ADDRESS** (HIGH): OWASP A01:2021 - Broken Access Control / CWE-200: Exposure of Sensitive Information to an Unauthorized Actor -- Use synthetic example addresses (e.g. user@example.com) in code, fixtures, and documentation.
- **PERSON** (HIGH): OWASP A01:2021 - Broken Access Control / CWE-359: Exposure of Private Personal Information to an Unauthorized Actor -- Use synthetic names in code, comments, and test fixtures.
- **LOCATION** (HIGH): OWASP A01:2021 - Broken Access Control / CWE-359: Exposure of Private Personal Information to an Unauthorized Actor -- Use synthetic addresses/locations in test data instead of real, individual-linked locations.
- **ORGANIZATION** (MEDIUM): OWASP A01:2021 - Broken Access Control / CWE-200: Exposure of Sensitive Information to an Unauthorized Actor -- Avoid committing confidential customer, partner, vendor, supplier, or internal project names; use synthetic organization names in source, documentation, logs, and test datasets unless the names are intentionally public.
- **URL** (LOW): OWASP A05:2021 - Security Misconfiguration / CWE-200: Exposure of Sensitive Information to an Unauthorized Actor -- Move environment-specific or credentialed URLs into configuration/secrets rather than hardcoding in source.
