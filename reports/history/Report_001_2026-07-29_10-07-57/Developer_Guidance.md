# Developer Guidance Report

## Executive Summary

This developer guidance report accompanies the PII scan of https://github.com/pallets/click.git. It explains, for each detected issue, why it was flagged and how to fix it -- the risk score and pipeline status themselves are decided exclusively by the deterministic risk engine and are reproduced here for reference only.

## Risk Score & Overall Severity

- **Risk score:** 182 (warning >= 20, fail >= 50)
- **Pipeline status:** FAIL
- **Total findings:** 26
- **Overall severity breakdown:**
  - Critical: 3
  - High: 17
  - Medium: 6

## Detected Issues, Root Cause & Recommended Fix

### F-000000 - MEDICAL_LICENSE [CRITICAL]

- **Location:** .github\workflows\lock.yaml:22
- **Category:** Medical Data
- **Detection confidence:** 1.0
- **Root cause:** A medical license number was committed directly into source or test data.
- **Likely developer mistake:** Reusing a real practitioner's license number in a fixture instead of a synthetic value.
- **Security impact:** Exposure can support impersonation of a licensed medical professional or fraudulent billing.
- **Recommended fix:** Remove hardcoded medical license numbers and replace with synthetic test data.
- **Security best practice:** Never hardcode medical license numbers; use synthetic practitioner data in tests.
- **OWASP:** OWASP A01:2021 - Broken Access Control
- **CWE:** CWE-359: Exposure of Private Personal Information to an Unauthorized Actor
- **References:** https://owasp.org/Top10/A01_2021-Broken_Access_Control/, https://cwe.mitre.org/data/definitions/359.html

### F-000011 - UK_NHS [CRITICAL]

- **Location:** tests\test_basic.py:325
- **Category:** Medical Data
- **Detection confidence:** 1.0
- **Root cause:** A UK National Health Service number was committed directly into source or test data.
- **Likely developer mistake:** Reusing a real patient record for local testing instead of synthetic health data.
- **Security impact:** NHS numbers link directly to an individual's medical history; exposure is a health-data (special category) privacy incident.
- **Recommended fix:** Remove hardcoded NHS numbers and replace with synthetic test data; treat as sensitive health-related identifier.
- **Security best practice:** Never hardcode health-system identifiers; use synthetic patient data in tests.
- **OWASP:** OWASP A01:2021 - Broken Access Control
- **CWE:** CWE-359: Exposure of Private Personal Information to an Unauthorized Actor
- **References:** https://owasp.org/Top10/A01_2021-Broken_Access_Control/, https://cwe.mitre.org/data/definitions/359.html

### F-000021 - UK_NHS [CRITICAL]

- **Location:** tests\test_defaults.py:551
- **Category:** Medical Data
- **Detection confidence:** 1.0
- **Root cause:** A UK National Health Service number was committed directly into source or test data.
- **Likely developer mistake:** Reusing a real patient record for local testing instead of synthetic health data.
- **Security impact:** NHS numbers link directly to an individual's medical history; exposure is a health-data (special category) privacy incident.
- **Recommended fix:** Remove hardcoded NHS numbers and replace with synthetic test data; treat as sensitive health-related identifier.
- **Security best practice:** Never hardcode health-system identifiers; use synthetic patient data in tests.
- **OWASP:** OWASP A01:2021 - Broken Access Control
- **CWE:** CWE-359: Exposure of Private Personal Information to an Unauthorized Actor
- **References:** https://owasp.org/Top10/A01_2021-Broken_Access_Control/, https://cwe.mitre.org/data/definitions/359.html

### F-000001 - PERSON [HIGH]

- **Location:** docs\click-concepts.md:32
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

### F-000002 - PERSON [HIGH]

- **Location:** docs\click-concepts.md:32
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

### F-000003 - IP_ADDRESS [HIGH]

- **Location:** docs\commands.md:334
- **Category:** Network Information
- **Detection confidence:** 0.6
- **Root cause:** An IP address was hardcoded into source or configuration instead of being read from environment-specific config.
- **Likely developer mistake:** Hardcoding a real internal or customer-facing IP address while debugging network connectivity.
- **Security impact:** Hardcoded internal IPs can reveal network topology to anyone with repository access, aiding reconnaissance.
- **Recommended fix:** Replace real IP addresses in code/config with placeholder or documentation-reserved ranges; move any environment-specific addresses into configuration/secrets rather than source.
- **Security best practice:** Move environment-specific IP addresses into configuration or secrets management rather than hardcoding in source.
- **OWASP:** OWASP A05:2021 - Security Misconfiguration
- **CWE:** CWE-200: Exposure of Sensitive Information to an Unauthorized Actor
- **References:** https://owasp.org/Top10/A05_2021-Security_Misconfiguration/, https://cwe.mitre.org/data/definitions/200.html

### F-000004 - IP_ADDRESS [HIGH]

- **Location:** docs\commands.md:411
- **Category:** Network Information
- **Detection confidence:** 0.6
- **Root cause:** An IP address was hardcoded into source or configuration instead of being read from environment-specific config.
- **Likely developer mistake:** Hardcoding a real internal or customer-facing IP address while debugging network connectivity.
- **Security impact:** Hardcoded internal IPs can reveal network topology to anyone with repository access, aiding reconnaissance.
- **Recommended fix:** Replace real IP addresses in code/config with placeholder or documentation-reserved ranges; move any environment-specific addresses into configuration/secrets rather than source.
- **Security best practice:** Move environment-specific IP addresses into configuration or secrets management rather than hardcoding in source.
- **OWASP:** OWASP A05:2021 - Security Misconfiguration
- **CWE:** CWE-200: Exposure of Sensitive Information to an Unauthorized Actor
- **References:** https://owasp.org/Top10/A05_2021-Security_Misconfiguration/, https://cwe.mitre.org/data/definitions/200.html

### F-000006 - EMAIL_ADDRESS [HIGH]

- **Location:** docs\standalone-apps.md:69
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

### F-000008 - US_DRIVER_LICENSE [HIGH]

- **Location:** docs\utils.md:26
- **Category:** Government IDs
- **Detection confidence:** 0.65
- **Root cause:** A U.S. driver's license number was committed directly into source or test data.
- **Likely developer mistake:** Reusing a real individual's license number for identity verification test fixtures.
- **Security impact:** Driver's license numbers are a common secondary identity document used in identity-theft and fraud schemes.
- **Recommended fix:** Remove hardcoded driver's license numbers and replace with synthetic test data.
- **Security best practice:** Never hardcode driver's license numbers; use synthetic identity documents in tests.
- **OWASP:** OWASP A01:2021 - Broken Access Control
- **CWE:** CWE-359: Exposure of Private Personal Information to an Unauthorized Actor
- **References:** https://owasp.org/Top10/A01_2021-Broken_Access_Control/, https://cwe.mitre.org/data/definitions/359.html

### F-000009 - US_DRIVER_LICENSE [HIGH]

- **Location:** docs\utils.md:26
- **Category:** Government IDs
- **Detection confidence:** 0.65
- **Root cause:** A U.S. driver's license number was committed directly into source or test data.
- **Likely developer mistake:** Reusing a real individual's license number for identity verification test fixtures.
- **Security impact:** Driver's license numbers are a common secondary identity document used in identity-theft and fraud schemes.
- **Recommended fix:** Remove hardcoded driver's license numbers and replace with synthetic test data.
- **Security best practice:** Never hardcode driver's license numbers; use synthetic identity documents in tests.
- **OWASP:** OWASP A01:2021 - Broken Access Control
- **CWE:** CWE-359: Exposure of Private Personal Information to an Unauthorized Actor
- **References:** https://owasp.org/Top10/A01_2021-Broken_Access_Control/, https://cwe.mitre.org/data/definitions/359.html

### F-000012 - US_DRIVER_LICENSE [HIGH]

- **Location:** tests\test_basic.py:253
- **Category:** Government IDs
- **Detection confidence:** 0.65
- **Root cause:** A U.S. driver's license number was committed directly into source or test data.
- **Likely developer mistake:** Reusing a real individual's license number for identity verification test fixtures.
- **Security impact:** Driver's license numbers are a common secondary identity document used in identity-theft and fraud schemes.
- **Recommended fix:** Remove hardcoded driver's license numbers and replace with synthetic test data.
- **Security best practice:** Never hardcode driver's license numbers; use synthetic identity documents in tests.
- **OWASP:** OWASP A01:2021 - Broken Access Control
- **CWE:** CWE-359: Exposure of Private Personal Information to an Unauthorized Actor
- **References:** https://owasp.org/Top10/A01_2021-Broken_Access_Control/, https://cwe.mitre.org/data/definitions/359.html

### F-000015 - EMAIL_ADDRESS [HIGH]

- **Location:** tests\test_defaults.py:174
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

### F-000016 - EMAIL_ADDRESS [HIGH]

- **Location:** tests\test_defaults.py:174
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

### F-000017 - EMAIL_ADDRESS [HIGH]

- **Location:** tests\test_defaults.py:176
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

### F-000018 - EMAIL_ADDRESS [HIGH]

- **Location:** tests\test_defaults.py:452
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

### F-000019 - EMAIL_ADDRESS [HIGH]

- **Location:** tests\test_defaults.py:457
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

### F-000020 - EMAIL_ADDRESS [HIGH]

- **Location:** tests\test_defaults.py:463
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

### F-000022 - US_DRIVER_LICENSE [HIGH]

- **Location:** tests\test_options.py:825
- **Category:** Government IDs
- **Detection confidence:** 0.65
- **Root cause:** A U.S. driver's license number was committed directly into source or test data.
- **Likely developer mistake:** Reusing a real individual's license number for identity verification test fixtures.
- **Security impact:** Driver's license numbers are a common secondary identity document used in identity-theft and fraud schemes.
- **Recommended fix:** Remove hardcoded driver's license numbers and replace with synthetic test data.
- **Security best practice:** Never hardcode driver's license numbers; use synthetic identity documents in tests.
- **OWASP:** OWASP A01:2021 - Broken Access Control
- **CWE:** CWE-359: Exposure of Private Personal Information to an Unauthorized Actor
- **References:** https://owasp.org/Top10/A01_2021-Broken_Access_Control/, https://cwe.mitre.org/data/definitions/359.html

### F-000024 - US_DRIVER_LICENSE [HIGH]

- **Location:** tests\test_utils\test_echo.py:15
- **Category:** Government IDs
- **Detection confidence:** 0.65
- **Root cause:** A U.S. driver's license number was committed directly into source or test data.
- **Likely developer mistake:** Reusing a real individual's license number for identity verification test fixtures.
- **Security impact:** Driver's license numbers are a common secondary identity document used in identity-theft and fraud schemes.
- **Recommended fix:** Remove hardcoded driver's license numbers and replace with synthetic test data.
- **Security best practice:** Never hardcode driver's license numbers; use synthetic identity documents in tests.
- **OWASP:** OWASP A01:2021 - Broken Access Control
- **CWE:** CWE-359: Exposure of Private Personal Information to an Unauthorized Actor
- **References:** https://owasp.org/Top10/A01_2021-Broken_Access_Control/, https://cwe.mitre.org/data/definitions/359.html

### F-000025 - US_DRIVER_LICENSE [HIGH]

- **Location:** tests\test_utils\test_echo.py:15
- **Category:** Government IDs
- **Detection confidence:** 0.65
- **Root cause:** A U.S. driver's license number was committed directly into source or test data.
- **Likely developer mistake:** Reusing a real individual's license number for identity verification test fixtures.
- **Security impact:** Driver's license numbers are a common secondary identity document used in identity-theft and fraud schemes.
- **Recommended fix:** Remove hardcoded driver's license numbers and replace with synthetic test data.
- **Security best practice:** Never hardcode driver's license numbers; use synthetic identity documents in tests.
- **OWASP:** OWASP A01:2021 - Broken Access Control
- **CWE:** CWE-359: Exposure of Private Personal Information to an Unauthorized Actor
- **References:** https://owasp.org/Top10/A01_2021-Broken_Access_Control/, https://cwe.mitre.org/data/definitions/359.html

...and 6 more finding(s). See `dashboard.json` for category-level aggregates or the full JSON report for every finding.

## Secure Coding Recommendations (by category)

- **MEDICAL_LICENSE** (CRITICAL): OWASP A01:2021 - Broken Access Control / CWE-359: Exposure of Private Personal Information to an Unauthorized Actor -- Never hardcode medical license numbers; use synthetic practitioner data in tests.
- **UK_NHS** (CRITICAL): OWASP A01:2021 - Broken Access Control / CWE-359: Exposure of Private Personal Information to an Unauthorized Actor -- Never hardcode health-system identifiers; use synthetic patient data in tests.
- **PERSON** (HIGH): OWASP A01:2021 - Broken Access Control / CWE-359: Exposure of Private Personal Information to an Unauthorized Actor -- Use synthetic names in code, comments, and test fixtures.
- **IP_ADDRESS** (HIGH): OWASP A05:2021 - Security Misconfiguration / CWE-200: Exposure of Sensitive Information to an Unauthorized Actor -- Move environment-specific IP addresses into configuration or secrets management rather than hardcoding in source.
- **EMAIL_ADDRESS** (HIGH): OWASP A01:2021 - Broken Access Control / CWE-200: Exposure of Sensitive Information to an Unauthorized Actor -- Use synthetic example addresses (e.g. user@example.com) in code, fixtures, and documentation.
- **US_DRIVER_LICENSE** (HIGH): OWASP A01:2021 - Broken Access Control / CWE-359: Exposure of Private Personal Information to an Unauthorized Actor -- Never hardcode driver's license numbers; use synthetic identity documents in tests.
- **ORGANIZATION** (MEDIUM): OWASP A01:2021 - Broken Access Control / CWE-200: Exposure of Sensitive Information to an Unauthorized Actor -- Avoid committing confidential customer, partner, vendor, supplier, or internal project names; use synthetic organization names in source, documentation, logs, and test datasets unless the names are intentionally public.
