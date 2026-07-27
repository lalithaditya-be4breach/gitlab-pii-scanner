# Developer Guidance Report

## Executive Summary

This developer guidance report accompanies the PII scan of D:\gitlab-pii-scanner\juice-shop. It explains, for each detected issue, why it was flagged and how to fix it -- the risk score and pipeline status themselves are decided exclusively by the deterministic risk engine and are reproduced here for reference only.

## Risk Score & Overall Severity

- **Risk score:** 252741 (warning >= 20, fail >= 50)
- **Pipeline status:** FAIL
- **Total findings:** 85387
- **Overall severity breakdown:**
  - Critical: 122
  - High: 17946
  - Medium: 28985
  - Low: 38334

## Detected Issues, Root Cause & Recommended Fix

### F-000578 - CREDIT_CARD [CRITICAL]

- **Location:** REFERENCES.md:473
- **Category:** Financial Data
- **Detection confidence:** 1.0
- **Root cause:** A payment card number was committed directly into source, configuration, or test data instead of being handled exclusively by a PCI-compliant payment processor.
- **Likely developer mistake:** Using a real (or realistic) card number for local testing or debugging instead of a card network's published test number range.
- **Security impact:** Exposure of payment card data in a repository is a PCI-DSS violation and a direct financial-fraud risk.
- **Recommended fix:** Remove hardcoded payment card data from source. Never store raw card numbers in code, config, or logs; use a PCI-compliant payment processor/tokenization service instead.
- **Security best practice:** Never store raw payment card numbers in code, config, or logs; tokenize via a PCI-compliant payment processor.
- **OWASP:** OWASP A02:2021 - Cryptographic Failures
- **CWE:** CWE-312: Cleartext Storage of Sensitive Information
- **References:** https://owasp.org/Top10/A02_2021-Cryptographic_Failures/, https://cwe.mitre.org/data/definitions/312.html

### F-000579 - CREDIT_CARD [CRITICAL]

- **Location:** REFERENCES.md:494
- **Category:** Financial Data
- **Detection confidence:** 1.0
- **Root cause:** A payment card number was committed directly into source, configuration, or test data instead of being handled exclusively by a PCI-compliant payment processor.
- **Likely developer mistake:** Using a real (or realistic) card number for local testing or debugging instead of a card network's published test number range.
- **Security impact:** Exposure of payment card data in a repository is a PCI-DSS violation and a direct financial-fraud risk.
- **Recommended fix:** Remove hardcoded payment card data from source. Never store raw card numbers in code, config, or logs; use a PCI-compliant payment processor/tokenization service instead.
- **Security best practice:** Never store raw payment card numbers in code, config, or logs; tokenize via a PCI-compliant payment processor.
- **OWASP:** OWASP A02:2021 - Cryptographic Failures
- **CWE:** CWE-312: Cleartext Storage of Sensitive Information
- **References:** https://owasp.org/Top10/A02_2021-Cryptographic_Failures/, https://cwe.mitre.org/data/definitions/312.html

### F-003178 - MEDICAL_LICENSE [CRITICAL]

- **Location:** .github\workflows\lock.yml:20
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

### F-005048 - CRYPTO [CRITICAL]

- **Location:** data\static\challenges.yml:848
- **Category:** Secrets
- **Detection confidence:** 1.0
- **Root cause:** A cryptocurrency wallet address or private key was committed directly into source instead of being retrieved from secure key storage at runtime.
- **Likely developer mistake:** Pasting a real wallet address or key into code or a config file for convenience during development.
- **Security impact:** Exposed wallet keys can be used to irreversibly move funds; unlike a password, a crypto private key cannot be revoked.
- **Recommended fix:** Remove hardcoded cryptocurrency wallet addresses/keys from source. Store private keys in a secrets manager, never in code.
- **Security best practice:** Never store private keys or wallet credentials in source; load them from a hardware wallet, HSM, or secrets manager.
- **OWASP:** OWASP A02:2021 - Cryptographic Failures
- **CWE:** CWE-798: Use of Hard-coded Credentials
- **References:** https://owasp.org/Top10/A02_2021-Cryptographic_Failures/, https://cwe.mitre.org/data/definitions/798.html

### F-005532 - CREDIT_CARD [CRITICAL]

- **Location:** data\static\users.yml:22
- **Category:** Financial Data
- **Detection confidence:** 1.0
- **Root cause:** A payment card number was committed directly into source, configuration, or test data instead of being handled exclusively by a PCI-compliant payment processor.
- **Likely developer mistake:** Using a real (or realistic) card number for local testing or debugging instead of a card network's published test number range.
- **Security impact:** Exposure of payment card data in a repository is a PCI-DSS violation and a direct financial-fraud risk.
- **Recommended fix:** Remove hardcoded payment card data from source. Never store raw card numbers in code, config, or logs; use a PCI-compliant payment processor/tokenization service instead.
- **Security best practice:** Never store raw payment card numbers in code, config, or logs; tokenize via a PCI-compliant payment processor.
- **OWASP:** OWASP A02:2021 - Cryptographic Failures
- **CWE:** CWE-312: Cleartext Storage of Sensitive Information
- **References:** https://owasp.org/Top10/A02_2021-Cryptographic_Failures/, https://cwe.mitre.org/data/definitions/312.html

### F-005533 - CREDIT_CARD [CRITICAL]

- **Location:** data\static\users.yml:26
- **Category:** Financial Data
- **Detection confidence:** 1.0
- **Root cause:** A payment card number was committed directly into source, configuration, or test data instead of being handled exclusively by a PCI-compliant payment processor.
- **Likely developer mistake:** Using a real (or realistic) card number for local testing or debugging instead of a card network's published test number range.
- **Security impact:** Exposure of payment card data in a repository is a PCI-DSS violation and a direct financial-fraud risk.
- **Recommended fix:** Remove hardcoded payment card data from source. Never store raw card numbers in code, config, or logs; use a PCI-compliant payment processor/tokenization service instead.
- **Security best practice:** Never store raw payment card numbers in code, config, or logs; tokenize via a PCI-compliant payment processor.
- **OWASP:** OWASP A02:2021 - Cryptographic Failures
- **CWE:** CWE-312: Cleartext Storage of Sensitive Information
- **References:** https://owasp.org/Top10/A02_2021-Cryptographic_Failures/, https://cwe.mitre.org/data/definitions/312.html

### F-005534 - CREDIT_CARD [CRITICAL]

- **Location:** data\static\users.yml:58
- **Category:** Financial Data
- **Detection confidence:** 1.0
- **Root cause:** A payment card number was committed directly into source, configuration, or test data instead of being handled exclusively by a PCI-compliant payment processor.
- **Likely developer mistake:** Using a real (or realistic) card number for local testing or debugging instead of a card network's published test number range.
- **Security impact:** Exposure of payment card data in a repository is a PCI-DSS violation and a direct financial-fraud risk.
- **Recommended fix:** Remove hardcoded payment card data from source. Never store raw card numbers in code, config, or logs; use a PCI-compliant payment processor/tokenization service instead.
- **Security best practice:** Never store raw payment card numbers in code, config, or logs; tokenize via a PCI-compliant payment processor.
- **OWASP:** OWASP A02:2021 - Cryptographic Failures
- **CWE:** CWE-312: Cleartext Storage of Sensitive Information
- **References:** https://owasp.org/Top10/A02_2021-Cryptographic_Failures/, https://cwe.mitre.org/data/definitions/312.html

### F-005535 - CREDIT_CARD [CRITICAL]

- **Location:** data\static\users.yml:82
- **Category:** Financial Data
- **Detection confidence:** 1.0
- **Root cause:** A payment card number was committed directly into source, configuration, or test data instead of being handled exclusively by a PCI-compliant payment processor.
- **Likely developer mistake:** Using a real (or realistic) card number for local testing or debugging instead of a card network's published test number range.
- **Security impact:** Exposure of payment card data in a repository is a PCI-DSS violation and a direct financial-fraud risk.
- **Recommended fix:** Remove hardcoded payment card data from source. Never store raw card numbers in code, config, or logs; use a PCI-compliant payment processor/tokenization service instead.
- **Security best practice:** Never store raw payment card numbers in code, config, or logs; tokenize via a PCI-compliant payment processor.
- **OWASP:** OWASP A02:2021 - Cryptographic Failures
- **CWE:** CWE-312: Cleartext Storage of Sensitive Information
- **References:** https://owasp.org/Top10/A02_2021-Cryptographic_Failures/, https://cwe.mitre.org/data/definitions/312.html

### F-005537 - CREDIT_CARD [CRITICAL]

- **Location:** data\static\users.yml:102
- **Category:** Financial Data
- **Detection confidence:** 1.0
- **Root cause:** A payment card number was committed directly into source, configuration, or test data instead of being handled exclusively by a PCI-compliant payment processor.
- **Likely developer mistake:** Using a real (or realistic) card number for local testing or debugging instead of a card network's published test number range.
- **Security impact:** Exposure of payment card data in a repository is a PCI-DSS violation and a direct financial-fraud risk.
- **Recommended fix:** Remove hardcoded payment card data from source. Never store raw card numbers in code, config, or logs; use a PCI-compliant payment processor/tokenization service instead.
- **Security best practice:** Never store raw payment card numbers in code, config, or logs; tokenize via a PCI-compliant payment processor.
- **OWASP:** OWASP A02:2021 - Cryptographic Failures
- **CWE:** CWE-312: Cleartext Storage of Sensitive Information
- **References:** https://owasp.org/Top10/A02_2021-Cryptographic_Failures/, https://cwe.mitre.org/data/definitions/312.html

### F-006963 - CRYPTO [CRITICAL]

- **Location:** data\static\codefixes\redirectChallenge_1.ts:3
- **Category:** Secrets
- **Detection confidence:** 1.0
- **Root cause:** A cryptocurrency wallet address or private key was committed directly into source instead of being retrieved from secure key storage at runtime.
- **Likely developer mistake:** Pasting a real wallet address or key into code or a config file for convenience during development.
- **Security impact:** Exposed wallet keys can be used to irreversibly move funds; unlike a password, a crypto private key cannot be revoked.
- **Recommended fix:** Remove hardcoded cryptocurrency wallet addresses/keys from source. Store private keys in a secrets manager, never in code.
- **Security best practice:** Never store private keys or wallet credentials in source; load them from a hardware wallet, HSM, or secrets manager.
- **OWASP:** OWASP A02:2021 - Cryptographic Failures
- **CWE:** CWE-798: Use of Hard-coded Credentials
- **References:** https://owasp.org/Top10/A02_2021-Cryptographic_Failures/, https://cwe.mitre.org/data/definitions/798.html

### F-006973 - CRYPTO [CRITICAL]

- **Location:** data\static\codefixes\redirectChallenge_2.ts:3
- **Category:** Secrets
- **Detection confidence:** 1.0
- **Root cause:** A cryptocurrency wallet address or private key was committed directly into source instead of being retrieved from secure key storage at runtime.
- **Likely developer mistake:** Pasting a real wallet address or key into code or a config file for convenience during development.
- **Security impact:** Exposed wallet keys can be used to irreversibly move funds; unlike a password, a crypto private key cannot be revoked.
- **Recommended fix:** Remove hardcoded cryptocurrency wallet addresses/keys from source. Store private keys in a secrets manager, never in code.
- **Security best practice:** Never store private keys or wallet credentials in source; load them from a hardware wallet, HSM, or secrets manager.
- **OWASP:** OWASP A02:2021 - Cryptographic Failures
- **CWE:** CWE-798: Use of Hard-coded Credentials
- **References:** https://owasp.org/Top10/A02_2021-Cryptographic_Failures/, https://cwe.mitre.org/data/definitions/798.html

### F-006984 - CRYPTO [CRITICAL]

- **Location:** data\static\codefixes\redirectChallenge_3.ts:3
- **Category:** Secrets
- **Detection confidence:** 1.0
- **Root cause:** A cryptocurrency wallet address or private key was committed directly into source instead of being retrieved from secure key storage at runtime.
- **Likely developer mistake:** Pasting a real wallet address or key into code or a config file for convenience during development.
- **Security impact:** Exposed wallet keys can be used to irreversibly move funds; unlike a password, a crypto private key cannot be revoked.
- **Recommended fix:** Remove hardcoded cryptocurrency wallet addresses/keys from source. Store private keys in a secrets manager, never in code.
- **Security best practice:** Never store private keys or wallet credentials in source; load them from a hardware wallet, HSM, or secrets manager.
- **OWASP:** OWASP A02:2021 - Cryptographic Failures
- **CWE:** CWE-798: Use of Hard-coded Credentials
- **References:** https://owasp.org/Top10/A02_2021-Cryptographic_Failures/, https://cwe.mitre.org/data/definitions/798.html

### F-006995 - CRYPTO [CRITICAL]

- **Location:** data\static\codefixes\redirectChallenge_4_correct.ts:3
- **Category:** Secrets
- **Detection confidence:** 1.0
- **Root cause:** A cryptocurrency wallet address or private key was committed directly into source instead of being retrieved from secure key storage at runtime.
- **Likely developer mistake:** Pasting a real wallet address or key into code or a config file for convenience during development.
- **Security impact:** Exposed wallet keys can be used to irreversibly move funds; unlike a password, a crypto private key cannot be revoked.
- **Recommended fix:** Remove hardcoded cryptocurrency wallet addresses/keys from source. Store private keys in a secrets manager, never in code.
- **Security best practice:** Never store private keys or wallet credentials in source; load them from a hardware wallet, HSM, or secrets manager.
- **OWASP:** OWASP A02:2021 - Cryptographic Failures
- **CWE:** CWE-798: Use of Hard-coded Credentials
- **References:** https://owasp.org/Top10/A02_2021-Cryptographic_Failures/, https://cwe.mitre.org/data/definitions/798.html

### F-007012 - CRYPTO [CRITICAL]

- **Location:** data\static\codefixes\redirectCryptoCurrencyChallenge_2.ts:3
- **Category:** Secrets
- **Detection confidence:** 1.0
- **Root cause:** A cryptocurrency wallet address or private key was committed directly into source instead of being retrieved from secure key storage at runtime.
- **Likely developer mistake:** Pasting a real wallet address or key into code or a config file for convenience during development.
- **Security impact:** Exposed wallet keys can be used to irreversibly move funds; unlike a password, a crypto private key cannot be revoked.
- **Recommended fix:** Remove hardcoded cryptocurrency wallet addresses/keys from source. Store private keys in a secrets manager, never in code.
- **Security best practice:** Never store private keys or wallet credentials in source; load them from a hardware wallet, HSM, or secrets manager.
- **OWASP:** OWASP A02:2021 - Cryptographic Failures
- **CWE:** CWE-798: Use of Hard-coded Credentials
- **References:** https://owasp.org/Top10/A02_2021-Cryptographic_Failures/, https://cwe.mitre.org/data/definitions/798.html

### F-007027 - CRYPTO [CRITICAL]

- **Location:** data\static\codefixes\redirectCryptoCurrencyChallenge_4.ts:3
- **Category:** Secrets
- **Detection confidence:** 1.0
- **Root cause:** A cryptocurrency wallet address or private key was committed directly into source instead of being retrieved from secure key storage at runtime.
- **Likely developer mistake:** Pasting a real wallet address or key into code or a config file for convenience during development.
- **Security impact:** Exposed wallet keys can be used to irreversibly move funds; unlike a password, a crypto private key cannot be revoked.
- **Recommended fix:** Remove hardcoded cryptocurrency wallet addresses/keys from source. Store private keys in a secrets manager, never in code.
- **Security best practice:** Never store private keys or wallet credentials in source; load them from a hardware wallet, HSM, or secrets manager.
- **OWASP:** OWASP A02:2021 - Cryptographic Failures
- **CWE:** CWE-798: Use of Hard-coded Credentials
- **References:** https://owasp.org/Top10/A02_2021-Cryptographic_Failures/, https://cwe.mitre.org/data/definitions/798.html

### F-007437 - CRYPTO [CRITICAL]

- **Location:** data\static\i18n\ar_SA.json:169
- **Category:** Secrets
- **Detection confidence:** 1.0
- **Root cause:** A cryptocurrency wallet address or private key was committed directly into source instead of being retrieved from secure key storage at runtime.
- **Likely developer mistake:** Pasting a real wallet address or key into code or a config file for convenience during development.
- **Security impact:** Exposed wallet keys can be used to irreversibly move funds; unlike a password, a crypto private key cannot be revoked.
- **Recommended fix:** Remove hardcoded cryptocurrency wallet addresses/keys from source. Store private keys in a secrets manager, never in code.
- **Security best practice:** Never store private keys or wallet credentials in source; load them from a hardware wallet, HSM, or secrets manager.
- **OWASP:** OWASP A02:2021 - Cryptographic Failures
- **CWE:** CWE-798: Use of Hard-coded Credentials
- **References:** https://owasp.org/Top10/A02_2021-Cryptographic_Failures/, https://cwe.mitre.org/data/definitions/798.html

### F-007438 - CRYPTO [CRITICAL]

- **Location:** data\static\i18n\ar_SA.json:169
- **Category:** Secrets
- **Detection confidence:** 1.0
- **Root cause:** A cryptocurrency wallet address or private key was committed directly into source instead of being retrieved from secure key storage at runtime.
- **Likely developer mistake:** Pasting a real wallet address or key into code or a config file for convenience during development.
- **Security impact:** Exposed wallet keys can be used to irreversibly move funds; unlike a password, a crypto private key cannot be revoked.
- **Recommended fix:** Remove hardcoded cryptocurrency wallet addresses/keys from source. Store private keys in a secrets manager, never in code.
- **Security best practice:** Never store private keys or wallet credentials in source; load them from a hardware wallet, HSM, or secrets manager.
- **OWASP:** OWASP A02:2021 - Cryptographic Failures
- **CWE:** CWE-798: Use of Hard-coded Credentials
- **References:** https://owasp.org/Top10/A02_2021-Cryptographic_Failures/, https://cwe.mitre.org/data/definitions/798.html

### F-008077 - CRYPTO [CRITICAL]

- **Location:** data\static\i18n\az_AZ.json:169
- **Category:** Secrets
- **Detection confidence:** 1.0
- **Root cause:** A cryptocurrency wallet address or private key was committed directly into source instead of being retrieved from secure key storage at runtime.
- **Likely developer mistake:** Pasting a real wallet address or key into code or a config file for convenience during development.
- **Security impact:** Exposed wallet keys can be used to irreversibly move funds; unlike a password, a crypto private key cannot be revoked.
- **Recommended fix:** Remove hardcoded cryptocurrency wallet addresses/keys from source. Store private keys in a secrets manager, never in code.
- **Security best practice:** Never store private keys or wallet credentials in source; load them from a hardware wallet, HSM, or secrets manager.
- **OWASP:** OWASP A02:2021 - Cryptographic Failures
- **CWE:** CWE-798: Use of Hard-coded Credentials
- **References:** https://owasp.org/Top10/A02_2021-Cryptographic_Failures/, https://cwe.mitre.org/data/definitions/798.html

### F-008078 - CRYPTO [CRITICAL]

- **Location:** data\static\i18n\az_AZ.json:169
- **Category:** Secrets
- **Detection confidence:** 1.0
- **Root cause:** A cryptocurrency wallet address or private key was committed directly into source instead of being retrieved from secure key storage at runtime.
- **Likely developer mistake:** Pasting a real wallet address or key into code or a config file for convenience during development.
- **Security impact:** Exposed wallet keys can be used to irreversibly move funds; unlike a password, a crypto private key cannot be revoked.
- **Recommended fix:** Remove hardcoded cryptocurrency wallet addresses/keys from source. Store private keys in a secrets manager, never in code.
- **Security best practice:** Never store private keys or wallet credentials in source; load them from a hardware wallet, HSM, or secrets manager.
- **OWASP:** OWASP A02:2021 - Cryptographic Failures
- **CWE:** CWE-798: Use of Hard-coded Credentials
- **References:** https://owasp.org/Top10/A02_2021-Cryptographic_Failures/, https://cwe.mitre.org/data/definitions/798.html

### F-008740 - CRYPTO [CRITICAL]

- **Location:** data\static\i18n\bg_BG.json:169
- **Category:** Secrets
- **Detection confidence:** 1.0
- **Root cause:** A cryptocurrency wallet address or private key was committed directly into source instead of being retrieved from secure key storage at runtime.
- **Likely developer mistake:** Pasting a real wallet address or key into code or a config file for convenience during development.
- **Security impact:** Exposed wallet keys can be used to irreversibly move funds; unlike a password, a crypto private key cannot be revoked.
- **Recommended fix:** Remove hardcoded cryptocurrency wallet addresses/keys from source. Store private keys in a secrets manager, never in code.
- **Security best practice:** Never store private keys or wallet credentials in source; load them from a hardware wallet, HSM, or secrets manager.
- **OWASP:** OWASP A02:2021 - Cryptographic Failures
- **CWE:** CWE-798: Use of Hard-coded Credentials
- **References:** https://owasp.org/Top10/A02_2021-Cryptographic_Failures/, https://cwe.mitre.org/data/definitions/798.html

...and 85367 more finding(s). See `dashboard.json` for category-level aggregates or the full JSON report for every finding.

## Secure Coding Recommendations (by category)

- **CREDIT_CARD** (CRITICAL): OWASP A02:2021 - Cryptographic Failures / CWE-312: Cleartext Storage of Sensitive Information -- Never store raw payment card numbers in code, config, or logs; tokenize via a PCI-compliant payment processor.
- **MEDICAL_LICENSE** (CRITICAL): OWASP A01:2021 - Broken Access Control / CWE-359: Exposure of Private Personal Information to an Unauthorized Actor -- Never hardcode medical license numbers; use synthetic practitioner data in tests.
- **CRYPTO** (CRITICAL): OWASP A02:2021 - Cryptographic Failures / CWE-798: Use of Hard-coded Credentials -- Never store private keys or wallet credentials in source; load them from a hardware wallet, HSM, or secrets manager.
- **UK_NHS** (CRITICAL): OWASP A01:2021 - Broken Access Control / CWE-359: Exposure of Private Personal Information to an Unauthorized Actor -- Never hardcode health-system identifiers; use synthetic patient data in tests.
- **PERSON** (HIGH): OWASP A01:2021 - Broken Access Control / CWE-359: Exposure of Private Personal Information to an Unauthorized Actor -- Use synthetic names in code, comments, and test fixtures.
- **LOCATION** (HIGH): OWASP A01:2021 - Broken Access Control / CWE-359: Exposure of Private Personal Information to an Unauthorized Actor -- Use synthetic addresses/locations in test data instead of real, individual-linked locations.
- **EMAIL_ADDRESS** (HIGH): OWASP A01:2021 - Broken Access Control / CWE-200: Exposure of Sensitive Information to an Unauthorized Actor -- Use synthetic example addresses (e.g. user@example.com) in code, fixtures, and documentation.
- **IP_ADDRESS** (HIGH): OWASP A05:2021 - Security Misconfiguration / CWE-200: Exposure of Sensitive Information to an Unauthorized Actor -- Move environment-specific IP addresses into configuration or secrets management rather than hardcoding in source.
- **US_DRIVER_LICENSE** (HIGH): OWASP A01:2021 - Broken Access Control / CWE-359: Exposure of Private Personal Information to an Unauthorized Actor -- Never hardcode driver's license numbers; use synthetic identity documents in tests.
- **PHONE_NUMBER** (HIGH): OWASP A01:2021 - Broken Access Control / CWE-200: Exposure of Sensitive Information to an Unauthorized Actor -- Use a reserved test number range (e.g. 555-01xx) instead of real phone numbers.
- **ORGANIZATION** (MEDIUM): OWASP A01:2021 - Broken Access Control / CWE-200: Exposure of Sensitive Information to an Unauthorized Actor -- Avoid committing confidential customer, partner, vendor, supplier, or internal project names; use synthetic organization names in source, documentation, logs, and test datasets unless the names are intentionally public.
- **URL** (LOW): OWASP A05:2021 - Security Misconfiguration / CWE-200: Exposure of Sensitive Information to an Unauthorized Actor -- Move environment-specific or credentialed URLs into configuration/secrets rather than hardcoding in source.
- **DATE_TIME** (LOW): OWASP A01:2021 - Broken Access Control / CWE-359: Exposure of Private Personal Information to an Unauthorized Actor -- Use synthetic dates in test data if a date is tied to a real individual (e.g. a date of birth).
- **NRP** (LOW): OWASP A01:2021 - Broken Access Control / CWE-359: Exposure of Private Personal Information to an Unauthorized Actor -- Avoid recording real, individual-linked nationality/religious/political detail in code, fixtures, or logs.
