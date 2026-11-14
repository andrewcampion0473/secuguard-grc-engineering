# Checks and plan rules

The project has 26 checks, which grade collected evidence, and eight plan rules, which evaluate a proposed change before it's applied.

The mapping of checks to requirements is the author's reading of each framework. It's a starting point for discussion with an assessor, not an assessor's opinion.

To print this information from the project, run `secuguard checks`.

## Checks

### Network

| Check | Passes when | Severity | PCI DSS 4.0.1 | SOC 2 | FedRAMP 20x |
|---|---|---|---|---|---|
| NET-01 | No administrative port is open to the internet | High | 1.3.1, 1.4.2 | CC6.6 | KSI-CNA-RNT, KSI-CNA-MAT |
| NET-02 | The card data zone accepts traffic only from in-scope systems | High | 1.3.1, 1.4.1 | CC6.1, CC6.6 | KSI-CNA-ULN, KSI-CNA-RNT |
| NET-03 | Default security groups allow nothing | Medium | 1.2.1 | CC6.6 | KSI-CNA-MAT |
| NET-04 | Network traffic is logged | Medium | 10.2.1 | CC7.2 | KSI-MLA-LET |

### Encryption and certificates

| Check | Passes when | Severity | PCI DSS 4.0.1 | SOC 2 | FedRAMP 20x |
|---|---|---|---|---|---|
| CRY-01 | Encryption keys rotate automatically | Medium | 3.7.4 | CC6.1 | KSI-SVC-ASM |
| CRY-02 | Storage is encrypted with keys SecuGuard controls | Medium | 3.5.1, 3.6.1 | CC6.1, CC6.7 | KSI-SVC-SIN |
| CRY-03 | Storage cannot be made public | High | 1.4.4 | CC6.1, CC6.6 | KSI-CNA-MAT, KSI-SVC-SIN |
| CRY-04 | Certificates use strong keys and signatures | High | 4.2.1 | CC6.7 | KSI-SVC-SIN, KSI-SVC-VCM |
| CRY-05 | No certificate is expired or about to expire | High | 4.2.1, 4.2.1.1 | CC6.7 | KSI-SVC-ASM |
| CRY-06 | Connections require TLS 1.2 or newer | High | 4.2.1 | CC6.7 | KSI-SVC-VCM, KSI-SVC-SIN |
| CRY-07 | Certificates in use are issued by a certificate authority | Medium | 4.2.1 | CC6.7 | KSI-SVC-VCM |

### PCI scope

| Check | Passes when | Severity | PCI DSS 4.0.1 | SOC 2 | FedRAMP 20x |
|---|---|---|---|---|---|
| SCP-01 | Every part of the network has a declared PCI scope | Medium | 12.5.2, 1.2.3 | CC3.4, CC6.1 | KSI-PIY-GIV |
| SCP-02 | Declared PCI scope matches the firewall rules | High | 12.5.2, 1.3.1 | CC3.4, CC6.6 | KSI-CNA-ULN, KSI-CNA-EIS |
| SCP-03 | The network matches the approved scope baseline | High | 12.5.2, 1.2.2 | CC3.4, CC8.1 | KSI-PIY-GIV, KSI-CMT-LMC |
| SCP-04 | The card data zone has no route to the internet | High | 1.4.4, 1.3.2 | CC6.6 | KSI-CNA-RNT, KSI-CNA-MAT |

### Identity and access

| Check | Passes when | Severity | PCI DSS 4.0.1 | SOC 2 | FedRAMP 20x |
|---|---|---|---|---|---|
| IAM-01 | The root user has MFA | High | 8.4.1 | CC6.1 | KSI-IAM-APM |
| IAM-02 | The root user has no access keys | High | 8.2.2 | CC6.1, CC6.3 | KSI-IAM-ELP |
| IAM-03 | A strong password policy is set | Medium | 8.3.6 | CC6.1 | KSI-IAM-APM |
| IAM-04 | Every user who can sign in has MFA | High | 8.4.2 | CC6.1 | KSI-IAM-APM |
| IAM-05 | No user holds administrator rights directly | High | 7.2.1, 7.2.2 | CC6.3 | KSI-IAM-ELP |
| IAM-06 | Access keys are in use and not stale | Medium | 8.2.6, 8.6.3 | CC6.2, CC6.3 | KSI-IAM-SNU, KSI-SVC-ASM |
| IAM-07 | Outside accounts need an external ID to use a role | Medium | 7.2.1, 8.2.7 | CC6.1, CC9.2 | KSI-IAM-ELP, KSI-IAM-SNU |

### Logging

| Check | Passes when | Severity | PCI DSS 4.0.1 | SOC 2 | FedRAMP 20x |
|---|---|---|---|---|---|
| LOG-01 | Account activity is recorded and the record is protected | High | 10.2.1, 10.3.4 | CC7.2 | KSI-MLA-LET, KSI-CMT-LMC |
| LOG-02 | Compliance evidence cannot be altered or deleted | High | 10.3.2, 10.5.1 | CC7.2 | KSI-SVC-VRI, KSI-SVC-SIN |

### Monitoring

| Check | Passes when | Severity | PCI DSS 4.0.1 | SOC 2 | FedRAMP 20x |
|---|---|---|---|---|---|
| MON-01 | Every change to the account's resources is recorded | High | 2.2.1, 12.5.1 | CC7.1 | KSI-CMT-LMC, KSI-PIY-GIV |
| MON-02 | The account is evaluated continuously against a security standard | Medium | 2.2.1 | CC4.1, CC7.1 | KSI-MLA-EVC, KSI-CNA-EIS |

## Plan rules

Every plan rule supports PCI DSS 1.2.2, 6.5.1, SOC 2 CC8.1, and FedRAMP 20x KSI-MLA-EVC, KSI-CMT-VTD.

| Rule | A change is allowed when |
|---|---|
| PLAN-01 | No administrative port is opened to the internet |
| PLAN-02 | Only in-scope groups are let into the card data zone |
| PLAN-03 | New network resources declare their PCI scope |
| PLAN-04 | Encryption keys are created with rotation on |
| PLAN-05 | Storage keeps its public access protections |
| PLAN-06 | Listeners require TLS 1.2 or newer |
| PLAN-07 | The evidence vault is not weakened or removed |
| PLAN-08 | Administrator rights are not attached directly to a user |

To set a rule aside for one resource, see [Record an exception](../automate/make-changes.md#record-an-exception).

## Check results

| Result | Meaning |
|---|---|
| PASS | Every resource the check examined meets the rule. |
| FAIL | At least one resource doesn't meet the rule. Each one is named. |
| N/A | The account has no resources of that kind. |
| NO EVIDENCE | The evidence the check needs is missing or couldn't be collected, so the check draws no conclusion. |
