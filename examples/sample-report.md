# SecuGuard check results

Run `20261112T225055Z-752165-66fc`. Account `123456789012` in `us-east-1` (mock mode). Evidence collected 2026-11-12T22:50:56Z.

**7 passed, 19 failed, 0 could not be assessed, 0 not applicable.**

## Checks

| Check | Result | Severity | What was checked | PCI DSS | SOC 2 | FedRAMP 20x |
|---|---|---|---|---|---|---|
| NET-01 | FAIL | high | No administrative port is open to the internet | 1.3.1, 1.4.2 | CC6.6 | KSI-CNA-RNT, KSI-CNA-MAT |
| NET-02 | FAIL | high | The card data zone accepts traffic only from in-scope systems | 1.3.1, 1.4.1 | CC6.1, CC6.6 | KSI-CNA-ULN, KSI-CNA-RNT |
| NET-03 | PASS | medium | Default security groups allow nothing | 1.2.1 | CC6.6 | KSI-CNA-MAT |
| NET-04 | FAIL | medium | Network traffic is logged | 10.2.1 | CC7.2 | KSI-MLA-LET |
| CRY-01 | FAIL | medium | Encryption keys rotate automatically | 3.7.4 | CC6.1 | KSI-SVC-ASM |
| CRY-02 | FAIL | medium | Storage is encrypted with keys SecuGuard controls | 3.5.1, 3.6.1 | CC6.1, CC6.7 | KSI-SVC-SIN |
| CRY-03 | FAIL | high | Storage cannot be made public | 1.4.4 | CC6.1, CC6.6 | KSI-CNA-MAT, KSI-SVC-SIN |
| CRY-04 | FAIL | high | Certificates use strong keys and signatures | 4.2.1 | CC6.7 | KSI-SVC-SIN, KSI-SVC-VCM |
| CRY-05 | FAIL | high | No certificate is expired or about to expire | 4.2.1, 4.2.1.1 | CC6.7 | KSI-SVC-ASM |
| CRY-06 | FAIL | high | Connections require TLS 1.2 or newer | 4.2.1 | CC6.7 | KSI-SVC-VCM, KSI-SVC-SIN |
| CRY-07 | FAIL | medium | Certificates in use are issued by a certificate authority | 4.2.1 | CC6.7 | KSI-SVC-VCM |
| SCP-01 | FAIL | medium | Every part of the network has a declared PCI scope | 12.5.2, 1.2.3 | CC3.4, CC6.1 | KSI-PIY-GIV |
| SCP-02 | FAIL | high | Declared PCI scope matches the firewall rules | 12.5.2, 1.3.1 | CC3.4, CC6.6 | KSI-CNA-ULN, KSI-CNA-EIS |
| SCP-03 | FAIL | high | The network matches the approved scope baseline | 12.5.2, 1.2.2 | CC3.4, CC8.1 | KSI-PIY-GIV, KSI-CMT-LMC |
| SCP-04 | PASS | high | The card data zone has no route to the internet | 1.4.4, 1.3.2 | CC6.6 | KSI-CNA-RNT, KSI-CNA-MAT |
| IAM-01 | FAIL | high | The root user has MFA | 8.4.1 | CC6.1 | KSI-IAM-APM |
| IAM-02 | PASS | high | The root user has no access keys | 8.2.2 | CC6.1, CC6.3 | KSI-IAM-ELP |
| IAM-03 | PASS | medium | A strong password policy is set | 8.3.6 | CC6.1 | KSI-IAM-APM |
| IAM-04 | FAIL | high | Every user who can sign in has MFA | 8.4.2 | CC6.1 | KSI-IAM-APM |
| IAM-05 | FAIL | high | No user holds administrator rights directly | 7.2.1, 7.2.2 | CC6.3 | KSI-IAM-ELP |
| IAM-06 | FAIL | medium | Access keys are in use and not stale | 8.2.6, 8.6.3 | CC6.2, CC6.3 | KSI-IAM-SNU, KSI-SVC-ASM |
| IAM-07 | FAIL | medium | Outside accounts need an external ID to use a role | 7.2.1, 8.2.7 | CC6.1, CC9.2 | KSI-IAM-ELP, KSI-IAM-SNU |
| LOG-01 | PASS | high | Account activity is recorded and the record is protected | 10.2.1, 10.3.4 | CC7.2 | KSI-MLA-LET, KSI-CMT-LMC |
| MON-01 | PASS | high | Every change to the account's resources is recorded | 2.2.1, 12.5.1 | CC7.1 | KSI-CMT-LMC, KSI-PIY-GIV |
| MON-02 | FAIL | medium | The account is evaluated continuously against a security standard | 2.2.1 | CC4.1, CC7.1 | KSI-MLA-EVC, KSI-CNA-EIS |
| LOG-02 | PASS | high | Compliance evidence cannot be altered or deleted | 10.3.2, 10.5.1 | CC7.2 | KSI-SVC-VRI, KSI-SVC-SIN |

## Findings

**NET-01: No administrative port is open to the internet.** SSH and Remote Desktop open to everyone is one of the most common ways attackers get in.

- security group secuguard-planted-open-admin (sg-e1003d6a40009d65c): open to the whole internet: SSH (port 22)

**NET-02: The card data zone accepts traffic only from in-scope systems.** Anything allowed to reach the cardholder data environment falls under PCI DSS. Unplanned paths widen scope.

- security group secuguard-cde (sg-cf8635368ad008a71): accepts traffic from sg-3727fc01f0fee94b2, tagged out-of-scope

**NET-04: Network traffic is logged.** Without flow logs there is no record of who connected to what when investigating an incident.

- VPC default (vpc-434d96aa41c404b26): no flow logs, so network traffic is not recorded

**CRY-01: Encryption keys rotate automatically.** A key that never changes protects more and more data with one secret. Rotation limits the damage if it leaks.

- KMS key alias/secuguard-legacy-no-rotation: automatic rotation is off

**CRY-02: Storage is encrypted with keys SecuGuard controls.** With its own keys, SecuGuard decides who can decrypt, can see every use of the key, and can revoke access.

- bucket secuguard-legacy-exports-123456789012: not encrypted with a customer managed key (uses the AWS default)

**CRY-03: Storage cannot be made public.** Publicly readable storage buckets are a leading cause of cloud data leaks.

- bucket secuguard-legacy-exports-123456789012: public access protections switched off: BlockPublicAcls, IgnorePublicAcls, BlockPublicPolicy, RestrictPublicBuckets

**CRY-04: Certificates use strong keys and signatures.** Short keys and outdated signature methods can be broken, letting an attacker impersonate the service.

- certificate legacy-api.secuguard.example: RSA key of 1024 bits, below the 2048-bit minimum

**CRY-05: No certificate is expired or about to expire.** An expired certificate causes an outage, and pushes people to click through security warnings.

- certificate legacy-api.secuguard.example: expires in 19 days, inside the 30-day warning window

**CRY-06: Connections require TLS 1.2 or newer.** TLS 1.0 and 1.1 have known weaknesses and are not accepted as strong cryptography.

- load balancer secuguard-portal port 443: TLS policy ELBSecurityPolicy-2016-08 still allows TLS 1.0 or 1.1

**CRY-07: Certificates in use are issued by a certificate authority.** A self-signed certificate has nobody vouching for it. Systems told to trust it can be fooled by a fake.

- certificate portal.secuguard.example: self-signed, and in use by load balancer secuguard-portal. No certificate authority vouches for it.

**SCP-01: Every part of the network has a declared PCI scope.** Scope is the first thing a PCI assessor confirms. Anything unlabelled is a decision nobody made.

- security group secuguard-planted-unclassified: has no PCI scope tag, so nobody has decided whether PCI DSS applies to it

**SCP-02: Declared PCI scope matches the firewall rules.** A system labelled out of scope that can reach card data is in scope, and is not getting PCI controls.

- security group secuguard-planted-analytics: declared out-of-scope, but it can reach the card data zone (port 5432 on secuguard-cde), so PCI DSS applies to it

**SCP-03: The network matches the approved scope baseline.** Scope should change only when someone decides it should. Anything new or altered needs review.

- security group secuguard-planted-analytics: not in the approved baseline (declared out-of-scope)
- security group secuguard-planted-open-admin: not in the approved baseline (declared out-of-scope)
- security group secuguard-planted-unclassified: not in the approved baseline (declared with no scope)

**IAM-01: The root user has MFA.** The root user can do anything, including closing the account. A password alone is not enough protection.

- root user: MFA is not on

**IAM-04: Every user who can sign in has MFA.** A stolen or guessed password should not be enough to get into the account.

- user secuguard-dev-alice: can sign in to the console with a password and no MFA

**IAM-05: No user holds administrator rights directly.** Broad rights attached to one user are easy to forget and hard to review. Rights should come from groups or roles.

- user secuguard-svc-reports: has AdministratorAccess attached directly

**IAM-06: Access keys are in use and not stale.** Unused and old keys are credentials nobody is watching. They should be removed or replaced.

- user secuguard-svc-reports access key ending YL67: active but has never been used

**IAM-07: Outside accounts need an external ID to use a role.** Without an external ID, a vendor's other customers could trick the vendor into using this role.

- role secuguard-legacy-vendor: trusts outside account 127311923021 with no external ID

**MON-02: The account is evaluated continuously against a security standard.** A standard that is checked automatically every day catches misconfigurations that an annual review misses.

- account: Security Hub is not switched on, so nothing is evaluating the account against a standard

## PCI scope of the network

What each part of the network is declared to be, and what the firewall rules make it.

| Kind | Name | Declared | Actually | Reaches the card data zone by |
|---|---|---|---|---|
| security group | secuguard-cde | cde | cde |  |
| security group | secuguard-corporate | out-of-scope | out-of-scope |  |
| security group | secuguard-planted-analytics | out-of-scope | connected | port 5432 on secuguard-cde |
| security group | secuguard-planted-open-admin | out-of-scope | out-of-scope |  |
| security group | secuguard-planted-unclassified | not declared | out-of-scope |  |
| security group | secuguard-shared | connected | connected | port 443 on secuguard-cde |
| subnet | secuguard-cde-a | cde | cde |  |
| subnet | secuguard-cde-b | cde | cde |  |
| subnet | secuguard-corporate-a | out-of-scope | out-of-scope |  |
| subnet | secuguard-corporate-b | out-of-scope | out-of-scope |  |
| subnet | secuguard-shared-a | connected | connected |  |
| subnet | secuguard-shared-b | connected | connected |  |

## Certificate inventory

| Name | Issuer | Key | Signature | Expires | In use by |
|---|---|---|---|---|---|
| legacy-api.secuguard.example | self-signed | RSA 1024 | SHA256 | 2026-12-02 | nothing |
| portal.secuguard.example | self-signed | RSA 2048 | SHA256 | 2027-11-12 | load balancer secuguard-portal |

## By framework

### FedRAMP 20x

| Requirement | Result | Checks |
|---|---|---|
| KSI-CMT-LMC | FAIL | SCP-03, LOG-01, MON-01 |
| KSI-CNA-EIS | FAIL | SCP-02, MON-02 |
| KSI-CNA-MAT | FAIL | NET-01, NET-03, CRY-03, SCP-04 |
| KSI-CNA-RNT | FAIL | NET-01, NET-02, SCP-04 |
| KSI-CNA-ULN | FAIL | NET-02, SCP-02 |
| KSI-IAM-APM | FAIL | IAM-01, IAM-03, IAM-04 |
| KSI-IAM-ELP | FAIL | IAM-02, IAM-05, IAM-07 |
| KSI-IAM-SNU | FAIL | IAM-06, IAM-07 |
| KSI-MLA-EVC | FAIL | MON-02 |
| KSI-MLA-LET | FAIL | NET-04, LOG-01 |
| KSI-PIY-GIV | FAIL | SCP-01, SCP-03, MON-01 |
| KSI-SVC-ASM | FAIL | CRY-01, CRY-05, IAM-06 |
| KSI-SVC-SIN | FAIL | CRY-02, CRY-03, CRY-04, CRY-06, LOG-02 |
| KSI-SVC-VCM | FAIL | CRY-04, CRY-06, CRY-07 |
| KSI-SVC-VRI | PASS | LOG-02 |

### PCI DSS 4.0.1

| Requirement | Result | Checks |
|---|---|---|
| 1.2.1 | PASS | NET-03 |
| 1.2.2 | FAIL | SCP-03 |
| 1.2.3 | FAIL | SCP-01 |
| 1.3.1 | FAIL | NET-01, NET-02, SCP-02 |
| 1.3.2 | PASS | SCP-04 |
| 1.4.1 | FAIL | NET-02 |
| 1.4.2 | FAIL | NET-01 |
| 1.4.4 | FAIL | CRY-03, SCP-04 |
| 2.2.1 | FAIL | MON-01, MON-02 |
| 3.5.1 | FAIL | CRY-02 |
| 3.6.1 | FAIL | CRY-02 |
| 3.7.4 | FAIL | CRY-01 |
| 4.2.1 | FAIL | CRY-04, CRY-05, CRY-06, CRY-07 |
| 4.2.1.1 | FAIL | CRY-05 |
| 7.2.1 | FAIL | IAM-05, IAM-07 |
| 7.2.2 | FAIL | IAM-05 |
| 8.2.2 | PASS | IAM-02 |
| 8.2.6 | FAIL | IAM-06 |
| 8.2.7 | FAIL | IAM-07 |
| 8.3.6 | PASS | IAM-03 |
| 8.4.1 | FAIL | IAM-01 |
| 8.4.2 | FAIL | IAM-04 |
| 8.6.3 | FAIL | IAM-06 |
| 10.2.1 | FAIL | NET-04, LOG-01 |
| 10.3.2 | PASS | LOG-02 |
| 10.3.4 | PASS | LOG-01 |
| 10.5.1 | PASS | LOG-02 |
| 12.5.1 | PASS | MON-01 |
| 12.5.2 | FAIL | SCP-01, SCP-02, SCP-03 |

### SOC 2

| Requirement | Result | Checks |
|---|---|---|
| CC3.4 | FAIL | SCP-01, SCP-02, SCP-03 |
| CC4.1 | FAIL | MON-02 |
| CC6.1 | FAIL | NET-02, CRY-01, CRY-02, CRY-03, SCP-01, IAM-01, IAM-02, IAM-03, IAM-04, IAM-07 |
| CC6.2 | FAIL | IAM-06 |
| CC6.3 | FAIL | IAM-02, IAM-05, IAM-06 |
| CC6.6 | FAIL | NET-01, NET-02, NET-03, CRY-03, SCP-02, SCP-04 |
| CC6.7 | FAIL | CRY-02, CRY-04, CRY-05, CRY-06, CRY-07 |
| CC7.1 | FAIL | MON-01, MON-02 |
| CC7.2 | FAIL | NET-04, LOG-01, LOG-02 |
| CC8.1 | FAIL | SCP-03 |
| CC9.2 | FAIL | IAM-07 |

