# FedRAMP 20x Key Security Indicator validation

Rules version 2026.11.02.01. Evidence collected 2026-11-12T22:50:56Z.

**16 of 46 indicators addressed: 1 validated, 14 failing, 1 covered by a preventive control only, 0 without evidence. 30 not covered.**

Indicator names and statements are FedRAMP's own text. The validation format is this project's own.

| Indicator | Status | Name | Checks |
|---|---|---|---|
| KSI-CMT-LMC | FAILING | Logging Changes | SCP-03 (fail), LOG-01 (pass), MON-01 (pass) |
| KSI-CMT-VTD | PREVENTIVE | Validating Throughout Deployment | plan check rules |
| KSI-CNA-EIS | FAILING | Enforcing Intended State | SCP-02 (fail), MON-02 (fail) |
| KSI-CNA-MAT | FAILING | Minimizing Attack Surface | NET-01 (fail), NET-03 (pass), CRY-03 (fail), SCP-04 (pass) |
| KSI-CNA-RNT | FAILING | Restricting Network Traffic | NET-01 (fail), NET-02 (fail), SCP-04 (pass) |
| KSI-CNA-ULN | FAILING | Using Logical Networking | NET-02 (fail), SCP-02 (fail) |
| KSI-IAM-APM | FAILING | Adopting Passwordless Methods | IAM-01 (fail), IAM-03 (pass), IAM-04 (fail) |
| KSI-IAM-ELP | FAILING | Ensuring Least Privilege | IAM-02 (pass), IAM-05 (fail), IAM-07 (fail) |
| KSI-IAM-SNU | FAILING | Securing Non-User Authentication | IAM-06 (fail), IAM-07 (fail) |
| KSI-MLA-EVC | FAILING | Evaluating Configurations | MON-02 (fail) |
| KSI-MLA-LET | FAILING | Logging Event Types | NET-04 (fail), LOG-01 (pass) |
| KSI-PIY-GIV | FAILING | Generating Inventories | SCP-01 (fail), SCP-03 (fail), MON-01 (pass) |
| KSI-SVC-ASM | FAILING | Automating Secret Management | CRY-01 (fail), CRY-05 (fail), IAM-06 (fail) |
| KSI-SVC-SIN | FAILING | Securing Information | CRY-02 (fail), CRY-03 (fail), CRY-04 (fail), CRY-06 (fail), LOG-02 (pass) |
| KSI-SVC-VCM | FAILING | Validating Communications | CRY-04 (fail), CRY-06 (fail), CRY-07 (fail) |
| KSI-SVC-VRI | VALIDATED | Validating Resource Integrity | LOG-02 (pass) |

## Detail

### KSI-CMT-LMC: Logging Changes (FAILING)

> Modifications to the cloud service offering are logged and monitored.

**What this project establishes.** AWS Config records every change to resources, CloudTrail records who made it, and scope changes are compared with an approved baseline.

**What it does not establish.** Review of those logs by a person or an alerting system.

- SCP-03 FAIL: The network matches the approved scope baseline
    - security group secuguard-planted-analytics: not in the approved baseline (declared out-of-scope)
    - security group secuguard-planted-open-admin: not in the approved baseline (declared out-of-scope)
    - security group secuguard-planted-unclassified: not in the approved baseline (declared with no scope)
- LOG-01 PASS: Account activity is recorded and the record is protected
- MON-01 PASS: Every change to the account's resources is recorded

### KSI-CMT-VTD: Validating Throughout Deployment (PREVENTIVE)

> Persistent testing and validation of changes throughout deployment is automated.

**What this project establishes.** Planned changes are validated by automated rules before deployment, and the deployed result is checked again on the next run.

**What it does not establish.** Testing during deployment itself, such as staged rollouts.

- Plan check: PLAN-01, PLAN-02, PLAN-03, PLAN-04, PLAN-05, PLAN-06, PLAN-07, PLAN-08 applied to every planned change

### KSI-CNA-EIS: Enforcing Intended State (FAILING)

> Class B: **Optional:** Automated services are used to persistently assess the security of all machine-based information resources and automatically enforce their intended operational state. Class C: Automated services are used to persistently assess the security of all machine-based information resources and automatically enforce their intended operational state.

**What this project establishes.** Declared PCI scope is compared with actual connectivity, and Security Hub evaluates the account against a standard.

**What it does not establish.** Automatic correction. Drift is reported, not reverted.

- SCP-02 FAIL: Declared PCI scope matches the firewall rules
    - security group secuguard-planted-analytics: declared out-of-scope, but it can reach the card data zone (port 5432 on secuguard-cde), so PCI DSS applies to it
- MON-02 FAIL: The account is evaluated continuously against a security standard
    - account: Security Hub is not switched on, so nothing is evaluating the account against a standard

### KSI-CNA-MAT: Minimizing Attack Surface (FAILING)

> Machine-based information resources are persistently reviewed to ensure they have a minimal attack surface and that lateral movement is minimized if compromised.

**What this project establishes.** Default firewall groups, internet-facing administrative ports, public storage settings, and internet routes are checked on every run.

**What it does not establish.** Software and services running on servers. This environment has no servers.

- NET-01 FAIL: No administrative port is open to the internet
    - security group secuguard-planted-open-admin (sg-e1003d6a40009d65c): open to the whole internet: SSH (port 22)
- NET-03 PASS: Default security groups allow nothing
- CRY-03 FAIL: Storage cannot be made public
    - bucket secuguard-legacy-exports-123456789012: public access protections switched off: BlockPublicAcls, IgnorePublicAcls, BlockPublicPolicy, RestrictPublicBuckets
- SCP-04 PASS: The card data zone has no route to the internet

### KSI-CNA-RNT: Restricting Network Traffic (FAILING)

> Machine-based information resources are persistently reviewed to ensure they are appropriately configured to limit inbound and outbound network traffic.

**What this project establishes.** Firewall rules are read on every run and checked for administrative ports open to the internet, for what may enter the card data zone, and for routes to the internet.

**What it does not establish.** Outbound traffic rules, and anything enforced outside AWS security groups and route tables.

- NET-01 FAIL: No administrative port is open to the internet
    - security group secuguard-planted-open-admin (sg-e1003d6a40009d65c): open to the whole internet: SSH (port 22)
- NET-02 FAIL: The card data zone accepts traffic only from in-scope systems
    - security group secuguard-cde (sg-cf8635368ad008a71): accepts traffic from sg-3727fc01f0fee94b2, tagged out-of-scope
- SCP-04 PASS: The card data zone has no route to the internet

### KSI-CNA-ULN: Using Logical Networking (FAILING)

> Logical networking and related capabilities are used and persistently reviewed to enforce traffic flow controls.

**What this project establishes.** The network is split into labelled zones, and the labels are compared with the real firewall rules on every run.

**What it does not establish.** Network controls inside a zone, between systems that share a security group.

- NET-02 FAIL: The card data zone accepts traffic only from in-scope systems
    - security group secuguard-cde (sg-cf8635368ad008a71): accepts traffic from sg-3727fc01f0fee94b2, tagged out-of-scope
- SCP-02 FAIL: Declared PCI scope matches the firewall rules
    - security group secuguard-planted-analytics: declared out-of-scope, but it can reach the card data zone (port 5432 on secuguard-cde), so PCI DSS applies to it

### KSI-IAM-APM: Adopting Passwordless Methods (FAILING)

> Secure passwordless methods are used for user authentication and authorization when feasible, otherwise strong passwords with phishing-resistant MFA is used.

**What this project establishes.** Root user MFA, MFA for every user with a console password, and the password policy are checked on every run.

**What it does not establish.** Whether the MFA in use is phishing-resistant, and identities managed in IAM Identity Center.

- IAM-01 FAIL: The root user has MFA
    - root user: MFA is not on
- IAM-03 PASS: A strong password policy is set
- IAM-04 FAIL: Every user who can sign in has MFA
    - user secuguard-dev-alice: can sign in to the console with a password and no MFA

### KSI-IAM-ELP: Ensuring Least Privilege (FAILING)

> Identity and access management measures are used and persistently reviewed to ensure each user or device can only access the resources they need.

**What this project establishes.** Users with administrator rights attached directly, root access keys, and roles that outside accounts may use are checked on every run.

**What it does not establish.** Whether each identity's rights are the minimum its job needs. That takes a review of each policy.

- IAM-02 PASS: The root user has no access keys
- IAM-05 FAIL: No user holds administrator rights directly
    - user secuguard-svc-reports: has AdministratorAccess attached directly
- IAM-07 FAIL: Outside accounts need an external ID to use a role
    - role secuguard-legacy-vendor: trusts outside account 127311923021 with no external ID

### KSI-IAM-SNU: Securing Non-User Authentication (FAILING)

> Appropriately secure authentication methods are used and persistently reviewed for non-user accounts and services.

**What this project establishes.** Access keys that are unused or older than 90 days, and outside-account trust, are checked on every run.

**What it does not establish.** Automatic disabling. Stale credentials are reported, not switched off.

- IAM-06 FAIL: Access keys are in use and not stale
    - user secuguard-svc-reports access key ending YL67: active but has never been used
- IAM-07 FAIL: Outside accounts need an external ID to use a role
    - role secuguard-legacy-vendor: trusts outside account 127311923021 with no external ID

### KSI-MLA-EVC: Evaluating Configurations (FAILING)

> The configuration of machine-based information resources, especially infrastructure as code, is persistently evaluated and tested.

**What this project establishes.** Every planned Terraform change is tested against rules before it is applied, and Security Hub evaluates the running account.

**What it does not establish.** Enforcement on every change. The plan check is run by choice on the author's computer until it is wired into GitHub.

- MON-02 FAIL: The account is evaluated continuously against a security standard
    - account: Security Hub is not switched on, so nothing is evaluating the account against a standard
- Plan check: PLAN-01, PLAN-02, PLAN-03, PLAN-04, PLAN-05, PLAN-06, PLAN-07, PLAN-08 applied to every planned change

### KSI-MLA-LET: Logging Event Types (FAILING)

> A list of information resources and event types that will be logged, monitored, and audited is maintained and persistently reviewed to ensure these activities occur.

**What this project establishes.** CloudTrail and network flow logging are checked on every run, including whether the trail covers every region and validates its files.

**What it does not establish.** A written list of which event types are logged and why.

- NET-04 FAIL: Network traffic is logged
    - VPC default (vpc-434d96aa41c404b26): no flow logs, so network traffic is not recorded
- LOG-01 PASS: Account activity is recorded and the record is protected

### KSI-PIY-GIV: Generating Inventories (FAILING)

> Authoritative sources are used to automatically generate real-time inventories of all information resources when needed.

**What this project establishes.** AWS Config keeps a live inventory of resources, and each run records the network, identities, keys, certificates, and storage directly from AWS.

**What it does not establish.** Software, data, and anything outside this AWS account and region.

- SCP-01 FAIL: Every part of the network has a declared PCI scope
    - security group secuguard-planted-unclassified: has no PCI scope tag, so nobody has decided whether PCI DSS applies to it
- SCP-03 FAIL: The network matches the approved scope baseline
    - security group secuguard-planted-analytics: not in the approved baseline (declared out-of-scope)
    - security group secuguard-planted-open-admin: not in the approved baseline (declared out-of-scope)
    - security group secuguard-planted-unclassified: not in the approved baseline (declared with no scope)
- MON-01 PASS: Every change to the account's resources is recorded

### KSI-SVC-ASM: Automating Secret Management (FAILING)

> Management, protection, and regular rotation of digital keys, certificates, and other secrets is automated and persistently reviewed.

**What this project establishes.** Encryption key rotation, certificate expiry, and access key age are checked on every run.

**What it does not establish.** Secrets held outside AWS KMS, ACM, and IAM, such as passwords in application settings.

- CRY-01 FAIL: Encryption keys rotate automatically
    - KMS key alias/secuguard-legacy-no-rotation: automatic rotation is off
- CRY-05 FAIL: No certificate is expired or about to expire
    - certificate legacy-api.secuguard.example: expires in 19 days, inside the 30-day warning window
- IAM-06 FAIL: Access keys are in use and not stale
    - user secuguard-svc-reports access key ending YL67: active but has never been used

### KSI-SVC-SIN: Securing Information (FAILING)

> Information is encrypted or otherwise secured from unwanted access or modification.

**What this project establishes.** Storage encryption, public access settings, certificate strength, TLS versions, and the evidence lock are checked on every run.

**What it does not establish.** Encryption inside applications and databases. This environment has none.

- CRY-02 FAIL: Storage is encrypted with keys SecuGuard controls
    - bucket secuguard-legacy-exports-123456789012: not encrypted with a customer managed key (uses the AWS default)
- CRY-03 FAIL: Storage cannot be made public
    - bucket secuguard-legacy-exports-123456789012: public access protections switched off: BlockPublicAcls, IgnorePublicAcls, BlockPublicPolicy, RestrictPublicBuckets
- CRY-04 FAIL: Certificates use strong keys and signatures
    - certificate legacy-api.secuguard.example: RSA key of 1024 bits, below the 2048-bit minimum
- CRY-06 FAIL: Connections require TLS 1.2 or newer
    - load balancer secuguard-portal port 443: TLS policy ELBSecurityPolicy-2016-08 still allows TLS 1.0 or 1.1
- LOG-02 PASS: Compliance evidence cannot be altered or deleted

### KSI-SVC-VCM: Validating Communications (FAILING)

> Class B: **Optional:** The authenticity and integrity of communications between machine-based information resources is persistently validated using automation. Class C: The authenticity and integrity of communications between machine-based information resources is persistently validated using automation.

**What this project establishes.** Certificate key strength, signature method, issuer, and the TLS policy on each listener are checked on every run.

**What it does not establish.** Connections between systems inside the network, which are not inspected.

- CRY-04 FAIL: Certificates use strong keys and signatures
    - certificate legacy-api.secuguard.example: RSA key of 1024 bits, below the 2048-bit minimum
- CRY-06 FAIL: Connections require TLS 1.2 or newer
    - load balancer secuguard-portal port 443: TLS policy ELBSecurityPolicy-2016-08 still allows TLS 1.0 or 1.1
- CRY-07 FAIL: Certificates in use are issued by a certificate authority
    - certificate portal.secuguard.example: self-signed, and in use by load balancer secuguard-portal. No certificate authority vouches for it.

### KSI-SVC-VRI: Validating Resource Integrity (VALIDATED)

> Use cryptographic methods to validate the integrity of machine-based information resources.

**What this project establishes.** Every evidence file is hashed, each run is chained to the one before, and the store is locked against change.

**What it does not establish.** Integrity of deployed software. This environment deploys none.

- LOG-02 PASS: Compliance evidence cannot be altered or deleted

## Not covered

These indicators need evidence this project does not collect, such as policies, training records, incident response, recovery testing, and supplier reviews.

| Indicator | Theme | Name |
|---|---|---|
| KSI-CED-RAT | Cybersecurity Education | Reviewing All Training |
| KSI-CMT-RMV | Change Management | Redeploying vs Modifying |
| KSI-CMT-RVP | Change Management | Reviewing Change Procedures |
| KSI-CNA-DFP | Cloud Native Architecture | Defining Functionality and Privileges |
| KSI-CNA-IBP | Cloud Native Architecture | Implementing Best Practices |
| KSI-CNA-OFA | Cloud Native Architecture | Optimizing for Availability |
| KSI-CNA-RVP | Cloud Native Architecture | Reviewing Protections |
| KSI-IAM-AAM | Identity and Access Management | Automating Account Management |
| KSI-IAM-JIT | Identity and Access Management | Authorizing Just-in-Time |
| KSI-IAM-SUS | Identity and Access Management | Responding to Suspicious Activity |
| KSI-INR-AAR | Incident Response | Generating After Action Reports |
| KSI-INR-RIR | Incident Response | Reviewing Incident Response Procedures |
| KSI-INR-RPI | Incident Response | Reviewing Past Incidents |
| KSI-MLA-ALA | Monitoring, Logging, and Auditing | Authorizing Log Access |
| KSI-MLA-OSM | Monitoring, Logging, and Auditing | Operating SIEM Capability |
| KSI-MLA-RVL | Monitoring, Logging, and Auditing | Reviewing Logs |
| KSI-PIY-RES | Policy and Inventory | Reviewing Executive Support |
| KSI-PIY-RIS | Policy and Inventory | Reviewing Investments in Security |
| KSI-PIY-RSD | Policy and Inventory | Reviewing Security in the SDLC |
| KSI-PIY-RVD | Policy and Inventory | Reviewing Vulnerability Disclosures |
| KSI-RPL-ABO | Recovery Planning | Aligning Backups with Objectives |
| KSI-RPL-ARP | Recovery Planning | Aligning Recovery Plan |
| KSI-RPL-RRO | Recovery Planning | Reviewing Recovery Objectives |
| KSI-RPL-TRC | Recovery Planning | Testing Recovery Capabilities |
| KSI-SCR-MIT | Supply Chain Risk | Mitigating Supply Chain Risk |
| KSI-SCR-MON | Supply Chain Risk | Monitoring Supply Chain Risk |
| KSI-SVC-ACM | Service Configuration | Automating Configuration Management |
| KSI-SVC-EIS | Service Configuration | Evaluating and Improving Security |
| KSI-SVC-PRR | Service Configuration | Preventing Residual Risk |
| KSI-SVC-RUD | Service Configuration | Removing Unwanted Data |

