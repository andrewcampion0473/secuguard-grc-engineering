# Glossary

| Term | Definition |
|---|---|
| access portal | The web page where you sign in to AWS as your administrator user. |
| API call | A request that one program sends to another. The collectors make API calls to AWS to ask how resources are configured, and each evidence file lists the calls that produced it. |
| AWS | Amazon Web Services, the cloud provider that this project uses. |
| AWS Config | The AWS service that records every change to every resource. Check MON-01 confirms that it's recording. |
| baseline | The approved PCI scope of the network, with who approved it and when. It's stored in `scope-baseline.json`, and every run compares the network with it. |
| branch | A separate line of work in Git, where a change is made without affecting the main branch. |
| bucket | A storage container in Amazon S3. The evidence vault is a bucket. |
| CDE | Cardholder data environment. The systems that store, process, or transmit payment card data. In this project, it's the network zone tagged `cde`. |
| certificate | A file that proves a service's identity and lets connections to it be encrypted. Checks CRY-04, CRY-05, and CRY-07 test certificates. |
| chain | The link from each evidence run to the run before it. Each manifest records the fingerprint of the previous manifest, so a rewritten run breaks the link. |
| check | An automated test that reads collected evidence and returns pass or fail. The project has 26. See [Checks and plan rules](checks.md). |
| CloudTrail | The AWS service that records who did what in an account. Check LOG-01 confirms that it's on. |
| collector | A program that asks AWS about one subject, such as the network, and saves the answer as evidence. The project has nine. |
| commit | A saved snapshot of the project in Git, with a description of what changed. |
| evidence | A saved, sealed record of how something was configured at a specific time. |
| exception | A recorded decision to accept a broken rule, with a reason, an approver, and an end date. Exceptions are stored in `policy\exceptions.json`. |
| FedRAMP 20x | The current approach of the U.S. government program that sets security requirements for cloud services sold to federal agencies. It's built around automated, machine-readable proof. |
| finding | One resource that failed a check, with the reason. |
| fingerprint | See *hash*. |
| flow logs | Records of the traffic in and out of a network. Check NET-04 confirms that they're on. |
| Git | A tool that tracks every change to a project's files. |
| GitHub | A website that hosts Git repositories and runs automated workflows on them. |
| GitHub Actions | The GitHub feature that runs workflows. In this project, it runs the self-tests, the daily evidence collection, and the plan check. |
| GRC | Governance, risk, and compliance. |
| hash | A fingerprint computed from a file's contents. The same file always produces the same hash, and any change to the file changes it. The project uses SHA-256. |
| IAM | Identity and Access Management. The AWS service that controls who can sign in and what they can do. |
| KMS | Key Management Service. The AWS service that creates and protects encryption keys. |
| KSI | Key Security Indicator. One of the 46 statements that FedRAMP 20x asks a cloud provider to show it meets. The project's checks address 16. |
| load balancer | A service that receives incoming connections and passes them to the systems behind it. The TLS settings for incoming traffic are set there, which check CRY-06 tests. |
| main branch | The authoritative copy of the project on GitHub. |
| manifest | The list of every file in an evidence run and each file's hash. |
| MFA | Multi-factor authentication. Signing in with a password and a second proof, such as a code from a phone. |
| Object Lock | An Amazon S3 feature that prevents a stored file from being changed or deleted until a set time passes. The project uses compliance mode, which nobody can override. |
| PCI DSS | Payment Card Industry Data Security Standard. The security requirements for organizations that handle payment card data. |
| permissions boundary | A limit on what an identity can do, regardless of the permissions attached to it. The planted users have a boundary that denies everything. |
| plan | Terraform's exact list of what it would create, change, or delete, produced before it does anything. |
| plan check | The project's test of a Terraform plan against eight rules. It's a preventive control, because it stops a problem before the problem exists. |
| practice mode | Running the collectors against a simulated AWS account on your computer, with `secuguard collect --mock`. |
| profile | A saved AWS sign-in on your computer. This project's profile is named `secuguard`. |
| pull request | A set of changes on a branch, offered for merging into the main branch. GitHub runs checks on it first. |
| region | The geographic location of the AWS data centers in use. This project uses `us-east-1`, US East (N. Virginia). |
| repository | A project stored in Git or on GitHub. |
| root user | The owner sign-in of an AWS account. It has unlimited access and is used only for rare account-level tasks. |
| ruleset | A GitHub setting that controls what can be merged into a branch. |
| scope | In PCI DSS, the systems that the requirements apply to: the CDE and anything that can connect to it. |
| security group | A set of AWS firewall rules that controls which traffic can reach a group of systems. |
| Security Hub | The AWS service that evaluates an account against AWS security standards. Check MON-02 confirms that it's on. |
| SOC 2 | An independent audit report on an organization's security controls. |
| state | Terraform's record of what it has built. |
| subnet | A section of a network. Each subnet in this project is tagged with its intended PCI scope. |
| Terraform | A tool that builds and removes cloud resources from written definitions. The same definitions always produce the same environment, so every change to the environment is an edit that can be reviewed. |
| terminal | A window where you enter commands. On Windows, this manual uses PowerShell. |
| TLS | Transport Layer Security. The encryption used for network connections. Versions 1.0 and 1.1 are outdated. |
| vault | This manual's name for the S3 bucket with Object Lock that holds the copy of record of all evidence. |
| VPC | Virtual private cloud. A private network in AWS. |
