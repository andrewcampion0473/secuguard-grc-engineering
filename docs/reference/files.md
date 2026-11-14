# Project files

## Documentation

| File or folder | Contents |
|---|---|
| `README.md` | The introduction shown on the repository's GitHub page |
| `MANUAL.md` | The entry point to this manual |
| `docs/` | The pages of this manual |
| `docs/manual.pdf` | This manual as a single PDF |
| `docs/project-guide.pdf` | The Project Guide, which explains how each part works and which requirements it addresses |
| `docs/architecture.md` | Four diagrams of how the system fits together |
| `docs/images/` | The same diagrams as images |
| `mkdocs.yml` | The settings that build this manual as a website |
| `examples/sample-report.html` | The web page report from one practice mode run |
| `examples/sample-report.md` | The same check results as a Markdown report |
| `examples/sample-ksi-validation.md` | The FedRAMP 20x validation from the same run |
| `examples/sample-run/` | The evidence files from that run |

## Evidence collection and grading

| File or folder | Contents |
|---|---|
| `src/secuguard_grc/collectors/` | The nine collectors: network, encryption keys, storage, sign-in settings, identities, certificates, load balancers, logging, and monitoring |
| `src/secuguard_grc/evidence.py` | Fingerprints, manifests, the chain between runs, and verification |
| `src/secuguard_grc/storage.py` | Uploads each run to the vault, reads runs back for verification, and runs the lock test |
| `src/secuguard_grc/checks.py` | The 26 checks, each with its reason and requirement mappings |
| `src/secuguard_grc/scope.py` | Calculates the PCI scope of the network and compares it with the tags and the baseline |
| `scope-baseline.json` | The approved PCI scope of the network, with who approved it and when |
| `src/secuguard_grc/ksi.py` | Maps FedRAMP 20x indicators to checks and states what each validation covers and leaves out |
| `src/secuguard_grc/data/fedramp_ksi.json` | The 46 FedRAMP 20x Key Security Indicators, in FedRAMP's wording |
| `src/secuguard_grc/report.py` | Produces the terminal and Markdown reports |
| `src/secuguard_grc/report_html.py` | Produces the web page report |
| `src/secuguard_grc/cli.py` | Defines the `secuguard` commands |
| `src/secuguard_grc/mock/environment.py` | Builds the simulated AWS account used in practice mode |

## Change control

| File or folder | Contents |
|---|---|
| `src/secuguard_grc/plan_check.py` | The eight rules that evaluate a Terraform plan |
| `policy/exceptions.json` | The exceptions register. Each entry has a reason, an approver, and an expiry date. |
| `examples/noncompliant-change.tf.example` | A sample noncompliant change |
| `examples/sample-noncompliant-plan.json` | The plan for that change, saved for use in practice mode |

## Environment

| File or folder | Contents |
|---|---|
| `terraform/network.tf` | The network, its three zones, and the security groups |
| `terraform/planted.tf` | The planted weaknesses |
| `terraform/evidence.tf` | The evidence vault and its encryption key |
| `terraform/monitoring.tf` | CloudTrail, flow logs, AWS Config, Security Hub, and the log bucket |
| `terraform/github_oidc.tf` | The role GitHub uses to collect evidence |
| `terraform/state.tf` | The Terraform state bucket and the read-only role GitHub uses to plan proposed changes |
| `terraform/backend.tf.example` | The setting that stores Terraform state in AWS |
| `terraform/variables.tf` | The settings you can change, each with a description |
| `terraform/outputs.tf` | The values Terraform prints after it builds |
| `terraform/terraform.tfvars.example` | A template for your settings file |

## Automation and support

| File or folder | Contents |
|---|---|
| `.github/workflows/ci.yml` | Runs the self-tests on every change |
| `.github/workflows/collect-evidence.yml` | Collects evidence every day |
| `.github/workflows/plan-check.yml` | Evaluates every pull request against the plan rules |
| `.github/workflows/docs.yml` | Builds and publishes this manual |
| `tests/` | Self-tests for the project's code |
| `.gitignore` | Lists the files that are kept out of GitHub |
| `pyproject.toml` | Lists the packages the project depends on |
| `requirements-docs.txt` | Lists the packages that build this manual |
