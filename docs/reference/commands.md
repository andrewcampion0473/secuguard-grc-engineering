# Command reference

## Start a session

Run these commands each time you open a new PowerShell window. The last two are needed only for a real AWS account.

```powershell
cd $HOME\Projects\secuguard-grc-engineering
.\.venv\Scripts\Activate.ps1
aws sso login --profile secuguard
$bucket = terraform -chdir=terraform output -raw evidence_bucket
```

## Collect evidence

| Task | Command |
|---|---|
| Collect in practice mode | `secuguard collect --mock` |
| Collect from AWS and store the run in the vault | `secuguard collect --profile secuguard --upload --bucket $bucket` |
| List the collectors and what each one gathers | `secuguard collectors` |

## Verify evidence

| Task | Command |
|---|---|
| Verify the evidence on your computer | `secuguard verify` |
| Verify the copy of record in the vault | `secuguard verify --vault --profile secuguard --bucket $bucket` |
| Confirm that the vault refuses deletion | `secuguard test-lock --profile secuguard --bucket $bucket` |

## Report results

| Task | Command |
|---|---|
| Show results by check and by framework | `secuguard report` |
| Create the report as a web page, and then open it | `secuguard report --html` and then `start report.html` |
| Save the report as a Markdown file | `secuguard report --markdown \| Out-File -Encoding utf8 report.md` |
| Grade earlier evidence with the current checks | `secuguard report --regrade` |
| List the checks and their requirement mappings | `secuguard checks` |

## Review PCI scope

| Task | Command |
|---|---|
| Show the scope of the network and any drift | `secuguard scope` |
| Approve the current network as the scope baseline | `secuguard scope --approve --by "Your Name"` |

## Validate FedRAMP 20x indicators

| Task | Command |
|---|---|
| Show the indicator validation | `secuguard ksi` |
| Save the full validation as a Markdown file | `secuguard ksi --markdown \| Out-File -Encoding utf8 ksi-report.md` |
| Show the machine-readable validation | `secuguard ksi --json` |

## Check and apply changes

| Task | Command |
|---|---|
| Check a planned change before you apply it | `secuguard plan-check` |
| Apply exactly the plan that was checked | `terraform -chdir=terraform apply tfplan` |
| Check the sample plan, with no AWS account | `secuguard plan-check --plan-json examples\sample-noncompliant-plan.json` |
| List every resource that Terraform built | `terraform -chdir=terraform state list` |

## Test the project

| Task | Command |
|---|---|
| Run the self-tests | `pytest` |
