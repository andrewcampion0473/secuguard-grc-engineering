# Troubleshooting

Find the message or symptom under the heading for the tool that produced it. If a problem isn't listed, read the last two or three lines of the error text, which usually state the cause. You can also open an issue on the project's GitHub page and paste the full error.

## Computer setup

### `winget` isn't recognized

Open Microsoft Store, search for **App Installer**, and then install or update it. Open a new PowerShell window.

### `git`, `terraform`, or `aws` isn't recognized after installation

Close PowerShell, and then open a new window. If the command still fails, restart the computer.

### `py` isn't recognized, or `python` opens Microsoft Store

Run the Python command from [Install the programs](get-started/set-up-your-computer.md#install-the-programs) again, and then open a new PowerShell window. Create the environment with `py -m venv .venv`, as shown in the manual.

### "Running scripts is disabled on this system"

Complete [Allow local scripts to run](get-started/set-up-your-computer.md#allow-local-scripts-to-run), and then try again.

### `secuguard` isn't recognized

The Python environment isn't active. If `(.venv)` isn't at the start of the prompt, run `.\.venv\Scripts\Activate.ps1` from the project folder. If `(.venv)` is there and the command still fails, run `pip install -e ".[dev]"` again.

### `report.html` opens as text, or `start report.html` does nothing

In File Explorer, go to the project folder, and then double-click `report.html`. If the file opens in an editor, right-click it, select **Open with**, and then select your browser.

## AWS sign-in

### The console shows no region name, or reports that a service "is not available to your project"

The account was created with the simplified sign-up flow. Don't select **Activate advanced features**, because that can't be undone. Create a new account by following [Create the account](run-in-aws/create-an-aws-account.md#create-the-account). The simplified account costs nothing while it's unused, and you can close it later.

### "Could not reach AWS," or a message about an expired token or SSO session

Your sign-in expired. Run `aws sso login --profile secuguard`, and then try again.

### "No valid credential sources found"

Your sign-in expired. Run `aws sso login --profile secuguard`. Also confirm that `terraform\terraform.tfvars` exists and contains `aws_profile = "secuguard"`.

## Terraform

### `secuguard plan-check` reports that Terraform wasn't found, or fails while it asks for a plan

Run the command from the project folder, with the Python environment active, after you sign in to AWS. The message is Terraform's own error. To see it in full, run `terraform -chdir=terraform plan`.

### A provider is missing

Run `terraform -chdir=terraform init -upgrade`, and then try again.

### `secuguard plan-check` blocks a planted resource because its exception expired

Exceptions in `policy\exceptions.json` have an end date. Decide whether each planted weakness is still wanted, and then extend its `expires` date. See [Record an exception](automate/make-changes.md#record-an-exception).

### `secuguard plan-check` blocks a change that you consider acceptable

Change the plan so that it meets the rule, or [record an exception](automate/make-changes.md#record-an-exception).

### "Invalid principal in policy" on the role `secuguard-legacy-vendor`

AWS lets a role trust only an account number that exists. Confirm that you have the latest project files, and then apply again. Resources that were already created aren't affected.

### The apply fails on the weak certificate, the load balancer, or its listener

AWS tightens what it accepts over time and might refuse a deliberately weak setting. If the load balancer or listener failed, add `planted_load_balancer = false` to `terraform\terraform.tfvars`, and then apply again. Resources that were already created aren't affected.

### The apply fails on CloudTrail, the flow log, the Config recorder, or Security Hub

Turn off the service that failed by adding the matching line to `terraform\terraform.tfvars`, and then apply again.

| Service | Setting |
|---|---|
| CloudTrail | `monitoring_cloudtrail = false` |
| Flow logs | `monitoring_flow_logs = false` |
| AWS Config | `monitoring_config = false` |
| Security Hub | `monitoring_security_hub = false` |

### Security Hub is already enabled, or a Config recorder already exists

The service was turned on in this account outside this project. Turn off that service in `terraform\terraform.tfvars`, as described in the previous entry. The checks read whatever is running, so MON-01 and MON-02 still report correctly.

### "timeout while waiting for state to become 'READY, INCOMPLETE'" on the Security Hub standard

Security Hub was still turning on the standard when Terraform stopped waiting. Nothing is broken, and everything else was created.

1. Wait about 10 minutes, and then check the standard's status.

    ```powershell
    aws securityhub get-enabled-standards --profile secuguard --query "StandardsSubscriptions[].StandardsStatus"
    ```

    Continue when the output is `READY` or `INCOMPLETE`. If the output is `PENDING`, wait a few minutes, and then check again.

2. Tell Terraform to keep the standard as it is.

    ```powershell
    terraform -chdir=terraform untaint 'aws_securityhub_standards_subscription.best_practices[0]'
    ```

3. Run `secuguard plan-check`. The output reports `No changes`.

### An OpenID Connect provider already exists

The AWS account already has a GitHub connection from another project. In the console, go to **IAM** > **Identity providers**, remove the existing provider, and then apply again.

### "Backend initialization required" or "Backend configuration changed"

Run `terraform -chdir=terraform init "-backend-config=backend.hcl"`. If `terraform\backend.tf` is missing, first run `Copy-Item terraform\backend.tf.example terraform\backend.tf`.

### The state is locked

An earlier run was interrupted. Find the lock ID in the message, and then run `terraform -chdir=terraform force-unlock` followed by the ID. Do this only when you're sure that no other Terraform run is in progress.

### `terraform destroy` fails on the evidence bucket with "Access Denied" or "bucket is not empty"

Some evidence is still locked. A lock lasts one day from the time each file was uploaded. Confirm that the daily collection on GitHub is turned off, wait until 24 hours after the last collection, and then run the command again.

## Evidence and checks

### `--upload needs a bucket`

`$bucket` is empty, usually because you opened a new PowerShell window. Run step 1 of [Collect and store evidence](run-in-aws/collect-evidence.md#collect-and-store-evidence) again.

### `secuguard report` finds no evidence runs

Run the command from the project folder, and collect at least once first.

### A check shows NO EVIDENCE

The collector that the check depends on couldn't read something. Run `secuguard report`, and then read the line that starts with `!` under the check. If the line names an access error on your computer, sign in to AWS again. If the problem happens only on GitHub, run `secuguard plan-check`, and then apply the plan so that the collector role has its current permissions.

### MON-02 fails after Security Hub is turned on

The standard can take a few minutes to register. Collect again after 10 minutes.

### `secuguard verify` reports a run that "does not link" to the one before it

Runs that GitHub collects and runs that you upload from your computer join the same chain in the vault. If your `evidence` folder is missing some of those runs, the folder shows a gap even though the vault's chain is complete. The vault is the copy of record. Verify it with `secuguard verify --vault --profile secuguard --bucket $bucket`.

### `secuguard test-lock` reports NOT PROTECTED

The vault isn't in compliance mode. Confirm that `terraform\terraform.tfvars` doesn't set `evidence_lock_mode = "GOVERNANCE"`, apply, and then run the test again.

### A delete in the evidence vault succeeded

Either **Show versions** was off, in which case the file was only hidden and is still stored, or the vault is in governance mode. Check `terraform\terraform.tfvars` as described in the previous entry, apply, collect again, and then repeat the test on the new run. Files uploaded before the change keep their original lock.

### `secuguard scope` shows unexpected drift

Part of the network differs from `scope-baseline.json`. Review the item that's named, and decide whether the change is correct. Undo the change, or correct the network and then approve a new baseline with `secuguard scope --approve --by "Your Name"`.

## GitHub

### The Collect evidence workflow is skipped

The `AWS_ROLE_ARN` variable is missing. Confirm that you added it on the **Variables** tab and not the **Secrets** tab. See [Add the repository variables](automate/collect-evidence-daily.md#add-the-repository-variables).

### "Not authorized to perform sts:AssumeRoleWithWebIdentity" in the Collect evidence workflow

AWS didn't recognize the repository. Check the following in order, and then run the workflow again.

1. `terraform.tfvars` contains the three `github_` lines, and the two numbers are the ones PowerShell printed for your repository.
2. The repository name matches GitHub exactly, including capitalization.
3. You applied the plan after you saved the file.
4. The workflow ran from the `main` branch.
5. The `AWS_ROLE_ARN` variable matches the `github_actions_role_arn` output exactly.

### Plan check fails at "Get short-lived, read-only AWS credentials"

AWS didn't recognize the pull request. Confirm that the `PLAN_ROLE_ARN` variable matches the `plan_checker_role_arn` output exactly and that `terraform.tfvars` still contains the three `github_` lines. Pull requests from a copy of the repository under another account are refused by design.

### "Source Account ID is needed if the Role Name is provided and not the Role Arn"

The `PLAN_ROLE_ARN` variable doesn't contain a full role address. The value was probably pasted with quotation marks, or the two variables were swapped. Run `terraform -chdir=terraform output -raw plan_checker_role_arn | Set-Clipboard`, edit the variable on GitHub, and then paste. The value must start with `arn:aws:iam::`. Rerun the failed job from the pull request.

### Plan check fails while Terraform starts or reads the state

Confirm that the `TF_STATE_BUCKET` variable matches the `terraform_state_bucket` output and that [Move the Terraform state to AWS](automate/block-noncompliant-changes.md#move-the-terraform-state-to-aws) ended with `Successfully configured the backend`.

### Plan check reports changes that you didn't make

Your `terraform.tfvars` file contains a setting that GitHub doesn't have, so the two plans differ. Compare the plan in the workflow log with the output of `secuguard plan-check` on your computer.

### `git push` to main is rejected because of a rule or a required pull request

The ruleset is working as intended. Put the change on a branch, and then open a pull request. See [Make a change](automate/make-changes.md#make-a-change).

### `git push` reports `src refspec ... does not match any`

Git has no branch with the name you entered. To list your branches, run `git branch`. The current branch is marked with an asterisk.
