# Block noncompliant changes

Have GitHub evaluate every proposed change to the environment, and add a rule so that a noncompliant change can't be merged.

**Time:** About 1 hour

**Prerequisite:** [Collect evidence daily](collect-evidence-daily.md)

You ran the plan check against a sample in practice mode and against your own plan before you built the environment. This page makes it a gate, which takes three parts.

| Part | Purpose |
|---|---|
| Terraform state stored in AWS | Terraform's record of what it has built is its state. While the state is a file on your computer, GitHub can't tell what exists. |
| A read-only role for GitHub | The role works only for proposed changes and can't change anything. You created it in [Collect evidence daily](collect-evidence-daily.md). |
| A ruleset on the main branch | GitHub refuses to merge a proposed change unless the plan check passes. |

A proposed change on GitHub is a pull request: a set of changes on a branch, offered for merging into the main branch.

> [!NOTE]
> **Audit relevance:** This is change management as a technical control. PCI DSS 6.5.1 and SOC 2 CC8.1 ask that changes be authorized and tested before they're made. Here the test is automatic, the authorization is the merge, and GitHub keeps a permanent record of both.

## Move the Terraform state to AWS

1. Sign in to AWS, and then back up the state file.

    ```powershell
    aws sso login --profile secuguard
    Copy-Item terraform\terraform.tfstate terraform\terraform.tfstate.before-move
    ```

    The backup is kept out of GitHub. Delete it after a week.

2. Record where the state will be stored.

    ```powershell
    $state = terraform -chdir=terraform output -raw terraform_state_bucket
    Set-Content -Encoding ascii terraform\backend.hcl @("bucket       = `"$state`"", 'key          = "secuguard/terraform.tfstate"', 'region       = "us-east-1"', 'profile      = "secuguard"', 'use_lockfile = true')
    Get-Content terraform\backend.hcl
    ```

    PowerShell prints the five lines of the new file. The first line names your state bucket.

    ```text
    bucket       = "secuguard-tfstate-123456789012"
    key          = "secuguard/terraform.tfstate"
    region       = "us-east-1"
    profile      = "secuguard"
    use_lockfile = true
    ```

3. Turn on remote state.

    ```powershell
    Copy-Item terraform\backend.tf.example terraform\backend.tf
    ```

4. Move the state.

    ```powershell
    terraform -chdir=terraform init -migrate-state "-backend-config=backend.hcl"
    ```

    Include the quotation marks. Without them, Terraform reports `No positional arguments are expected`.

5. When Terraform asks `Do you want to copy existing state to the new backend?`, enter `yes`.

    The output includes `Successfully configured the backend "s3"!`

6. Confirm the move.

    ```powershell
    secuguard plan-check
    ```

    The output reports `No changes` and `ALLOWED`, which confirms that Terraform can read everything it built from the new location.

If step 4 fails, Terraform leaves the state on your computer unchanged. To return to the earlier setup, run `Remove-Item terraform\backend.tf`, and then run `terraform -chdir=terraform init`.

## Add the repository variables

1. On GitHub, open your repository, and then select **Settings** > **Secrets and variables** > **Actions** > **Variables**.
2. Copy the plan checker role to the clipboard.

    ```powershell
    terraform -chdir=terraform output -raw plan_checker_role_arn | Set-Clipboard
    ```

3. Add a variable named `PLAN_ROLE_ARN`, and then paste the value.

    The value starts with `arn:aws:iam::` and ends with `secuguard-plan-checker`.

4. Copy the state bucket name to the clipboard.

    ```powershell
    terraform -chdir=terraform output -raw terraform_state_bucket | Set-Clipboard
    ```

5. Add a variable named `TF_STATE_BUCKET`, and then paste the value.

    The value starts with `secuguard-tfstate-`.

## Propose a noncompliant change

Open a pull request that contains the sample change from practice mode, this time against your real environment.

1. Create a branch, add the change, and then push the branch.

    ```powershell
    git checkout -b noncompliant-change
    Copy-Item examples\noncompliant-change.tf.example terraform\noncompliant-change.tf
    git add terraform\noncompliant-change.tf
    git commit -m "Let the reporting team query the card database"
    git push -u origin noncompliant-change
    ```

2. On GitHub, open your repository. In the banner that mentions `noncompliant-change`, select **Compare & pull request**, and then select **Create pull request**.
3. Wait about two minutes, and then review the checks at the bottom of the pull request.

    **Tests** passes. **Plan check** fails.

4. Next to **Plan check**, select **Details**, and then select **Summary**.

    ```text
    Plan: 2 to add, 0 to change, 0 to destroy.
    Examined 2 planned changes against 8 rules.

    BLOCKED. 2 change(s) break a rule:
      PLAN-04  Encryption keys are created with rotation on
      PLAN-02  Only in-scope groups are let into the card data zone
    ```

GitHub produced that result by reading your AWS account with a role that can't change anything.

> [!WARNING]
> **Merge pull request** is still available at this point. Don't merge. The next procedure closes that gap.

If **Plan check** fails for another reason, such as a sign-in error, the cause is setup and not a blocked plan. See [Troubleshooting](../troubleshooting.md#github).

## Require the plan check

1. On GitHub, open your repository, and then select **Settings** > **Rules** > **Rulesets**.
2. Select **New ruleset** > **New branch ruleset**.
3. For the name, enter `Protect main`.
4. Set **Enforcement status** to **Active**.
5. Under **Target branches**, select **Add target** > **Include default branch**.
6. Select the following rules:

    - **Restrict deletions**
    - **Require a pull request before merging**. If you work alone, leave the required approvals at 0.
    - **Require status checks to pass**. Select **Add checks**, and then add `plan-check` and `test`.
    - **Block force pushes**

7. Leave the bypass list empty, and then select **Create**.

    With nobody on the bypass list, the ruleset applies to you too.

8. Return to the pull request, and then refresh the page.

    The merge button is unavailable, and each check is marked **Required**.

> [!NOTE]
> **Audit relevance:** A change that would have opened the card database to the office network can't reach the main branch, and nobody had to notice it. GitHub keeps the pull request, its failed check, and the fact that it was never merged as a permanent record.

## Withdraw the change

1. On the pull request, select **Close pull request**, and then select **Delete branch**.
2. In PowerShell, return to the main branch, and then delete the local branch.

    ```powershell
    git checkout main
    git branch -D noncompliant-change
    secuguard plan-check
    ```

    The output reports `No changes` and `ALLOWED`.

> [!NOTE]
> **Limits of this control:** GitHub decides what can be merged, but changes are still applied from your computer. An administrator could apply an unmerged change or edit the ruleset. Both leave a record: CloudTrail logs the apply, and GitHub logs every ruleset change.

## Next step

[Make and approve changes](make-changes.md)
