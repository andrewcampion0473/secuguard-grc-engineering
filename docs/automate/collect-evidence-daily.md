# Collect evidence daily

Put your copy of the project in your own GitHub repository, and have GitHub collect evidence every day without a stored password.

**Time:** About 45 minutes

**Prerequisite:** [Review the results](../run-in-aws/review-results.md)

> [!NOTE]
> **Audit relevance:** A control that depends on someone remembering to run it has gaps. A scheduled job that holds no credentials produces dated evidence that a control operated across a period, which is what a SOC 2 Type 2 or continuous monitoring review looks for.

## Create your repository

You downloaded the project from the author's repository. To run jobs, you need your own.

1. If you don't have a GitHub account, create one at `https://github.com`.
2. On GitHub, select your profile picture, and then select **Settings** > **Emails**.
3. Turn on **Keep my email addresses private**, and then copy the address that ends in `@users.noreply.github.com`.
4. In PowerShell, set your Git identity. Replace both values with your own.

    ```powershell
    git config --global user.name "Your Name"
    git config --global user.email "your-private-address@users.noreply.github.com"
    ```

5. On GitHub, select **+** in the upper-right corner, and then select **New repository**.
6. Name the repository `secuguard-grc-engineering`, and then select **Public**.
7. Leave every **Add** and **Initialize** option turned off, and then select **Create repository**.

    The repository must start empty.

8. In PowerShell, save your GitHub username in a variable. Replace `your-github-username` with your own.

    ```powershell
    $me = "your-github-username"
    ```

9. Point your copy of the project at your repository, and then push it.

    ```powershell
    git remote set-url origin "https://github.com/$me/secuguard-grc-engineering.git"
    git push -u origin main
    ```

    The first time you push, a browser window asks you to sign in to GitHub.

10. On GitHub, refresh the repository page, and then select the **Actions** tab.

    The files appear in the repository, and a workflow named **Tests** is running or shows a green check mark.

Your `evidence` folder, your `terraform.tfvars` file, and Terraform's state stay on your computer. The `.gitignore` file lists everything that's kept out of GitHub.

## Allow GitHub to sign in to AWS

GitHub proves to AWS which repository is asking, and AWS returns access that expires within the hour. That access can read configuration and add files to the evidence vault. It can't delete evidence or change anything else.

AWS identifies your repository by its name and by two permanent numbers. A name can be given up and registered by someone else. The numbers never change hands.

1. Print the three settings that Terraform needs.

    ```powershell
    $repo = Invoke-RestMethod "https://api.github.com/repos/$me/secuguard-grc-engineering"
    "github_repository    = `"$($repo.full_name)`""
    "github_owner_id      = `"$($repo.owner.id)`""
    "github_repository_id = `"$($repo.id)`""
    ```

    PowerShell prints three lines. The first ends with your repository name. The second and third each end with a number in quotation marks.

2. Select the three printed lines, and then copy them.
3. Open your settings file.

    ```powershell
    code terraform\terraform.tfvars
    ```

4. Paste the three lines at the end of the file, and then press Ctrl+S.
5. Check the plan, and then apply it.

    ```powershell
    secuguard plan-check
    terraform -chdir=terraform apply tfplan
    ```

    The plan check reports `Plan: 7 to add, 0 to change, 0 to destroy.` and `ALLOWED`. The apply ends with `Apply complete! Resources: 7 added`.

The seven resources are two roles for GitHub and their permissions: one for collecting evidence, and one for [blocking noncompliant changes](block-noncompliant-changes.md).

## Add the repository variables

1. On GitHub, open your repository, and then select **Settings** > **Secrets and variables** > **Actions** > **Variables**.
2. Copy the collector role to the clipboard.

    ```powershell
    terraform -chdir=terraform output -raw github_actions_role_arn | Set-Clipboard
    ```

    The command prints nothing.

3. Select **New repository variable**. For **Name**, enter `AWS_ROLE_ARN`. For **Value**, press Ctrl+V. Then select **Add variable**.

    The value starts with `arn:aws:iam::` and ends with `secuguard-evidence-collector`.

4. Copy the vault name to the clipboard.

    ```powershell
    terraform -chdir=terraform output -raw evidence_bucket | Set-Clipboard
    ```

5. Select **New repository variable**. For **Name**, enter `EVIDENCE_BUCKET`. For **Value**, press Ctrl+V. Then select **Add variable**.

    The value starts with `secuguard-evidence-`.

Neither value is a secret. Both are names, not keys.

## Run the first collection

1. On GitHub, select the **Actions** tab.
2. Select **Collect evidence** > **Run workflow** > **Run workflow**.
3. Wait about a minute, and then refresh the page.

    The run shows a green check mark.

4. Select the run.

    The **Summary** page shows the check results and the FedRAMP 20x validation for your account. Under **Artifacts**, **secuguard-report** contains the same results as a web page.

The workflow now runs every day at 11:17 UTC. Each run links to the one before it, so the vault holds an unbroken daily record.

## Next step

[Block noncompliant changes](block-noncompliant-changes.md)
