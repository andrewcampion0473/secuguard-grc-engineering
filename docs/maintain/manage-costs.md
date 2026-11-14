# Manage costs and shut down

Reduce what the environment costs, or remove it.

## Costs

The environment costs about $26 a month.

| Item | Cost |
|---|---|
| Load balancer | About $17 a month |
| Four encryption keys | About $1 a month each |
| AWS Config and Security Hub | A few dollars a month in an account this small. Security Hub is free for its first 30 days. |
| CloudTrail, flow logs, and storage | Cents |
| Network, security groups, users, roles, and certificates | Free |
| GitHub Actions on a public repository | Free |

AWS Config and Security Hub charge by how much they record and evaluate, so their cost can't be stated exactly in advance. Your [spending alert](../run-in-aws/create-an-aws-account.md#set-a-spending-alert) emails you if the total approaches the amount you set.

## Pause the load balancer

1. Open `terraform\terraform.tfvars`, add the following line, and then save the file.

    ```text
    planted_load_balancer = false
    ```

2. Check the plan, and then apply it.

    ```powershell
    secuguard plan-check
    terraform -chdir=terraform apply tfplan
    ```

Check CRY-06 now reports N/A, because the account has no load balancer. To restore the load balancer, delete the line, and then repeat step 2.

## Pause the monitoring services

1. Open `terraform\terraform.tfvars`, add the following line, and then save the file.

    ```text
    monitoring = false
    ```

2. Check the plan, and then apply it.

    ```powershell
    secuguard plan-check
    terraform -chdir=terraform apply tfplan
    ```

Checks LOG-01, MON-01, and MON-02 now report FAIL, which is accurate.

## Remove the environment

Evidence in the vault is locked for one day, and nobody can remove it early. Removal therefore takes two sessions, at least 24 hours apart.

### Day 1: Stop collecting

1. If you moved the Terraform state to AWS, move it back to your computer.

    ```powershell
    Remove-Item terraform\backend.tf
    terraform -chdir=terraform init -migrate-state
    ```

    When Terraform asks whether to copy the state, enter `yes`. Terraform can't delete the bucket that holds its own state while it's using that bucket.

2. On GitHub, select **Actions** > **Collect evidence**. Select the **...** menu, and then select **Disable workflow**.
3. Don't run `secuguard collect --upload` again.

### Day 2: Remove everything

1. At least 24 hours after the last collection, run the following command.

    ```powershell
    terraform -chdir=terraform destroy
    ```

2. When Terraform asks you to confirm, enter `yes`.

Terraform removes everything it built, including the vault and the evidence in it. AWS schedules each encryption key for deletion after a required waiting period.

If you run the command too early, Terraform removes everything except the vault and then stops with an error about the bucket. Nothing is harmed. Wait until 24 hours have passed since the last collection, and then run the command again.

Removing the environment doesn't close your AWS account. To close the account, sign in as the root user, and then use the **Account** page.
