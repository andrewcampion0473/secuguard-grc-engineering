# Collect evidence and test the vault

Run the collectors against your AWS account, store the results in the evidence vault, and confirm that the vault refuses deletion.

**Time:** About 15 minutes

**Prerequisite:** [Build the environment](build-the-environment.md)

## Collect and store evidence

1. Save the vault's name in a variable.

    ```powershell
    $bucket = terraform -chdir=terraform output -raw evidence_bucket
    $bucket
    ```

    The second line prints the name, which starts with `secuguard-evidence-`.

2. Collect evidence, and then upload it to the vault.

    ```powershell
    secuguard collect --profile secuguard --upload --bucket $bucket
    ```

    The output matches practice mode, with three differences: it shows `aws mode`, it shows your account number, and it ends with an upload line.

    ```text
    Uploaded 14 files to s3://secuguard-evidence-123456789012/runs/20261110T.../
    ```

    The 14 files are nine evidence files, a copy of the approved scope baseline, the check results, the FedRAMP 20x validation, the manifest, and the manifest's fingerprint.

> [!IMPORTANT]
> PowerShell forgets `$bucket` when you close the window. Run step 1 again in each new window.

The collectors have read-only access. They can't change the environment.

> [!NOTE]
> **Audit relevance:** The check results and the FedRAMP 20x validation are sealed and stored with the evidence they were graded from. Nobody can change a fail to a pass afterward.

## Test the lock

Run the following command.

```powershell
secuguard test-lock --profile secuguard --bucket $bucket
```

The command uploads a marker file and then asks AWS, with your administrator rights, to permanently delete that stored version and to bypass the lock. No evidence is affected.

```text
Uploaded a marker file to s3://secuguard-evidence-.../lock-test/20261112T....txt
  lock mode     COMPLIANCE
  locked until  2026-11-13 15:31 UTC
Tried to delete that stored version permanently, asking AWS to bypass the lock.
REFUSED (AccessDenied). The vault would not delete a locked file, even on request to bypass.
```

> [!NOTE]
> **Audit relevance:** The vault uses S3 Object Lock in compliance mode. Until a file's lock ends, nobody can change or delete it, including administrators and the root user. Governance mode, which an administrator can override, isn't used. The lock lasts one day in this demonstration so that the project can be removed. An organization would set it to its evidence retention period.

## Test the lock in the console

This procedure is optional. It repeats the test by hand.

1. In the AWS console, open **S3**, and then open your evidence bucket > `runs` > your run.
2. Turn on **Show versions**.

    With **Show versions** off, a delete only hides the file, and AWS reports success. With it on, you ask AWS to remove the stored file permanently.

3. Select the check box next to `iam.json`, and then select **Delete**.
4. Enter `permanently delete` in the confirmation box, and then select **Delete objects**.

A red banner reports that the delete failed. `iam.json` appears under **Failed to delete** with an **Access denied** error.

## Verify the copy of record

Run the following command.

```powershell
secuguard verify --vault --profile secuguard --bucket $bucket
```

The command reads every run from the vault, recomputes every fingerprint, and confirms that each run links to the one before it. The output reports how many files were read, followed by `OK` and the number of runs verified.

## Next step

[Review the results](review-results.md)
