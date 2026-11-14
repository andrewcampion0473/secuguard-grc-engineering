# Review the results

Read the results from your AWS account, fix one finding and see the result change, and try to approve a scope change.

The commands are the same as in [practice mode](../get-started/run-in-practice-mode.md). This page covers what differs with real evidence.

**Time:** About 30 minutes

**Prerequisite:** [Collect evidence and test the vault](collect-evidence.md)

## Open the report

Run the following commands.

```powershell
secuguard report --html
start report.html
```

To show the report in PowerShell instead, run `secuguard report`.

`report.html` names your AWS account, so the project keeps the file out of GitHub.

### Check results

| Result | Meaning |
|---|---|
| PASS | Every resource the check examined meets the rule. |
| FAIL | At least one resource doesn't meet the rule. Each one is named. |
| N/A | The account has no resources of that kind. |
| NO EVIDENCE | The evidence the check needs is missing or couldn't be collected, so the check draws no conclusion. |

A check never reports PASS without evidence. If a collector is denied permission, the checks that depend on it report NO EVIDENCE.

### Expected results

Most checks fail. That's the intent.

| Check | Expected | Reason |
|---|---|---|
| NET-01, CRY-01 to CRY-07, IAM-04 to IAM-07 | FAIL | Planted weaknesses |
| NET-02, SCP-01 to SCP-03 | FAIL | Planted scope drift |
| LOG-01, LOG-02, MON-01, MON-02 | PASS | The vault and the monitoring services are built correctly |
| SCP-04 | PASS | The card data zone has no route to the internet |
| IAM-01, IAM-02 | PASS | You protected the root user |
| IAM-03 | FAIL | A real finding. The account has no password policy. |
| NET-03, NET-04 | FAIL | Real findings. Every AWS account includes a default network with a permissive security group and no traffic logging. |

If MON-02 fails, Security Hub is still starting. Collect again in 10 minutes.

> [!NOTE]
> **Audit relevance:** The last two rows aren't planted. The project found real weaknesses in a new AWS account.

## Fix a finding

IAM-03 fails because the account has no password policy.

1. Set a password policy.

    ```powershell
    aws iam update-account-password-policy --minimum-password-length 14 --require-symbols --require-numbers --require-uppercase-characters --require-lowercase-characters --password-reuse-prevention 24 --profile secuguard
    ```

    The command prints nothing when it succeeds.

2. Collect evidence again, and then show the report.

    ```powershell
    secuguard collect --profile secuguard --upload --bucket $bucket
    secuguard report
    ```

    IAM-03 and PCI DSS requirement 8.3.6 now show PASS.

> [!NOTE]
> **Audit relevance:** The vault now holds two sealed runs: one from before the fix that shows FAIL, and one from after that shows PASS. Neither can be altered. Together they're the remediation evidence an auditor asks for.

## Try to approve a scope change

The approved baseline is the file `scope-baseline.json`. It lists each part of the network and its approved scope, with who approved it and when.

1. Show the current scope.

    ```powershell
    secuguard scope
    ```

    The output shows the same mismatch and drift as practice mode, now from your network.

2. Try to approve the current network as the new baseline.

    ```powershell
    secuguard scope --approve --by "Your Name"
    ```

    ```text
    Not approved. A baseline should record a correct network, and this one has problems:
      security group secuguard-planted-analytics: declared out-of-scope but can reach the card data zone
      security group secuguard-planted-unclassified: has no declared scope
    Fix these first, collect again, then approve.
    ```

> [!NOTE]
> **Audit relevance:** The project refuses the approval. Approval records a correct network. It doesn't make a finding go away. An accepted approval rewrites `scope-baseline.json`, and the file's history in GitHub becomes the record of who approved each scope change and when.

## Review the FedRAMP 20x validation

1. Show the validation.

    ```powershell
    secuguard ksi
    ```

    Expect about two indicators validated and 13 failing, because one failed check fails the indicator.

2. Optional: Show the machine-readable version.

    ```powershell
    secuguard ksi --json
    ```

    The `evidence_files` list gives each evidence file the validation rests on and its fingerprint. A recipient can confirm that the evidence they received is the evidence the validation was built from.

## Compare the results with AWS tools

This procedure is optional. The monitoring services take a few hours to fill in.

1. In the AWS console, confirm that the top bar shows **N. Virginia**.
2. In the search box, enter `Security Hub CSPM`, and then open it.

    The summary shows a score and a list of findings. Many are about the planted weaknesses. If a page offers to "Try the new Security Hub," go back and search for the CSPM name.

3. In the search box, enter `Config`, and then open it. Select a resource, and then select **Resource timeline** to see its change history.
4. In the search box, enter `CloudTrail`, and then select **Event history** to see recent actions, including your Terraform run.

## Grade earlier evidence again

Checks read evidence files and don't contact AWS. To grade an earlier run with the current checks, run the following command.

```powershell
secuguard report --regrade
```

Use this option when a framework changes or a check is improved. The evidence doesn't have to be collected again.

## Next step

To collect evidence on a schedule, go to [Collect evidence daily](../automate/collect-evidence-daily.md). To stop here, see [Manage costs and shut down](../maintain/manage-costs.md).
