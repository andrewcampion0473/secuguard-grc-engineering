# Run the project in practice mode

Run the whole system against a simulated AWS account on your computer. You collect evidence, alter it and see the alteration detected, read the results for all three frameworks, and see a noncompliant change blocked.

In practice mode, the collectors and checks run exactly as they do against a real account. The simulated account contains the same deliberate weaknesses as the real environment.

**Time:** About 30 minutes

**Cost:** Free. No AWS account is involved.

**Prerequisite:** [Install the project](install-the-project.md)

## Collect evidence

Run the following command.

```powershell
secuguard collect --mock
```

The output looks like this. Your run name and fingerprints differ.

```text
Run 20261110T150035Z-482913-a67f  (mock mode, account 123456789012, us-east-1)
  ok      network       -> evidence\20261110T150035Z-482913-a67f\network.json
  ok      kms           -> evidence\20261110T150035Z-482913-a67f\kms.json
  ok      s3            -> evidence\20261110T150035Z-482913-a67f\s3.json
  ok      iam           -> evidence\20261110T150035Z-482913-a67f\iam.json
  ok      identities    -> evidence\20261110T150035Z-482913-a67f\identities.json
  ok      certificates  -> evidence\20261110T150035Z-482913-a67f\certificates.json
  ok      loadbalancers -> evidence\20261110T150035Z-482913-a67f\loadbalancers.json
  ok      audit_logging -> evidence\20261110T150035Z-482913-a67f\audit_logging.json
  ok      monitoring    -> evidence\20261110T150035Z-482913-a67f\monitoring.json
  graded  26 checks -> evidence\20261110T150035Z-482913-a67f\check-results.json
          7 passed, 19 failed, 0 could not be assessed
          FedRAMP 20x: 1 indicators validated, 14 failing, 30 not covered
Manifest evidence\20261110T150035Z-482913-a67f\manifest.json
  sha256   8ae916fbe7992ae1...
  previous none (first run in this chain)
```

| Line | Meaning |
|---|---|
| `Run` | The name of this collection. It starts with the date and time. |
| `ok` | One collector finished and saved its evidence file. |
| `graded` | The checks read the evidence and decided pass or fail. Most fail on purpose, because the environment contains planted weaknesses. |
| `Manifest` | The list of every file in the run and each file's fingerprint. |
| `previous` | The fingerprint of the run before this one. There isn't one yet. |

## Review an evidence file

1. Open the evidence folder in Visual Studio Code.

    ```powershell
    code evidence
    ```

2. Open the run folder, and then select `identities.json`.

Each evidence file records the following fields.

| Field | Meaning |
|---|---|
| `api_calls` | The questions that were asked of AWS |
| `collected_at` | When the evidence was gathered |
| `description` | What the file covers |
| `payload` | What AWS answered |
| `payload_sha256` | The fingerprint of that answer |
| `relevant_to` | The PCI DSS, SOC 2, and FedRAMP 20x requirements the evidence supports |
| `source` | The account and region the evidence came from |

> [!NOTE]
> **Audit relevance:** This file replaces a screenshot. It states its own method, time, and source, and a program can read it again later.

## Verify the evidence

1. Collect a second run.

    ```powershell
    secuguard collect --mock
    ```

    The `previous` line now shows the fingerprint of the first run. The two runs are linked.

2. Verify both runs.

    ```powershell
    secuguard verify
    ```

    ```text
    OK. 2 run(s) verified. Every file matches its recorded hash and every run links to the one before it.
    ```

Verification recomputes every fingerprint from the files as they are now and compares each one with the fingerprint recorded at collection.

## Alter the evidence

Change one evidence file so that it claims a user has multi-factor authentication (MFA) when she doesn't.

1. In Visual Studio Code, open `identities.json` in either run folder.
2. Press Ctrl+F, and then search for `secuguard-dev-alice`.
3. A few lines above the name, change `"mfa_devices": 0` to `"mfa_devices": 1`.
4. Press Ctrl+S to save the file.
5. Verify the evidence again.

    ```powershell
    secuguard verify
    ```

    ```text
    TAMPERING OR DAMAGE DETECTED in 2 run(s) checked:
      - 20261110T150035Z-482913-a67f/identities.json: file hash does not match the manifest
    ```

6. Delete the altered evidence, and then collect a clean run.

    ```powershell
    Remove-Item -Recurse evidence
    secuguard collect --mock
    ```

> [!NOTE]
> **Audit relevance:** One changed character is detected, and the altered file is named. This addresses evidence integrity under PCI DSS 10.3.2 and SOC 2 CC7.2. Files on your computer can still be edited. In paths 2 and 3, the copy of record is stored where it can't be.

## Read the check results

1. Show the report.

    ```powershell
    secuguard report
    ```

    The first section lists every check. Each line that starts with `x` names one resource that failed and gives the reason.

    ```text
    Check   Result       Severity  What was checked
    ------------------------------------------------------------------------------------------------
    NET-01  FAIL         high      No administrative port is open to the internet
              x security group secuguard-planted-open-admin (sg-0abc...): open to the whole internet: SSH (port 22)
    CRY-01  FAIL         medium    Encryption keys rotate automatically
              x KMS key alias/secuguard-legacy-no-rotation: automatic rotation is off
    ```

    The second section shows the same results by framework.

    ```text
    PCI DSS 4.0.1
      1.3.1         FAIL         NET-01, NET-02, SCP-02
      3.7.4         FAIL         CRY-01
      10.3.2        PASS         LOG-02
    ```

    Read a line as "Requirement 1.3.1 is tested by checks NET-01, NET-02, and SCP-02, and at least one of them failed."

2. Open the same report as a web page.

    ```powershell
    secuguard report --html
    start report.html
    ```

    The report opens in your browser. A banner at the top states whether the evidence behind the report passed verification. The page is a single file that needs no internet connection, so you can email it or save it to a shared drive.

For what each check tests and the requirements it maps to, see [Checks and plan rules](../reference/checks.md).

> [!NOTE]
> **Audit relevance:** Each check is written once. Its result appears under PCI DSS, SOC 2, and FedRAMP 20x with no added work.

## Review PCI scope

Run the following command.

```powershell
secuguard scope
```

```text
Kind            Name                              Declared       Actually
--------------------------------------------------------------------------------
security group  secuguard-cde                     cde            cde
security group  secuguard-corporate               out-of-scope   out-of-scope
security group  secuguard-planted-analytics       out-of-scope   connected        <-- mismatch
security group  secuguard-planted-unclassified    not declared   out-of-scope
security group  secuguard-shared                  connected      connected

Baseline approved by SecuGuard security lead (fictional) on 2026-11-10.
DRIFT. 3 difference(s) from the approved baseline:
  added   security group secuguard-planted-analytics: not in the approved baseline (declared out-of-scope)
```

| Column | Meaning |
|---|---|
| `Declared` | The scope label on that part of the network |
| `Actually` | The scope that the firewall rules produce |

The line marked `mismatch` is a system labeled out of scope that can reach card data.

> [!NOTE]
> **Audit relevance:** PCI DSS 12.5.2 requires scope to be documented and confirmed at least annually. The project recalculates scope from the firewall rules on every run and compares it with a baseline that a named person approved.

## Review the FedRAMP 20x validation

1. Show the summary.

    ```powershell
    secuguard ksi
    ```

    ```text
    16 of 46 indicators addressed: 1 validated, 14 failing, 1 covered by a preventive control only, 0 without evidence. 30 not covered.

    Indicator     Status        Name
    KSI-CMT-LMC   FAILING       Logging Changes
                    SCP-03 FAIL  The network matches the approved scope baseline
                    LOG-01 PASS  Account activity is recorded and the record is protected
    ```

    FedRAMP 20x defines 46 Key Security Indicators. The project tests 16 and lists the other 30 as not covered.

2. Optional: Save the full validation, and then open it.

    ```powershell
    secuguard ksi --markdown | Out-File -Encoding utf8 ksi-report.md
    code ksi-report.md
    ```

    To see the file formatted, press Ctrl+Shift+V in Visual Studio Code. For each indicator, the file gives FedRAMP's wording and states what the evidence does and doesn't establish.

## Test a noncompliant change

The project evaluates proposed changes to the environment against eight rules before the changes are made. The sample change lets the reporting team query the card database from the office network and creates an encryption key for their exports.

Run the following command.

```powershell
secuguard plan-check --plan-json examples\sample-noncompliant-plan.json
```

```text
Examined 2 planned changes against 8 rules.

BLOCKED. 2 change(s) break a rule:
  PLAN-04  Encryption keys are created with rotation on
           aws_kms_key.risky_reports
           creates an encryption key with rotation off
  PLAN-02  Only in-scope groups are let into the card data zone
           aws_vpc_security_group_ingress_rule.risky_office_to_card_database
           lets address range 10.20.30.0/24 into the card data zone. Only named in-scope groups may be let in.

Nothing was applied. Fix the change, or record an approved exception, and run this again.
```

> [!NOTE]
> **Audit relevance:** The earlier steps are detective controls, which find a problem after it exists. The plan check is a preventive control. The second finding is scope drift, caught before it happens.

## Clean up

```powershell
Remove-Item -Recurse evidence
Remove-Item report.html, ksi-report.md -ErrorAction SilentlyContinue
```

## Next step

You've now seen every capability of the project. To run the same system against a real AWS account, go to [Create and secure an AWS account](../run-in-aws/create-an-aws-account.md).
