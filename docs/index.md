# SecuGuard GRC Engineering manual

Use this manual to run the SecuGuard GRC engineering project yourself. It's written for governance, risk, and compliance (GRC) professionals and assumes no experience with a terminal, Amazon Web Services (AWS), or GitHub.

This manual covers how to run the project. For how each part works and which requirements it addresses, see the [Project Guide](project-guide.pdf).

To read the manual offline, download it as a [PDF](manual.pdf).

## What the project does

Compliance teams have to prove that security settings are in place. That proof is usually a screenshot taken by hand. A screenshot goes out of date, nothing shows whether it was edited, and the same setting is captured again for every framework that asks about it.

This project replaces that work with a system that runs by itself. Every day it asks AWS how each resource is configured, saves the answers as evidence, seals the evidence so that any alteration is detected, and grades it against PCI DSS 4.0.1, SOC 2, and FedRAMP 20x from one set of 26 checks. It also recalculates PCI scope on every run and blocks noncompliant infrastructure changes before they're deployed.

SecuGuard is a fictional card-issuing software company invented for this project.

## Choose a path

Each path builds on the one before it. To evaluate the project, path 1 is enough.

| Path | What you get | Time | Cost |
|---|---|---|---|
| **1. Run it on your computer** | The whole system running against a simulated AWS account: evidence, tamper detection, reports for all three frameworks, and a blocked change | About 1 hour | Free. No AWS account needed. |
| **2. Run it in your AWS account** | Evidence from a real account, stored in a vault that refuses deletion | About 2 hours | About $26 a month while it runs |
| **3. Automate it on GitHub** | Evidence collected daily with no one involved, and noncompliant changes blocked before they merge | About 2 hours | No added cost |

### Path 1: Run it on your computer

1. [Set up your computer](get-started/set-up-your-computer.md)
2. [Install the project](get-started/install-the-project.md)
3. [Run the project in practice mode](get-started/run-in-practice-mode.md)

### Path 2: Run it in your AWS account

1. [Create and secure an AWS account](run-in-aws/create-an-aws-account.md)
2. [Build the environment](run-in-aws/build-the-environment.md)
3. [Collect evidence and test the vault](run-in-aws/collect-evidence.md)
4. [Review the results](run-in-aws/review-results.md)

### Path 3: Automate it on GitHub

1. [Collect evidence daily](automate/collect-evidence-daily.md)
2. [Block noncompliant changes](automate/block-noncompliant-changes.md)
3. [Make and approve changes](automate/make-changes.md)

## Requirements

- A computer running Windows 10 or Windows 11. The project also runs on macOS and Linux, but this manual doesn't cover setup on those systems.
- An internet connection.
- For paths 2 and 3: an email address, a phone with an authenticator app, and a credit or debit card for the AWS account.

## Conventions

- **Commands** appear in code blocks. Copy the whole block, paste it into PowerShell, and press Enter.
- **Expected results** follow the step that produces them. If you see something different, go to [Troubleshooting](troubleshooting.md).
- **Bold text** is the name of something on the screen that you select.
- **Audit relevance** notes explain why a step matters to an auditor or assessor.

## Reference

- [Command reference](reference/commands.md)
- [Checks and plan rules](reference/checks.md)
- [Project files](reference/files.md)
- [Architecture diagrams](architecture.md)
- [Glossary](reference/glossary.md)
- [Troubleshooting](troubleshooting.md)
