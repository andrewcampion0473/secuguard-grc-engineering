# SecuGuard GRC Engineering manual

Use this manual to run the SecuGuard GRC engineering project yourself. It's written for governance, risk, and compliance (GRC) professionals and assumes no experience with a terminal, Amazon Web Services (AWS), or GitHub.

- **Read it as a website:** <https://andrewcampion0473.github.io/secuguard-grc-engineering/>
- **Read it on GitHub:** start at [docs/index.md](docs/index.md), or select a page below.
- **Read it as a PDF:** [docs/manual.pdf](docs/manual.pdf)

This manual covers how to run the project. For how each part works and which requirements it addresses, see the [Project Guide](docs/project-guide.pdf).

## Choose a path

Each path builds on the one before it. To evaluate the project, path 1 is enough.

| Path | What you get | Time | Cost |
|---|---|---|---|
| **1. Run it on your computer** | The whole system running against a simulated AWS account | About 1 hour | Free. No AWS account needed. |
| **2. Run it in your AWS account** | Evidence from a real account, stored in a vault that refuses deletion | About 2 hours | About $26 a month while it runs |
| **3. Automate it on GitHub** | Daily evidence collection, and noncompliant changes blocked before they merge | About 2 hours | No added cost |

## Path 1: Run it on your computer

1. [Set up your computer](docs/get-started/set-up-your-computer.md)
2. [Install the project](docs/get-started/install-the-project.md)
3. [Run the project in practice mode](docs/get-started/run-in-practice-mode.md)

## Path 2: Run it in your AWS account

1. [Create and secure an AWS account](docs/run-in-aws/create-an-aws-account.md)
2. [Build the environment](docs/run-in-aws/build-the-environment.md)
3. [Collect evidence and test the vault](docs/run-in-aws/collect-evidence.md)
4. [Review the results](docs/run-in-aws/review-results.md)

## Path 3: Automate it on GitHub

1. [Collect evidence daily](docs/automate/collect-evidence-daily.md)
2. [Block noncompliant changes](docs/automate/block-noncompliant-changes.md)
3. [Make and approve changes](docs/automate/make-changes.md)

## Maintain

- [Manage costs and shut down](docs/maintain/manage-costs.md)
- [Troubleshooting](docs/troubleshooting.md)

## Reference

- [Command reference](docs/reference/commands.md)
- [Checks and plan rules](docs/reference/checks.md)
- [Project files](docs/reference/files.md)
- [Architecture diagrams](docs/architecture.md)
- [Glossary](docs/reference/glossary.md)

## About this manual

The manual is written in Markdown, follows the Microsoft Writing Style Guide, and is built as a website with MkDocs. A GitHub workflow rebuilds the website on every change and fails if a link is broken. To build it on your computer, run `pip install -r requirements-docs.txt`, and then run `mkdocs serve`.
