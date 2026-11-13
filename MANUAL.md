# SecuGuard GRC Engineering: The Manual

This manual takes you from a Windows computer with nothing installed to a working compliance evidence system running in a real AWS account. It assumes you have never used a terminal, AWS, or Git before. Follow the parts in order. Each part says what you are about to do, why, and what you should see when it works.

SecuGuard is a fictional company invented for this project. It is not a real business, and nothing here describes a real company's systems.

**This manual covers stages 1 to 4 of the project.** Parts 3 to 9 set up stage 1, the evidence foundation. Parts 10 to 12 add stage 2, the checks. Parts 13 and 14 add stage 3, scope drift and the check that blocks risky changes. Parts 15 to 17 add stage 4: monitoring, FedRAMP 20x validation, and the plan check enforced on GitHub. New parts are added as each later stage is built.

## Contents

- [Part 1: What this project is](#part-1-what-this-project-is)
- [Part 2: The ideas you need](#part-2-the-ideas-you-need)
- [Part 3: Set up your Windows computer](#part-3-set-up-your-windows-computer)
- [Part 4: Put the project on your computer](#part-4-put-the-project-on-your-computer)
- [Part 5: Run it in practice mode](#part-5-run-it-in-practice-mode)
- [Part 6: Create and secure your AWS account](#part-6-create-and-secure-your-aws-account)
- [Part 7: Build SecuGuard's cloud environment](#part-7-build-secuguards-cloud-environment)
- [Part 8: Collect real evidence](#part-8-collect-real-evidence)
- [Part 9: Publish to GitHub and collect evidence every day](#part-9-publish-to-github-and-collect-evidence-every-day)
- [Part 10: Stage 2: Give the checks something to find](#part-10-stage-2-give-the-checks-something-to-find)
- [Part 11: Read the check results](#part-11-read-the-check-results)
- [Part 12: Prove the vault from the command line](#part-12-prove-the-vault-from-the-command-line)
- [Part 13: Stage 3: Catch scope drift](#part-13-stage-3-catch-scope-drift)
- [Part 14: Block risky changes before they are made](#part-14-block-risky-changes-before-they-are-made)
- [Part 15: Stage 4: Switch on monitoring and fix real findings](#part-15-stage-4-switch-on-monitoring-and-fix-real-findings)
- [Part 16: Validate against FedRAMP 20x](#part-16-validate-against-fedramp-20x)
- [Part 17: Enforce the plan check on GitHub](#part-17-enforce-the-plan-check-on-github)
- [Part 18: Costs and shutting down](#part-18-costs-and-shutting-down)
- [Part 19: Daily use](#part-19-daily-use)
- [Part 20: When something goes wrong](#part-20-when-something-goes-wrong)
- [Part 21: Glossary](#part-21-glossary)
- [Part 22: What each file in the project does](#part-22-what-each-file-in-the-project-does)

---

## Part 1: What this project is

### The problem

Companies that handle payment cards, sell software to businesses, or sell to the U.S. government have to prove their systems are secure. The rulebooks they answer to include:

- **PCI DSS**, for anyone who handles payment card data
- **SOC 2**, a report many business customers ask their vendors for
- **FedRAMP**, required to sell cloud services to U.S. federal agencies

The people who do this proving are called a GRC team. GRC stands for governance, risk, and compliance. Most GRC teams gather their proof by hand. Someone asks an engineer for a screenshot of a settings page. The screenshot goes into a folder. Months later an auditor looks at it.

That approach has four weaknesses:

1. **A screenshot is out of date the moment it is taken.** It shows one moment. The setting could change the next day and nobody would know until the next audit.
2. **Nothing proves a screenshot is real.** It can be edited, cropped, or taken from the wrong system.
3. **The same work is done several times.** One setting, such as "storage is encrypted," is asked about by all three rulebooks, and each one often gets its own screenshot and its own spreadsheet row.
4. **It does not scale.** The work grows with every system and every rulebook.

### The fix

GRC engineering replaces hand-gathered proof with small programs. The programs ask the cloud provider directly how things are configured, save the answers, and seal each answer so that tampering can be detected. They run every day, not once a year.

### What stage 1 builds

Stage 1 builds the foundation that every later stage uses:

- **A small cloud environment for SecuGuard**, with a network divided into a card data zone, a connected zone, and an office zone
- **Four collectors**, which are programs that ask AWS how the network, encryption keys, storage, and account sign-in settings are configured
- **Labels for all three rulebooks** on every piece of evidence, so one collection answers PCI DSS, SOC 2, and FedRAMP 20x at once
- **A sealing system**, which fingerprints every piece of evidence and links each day's evidence to the day before
- **A locked storage vault** in AWS where evidence cannot be changed or deleted
- **Practice mode**, which runs everything on your own computer against a simulated AWS, for free
- **A daily schedule** that collects evidence automatically

### How the three rulebooks are covered

Every piece of evidence names the requirements it supports in all three rulebooks. For example, the network evidence supports PCI DSS requirements 1.2 to 1.4, SOC 2 criteria CC6.1 and CC6.6, and the FedRAMP 20x indicators for restricting network traffic. Run `secuguard collectors` to see the full list.

The FedRAMP 20x indicator names come from the rules FedRAMP publishes for computers to read, at https://github.com/FedRAMP/rules. This project uses version 2026.11.02.01 of those rules.

Stage 1 collects and seals evidence. It does not judge it. Stage 2 adds the pass or fail checks, and each check is written once and reported against all three rulebooks.

### What stage 2 adds

Stage 2 grades the evidence. Parts 10 to 12 cover it.

- **Realistic resources with deliberate weaknesses**: users, a service account, a vendor role, certificates, a load balancer, an old encryption key, and a storage bucket
- **Four more collectors**, for identities, certificates, load balancers, and logging
- **Checks** across network, encryption, identity, and logging. There are 26 once stages 3 and 4 are included. Each is written once and reported against PCI DSS, SOC 2, and FedRAMP 20x.
- **A report** showing results by check and by framework
- **Two commands that prove the vault**: one tests the lock, one verifies the copy of record

### What stage 3 adds

Stage 3 watches PCI scope and stops risky changes. Parts 13 and 14 cover it.

- **Scope drift detection**: the project works out from the firewall rules what can really reach the card data zone, compares that with each label, and compares the whole network with a baseline a person approved
- **A preventive check**, `secuguard plan-check`, which reads a planned change and blocks it if it breaks a rule, before anything reaches AWS
- **An exceptions register** recording each accepted risk with a reason, an approver, and an expiry date
- **A certificate inventory** in the report, and a check for certificates no authority has issued

### What stage 4 adds

Stage 4 switches on monitoring, reports against FedRAMP 20x, and turns the plan check into a gate. Parts 15 to 17 cover it.

- **Four monitoring services**: CloudTrail, network flow logs, AWS Config, and Security Hub, which fix real findings the earlier stages reported
- **A FedRAMP 20x validation**: a statement about each of FedRAMP's 46 Key Security Indicators, saying which are validated, which are failing, and which this project does not cover, with the evidence each rests on
- **An enforced gate on GitHub**: every proposed change is judged against the real AWS account, and one that breaks a rule cannot be merged

### What comes later

| Stage | What it adds |
|---|---|
| 5 | A readable report, diagrams, and the video walkthrough |

---|---|
| 4 | A FedRAMP 20x validation run covering 10 to 12 indicators end to end, with AWS Config and Security Hub |
| 5 | A readable report, diagrams, and the video walkthrough |

---|---|
| 3 | Detection of systems drifting into PCI scope, plus a check that blocks risky changes before they are made |
| 4 | A FedRAMP 20x validation run covering 10 to 12 indicators end to end, with AWS Config and Security Hub |
| 5 | A readable report, diagrams, and the video walkthrough |

---|---|---|---|---|
| 1 (this stage) | Sealed evidence, labelled for each rulebook | Labelled | Labelled | Labelled |
| 2 | Checks on certificates and encryption strength | Checked | Checked | Checked |
| 3 | Detection of systems drifting into PCI scope, plus a check that blocks risky changes before they are made | Checked | Checked | Checked |
| 4 | A FedRAMP 20x validation run covering 10 to 12 indicators end to end | | | Checked in depth |
| 5 | A readable report, diagrams, and the video walkthrough | Reported | Reported | Reported |

---|---|
| 2 | Checks on certificates and encryption strength |
| 3 | Detection of systems drifting into PCI scope, plus a check that blocks risky changes before they are made |
| 4 | Automated validation for FedRAMP 20x |
| 5 | A readable report, diagrams, and the video walkthrough |

---

## Part 2: The ideas you need

You only need eight ideas to follow the rest of this manual. Each one comes with a comparison to something familiar.

**The cloud and AWS.** AWS (Amazon Web Services) rents out computers, storage, and networks over the internet. You build things there by clicking in a website or by sending instructions. When this manual says "the cloud environment," it means the things you rent from AWS.

**The terminal.** A terminal is a window where you type commands instead of clicking buttons. On Windows the terminal program is called PowerShell. Every command in this manual is meant to be copied, pasted into PowerShell, and run by pressing Enter.

**Security Hub.** The AWS service that evaluates an account against security standards and gathers the findings in one place.

**Service account.** An identity used by a program instead of a person.

**Terraform.** Terraform is a tool that builds cloud environments from written instructions. Think of a blueprint. You hand Terraform the blueprint and it builds exactly that. Hand it the same blueprint tomorrow and it changes nothing. Tell it to tear down and it removes everything it built. The blueprint for this project is in the `terraform` folder.

**Detective control.** A safeguard that finds a problem after it exists. The checks are detective controls.

**Drift.** A difference between how something was approved to be and how it is now.

**Evidence.** Evidence is a saved answer to the question "how is this configured right now?" In this project every piece of evidence is a text file that records what was asked, which account was asked, when, and what AWS answered.

**A hash.** A hash is a fingerprint for a file. A program reads the file and produces a string of 64 letters and numbers. The same file always gives the same fingerprint. Change a single character in the file and the fingerprint comes out completely different. That is how tampering is detected: recompute the fingerprint and compare it to the one recorded earlier.

**The manifest and the chain.** Each time evidence is collected, the project writes a manifest. It works like a packing slip: a list of every evidence file from that run and its fingerprint. Each manifest also records the fingerprint of the previous run's manifest. That links the runs into a chain. If someone rewrites an old run, the link from the next run no longer matches, and the break shows.

**Object Lock.** Fingerprints only help if the fingerprints themselves cannot be quietly replaced. So a copy of every run goes to an AWS storage area with Object Lock turned on. Think of a safe with a time lock. Once a file goes in, nobody can change or delete it until the timer runs out. That locked copy is the copy of record.

**The CDE and PCI scope.** The CDE is the cardholder data environment: the systems that store, process, or send payment card data. PCI DSS rules apply to the CDE and to anything that can connect to it. Those systems are "in scope." Everything else is "out of scope." Keeping the in-scope area small and clearly marked is one of the most important jobs in PCI compliance, and stage 3 of this project checks it automatically.

---

## Part 3: Set up your Windows computer

**What you will do:** install five free programs.
**Time:** about 30 minutes.

| Program | What it is for |
|---|---|
| Git | Tracks changes to the project and sends it to GitHub |
| Python | Runs the collectors |
| Terraform | Builds the cloud environment |
| AWS CLI | Lets your computer sign in to AWS from the terminal |
| Visual Studio Code | A text editor for reading and changing project files |

### Step 1: Open PowerShell

1. Click the Start button.
2. Type `PowerShell`.
3. Click **Windows PowerShell**.

A window with a blinking cursor opens. This is the terminal.

To paste into PowerShell, right-click inside the window or press Ctrl+V.

### Step 2: Install the programs

Copy this whole block, paste it into PowerShell, and press Enter.

```powershell
winget install --id Git.Git -e
winget install --id Python.Python.3.13 -e
winget install --id Hashicorp.Terraform -e
winget install --id Amazon.AWSCLI -e
winget install --id Microsoft.VisualStudioCode -e
```

`winget` is the installer built into Windows. The first time you use it, it may ask you to agree to terms. Type `Y` and press Enter. Windows may also show a pop-up asking whether to allow each installer to make changes. Click **Yes**.

### Step 3: Close and reopen PowerShell

Close the PowerShell window and open a new one. Newly installed programs are not available until you do this.

### Step 4: Confirm everything installed

Run these one at a time.

```powershell
git --version
py --version
terraform -version
aws --version
```

**What you should see:** each command prints a version number, for example `git version 2.47.0.windows.1`. The exact numbers do not matter. If a command prints an error instead, see [Part 20](#part-20-when-something-goes-wrong).

### Step 5: Allow PowerShell to run setup scripts

Windows blocks one script this project needs. Run this once to allow it.

```powershell
Set-ExecutionPolicy -Scope CurrentUser -ExecutionPolicy RemoteSigned
```

If it asks you to confirm, type `Y` and press Enter. This allows scripts on your own computer to run and still blocks unsigned scripts downloaded from the internet. It changes the setting for your Windows user only.

### Step 6: Tell Git who you are

Git labels every saved change with a name and an email address. Because this project will be public, use the private address GitHub gives you so your real email is not published.

1. If you do not have a GitHub account, create one at https://github.com.
2. On GitHub, click your profile picture, then **Settings**, then **Emails**.
3. Turn on **Keep my email addresses private**.
4. Copy the address shown there. It ends in `@users.noreply.github.com`.

Then run these two commands with your own name and that address.

```powershell
git config --global user.name "Your Name"
git config --global user.email "your-private-address@users.noreply.github.com"
```

---

## Part 4: Put the project on your computer

**What you will do:** unzip the project and install its parts.
**Time:** about 10 minutes.

### Step 1: Unzip the project

1. Open File Explorer and go to your user folder, for example `C:\Users\YourName`.
2. Create a folder named `Projects`.
3. Move the project zip file into `Projects`.
4. Right-click the zip file and choose **Extract All**, then **Extract**.

You should now have a folder named `secuguard-grc-engineering` that contains `MANUAL.md`, `README.md`, and folders named `src` and `terraform`. If extracting created a folder inside a folder with the same name, use the inner one.

### Step 2: Open the project in PowerShell

```powershell
cd $HOME\Projects\secuguard-grc-engineering
```

`cd` means "change directory." It moves the terminal into that folder. Every command from here on assumes you are in this folder.

**What you should see:** the text to the left of your cursor now ends with `secuguard-grc-engineering>`.

### Step 3: Create a private workspace for Python

```powershell
py -m venv .venv
```

This creates a folder named `.venv` that holds this project's Python parts, separate from anything else on your computer. It takes a few seconds and prints nothing.

### Step 4: Turn the workspace on

```powershell
.\.venv\Scripts\Activate.ps1
```

**What you should see:** `(.venv)` appears at the start of the line.

You must do this every time you open a new PowerShell window to work on the project. If `(.venv)` is not showing, the project's commands will not be found.

### Step 5: Install the project

```powershell
pip install -e ".[dev]"
```

This downloads the libraries the project depends on and installs the `secuguard` command. It takes a minute or two and prints many lines.

**What you should see:** the last line starts with `Successfully installed`.

---

## Part 5: Run it in practice mode

**What you will do:** collect evidence from a simulated AWS, check it, then tamper with it and watch the tampering get caught.
**Time:** about 10 minutes.
**Cost:** nothing. No AWS account is involved.

Practice mode works like a flight simulator. The collectors run exactly as they will against real AWS, but the "AWS" answering them is a simulation running in your computer's memory.

### Step 1: Collect evidence

```powershell
secuguard collect --mock
```

**What you should see:**

```
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

Your run name and fingerprints will be different. Here is what each line means:

- **Run** is the name of this collection. It starts with the date and time.
- Each **ok** line is one collector finishing and saving its evidence file.
- **graded** is the checks reading that evidence and deciding pass or fail. Most fail on purpose. Parts 10 and 11 explain why and how to read the results.
- **Manifest** is the packing slip listing every file and its fingerprint.
- **sha256** is the fingerprint of the manifest itself.
- **previous** is the fingerprint of the run before this one. There is none yet.

### Step 2: Look at a piece of evidence

```powershell
code evidence
```

This opens the evidence folder in Visual Studio Code. Open the run folder and click `s3.json`. Near the top you will find:

| Field | Meaning |
|---|---|
| `collected_at` | When the evidence was gathered |
| `source` | Which account and region it came from, and who collected it |
| `api_calls` | The exact questions that were asked of AWS |
| `relevant_to` | Which PCI DSS, SOC 2, and FedRAMP 20x requirements this evidence helps answer |
| `payload` | What AWS answered |
| `payload_sha256` | The fingerprint of that answer |

### Step 3: Collect a second time

```powershell
secuguard collect --mock
```

Look at the `previous` line this time. It now shows the fingerprint of your first run. The two runs are linked.

### Step 4: Verify the evidence

```powershell
secuguard verify
```

**What you should see:**

```
OK. 2 run(s) verified. Every file matches its recorded hash and every run links to the one before it.
```

Verifying means recomputing every fingerprint from the files as they are now and comparing each one to what was recorded when the evidence was collected.

### Step 5: Tamper with the evidence

Now play the part of someone trying to make the company look better than it is.

1. In Visual Studio Code, open `iam.json` in either run folder.
2. Find the line `"MinimumPasswordLength": 14`.
3. Change `14` to `20`.
4. Save the file with Ctrl+S.

Verify again.

```powershell
secuguard verify
```

**What you should see:**

```
TAMPERING OR DAMAGE DETECTED in 2 run(s) checked:
  - 20261110T150035Z-482913-a67f/iam.json: file hash does not match the manifest
```

One changed character was enough. This is the difference between this evidence and a screenshot.

### Step 6: Clean up

Delete the practice evidence so it does not mix with real evidence later.

```powershell
Remove-Item -Recurse evidence
```

### Optional: run the project's self-tests

```powershell
pytest
```

**What you should see:** a row of dots and `67 passed`. These tests check that the sealing system catches edited files, missing files, added files, and rewritten history, and that every check finds the weaknesses it is meant to find.

---

## Part 6: Create and secure your AWS account

**What you will do:** open an AWS account, protect it, and connect your computer to it.
**Time:** about 45 minutes.
**You need:** an email address, a phone, a credit or debit card, and an authenticator app on your phone such as Google Authenticator or Microsoft Authenticator.

AWS changes its screens often. If a button is named slightly differently from what this manual says, look for the closest match.

### Step 1: Create the account

AWS has two ways to sign up, and only one of them works for this project.

| Sign-up | What you get | Use it? |
|---|---|---|
| **New** (the main "Create an account" button on the AWS website) | A simplified account fixed to one region, with many security services turned off | No |
| **Advanced** | A full account with every service and a choice of region | Yes |

AWS itself recommends the advanced sign-up for FedRAMP and other regulated work. To be sure you get it, start from the link in step 1 below, not from the AWS home page.

1. Open this address:

   ```
   https://signin.aws.amazon.com/signup?request_type=register
   ```

2. Enter an email address and an account name, then choose **Verify email address**. `secuguard-grc` works well as the name.

   The email address becomes the sign-in for the account's owner. If you have ever signed up for AWS before, use an email address that is not already tied to an AWS account.
3. Enter the code AWS emails you and choose **Verify**.
4. Create a password and choose **Continue**.
5. When asked to choose an account plan, pick the **paid plan**. The free plan limits which services you can use, and later stages need services outside it. You are still charged only for what you use.
6. Enter your contact details and accept the customer agreement.
7. Enter your card details.
8. Confirm your identity with the code AWS sends to your phone.
9. For the support plan, choose **Basic**. It is free.
10. Choose **Complete sign up**. AWS emails you when the account is ready, usually within a few minutes.
11. Sign in at https://console.aws.amazon.com. Choose the option to sign in as the **root user** with the email and password you just created.

**How to tell you are in the right kind of account:** the top bar of the console shows a region name, such as **N. Virginia** or **Ohio**, to the left of your account name. If you see buttons named **Manage projects** and **Manage team** and no region name, you are in the simplified kind. Sign out and start this step again from the link above.

The email and password you just created belong to the **root user**. The root user can do anything to the account, including closing it. You will protect it now and then stop using it.

### Step 2: Protect the root user

1. Sign in to the AWS Console at https://console.aws.amazon.com as the root user.
2. Click your account name in the top right corner, then **Security credentials**.
3. Under **Multi-factor authentication (MFA)**, choose **Assign MFA device**.
4. Choose **Authenticator app** and follow the prompts to scan the code with your phone.

From now on, signing in as root needs both the password and a code from your phone.

Do not create access keys for the root user. If the page offers to, decline.

### Step 3: Set a spending alert

1. In the search bar at the top of the console, type `Budgets` and open **Budgets**.
2. Choose **Create budget**.
3. Choose **Use a template**, then **Monthly cost budget**.
4. Enter an amount of `50` and your email address.
5. Choose **Create budget**.

This does not stop spending. It emails you if the month's bill is heading past the amount, so nothing surprises you. Stage 1 costs about one dollar a month.

### Step 4: Create your everyday sign-in

You will do all your work as a separate user, not as root. The service that manages this is called IAM Identity Center.

This project uses the AWS region called **US East (N. Virginia)**. Its code is `us-east-1`.

1. Look at the top bar of the console, to the left of your account name. It shows the current region.
2. If it does not say **N. Virginia**, click the region name and choose **US East (N. Virginia)**.

   If the page you are on shows **Global** there, or no region at all, that page is not tied to a region. Carry on to the next step and check again once IAM Identity Center is open.
3. In the search bar, type `IAM Identity Center` and open it.
4. Check the region again. The top bar should say **N. Virginia**, and the address in your browser should contain `us-east-1`.

   Do not skip this check. IAM Identity Center is set up in whichever region is selected when you enable it, and the rest of this manual assumes `us-east-1`.
5. Choose **Enable**. If asked, choose to enable it with AWS Organizations.
6. In the left menu, choose **Users**, then **Add user**. Enter a username, your email, and your name. Finish the prompts.
7. Check your email for an invitation from AWS. Accept it, set a password, and set up MFA with your authenticator app when asked.
8. Back in IAM Identity Center, choose **Permission sets** in the left menu, then **Create permission set**.
9. Choose **Predefined permission set**, then **AdministratorAccess**. Finish the prompts.
10. In the left menu, choose **AWS accounts**. Tick the box next to your account and choose **Assign users or groups**.
11. Select your user, then select the **AdministratorAccess** permission set, and submit.
12. In the left menu, choose **Settings** and scroll down to **AWS access portal URLs**. Two addresses are listed. Copy the one labelled **IPv4-only**, which ends in `awsapps.com/start`. You need it in the next step.

### Step 5: Connect your computer to AWS

In PowerShell, run:

```powershell
aws configure sso
```

Answer the questions like this:

| Question | Your answer |
|---|---|
| SSO session name | `secuguard` |
| SSO start URL | Paste the AWS access portal URL you copied |
| SSO region | `us-east-1` |
| SSO registration scopes | Press Enter to accept the default |

Your browser opens. Sign in with the user you created in step 4 and approve the request. Return to PowerShell and finish answering:

| Question | Your answer |
|---|---|
| Account and role | If asked, pick your account and `AdministratorAccess` |
| Default client Region | `us-east-1` |
| CLI default output format | `json` |
| Profile name | `secuguard` |

A **profile** is a saved sign-in. Every command that talks to AWS will name this profile.

### Step 6: Confirm the connection

```powershell
aws sts get-caller-identity --profile secuguard
```

**What you should see:** three lines showing a `UserId`, your twelve-digit `Account` number, and an `Arn` that contains `AdministratorAccess`.

The sign-in lasts a few hours. When it expires, commands fail with a message about an expired token. Sign in again with:

```powershell
aws sso login --profile secuguard
```

---

## Part 7: Build SecuGuard's cloud environment

**What you will do:** have Terraform build the network and the evidence vault in your AWS account.
**Time:** about 15 minutes.
**Cost:** about $25 a month while it exists. Most of that is one load balancer, which [Part 18](#part-18-costs-and-shutting-down) shows how to pause.

### What gets built

**A private network** with no connection to the internet, divided into three zones. Each zone carries a label saying where it sits in PCI scope.

| Zone | PCI scope label | What it represents |
|---|---|---|
| `cde` | `cde` | Systems that handle card data |
| `shared` | `connected` | Systems allowed to reach the CDE, so they are in scope too |
| `corporate` | `out-of-scope` | Office systems with no path to the CDE |

**Firewall rules between the zones.** In AWS these are called security groups. The CDE accepts encrypted web traffic from the shared zone and nothing else. The corporate zone can reach the shared zone but has no rule into the CDE.

**The evidence vault.** A storage area (AWS calls it an S3 bucket) with four protections: it is encrypted, it is closed to the public, it keeps every version of every file, and Object Lock stops any version from being changed or deleted.

**An encryption key** that protects the vault and replaces itself every year.

No servers are created. The only thing billed by the hour is the load balancer that stage 2 adds.

### Step 1: Go to the Terraform folder

Make sure you are signed in (`aws sso login --profile secuguard`), then:

```powershell
cd terraform
```

### Step 2: Create your settings file

```powershell
Copy-Item terraform.tfvars.example terraform.tfvars
```

This file tells Terraform which region and which saved sign-in to use. The defaults are correct, so you do not need to edit it yet.

### Step 3: Prepare Terraform

```powershell
terraform init
```

This downloads the plugin Terraform uses to talk to AWS. You do this once.

**What you should see:** `Terraform has been successfully initialized!`

### Step 4: Preview the build

```powershell
terraform plan
```

Terraform lists everything it intends to create and changes nothing. Read through it. Each block starting with `+` is one thing to be created.

**What you should see:** the last line reads `Plan: 81 to add, 0 to change, 0 to destroy.`

Of those 81, 30 are the foundation described above. Another 28 are deliberate, harmless weaknesses for the checks to find later, explained in [Part 10](#part-10-stage-2-give-the-checks-something-to-find) and [Part 13](#part-13-stage-3-catch-scope-drift). Another 16 are monitoring services, explained in [Part 15](#part-15-stage-4-switch-on-monitoring-and-fix-real-findings). The last 7 are a bucket for Terraform's own records, explained in [Part 17](#part-17-enforce-the-plan-check-on-github).

### Step 5: Build it

```powershell
terraform apply
```

Terraform shows the plan again and asks for confirmation. Type `yes` and press Enter. The build takes about a minute.

The load balancer takes two to three minutes to create, so expect a wait near the end.

**What you should see:** `Apply complete! Resources: 81 added, 0 changed, 0 destroyed.` followed by a list of outputs, including a line like:

```
evidence_bucket = "secuguard-evidence-123456789012"
```

That is the name of your evidence vault.

### Step 6: See it in the AWS Console

This step is optional, and worth doing once so you can picture what you built.

1. Sign in to the console through your AWS access portal URL.
2. Search for `VPC`, open it, and choose **Subnets**. You will see six subnets whose names start with `secuguard-`. Click one and open its **Tags** tab to see the `secuguard:pci-scope` label.
3. Search for `S3` and open it. You will see the `secuguard-evidence-` bucket. Open its **Properties** tab and scroll to **Object Lock** to see that it is enabled.

### Step 7: Return to the project folder

```powershell
cd ..
```

---

## Part 8: Collect real evidence

**What you will do:** run the collectors against your real AWS account and store the results in the vault.
**Time:** about 10 minutes.

### Step 1: Look up the vault's name

```powershell
$bucket = terraform -chdir=terraform output -raw evidence_bucket
$bucket
```

The first line asks Terraform for the vault's name and saves it under the short name `$bucket`. The second line prints it so you can see it worked.

`$bucket` is forgotten when you close PowerShell. Run this step again in each new window.

### Step 2: Collect and upload

```powershell
secuguard collect --profile secuguard --upload --bucket $bucket
```

**What you should see:** the same kind of output as practice mode, with three differences. It says `aws mode`. The account number is your own. And a final line reads:

```
Uploaded 14 files to s3://secuguard-evidence-123456789012/runs/20261110T.../
```

The fourteen files are nine evidence files, a copy of the approved scope baseline, the check results, the FedRAMP 20x validation, the manifest, and the manifest's fingerprint.

The collectors only read. They ask AWS how things are configured and cannot change anything in your environment.

### Step 3: Verify it

```powershell
secuguard verify
```

**What you should see:** `OK. 1 run(s) verified.`

### Step 4: Read what was collected

```powershell
code evidence
```

Open `network.json`. Under `payload`, then `subnets`, you will find the six subnets Terraform built, each with its `secuguard:pci-scope` tag. Open `s3.json` and you will find your evidence vault describing its own protections: encryption, versioning, public access block, and Object Lock.

This is real evidence. It came from AWS itself, it records exactly when and how it was gathered, and it is sealed.

### Step 5: Try to destroy the copy of record

This shows why the vault matters. Your laptop copy can be edited, as you saw in practice mode. The vault copy cannot, even by you, and you are the administrator.

1. In the AWS Console, open **S3**, then your evidence bucket, then the `runs` folder, then your run.
2. Turn on the **Show versions** switch above the file list. This step matters. With the switch off, deleting only hides a file and AWS reports success. With it on, you are asking AWS to remove the stored file for good.
3. Tick the box next to `iam.json` and choose **Delete**.
4. Type `permanently delete` in the confirmation box and choose **Delete objects**.

**What you should see:** a red banner saying the delete failed, and `iam.json` listed under **Failed to delete** with an **Access Denied** error.

The vault uses a lock mode called **compliance mode**. In this mode nobody can remove or change a locked file until its lock ends. That includes administrators and the root user. There is no override.

AWS has a weaker mode called governance mode. It blocks ordinary users, but the AWS Console removes the lock automatically for administrators, so an administrator can delete evidence with two clicks. That is not good enough for evidence an auditor has to trust, so this project does not use it.

In this demo the lock lasts one day, so the project can be removed the day after you finish. A real company would lock evidence for at least a year. The length is one line in `terraform/variables.tf`.

---

## Part 9: Publish to GitHub and collect evidence every day

**What you will do:** put the project on GitHub, then set it to collect evidence automatically each day.
**Time:** about 30 minutes.

### Step 1: Create an empty repository on GitHub

A repository is a project's home on GitHub.

1. Sign in at https://github.com.
2. Click the **+** in the top right corner, then **New repository**.
3. Name it `secuguard-grc-engineering`.
4. Choose **Public**.
5. Leave every "Add" or "Initialize" option turned off. The repository must start empty.
6. Choose **Create repository**.

### Step 2: Send the project to GitHub

In PowerShell, in the project folder, run these one at a time. The address in the fourth line uses the GitHub username `andrewcampion0473`. If you are setting up your own copy of this project, put your own username there.

```powershell
git init -b main
git add .
git commit -m "Stage 1: evidence pipeline, Terraform baseline, and practice mode"
git remote add origin https://github.com/andrewcampion0473/secuguard-grc-engineering.git
git push -u origin main
```

What each line does:

1. Starts tracking this folder with Git.
2. Selects every file to be saved.
3. Saves a snapshot with a description.
4. Tells Git where the GitHub repository is.
5. Sends the snapshot to GitHub.

The first time you push, a browser window opens asking you to sign in to GitHub. Sign in and approve.

Some files are deliberately left out of GitHub: your `evidence` folder, your `terraform.tfvars` settings, and Terraform's record of what it built. The file `.gitignore` lists them. None of them belong in a public place.

**What you should see:** refresh the repository page on GitHub and your files are there. Click the **Actions** tab. A job named **Tests** is running or finished with a green check mark. GitHub just ran the project's self-tests and a full practice-mode collection on its own computers.

### Step 3: Let GitHub sign in to AWS without a password

The daily collection runs on GitHub's computers, so GitHub needs permission to read your AWS account. The safe way to do this involves no stored password or key at all. GitHub proves to AWS which repository is asking, and AWS hands back a pass that expires in one hour. The pass can read configuration and add new files to the evidence vault. It cannot delete evidence or change anything else.

AWS needs to know exactly which repository to trust. GitHub identifies a repository by its name and by two permanent numbers: one for your account and one for the repository. The numbers matter because a name can be given up and registered by someone else, but the numbers never change hands.

1. Have PowerShell look up the two numbers and print the three lines you need:

   ```powershell
   $repo = Invoke-RestMethod https://api.github.com/repos/andrewcampion0473/secuguard-grc-engineering
   "github_repository    = `"$($repo.full_name)`""
   "github_owner_id      = `"$($repo.owner.id)`""
   "github_repository_id = `"$($repo.id)`""
   ```

   If you are setting up your own copy, use your own username in the address.

   **What you should see:** three lines. The first ends with your repository name. The second and third each end with a number in quotation marks.
2. Select those three printed lines in PowerShell and copy them.
3. Open the settings file:

   ```powershell
   code terraform\terraform.tfvars
   ```

4. Paste the three lines at the bottom of the file. Use exactly what PowerShell printed. The numbers are different for every account and every repository, so numbers from anywhere else will not work.
5. Save the file with Ctrl+S.
6. Apply the change:

   ```powershell
   terraform -chdir=terraform apply
   ```

   Type `yes` when asked.

**What you should see:** `Apply complete! Resources: 4 added, 0 changed, 0 destroyed.` Among the outputs are a line that starts with `github_actions_role_arn = "arn:aws:iam::` and a line like this:

```
github_actions_subject = "repo:andrewcampion0473@OWNER-NUMBER/secuguard-grc-engineering@REPOSITORY-NUMBER:ref:refs/heads/main"
```

In your output, your two numbers appear where this example says OWNER-NUMBER and REPOSITORY-NUMBER. That line is the exact identity AWS will accept. Only a job running from the main branch of that one repository matches it.

### Step 4: Give GitHub the two values it needs

1. Print what Terraform built:

   ```powershell
   terraform -chdir=terraform output
   ```

   Among the lines it prints, find these two:

   ```
   evidence_bucket = "secuguard-evidence-123456789012"
   github_actions_role_arn = "arn:aws:iam::123456789012:role/secuguard-evidence-collector"
   ```

   Yours will show your own twelve-digit account number. The values you need are the text between the quotation marks, without the quotation marks.

   If `github_actions_role_arn` shows empty quotation marks, step 3 has not been applied yet. Go back and finish it.
2. On GitHub, open your repository, then **Settings**, then **Secrets and variables**, then **Actions**.
3. Click the **Variables** tab.
4. Choose **New repository variable**. In **Name**, type `AWS_ROLE_ARN`. In **Value**, paste the `github_actions_role_arn` value. It starts with `arn:aws:iam::` and ends with `secuguard-evidence-collector`. Save.
5. Choose **New repository variable** again. In **Name**, type `EVIDENCE_BUCKET`. In **Value**, paste the `evidence_bucket` value. It starts with `secuguard-evidence-`. Save.

Neither value is a secret. They are names, not keys. Knowing them does not let anyone into your account.

### Step 5: Run the first automated collection

1. On GitHub, open the **Actions** tab.
2. In the left list, click **Collect evidence**.
3. Click **Run workflow**, then the green **Run workflow** button.
4. Wait about a minute and refresh the page.

**What you should see:** a green check mark. Click the run, then **collect**, then **Collect, grade, and upload evidence** to see the same output you saw on your own computer, ending with `Uploaded 14 files`.

From now on this runs by itself every day at 11:17 UTC. Each run links to the one before it, so the vault holds an unbroken daily record of how SecuGuard's environment was configured.

---

## Part 10: Stage 2: Give the checks something to find

**What you will do:** update the project, add realistic resources with deliberate weaknesses to SecuGuard's AWS environment, and collect evidence about them.
**Time:** about 30 minutes.
**Cost:** about $18 a month more while the load balancer exists. See [Part 18](#part-18-costs-and-shutting-down).

Stage 1 collected evidence and stopped there. Stage 2 adds **checks**. A check is a rule that reads the evidence and answers pass or fail, for example "every encryption key rotates automatically."

A check that only ever says "pass" proves nothing, so stage 2 also adds things for the checks to catch. These are the problems GRC teams find in real accounts.

### What gets added, and which check catches it

| Area | What is created | The weakness | Check |
|---|---|---|---|
| Network | A firewall rule group in the office zone | SSH is open to the whole internet | NET-01 |
| Encryption | An encryption key named `secuguard-legacy-no-rotation` | Automatic rotation is off | CRY-01 |
| Storage | A bucket named `secuguard-legacy-exports-...` | No key of its own, and its public access protections are off | CRY-02, CRY-03 |
| Certificates | A certificate for `legacy-api.secuguard.example` | A short 1024-bit key, and it expires 20 days after it is created | CRY-04, CRY-05 |
| Certificates | A certificate for `portal.secuguard.example` | None. It is healthy, for comparison | |
| Load balancer | A load balancer named `secuguard-portal` | It still accepts the outdated TLS 1.0 and 1.1 | CRY-06 |
| People | A user named `secuguard-dev-alice` | Can sign in with a password and has no MFA | IAM-04 |
| Machines | A service account named `secuguard-svc-reports` | Administrator rights attached directly, and an access key nobody has ever used | IAM-05, IAM-06 |
| People | A user named `secuguard-audit-carol` | None. She gets read-only rights through a group, for comparison | |
| Vendors | A role named `secuguard-legacy-vendor` | An outside account may use it with no extra proof of identity | IAM-07 |

Other checks look at what is already true of your account. Those findings are real, not planted. For example, your account has no CloudTrail trail recording activity yet, and LOG-01 reports that.

### Why this is safe to build in a real account

- **The users and the role can do nothing.** Each one carries a permissions boundary, which is a hard cap on what an identity can do. This one denies every action. Their attached rights are visible to the checks but have no effect, even if a password or key leaked.
- **The bucket is empty** and has no setting that makes it public. Only its protections are missing.
- **Nothing is reachable from the internet.** The network still has no internet gateway. The open SSH rule and the load balancer have nothing behind them and no path in.

To remove every planted weakness at any time, add `planted_findings = false` to `terraform\terraform.tfvars` and run `terraform -chdir=terraform apply`.

### Step 1: Update the project files

1. Download the newest `secuguard-grc-engineering.zip`.
2. Unzip it over your project folder, replacing files when asked. Your `.venv`, `terraform.tfvars`, and `evidence` folder are not in the zip and are left alone.

### Step 2: Update the Python parts

Open PowerShell in the project folder, turn on the workspace, and install again. Stage 2 uses two more libraries.

```powershell
cd $HOME\Projects\secuguard-grc-engineering
.\.venv\Scripts\Activate.ps1
pip install -e ".[dev]"
```

Use your own folder if the project is somewhere else.

**What you should see:** the last line starts with `Successfully installed`.

### Step 3: Run the tests

```powershell
pytest
```

**What you should see:** `67 passed`. The new tests confirm that every planted weakness is caught, that healthy resources are left alone, and that a check never reports pass when its evidence is missing.

### Step 4: Try it in practice mode first

```powershell
secuguard collect --mock
secuguard report
```

**What you should see:** the first command prints nine `ok` lines, then a line like `graded 26 checks` followed by how many passed and failed. The second prints a table of every check, then the same results grouped by framework. [Part 11](#part-11-read-the-check-results) explains how to read it.

Then delete the practice evidence so it does not mix with real evidence:

```powershell
Remove-Item -Recurse evidence
```

If you have real evidence in that folder that you want to keep, skip the delete. Practice runs are labelled `mock mode` and do no harm.

### Step 5: Build the new resources in AWS

1. Sign in:

   ```powershell
   aws sso login --profile secuguard
   ```

2. Let Terraform fetch one more plugin. Stage 2 uses it to generate the certificates.

   ```powershell
   terraform -chdir=terraform init -upgrade
   ```

   **What you should see:** `Terraform has been successfully initialized!`

3. Preview the build:

   ```powershell
   terraform -chdir=terraform plan
   ```

   **What you should see:** a last line starting with `Plan:` that ends in `0 to destroy`. Nothing should be removed.

   If you set the project up for the first time with this version of the manual, Part 7 already built these resources. Terraform then says `No changes`, and you can skip to step 6.

4. Build it:

   ```powershell
   terraform -chdir=terraform apply
   ```

   Type `yes` when asked. The load balancer takes two to three minutes to create, so this apply is slower than the first one.

   **What you should see:** a line starting with `Apply complete!` that ends in `0 destroyed`.

### Step 6: Collect evidence about the new resources

```powershell
$bucket = terraform -chdir=terraform output -raw evidence_bucket
secuguard collect --profile secuguard --upload --bucket $bucket
```

**What you should see:** nine `ok` lines, a `graded 26 checks` line with pass and fail counts, and `Uploaded 14 files`. The fourteen files are nine evidence files, a copy of the approved scope baseline, the check results, the FedRAMP 20x validation, the manifest, and the manifest's fingerprint.

The check results are sealed and stored in the vault with the evidence they were graded from. Nobody can quietly change a "fail" to a "pass" afterward.

---

## Part 11: Read the check results

**What you will do:** read the report, fix one real finding, and watch the result change.
**Time:** about 20 minutes.

### Step 1: Show the report

```powershell
secuguard report
```

This shows the newest run in your `evidence` folder. The top half lists every check:

```
Check   Result       Severity  What was checked
------------------------------------------------------------------------------------------------
NET-01  FAIL         high      No administrative port is open to the internet
          x security group secuguard-planted-open-admin (sg-0abc...): open to the whole internet: SSH (port 22)
NET-02  PASS         high      The card data zone accepts traffic only from in-scope systems
CRY-01  FAIL         medium    Encryption keys rotate automatically
          x KMS key alias/secuguard-legacy-no-rotation: automatic rotation is off
```

Each line starting with `x` names one resource that broke the rule and says why.

The bottom half shows the same results turned around, by framework:

```
PCI DSS 4.0.1
  1.3.1         FAIL         NET-01, NET-02
  3.7.4         FAIL         CRY-01
  10.3.2        PASS         LOG-02
```

Read a line as: "requirement 1.3.1 is spoken to by checks NET-01 and NET-02, and at least one of them failed." A requirement shows FAIL if any of its checks failed.

This is the point of the whole project. Each check was written once. The report shows its result under PCI DSS, SOC 2, and FedRAMP 20x without any extra work.

### What the four results mean

| Result | Meaning |
|---|---|
| PASS | Every resource the check looked at meets the rule |
| FAIL | At least one resource does not. The `x` lines name them. |
| N/A | There was nothing of that kind to look at |
| NO EVIDENCE | The evidence the check needs is missing or could not be collected, so it draws no conclusion |

NO EVIDENCE matters. A check never reports PASS on evidence it does not have. If a collector is refused permission, the checks that depend on it say so plainly.

### What you should expect to see

Your exact counts depend on your account. Expect most checks to fail, which is the intent of this stage.

| Check | Expected | Why |
|---|---|---|
| NET-01, CRY-01 to CRY-06, IAM-04 to IAM-07 | FAIL | The planted weaknesses from Part 10 |
| NET-02, SCP-01 to SCP-03 | FAIL | The planted scope drift, explained in Part 13 |
| CRY-07 | FAIL | Real finding: the certificate on the load balancer was not issued by a certificate authority |
| LOG-02, SCP-04 | PASS | The evidence vault is built correctly, and the card data zone has no route to the internet |
| LOG-01, MON-01, MON-02 | PASS | The monitoring services from Part 15 are switched on. LOG-01 failed until then. |
| IAM-01, IAM-02 | PASS | You protected the root user in Part 6 |
| IAM-03 | FAIL | Real finding: no password policy has been set |
| NET-03 | FAIL | Real finding: AWS's own default network in your account has a permissive default firewall group |
| NET-04 | FAIL | Real finding: AWS's own default network is not being logged |

### Step 2: See what a check means

```powershell
secuguard checks
```

This lists all 26 checks. Each one shows a plain-language reason it matters and the requirements it reports against in each framework.

### Step 3: Fix a real finding and watch it change

IAM-03 fails because your account has no password policy. Fix it for real.

1. Set a policy:

   ```powershell
   aws iam update-account-password-policy --minimum-password-length 14 --require-symbols --require-numbers --require-uppercase-characters --require-lowercase-characters --password-reuse-prevention 24 --profile secuguard
   ```

   It prints nothing when it works.

2. Collect again:

   ```powershell
   secuguard collect --profile secuguard --upload --bucket $bucket
   ```

3. Show the report:

   ```powershell
   secuguard report
   ```

**What you should see:** IAM-03 now reads PASS, and PCI DSS requirement 8.3.6 with it. One more check passed than last time.

You now have two sealed runs in the vault: one from before the fix showing FAIL, and one from after showing PASS. That pair is what an auditor asks for when they want proof that a finding was fixed.

### Step 4: Save a copy of the report and open it

```powershell
secuguard report --markdown | Out-File -Encoding utf8 report.md
code report.md
```

The first line writes `report.md`, a formatted version with a Findings section that explains each failure. The second line opens it in Visual Studio Code.

Once it is open, press Ctrl+Shift+V to see it formatted with tables and headings. Press Ctrl+K, then V, to show the formatted view beside the text.

`report.md` is kept out of GitHub, because it names your AWS account.

### Grading old evidence again

Checks read evidence files. They do not talk to AWS. So you can grade a run from last week with today's checks:

```powershell
secuguard report --regrade
```

This matters when a framework changes or a check is improved. The evidence does not need to be collected again.

---

## Part 12: Prove the vault from the command line

**What you will do:** test the vault's lock with one command, and verify the copy of record directly.
**Time:** about 10 minutes.

### Step 1: Test the lock

In Part 8 you proved the lock by clicking through the AWS Console. This command does the same test in a few seconds and is easy to show someone.

```powershell
secuguard test-lock --profile secuguard --bucket $bucket
```

It uploads a small marker file, then asks AWS to delete that exact stored version for good, and to bypass the lock if it can. No evidence is touched.

**What you should see:**

```
Uploaded a marker file to s3://secuguard-evidence-.../lock-test/20261112T....txt
  lock mode     COMPLIANCE
  locked until  2026-11-13 15:31 UTC
Tried to delete that stored version permanently, asking AWS to bypass the lock.
REFUSED (AccessDenied). The vault would not delete a locked file, even on request to bypass.
```

If it prints NOT PROTECTED, the vault is not in compliance mode. See [Part 20](#part-20-when-something-goes-wrong).

### Step 2: Verify the copy of record

`secuguard verify` checks the evidence folder on your computer. That folder does not hold the runs GitHub collects each day, so it is not the full record. This command checks the vault itself:

```powershell
secuguard verify --vault --profile secuguard --bucket $bucket
```

It reads every run from the vault, recomputes every fingerprint, and checks that each run links to the one before it.

**What you should see:** a line saying how many files were read, then a result.

If you followed Part 8 while the vault was still in its first, weaker lock mode, expect one problem to be reported: a file listed in a manifest but missing. That is the evidence file you deleted during that test. The report is correct. Evidence was destroyed, the record shows it, and it cannot be hidden. Every run after the switch to compliance mode verifies.

### Step 3: Publish stage 2

```powershell
git add .
git commit -m "Stage 2: checks across PCI DSS, SOC 2, and FedRAMP 20x"
git push
```

**What you should see:** on GitHub, the **Tests** job goes green. Click into it and open its **Summary** page. The check results from the simulated environment are printed there as a formatted report.

The daily **Collect evidence** job does the same with real results. Run it once by hand from the **Actions** tab, open the run, and look at its Summary page. From now on, each day's results for all three frameworks appear there without anyone running anything.

---

## Part 13: Stage 3: Catch scope drift

**What you will do:** add three resources that quietly change what PCI DSS applies to, and watch the project notice.
**Time:** about 25 minutes.
**Cost:** nothing extra. Firewall rule groups are free.

### What scope drift is

PCI DSS applies to the card data zone and to anything that can connect to it. That set of systems is the **scope**. Keeping scope small is how a company keeps PCI DSS manageable, and confirming scope is the first thing an assessor does.

Scope is usually written down once: a diagram, a spreadsheet, a set of labels. Then the network keeps changing. Someone adds a firewall rule so a reporting tool can query the card database. Nobody updates the diagram. The reporting tool is now in scope, with none of the PCI controls applied to it, and nobody knows until the next assessment. That is scope drift.

Stage 3 catches it three ways.

| Question | How it is answered | Check |
|---|---|---|
| Has every part of the network been given a scope? | Look for the `secuguard:pci-scope` tag | SCP-01 |
| Is each label true? | Work out from the firewall rules what can really reach the card data zone, and compare | SCP-02 |
| Has anything changed since a person last approved the scope? | Compare the network with an approved list, the baseline | SCP-03 |

A fourth check, SCP-04, confirms the card data zone has no route to the internet.

### What gets added

| What is created | The problem | Checks that catch it |
|---|---|---|
| A firewall group named `secuguard-planted-analytics`, labelled out of scope | It is allowed straight into the card data zone on the database port. The label says PCI DSS does not apply. The rule says it does. | NET-02, SCP-02, SCP-03 |
| A firewall group named `secuguard-planted-unclassified` | It has no scope label at all | SCP-01, SCP-03 |

Both are attached to nothing, so no system gains any access.

Stage 3 also adds check CRY-07, which reports certificates in use that no certificate authority has issued, and a certificate inventory in the report.

### Step 1: Update the project

1. Download the newest `secuguard-grc-engineering.zip` and unzip it over your project folder, replacing files.
2. In PowerShell, in the project folder with the workspace on:

   ```powershell
   pip install -e ".[dev]"
   pytest
   ```

**What you should see:** `67 passed`.

### Step 2: See drift in practice mode

```powershell
secuguard collect --mock
secuguard scope
```

**What you should see:** a table of the network, then the drift.

```
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

**Declared** is the label. **Actually** is what the firewall rules make it. The line marked `mismatch` is a system someone labelled out of scope that can reach card data.

Delete the practice evidence afterward if you do not want it mixed with real runs. Find the newest folder in `evidence` whose files say `mock` and remove it, or leave it. Practice runs are clearly labelled.

### Step 3: Add the drift to your real network

1. Sign in if needed:

   ```powershell
   aws sso login --profile secuguard
   ```

2. Preview and build:

   ```powershell
   terraform -chdir=terraform plan
   terraform -chdir=terraform apply
   ```

   Type `yes` when asked.

**What you should see:** a plan ending in `0 to destroy`, and then a line starting with `Apply complete!`. If Part 7 already built everything, Terraform says `No changes`.

### Step 4: Collect and look

```powershell
$bucket = terraform -chdir=terraform output -raw evidence_bucket
secuguard collect --profile secuguard --upload --bucket $bucket
secuguard scope
```

**What you should see:** `graded 26 checks`, `Uploaded 14 files`, and then the same mismatch and drift you saw in practice mode, now from your real network.

One of those files is a copy of the approved baseline as it stood at the moment of collection, sealed with the rest. That way the record shows what was approved at the time, even if the baseline changes later.

Now show the full report:

```powershell
secuguard report
```

**What you should see:** five new checks, CRY-07 and SCP-01 to SCP-04. NET-02, which passed before, now fails, because the card data zone accepts traffic from a group labelled out of scope. Below the checks are two new sections: the PCI scope of the network, and a certificate inventory listing each certificate with its issuer, key, expiry date, and what is using it.

### Step 5: Try to approve the drift

The baseline is the file `scope-baseline.json` in the project folder. It lists each part of the network and its approved scope, with who approved it and when. To accept the current network as the new baseline, a person runs an approval:

```powershell
secuguard scope --approve --by "Your Name"
```

**What you should see:**

```
Not approved. A baseline should record a correct network, and this one has problems:
  security group secuguard-planted-analytics: declared out-of-scope but can reach the card data zone
  security group secuguard-planted-unclassified: has no declared scope
Fix these first, collect again, then approve.
```

The project refuses. Approval is for recording a correct network, not for making a finding go away. In this project the two planted groups stay as findings, so the baseline stays as it is.

When an approval is accepted, it rewrites `scope-baseline.json`. That file is tracked by Git, so its history is a permanent record of who approved each change to scope and when.

---

## Part 14: Block risky changes before they are made

**What you will do:** run a check on a planned change before it reaches AWS, and watch a risky change get refused.
**Time:** about 20 minutes.

Everything so far finds a problem after it exists. That is a **detective** control. This part adds a **preventive** control: it reads what Terraform is about to do and refuses changes that break a rule, so the problem never reaches AWS.

### How it works

Before Terraform changes anything, it produces a plan: an exact list of what it would create, change, or delete. `secuguard plan-check` asks Terraform for that plan and tests each planned change against eight rules.

| Rule | What it blocks |
|---|---|
| PLAN-01 | Opening SSH or Remote Desktop to the whole internet |
| PLAN-02 | Letting anything into the card data zone except a named, in-scope group |
| PLAN-03 | Creating a network resource with no PCI scope label |
| PLAN-04 | Creating an encryption key with rotation off |
| PLAN-05 | Switching off a storage bucket's public access protections |
| PLAN-06 | A listener that accepts unencrypted traffic or outdated TLS |
| PLAN-07 | Weakening or removing the evidence vault |
| PLAN-08 | Attaching administrator rights directly to a user |

### Step 1: Check a plan with nothing in it

```powershell
secuguard plan-check
```

**What you should see:**

```
Asking Terraform what it would change...
No changes. Your infrastructure matches the configuration.
Examined 0 planned changes against 8 rules.

ALLOWED. No planned change breaks a rule.
```

### Step 2: Propose a risky change

The project includes a sample change that looks reasonable. The reporting team wants to query the card database from the office network, and wants an encryption key for its exports.

1. Copy the sample into the Terraform folder:

   ```powershell
   Copy-Item examples\risky-change.tf.example terraform\risky-change.tf
   ```

2. Check it:

   ```powershell
   secuguard plan-check
   ```

**What you should see:**

```
Asking Terraform what it would change...
Plan: 2 to add, 0 to change, 0 to destroy.
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

Nothing was created in AWS. The second finding is scope drift, caught before it happened instead of the day after.

### Step 3: Withdraw the change

```powershell
Remove-Item terraform\risky-change.tf
secuguard plan-check
```

**What you should see:** `No changes` and `ALLOWED` again.

Do not skip this step. If the file stays in the `terraform` folder, a plain `terraform apply` would build it.

### Step 4: Read the exceptions register

Some rule-breaking changes are accepted on purpose. In this project those are the planted weaknesses. They are recorded in `policy\exceptions.json`. Open it:

```powershell
code policy\exceptions.json
```

Each entry has five parts.

| Field | Meaning |
|---|---|
| `address` | The one resource the exception covers |
| `rule` | The one rule it is excused from |
| `reason` | Why the risk is accepted |
| `approved_by` | Who accepted it |
| `expires` | The date the approval ends |

An exception past its `expires` date stops counting, and the change is blocked again. Accepted risks get reviewed instead of living forever. The file is tracked by Git, so every exception has a history.

When the planted resources appear in a plan, `plan-check` lists them under **Accepted exceptions** with the reason and expiry date, and still allows the plan.

### The habit to adopt

From now on, make changes to AWS this way:

1. Edit the Terraform files.
2. Run `secuguard plan-check`.
3. If it says ALLOWED and you agree with the plan, run the command it prints:

   ```powershell
   terraform -chdir=terraform apply tfplan
   ```

That applies exactly the plan that was checked. If the plan is blocked, `plan-check` deletes the saved plan so it cannot be applied by mistake.

### What this is and is not

On your computer, `plan-check` is a step you choose to run. Anyone with access could still run `terraform apply` directly. [Part 17](#part-17-enforce-the-plan-check-on-github) turns it into a gate: GitHub runs the same check on every proposed change and refuses to merge one that is blocked. The rules and the exceptions register do not change.

### Step 5: Publish stage 3

```powershell
git add .
git commit -m "Stage 3: PCI scope drift detection and a preventive plan check"
git push
```

**What you should see:** the **Tests** job on GitHub goes green. Its Summary page now shows the scope table and the certificate inventory. Run **Collect evidence** once by hand and open its Summary to see the same for your real account.

---

## Part 15: Stage 4: Switch on monitoring and fix real findings

**What you will do:** turn on four AWS services that watch the account, and see three failing checks turn to PASS.
**Time:** about 25 minutes.
**Cost:** a few dollars a month. See [Part 18](#part-18-costs-and-shutting-down).

Since stage 2, the report has shown real findings about your account that nothing planted caused. Nobody was recording who did what, nobody was recording network traffic, and nothing was keeping a history of changes. Stage 4 fixes them.

| Service | What it does | Check it satisfies |
|---|---|---|
| CloudTrail | Records every action taken in the account, by whom, and when, in every region | LOG-01 |
| VPC flow logs | Record the network traffic in SecuGuard's network | NET-04, for that network |
| AWS Config | Records every change to every resource, and keeps a live inventory | MON-01 |
| Security Hub CSPM | Evaluates the account against AWS's security best practices standard every day. AWS used to call it Security Hub. | MON-02 |

All four write to a new log bucket with its own encryption key. Each service may write only to its own folder in that bucket.

MON-01 and MON-02 are new checks in this stage.

### Step 1: Update the project

1. Download the newest `secuguard-grc-engineering.zip` and unzip it over your project folder, replacing files.
2. In PowerShell, in the project folder with the workspace on:

   ```powershell
   pip install -e ".[dev]"
   pytest
   ```

**What you should see:** `67 passed`.

### Step 2: Check the change before making it

Use the habit from Part 14. Sign in, then let the plan check judge the change.

```powershell
aws sso login --profile secuguard
secuguard plan-check
```

**What you should see:**

```
Asking Terraform what it would change...
Plan: 16 to add, 1 to change, 0 to destroy.
Examined 17 planned changes against 8 rules.

ALLOWED. No planned change breaks a rule.
```

The one change gives the GitHub collector permission to read the two new services. If you built the project for the first time with this version of the manual, Part 7 already created these resources and the plan says `No changes`.

### Step 3: Apply the plan that was checked

```powershell
terraform -chdir=terraform apply tfplan
```

There is no `yes` to type this time. Applying a saved plan runs exactly what was checked.

**What you should see:** `Apply complete! Resources: 16 added, 1 changed, 0 destroyed.` It takes a minute or two.

### Step 4: Collect and compare

```powershell
$bucket = terraform -chdir=terraform output -raw evidence_bucket
secuguard collect --profile secuguard --upload --bucket $bucket
secuguard report
```

**What you should see:** nine `ok` lines, `graded 26 checks`, a new line starting `FedRAMP 20x:`, and `Uploaded 14 files`.

In the report, three checks that could not pass before now do:

| Check | Before | Now |
|---|---|---|
| LOG-01 Account activity is recorded and the record is protected | FAIL | PASS |
| MON-01 Every change to the account's resources is recorded | did not exist | PASS |
| MON-02 The account is evaluated continuously against a security standard | did not exist | PASS |

NET-04 still shows FAIL, with one line where there were two. SecuGuard's network is now logged. The line that remains is AWS's own default network, which exists in every account and which this project does not manage. That is a real finding, reported accurately.

You now have a sealed run from before the fix showing LOG-01 failing, and one from after showing it passing. Together they are the proof of remediation an auditor asks for.

### Step 5: Look at what the services collect

This step is optional. It takes a few hours for the services to fill in.

1. In the AWS Console, check that the region in the top bar says **N. Virginia**. If it says anything else, switch it. The services exist only in the region where they were switched on.
2. Search for **Security Hub CSPM** and open it. AWS has two products with similar names. **Security Hub CSPM** is the one this project uses. If you land on a page offering to "Try the new Security Hub," that is the other product. Do not choose **Get started** there. Go back and search for the CSPM name.

   Its summary shows a score against the best practices standard and a list of findings. Many will be about the planted weaknesses. Two independent tools, this project and Security Hub CSPM, are now reporting on the same account.
3. Search for **Config** and open it. **Resources** lists everything in the account. Click any resource, then **Resource timeline**, to see its history of changes.
4. Search for **CloudTrail** and open **Event history** to see recent actions, including your own Terraform runs.

---

## Part 16: Validate against FedRAMP 20x

**What you will do:** produce a statement about each FedRAMP 20x Key Security Indicator, backed by sealed evidence.
**Time:** about 15 minutes.

### What FedRAMP 20x asks for

FedRAMP is the U.S. government's program for approving cloud services. Its older process ran on long written documents reviewed by hand. FedRAMP 20x replaces much of that with **Key Security Indicators**, or KSIs. Each is a short statement of something a provider must be able to show, for example "Information is encrypted or otherwise secured from unwanted access or modification." Providers are expected to show it with evidence a computer can read and re-check, kept up to date continuously.

FedRAMP publishes the indicators in a form software can read. This project uses version 2026.11.02.01, which has 46 indicators.

### Step 1: Show the validation

```powershell
secuguard ksi
```

**What you should see:** a headline, then each indicator this project speaks to with the checks behind it.

```
FedRAMP 20x Key Security Indicators, rules version 2026.11.02.01

16 of 46 indicators addressed: 2 validated, 13 failing, 1 covered by a preventive control only, 0 without evidence. 30 not covered.

Indicator     Status        Name
------------------------------------------------------------------------------------------------
KSI-CMT-LMC   FAILING       Logging Changes
                SCP-03 FAIL  The network matches the approved scope baseline
                LOG-01 PASS  Account activity is recorded and the record is protected
                MON-01 PASS  Every change to the account's resources is recorded
KSI-SVC-VRI   VALIDATED     Validating Resource Integrity
                LOG-02 PASS  Compliance evidence cannot be altered or deleted
```

Your counts will differ a little. The list of indicators not covered is printed at the end.

### What the statuses mean

| Status | Meaning |
|---|---|
| VALIDATED | Every check that speaks to this indicator passed |
| FAILING | At least one of its checks failed |
| PREVENTIVE | No check reads evidence for it, but the plan check enforces it before changes are made |
| NO EVIDENCE | A check it depends on could not read its evidence |
| NOT COVERED | This project collects nothing for it |

Most indicators show FAILING. That is expected and it is the point of the planted weaknesses: one weak certificate is enough to fail the indicator about validating communications. A tool that reported everything as validated in this account would be wrong.

### Step 2: Read the full report

```powershell
secuguard ksi --markdown | Out-File -Encoding utf8 ksi-report.md
code ksi-report.md
```

Press Ctrl+Shift+V to see it formatted. For each indicator it shows:

- **FedRAMP's own statement**, word for word
- **What this project establishes** about it
- **What it does not establish**
- **Each check and its result**, with the specific resources that failed

The third item matters most. Each indicator is broad, and a handful of automated checks cannot prove all of it. Saying exactly where the evidence stops is what makes the rest believable.

### Step 3: See the machine-readable version

```powershell
secuguard ksi --json
```

This prints the same validation as structured data. It includes a list named `evidence_files`, giving each evidence file the validation rests on and its fingerprint. Someone receiving this can confirm that the evidence they were handed is the evidence the validation was built from.

A copy is written into every run as `ksi-validation.json`, sealed in the manifest and stored in the vault with everything else.

### What this is and is not

- **It covers 16 of 46 indicators.** The other 30 need things this project does not collect: policies, training records, incident response, recovery testing, and supplier reviews. They are listed, not hidden.
- **The format is this project's own.** FedRAMP has published the indicators. This project has not been reviewed by FedRAMP or by an assessor, and it does not claim to meet any submission format.
- **The mapping is the author's reading.** Which checks speak to which indicator is a judgment. It is written down in `src\secuguard_grc\checks.py` and `src\secuguard_grc\ksi.py` so it can be challenged.
- **SecuGuard is fictional.** Nothing here is a real authorization.

### Step 4: Publish stage 4

```powershell
git add .
git commit -m "Stage 4: monitoring services and FedRAMP 20x indicator validation"
git push
```

**What you should see:** the **Tests** job on GitHub goes green. Run **Collect evidence** once by hand. Its Summary page now ends with the FedRAMP 20x validation for your real account, refreshed every day from then on.

---

## Part 17: Enforce the plan check on GitHub

**What you will do:** move Terraform's records into AWS, let GitHub judge every proposed change, and add a rule so a change that breaks a rule cannot be merged.
**Time:** about 45 minutes.
**Cost:** about $1 a month more, for one encryption key.

In Part 14 the plan check was a step you chose to run. This part makes it a gate. Three pieces make that work.

| Piece | Why it is needed |
|---|---|
| Terraform's state kept in AWS | Terraform's record of what it has built is called its **state**. Until now it was a file on your computer, so GitHub could not tell what exists. In a bucket in AWS, GitHub can read it. |
| A second role for GitHub | The evidence collector's role works only from the main branch. A proposed change is not on main yet. This new role works only for proposed changes, and it is read-only. |
| A rule on the main branch | GitHub refuses to merge a proposed change unless the plan check passed. |

A proposed change on GitHub is called a **pull request**. It is a set of changes on a side copy of the project, called a **branch**, offered for merging into main.

### Step 1: Update the project

1. Download the newest `secuguard-grc-engineering.zip` and unzip it over your project folder, replacing files.
2. In PowerShell, in the project folder with the workspace on:

   ```powershell
   pip install -e ".[dev]"
   pytest
   ```

**What you should see:** `67 passed`.

### Step 2: Build the state bucket and the new role

```powershell
aws sso login --profile secuguard
secuguard plan-check
```

**What you should see:** `Plan: 10 to add, 0 to change, 0 to destroy.` and `ALLOWED`.

```powershell
terraform -chdir=terraform apply tfplan
```

**What you should see:** `Apply complete! Resources: 10 added, 0 changed, 0 destroyed.`

### Step 3: Back up the state

The next steps move the state file. Make a copy first.

```powershell
Copy-Item terraform\terraform.tfstate terraform\terraform.tfstate.before-move
```

This copy holds secret values, like the state itself. It is kept out of GitHub automatically. Delete it in a week, once you are sure everything works.

### Step 4: Write down where the state will live

```powershell
$state = terraform -chdir=terraform output -raw terraform_state_bucket
Set-Content -Encoding ascii terraform\backend.hcl @("bucket       = `"$state`"", 'key          = "secuguard/terraform.tfstate"', 'region       = "us-east-1"', 'profile      = "secuguard"', 'use_lockfile = true')
Get-Content terraform\backend.hcl
```

**What you should see:** five lines, the first naming your state bucket.

```
bucket       = "secuguard-tfstate-123456789012"
key          = "secuguard/terraform.tfstate"
region       = "us-east-1"
profile      = "secuguard"
use_lockfile = true
```

Run these three lines before step 5. Once the switch in step 5 is made, Terraform cannot answer the first line until the move is finished.

### Step 5: Tell Terraform to keep its state in AWS

```powershell
Copy-Item terraform\backend.tf.example terraform\backend.tf
```

### Step 6: Move the state

```powershell
terraform -chdir=terraform init -migrate-state -backend-config=backend.hcl
```

Terraform asks: `Do you want to copy existing state to the new backend?` Type `yes` and press Enter.

**What you should see:** `Successfully configured the backend "s3"!`

If this step fails, Terraform says so and leaves the state on your computer unchanged. To go back to how things were, run `Remove-Item terraform\backend.tf` and then `terraform -chdir=terraform init`. Then send the error text so it can be fixed.

### Step 7: Confirm the move

```powershell
secuguard plan-check
aws s3 ls s3://$state/secuguard/ --profile secuguard
```

**What you should see:** `No changes` and `ALLOWED` from the first command, which proves Terraform can read everything it built from the new location. The second command lists one file, `terraform.tfstate`.

The state now lives in AWS, encrypted with its own key, with every earlier version kept.

### Step 8: Give GitHub two more values

1. Print them:

   ```powershell
   terraform -chdir=terraform output
   ```

   Find the lines starting `plan_checker_role_arn` and `terraform_state_bucket`.
2. On GitHub, open your repository, then **Settings**, then **Secrets and variables**, then **Actions**, then the **Variables** tab.
3. Add a variable named `PLAN_ROLE_ARN` with the `plan_checker_role_arn` value. It ends in `secuguard-plan-checker`.
4. Add a variable named `TF_STATE_BUCKET` with the `terraform_state_bucket` value. It starts with `secuguard-tfstate-`.

### Step 9: Publish this stage

This is the last time you push straight to main.

```powershell
git add .
git commit -m "Stage 4: plan check enforced on GitHub, with Terraform state in AWS"
git push
```

### Step 10: Propose a risky change

Use the same sample change as Part 14, this time as a pull request.

1. Create a branch and add the change to it:

   ```powershell
   git checkout -b risky-change
   Copy-Item examples\risky-change.tf.example terraform\risky-change.tf
   git add terraform\risky-change.tf
   git commit -m "Let the reporting team query the card database"
   git push -u origin risky-change
   ```

2. Open your repository on GitHub. A yellow banner mentions `risky-change`. Choose **Compare & pull request**, then **Create pull request**.
3. Wait about two minutes and watch the checks at the bottom of the pull request.

**What you should see:** **Tests** passes with a green check. **Plan check** fails with a red X. Click **Details** beside it, then **Summary**, to read why:

```
Plan: 2 to add, 0 to change, 0 to destroy.
Examined 2 planned changes against 8 rules.

BLOCKED. 2 change(s) break a rule:
  PLAN-04  Encryption keys are created with rotation on
  PLAN-02  Only in-scope groups are let into the card data zone
```

GitHub worked that out by reading your real AWS account with a role that cannot change anything.

Notice that the **Merge pull request** button still works. The check objected, but nothing stops the merge yet. Do not merge. The next step closes that gap.

If **Plan check** fails for a different reason, such as not being able to sign in to AWS or to read the state, that is a setup problem and not a blocked plan. Copy the error from the job's log so it can be fixed.

### Step 11: Add the rule that makes it a gate

1. On GitHub, open your repository, then **Settings**, then **Rules**, then **Rulesets**.
2. Choose **New ruleset**, then **New branch ruleset**.
3. Name it `Protect main`.
4. Set **Enforcement status** to **Active**.
5. Under **Target branches**, choose **Add target**, then **Include default branch**.
6. Under the rules, tick these four:
   - **Restrict deletions**
   - **Require a pull request before merging**. Leave required approvals at 0, since you are working alone.
   - **Require status checks to pass**. Choose **Add checks**, then add `plan-check` and `test`.
   - **Block force pushes**
7. Choose **Create**.

Leave the bypass list empty. With nobody on it, the rule applies to you as well.

GitHub rearranges its settings pages from time to time. If a name here does not match what you see, look for the closest match.

### Step 12: Watch the gate hold

Go back to the pull request and refresh the page.

**What you should see:** the merge button is now disabled, with a message that a required check has failed or that merging is blocked.

A change that would have let the office network into the card database cannot reach main. Take a screenshot. This is the preventive control, enforced.

### Step 13: Withdraw the change

1. On the pull request, choose **Close pull request**, then **Delete branch**.
2. On your computer:

   ```powershell
   git checkout main
   git branch -D risky-change
   ```

Switching back to main removes `risky-change.tf` from the `terraform` folder, because that file existed only on the branch. Confirm with `secuguard plan-check`, which should say `No changes`.

### How to make changes from now on

Main only accepts pull requests now. Each change follows the same path.

1. Start a branch: `git checkout -b short-name-for-the-change`
2. Edit files.
3. Save and send the branch:

   ```powershell
   git add .
   git commit -m "What changed"
   git push -u origin short-name-for-the-change
   ```

4. On GitHub, open a pull request and wait for **Tests** and **Plan check** to pass.
5. Choose **Merge pull request**, then **Delete branch**.
6. Bring your computer up to date:

   ```powershell
   git checkout main
   git pull
   ```

7. If the change touched Terraform, apply it: run `secuguard plan-check`, then the `terraform apply tfplan` command it prints.

GitHub keeps every pull request, with its checks and who merged it. That history is the change record an auditor asks for.

### What this is and is not

- **GitHub decides what may be merged. Applying is still done by you.** After a merge, you run the apply from your computer. A team would usually have GitHub apply merged changes as well.
- **An administrator can still go around it.** You could apply an unmerged change from your computer, or edit the rule. Both leave a trace: CloudTrail records the apply, and GitHub records every change to a ruleset. The control makes the approved path the easy one and the other path visible.
- **The plan role can read the state, which holds secret values.** In this project those belong to the planted users, which can do nothing. In a real environment, who may open a pull request would be controlled just as carefully.
- **Settings in your `terraform.tfvars` are not on GitHub.** That file stays on your computer. If you change a setting there, such as pausing the load balancer, GitHub's plan will show a difference until the same value is given to the workflow.

---

## Part 18: Costs and shutting down

### What it costs

| Item | Stage | Cost |
|---|---|---|
| Evidence encryption key | 1 | About $1 a month |
| Evidence storage | 1 | Less than a cent a month |
| Network, firewall rules, sign-in setup | 1 | Free |
| GitHub Actions on a public repository | 1 | Free |
| Load balancer with the outdated TLS policy | 2 | About $17 a month |
| Second encryption key, with rotation off | 2 | About $1 a month |
| Users, role, certificates, empty bucket | 2 | Free |
| Log encryption key | 4 | About $1 a month |
| AWS Config and Security Hub | 4 | A few dollars a month in an account this small. Security Hub is free for its first 30 days. |
| CloudTrail, flow logs, log storage | 4 | Cents |
| Terraform state encryption key | 4 | About $1 a month |

Together that is roughly $26 a month. The load balancer is most of it. AWS Config and Security Hub charge by how much they record and evaluate, so their cost cannot be stated exactly in advance. Your budget alert from Part 6 will tell you if the total heads past what you set.

### How to pause the monitoring services

Add this line to `terraform\terraform.tfvars`, then run `secuguard plan-check` and apply the plan it saves:

```
monitoring = false
```

Checks LOG-01, MON-01, and MON-02 go back to FAIL, which is accurate. Delete the line and apply again to switch monitoring back on.

### How to pause the load balancer

If you will not touch the project for a while, remove the load balancer and keep everything else.

1. Open `terraform\terraform.tfvars` and add this line:

   ```
   planted_load_balancer = false
   ```

2. Run `terraform -chdir=terraform apply` and type `yes`.

Check CRY-06 then reports N/A, because there is no load balancer to look at. Delete the line and apply again to bring it back.

### How to remove everything

Only do this when you are completely finished, or if you want to start over.

Evidence in the vault is locked for one day and cannot be removed early by anyone. So shutting down takes two sittings, a day apart.

**First, if you did Part 17, bring the state back to your computer.** Terraform cannot delete the bucket that holds its own records while it is using it.

```powershell
Remove-Item terraform\backend.tf
terraform -chdir=terraform init -migrate-state
```

Type `yes` when Terraform asks whether to copy the state. On GitHub, also set the `Protect main` ruleset to **Disabled** under **Settings**, **Rules**, **Rulesets**, if you want to push without pull requests again.

**Day 1: stop collecting.**

1. On GitHub, open **Actions**, click **Collect evidence**, click the **...** button, and choose **Disable workflow**.
2. Do not run `secuguard collect --upload` again.

**Day 2 or later, at least 24 hours after the last collection: remove everything.**

```powershell
terraform -chdir=terraform destroy
```

Type `yes` when asked. Terraform removes everything it built, including the vault and the evidence in it. The encryption key is scheduled for deletion after a seven-day waiting period that AWS requires.

If you run the destroy too early, it removes everything except the vault and stops with an error about the bucket. Nothing is harmed. Wait until 24 hours have passed since the last collection and run it again.

To rebuild later, run `terraform -chdir=terraform apply` again.

Destroying the environment does not close your AWS account. If you want to close the account too, sign in as the root user and use the **Account** page.

---

## Part 19: Daily use

Once everything is set up, a working session looks like this.

```powershell
cd $HOME\Projects\secuguard-grc-engineering
.\.venv\Scripts\Activate.ps1
aws sso login --profile secuguard
$bucket = terraform -chdir=terraform output -raw evidence_bucket
```

Then use whichever command you need.

| To do this | Run this |
|---|---|
| Collect in practice mode | `secuguard collect --mock` |
| Collect from AWS and store in the vault | `secuguard collect --profile secuguard --upload --bucket $bucket` |
| Show check results by check and by framework | `secuguard report` |
| Show the PCI scope of the network and any drift | `secuguard scope` |
| Show the FedRAMP 20x indicator validation | `secuguard ksi` |
| Save the FedRAMP 20x report and open it | `secuguard ksi --markdown \| Out-File -Encoding utf8 ksi-report.md` then `code ksi-report.md` |
| Check a planned change before applying it | `secuguard plan-check` |
| Start a change on its own branch | `git checkout -b short-name` |
| Return to main and bring it up to date | `git checkout main` then `git pull` |
| Apply exactly the plan that was checked | `terraform -chdir=terraform apply tfplan` |
| Save the report as a file and open it | `secuguard report --markdown \| Out-File -Encoding utf8 report.md` then `code report.md` |
| List the checks and what each reports against | `secuguard checks` |
| Check that local evidence has not been altered | `secuguard verify` |
| Check the copy of record in the vault | `secuguard verify --vault --profile secuguard --bucket $bucket` |
| Prove the vault refuses deletion | `secuguard test-lock --profile secuguard --bucket $bucket` |
| List the collectors and what each gathers | `secuguard collectors` |
| Run the project's self-tests | `pytest` |
| Preview changes to the cloud environment | `terraform -chdir=terraform plan` |
| Apply changes to the cloud environment | `terraform -chdir=terraform apply` |
| Save and send a branch to GitHub | `git add .` then `git commit -m "what changed"` then `git push -u origin short-name`, then open a pull request |

---

## Part 20: When something goes wrong

**The AWS Console has no region name in the top bar, or says a service "is not available to your project."**
The account was created with AWS's simplified sign-up. Do not choose **Activate advanced features**, because that cannot be undone. Create a new account with the advanced sign-up link in Part 6, step 1, and use that account for this project. The simplified account costs nothing while it sits unused, and you can close it later.

**`winget` is not recognized.**
Open the Microsoft Store, search for **App Installer**, and install or update it. Then open a new PowerShell window.

**`git`, `terraform`, or `aws` is not recognized right after installing.**
Close PowerShell and open a new window. If it still fails, restart the computer.

**`py` is not recognized, or typing `python` opens the Microsoft Store.**
Run the Python install line from Part 3 again, then open a new PowerShell window. Always create the workspace with `py -m venv .venv` as shown.

**"Running scripts is disabled on this system" when turning on the workspace.**
Run the command in Part 3, step 5, then try again.

**`secuguard` is not recognized.**
The workspace is not turned on. Look for `(.venv)` at the start of the line. If it is missing, run `.\.venv\Scripts\Activate.ps1` from the project folder. If it is showing and the command still fails, run `pip install -e ".[dev]"` again.

**"Could not reach AWS," or a message about an expired token or SSO session.**
Your sign-in ran out. Run `aws sso login --profile secuguard` and try again.

**Terraform says "No valid credential sources found."**
Same cause. Sign in again. Also confirm `terraform.tfvars` exists in the `terraform` folder and contains `aws_profile = "secuguard"`.

**`--upload needs a bucket`.**
`$bucket` is empty, usually because you opened a new PowerShell window. Run Part 8, step 1 again.

**`terraform apply` fails with an error about an OpenID Connect provider that already exists.**
Your AWS account already has a GitHub connection from an earlier project. This is not expected in a new account. Remove the old one in the console under **IAM**, then **Identity providers**, and apply again.

**The Collect evidence job on GitHub is skipped.**
The `AWS_ROLE_ARN` variable is missing. Check Part 9, step 4, and make sure you added it under the **Variables** tab, not the **Secrets** tab.

**The Collect evidence job fails with "Not authorized to perform sts:AssumeRoleWithWebIdentity."**
AWS did not recognize the repository. Check these in order:

1. `terraform.tfvars` has all three lines from Part 9, step 3: `github_repository`, `github_owner_id`, and `github_repository_id`, and the two numbers are the ones PowerShell printed for your repository. Repositories created after July 15, 2026 need the two numbers. Without them, AWS is waiting for an older style of identity that GitHub no longer sends for new repositories.
2. The repository name matches GitHub exactly, including capital letters.
3. You ran `terraform -chdir=terraform apply` after saving the file.
4. The job ran from the `main` branch.
5. The `AWS_ROLE_ARN` variable on GitHub matches the `github_actions_role_arn` output exactly.

Then run the job again.

**`secuguard verify` reports a run that "does not link" to the one before it.**
Runs collected by GitHub link to each other inside the vault. Runs you collect on your computer with `--upload` join that same chain. If your local `evidence` folder is missing some of those runs, the local folder shows a gap even though the vault's chain is whole. This is expected when you mix the two. The vault is the copy of record.

**`terraform destroy` fails with an error about the evidence bucket, such as "Access Denied" or "bucket is not empty."**
Some evidence is still locked. Locks last one day from the moment each file was uploaded and cannot be removed early. Make sure the daily collection on GitHub is disabled, wait until 24 hours after the last collection, and run the destroy command again.

**Deleting a file in the evidence vault succeeded when it should have been refused.**
Either the **Show versions** switch was off, in which case the file was only hidden and is still stored, or the vault is in governance mode. Check that `terraform/terraform.tfvars` does not set `evidence_lock_mode = "GOVERNANCE"`, run `terraform -chdir=terraform apply`, collect again, and repeat the test on the new run. Files uploaded before the change keep the lock they were given.

**`terraform plan` or `apply` says a provider is missing, or mentions `hashicorp/tls`.**
Stage 2 needs one more plugin. Run `terraform -chdir=terraform init -upgrade`, then try again.

**`terraform apply` fails with "Invalid principal in policy" on the role `secuguard-legacy-vendor`.**
AWS only lets a role trust an account number that exists. Make sure you have the newest project files, which use a real account number owned by AWS, and run `terraform -chdir=terraform apply` again. Everything already created stays in place, and only the role is added.

**`terraform apply` fails while creating the weak certificate, the load balancer, or its listener.**
AWS tightens what it accepts over time, and a deliberately weak setting may be refused. Copy the error text so it can be fixed in the project. To carry on meanwhile, add `planted_load_balancer = false` to `terraform\terraform.tfvars` if the load balancer or listener failed, then apply again. Everything already created stays in place.

**A check shows NO EVIDENCE.**
The collector it depends on could not read something. Run `secuguard report` and read the line starting with `!` under that check. If it names an access error on your own computer, sign in again with `aws sso login --profile secuguard`. If it happens only in the GitHub job, run `terraform -chdir=terraform apply` so the collector's role gets the stage 2 read permissions.

**`secuguard test-lock` prints NOT PROTECTED.**
The vault is not in compliance mode. Check that `terraform\terraform.tfvars` does not set `evidence_lock_mode = "GOVERNANCE"`, run `terraform -chdir=terraform apply`, and run the test again.

**`secuguard report` says no evidence runs were found.**
Run it from the project folder, and collect at least once first.

**`secuguard plan-check` says Terraform was not found, or fails while asking Terraform for a plan.**
Run it from the project folder, with the workspace on, after signing in with `aws sso login --profile secuguard`. The text it prints is Terraform's own error. Run `terraform -chdir=terraform plan` to see it in full.

**`secuguard plan-check` blocks a change you believe is acceptable.**
Either fix the change so it meets the rule, or record an exception in `policy\exceptions.json` with a reason, an approver, and an expiry date. Use the planted entries in that file as a pattern.

**`secuguard plan-check` blocks a planted resource and says its exception expired.**
The approvals in `policy\exceptions.json` have an end date. Review whether each planted weakness is still wanted, then move its `expires` date forward.

**`secuguard scope` or the report shows drift you did not expect.**
Something in the network differs from `scope-baseline.json`. That is the check doing its job. Look at the item named, decide whether the change is correct, and either undo it or, once the network is right, approve a new baseline as shown in Part 13.

**`terraform apply` fails while creating the CloudTrail trail, the flow log, the Config recorder, or Security Hub.**
Copy the error text so it can be fixed in the project. To carry on meanwhile, switch off the one service that failed by adding the matching line to `terraform\terraform.tfvars`: `monitoring_cloudtrail = false`, `monitoring_flow_logs = false`, `monitoring_config = false`, or `monitoring_security_hub = false`. Then run the apply again. Everything already created stays in place.

**`terraform apply` stops with "timeout while waiting for state to become 'READY, INCOMPLETE'" on the Security Hub standard.**
Security Hub was still switching the standard on when Terraform stopped waiting. Nothing is broken, and everything else was created. Finish it this way:

1. Wait about ten minutes, then ask AWS whether the standard is ready:

   ```powershell
   aws securityhub get-enabled-standards --profile secuguard --query "StandardsSubscriptions[].StandardsStatus"
   ```

   Carry on when it prints `READY` or `INCOMPLETE`. If it prints `PENDING`, wait a few more minutes and ask again.
2. Tell Terraform the standard is fine as it is, so it does not delete and recreate it:

   ```powershell
   terraform -chdir=terraform untaint 'aws_securityhub_standards_subscription.best_practices[0]'
   ```

3. Run `secuguard plan-check`. It should say `No changes`.

**Security Hub says it is already enabled, or AWS Config says a recorder already exists.**
The service was switched on in this account before, outside this project. Switch off that one service in `terraform\terraform.tfvars` as described above. The checks read whatever is running, so MON-01 and MON-02 still report correctly.

**MON-02 fails right after Security Hub is switched on.**
The standard can take a few minutes to register. Collect again after ten minutes.

**`git push` is rejected with a message about a protected branch or a ruleset.**
Main only accepts pull requests after Part 17. Move your work to a branch and propose it: `git checkout -b short-name`, then `git push -u origin short-name`, then open a pull request on GitHub.

**The Plan check job on GitHub fails at "Get short-lived, read-only AWS credentials."**
AWS did not recognize the pull request. Check that the `PLAN_ROLE_ARN` variable on GitHub matches the `plan_checker_role_arn` output exactly, and that `terraform.tfvars` still holds the three `github_` lines from Part 9. Pull requests opened from a copy of the repository under another account are refused on purpose.

**The Plan check job fails while Terraform is starting up or reading the state.**
Check that the `TF_STATE_BUCKET` variable on GitHub matches the `terraform_state_bucket` output, and that Part 17, step 6 finished with `Successfully configured the backend`. If the error mentions a permission, copy it so the role can be corrected.

**The Plan check job reports changes you did not make.**
Your `terraform.tfvars` holds a setting that GitHub does not have, so its plan differs from yours. Compare the plan in the job's log with `secuguard plan-check` on your computer.

**Terraform says "Backend initialization required" or "Backend configuration changed."**
Run `terraform -chdir=terraform init -backend-config=backend.hcl`. This happens after unzipping an update, because the update does not include your `backend.tf`. If `terraform\backend.tf` is missing, copy it again with `Copy-Item terraform\backend.tf.example terraform\backend.tf` first.

**Terraform says the state is locked.**
A previous run was interrupted. Read the lock ID in the message, then run `terraform -chdir=terraform force-unlock` followed by that ID. Only do this when you are sure no other Terraform run is in progress.

**Something else.**
Copy the full error text. Most of the time the last two or three lines say what is wrong. Search for that text along with the name of the tool that printed it.

---

## Part 21: Glossary

**Access portal.** The web page where you sign in to AWS with your everyday user.

**API call.** A question or instruction sent from one program to another. The collectors make API calls to AWS to ask how things are configured.

**AWS.** Amazon Web Services, the cloud provider this project uses.

**Baseline.** A list of what the network should look like, approved by a named person on a date. The project compares the real network against it.

**AWS Config.** The AWS service that records every change to every resource and keeps a live inventory.

**Branch.** A side copy of the project in Git where a change is made without touching main.

**Bucket.** AWS's name for a storage container in its S3 storage service.

**CDE.** Cardholder data environment. The systems that store, process, or send payment card data.

**Certificate.** A file that proves a website or service is who it says it is, and lets connections to it be encrypted. It has an expiry date and a key of a certain strength.

**Chain.** The link from each evidence run to the one before it, made by recording the earlier manifest's fingerprint.

**Check.** A rule that reads collected evidence and answers pass or fail. This project has 19.

**CloudTrail.** The AWS service that records who did what in an account.

**Collector.** A small program that asks AWS about one area, such as the network, and saves the answer as evidence.

**Commit.** A saved snapshot of the project in Git, with a description of what changed.

**Evidence.** A saved, sealed record of how something was configured at a specific time.

**Exception.** A recorded decision to accept a rule being broken, with a reason, an approver, and an end date.

**FedRAMP.** The U.S. government program that sets security requirements for cloud services sold to federal agencies. FedRAMP 20x is its newer approach, built around automated proof.

**Finding.** One resource that broke a check's rule, with the reason.

**Flow logs.** Records of the network traffic going in and out of a network.

**Git.** A tool that tracks every change made to a project's files.

**GitHub.** A website that hosts Git projects and can run automated jobs on them.

**GitHub Actions.** The part of GitHub that runs automated jobs, such as the daily evidence collection.

**GRC.** Governance, risk, and compliance. The function responsible for proving an organization meets its security obligations.

**Hash.** A fingerprint computed from a file's contents. Any change to the file changes the hash. This project uses a type called SHA-256.

**IAM.** Identity and Access Management. The AWS service that controls who can sign in and what they can do.

**KMS.** Key Management Service. The AWS service that creates and guards encryption keys.

**KSI.** Key Security Indicator. One of the short statements FedRAMP 20x asks a cloud provider to show it meets.

**Load balancer.** A service that receives incoming connections and passes them to the systems behind it. It is where encryption settings for incoming traffic are chosen.

**Manifest.** The list of every file in an evidence run and each file's hash.

**MFA.** Multi-factor authentication. Signing in with a password plus a second proof, such as a code from your phone.

**Mock mode.** Practice mode. The collectors run against a simulated AWS on your own computer.

**Object Lock.** An S3 feature that stops a stored file from being changed or deleted until a set time has passed. This project uses its compliance mode, which nobody can override.

**Permissions boundary.** A hard cap on what an identity can do, whatever rights are attached to it. This project uses one that denies everything to make the planted users harmless.

**PCI DSS.** Payment Card Industry Data Security Standard. The security rules for anyone handling payment card data.

**Plan.** Terraform's exact list of what it would create, change, or delete, produced before it does anything.

**Preventive control.** A safeguard that stops a problem before it happens. `secuguard plan-check` is a preventive control.

**Profile.** A saved AWS sign-in on your computer. This project's profile is named `secuguard`.

**Pull request.** A set of changes on a branch, offered for merging into main. GitHub runs checks on it first.

**Region.** The geographic location of the AWS data centers you are using. This project uses `us-east-1`, in Northern Virginia.

**Repository.** A project stored in Git or on GitHub.

**Root user.** The original owner sign-in of an AWS account. It has unlimited power and should be used only for rare account-level tasks.

**Scope.** In PCI DSS, the set of systems the rules apply to: the CDE plus anything that can connect to it.

**Security group.** AWS's name for a set of firewall rules that control which traffic can reach a group of systems.

**SOC 2.** An independent audit report on a company's security controls, widely requested by business customers.

**State.** Terraform's record of what it has built. Without it, Terraform cannot tell which resources it owns.

**Subnet.** A section of a network.

**Terraform.** A tool that builds and removes cloud resources based on written instructions.

**Terminal.** A window for typing commands. On Windows, the terminal used here is PowerShell.

**TLS.** The encryption used for connections over a network, such as web traffic. Versions 1.0 and 1.1 are outdated. 1.2 and 1.3 are current.

**VPC.** Virtual Private Cloud. Your own private network inside AWS.

---

## Part 22: What each file in the project does

| File or folder | What it is |
|---|---|
| `MANUAL.md` | This manual |
| `README.md` | The short introduction people see first on GitHub |
| `terraform/network.tf` | The blueprint for the network, its three zones, and the firewall rules |
| `terraform/monitoring.tf` | The blueprint for CloudTrail, flow logs, AWS Config, Security Hub, and the log bucket |
| `terraform/state.tf` | The blueprint for the bucket that holds Terraform's state, and the read-only role GitHub uses to plan proposed changes |
| `terraform/backend.tf.example` | The switch that moves Terraform's state into AWS, copied into place in Part 17 |
| `terraform/planted.tf` | The blueprint for the deliberate, harmless weaknesses the checks are meant to find |
| `terraform/evidence.tf` | The blueprint for the evidence vault and its encryption key |
| `terraform/github_oidc.tf` | The blueprint for GitHub's password-free, read-only access |
| `terraform/variables.tf` | The settings you can change, each with an explanation |
| `terraform/outputs.tf` | The values Terraform prints after building |
| `terraform/terraform.tfvars.example` | A template for your personal settings file |
| `src/secuguard_grc/collectors/` | The nine collectors: network, encryption keys, storage, sign-in settings, identities, certificates, load balancers, logging, and monitoring |
| `src/secuguard_grc/checks.py` | The 26 checks, each with its reason and the requirements it reports against |
| `src/secuguard_grc/ksi.py` | Lines FedRAMP's indicators up with the checks, and states what each validation covers and leaves out |
| `src/secuguard_grc/data/fedramp_ksi.json` | FedRAMP's 46 Key Security Indicators, in FedRAMP's own words |
| `src/secuguard_grc/scope.py` | Works out the real PCI scope of the network and compares it with the labels and the baseline |
| `src/secuguard_grc/plan_check.py` | The eight rules that judge a Terraform plan before it is applied |
| `scope-baseline.json` | The approved PCI scope of the network, with who approved it and when |
| `policy/exceptions.json` | The register of accepted rule-breaking changes, each with a reason and an expiry date |
| `examples/risky-change.tf.example` | A sample risky change for trying the plan check |
| `src/secuguard_grc/report.py` | Turns check results into the terminal table and the Markdown report |
| `src/secuguard_grc/evidence.py` | The sealing system: fingerprints, manifests, the chain, and verification |
| `src/secuguard_grc/storage.py` | Copies each run into the vault, reads runs back for verification, and runs the lock test |
| `src/secuguard_grc/cli.py` | Defines the `secuguard` commands |
| `src/secuguard_grc/mock/environment.py` | Builds the simulated AWS used in practice mode |
| `tests/` | Self-tests that prove tampering is caught |
| `examples/sample-ksi-validation.md` | The FedRAMP 20x validation from one practice-mode run |
| `examples/sample-report.md` | The check results from one practice-mode run, as a formatted report |
| `examples/sample-run/` | One practice-mode run, so readers can see evidence without installing anything |
| `.github/workflows/ci.yml` | Tells GitHub to run the self-tests on every change |
| `.github/workflows/plan-check.yml` | Tells GitHub to judge every pull request against the plan rules |
| `.github/workflows/collect-evidence.yml` | Tells GitHub to collect evidence every day |
| `.gitignore` | Lists files that must never be sent to GitHub |
| `pyproject.toml` | Lists the libraries the project depends on |
