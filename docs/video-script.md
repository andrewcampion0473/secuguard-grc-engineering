# Video walkthrough: script and shot list

Two videos come out of this file:

- **The full walkthrough**, 8 to 10 minutes, for a hiring team that wants to see how it works.
- **The short cut**, about 90 seconds, for LinkedIn.

The audience is compliance people, not engineers. The script avoids terms they would have to look up. Where a number depends on your own account, the script says **[read from screen]**. Say the number you see.

Part 18 of [MANUAL.md](../MANUAL.md) covers how to get the screen ready and how to record.

## Before you record

Have these open, in this order, so you can move left to right through them:

1. The diagram pictures in `docs/images/`, opened in the Windows Photos app
2. PowerShell, in the project folder, workspace on, signed in to AWS, text size increased
3. `report.html`, made from a fresh real run, in a browser
4. GitHub, on your repository's **Pull requests** tab with **Closed** selected
5. GitHub, on your repository's **Actions** tab

Three rules for the recording:

- Record one scene at a time. A mistake then costs you one scene, not the whole video.
- Stop talking while a command runs. Cut the wait out later.
- Say what the viewer should look at before you point at it.

## The full walkthrough

About 1,300 words. At an easy speaking pace that is 9 minutes.

### Scene 1: The problem (0:00 to 0:45)

| On screen | Say |
|---|---|
| You, on camera, or the README's "old way" table | "Most compliance evidence is still a screenshot in a folder. A screenshot is out of date the day it's taken. Nothing proves it wasn't edited. And the same setting gets captured three times, once for each framework that asks about it." |
| Same | "I wanted to see what it looks like when evidence is gathered the way an engineer would do it. So I built a small company in AWS, called SecuGuard. It's fictional. It issues payment cards, so it has to meet PCI DSS, SOC 2, and FedRAMP. Then I built a system that collects its evidence automatically, proves the evidence hasn't been altered, and grades it against all three frameworks at once." |

### Scene 2: The parts (0:45 to 1:30)

| On screen | Say |
|---|---|
| `1-parts.png` | "Here's the whole thing in one picture. On the left, the environment is built from a blueprint, so it can be rebuilt the same way every time." |
| Point at the middle | "In the middle, small programs called collectors ask AWS directly how things are configured. They can only read. They can't change anything." |
| Point at the right | "What they write down is the evidence. Checks grade the evidence. The results are sealed and stored in a vault that nobody can alter. Nobody takes a screenshot at any point." |

### Scene 3: Collect evidence from the source (1:30 to 2:30)

| On screen | Say |
|---|---|
| PowerShell. Run `secuguard collect --profile secuguard --upload --bucket $bucket` | "This is one evidence run against the real AWS account. It takes under a minute." |
| The output as it finishes | "Nine collectors ran. Each wrote a file. Then 26 checks graded those files, and the whole run was copied to the vault." |
| Run `code evidence` and open `identities.json` from the newest run | "This is one piece of evidence. It says what was asked, when, which account, and which requirements it's relevant to. This file is what an assessor would read instead of a screenshot." |

### Scene 4: Prove it has not been altered (2:30 to 4:00)

| On screen | Say |
|---|---|
| `2-evidence-chain.png` | "Every file gets a fingerprint. If one character in the file changes, the fingerprint changes. Each run also records the fingerprint of the run before it, so the runs form a chain." |
| PowerShell. Run `secuguard collect --mock --output demo`, then `secuguard verify demo` | "I'll show that on a practice copy. Right now, everything verifies." |
| Run `code demo`, open `identities.json`, find `secuguard-dev-alice`, change `"mfa_devices": 0` to `"mfa_devices": 1`, save | "Now I'll do what someone might do before an audit. This user has no MFA. I'll change the zero to a one, so the evidence says she does." |
| Run `secuguard verify demo` | "And it's caught. It names the file that no longer matches." |
| Run `secuguard test-lock --profile secuguard --bucket $bucket` | "That covers editing. What about deleting? This command stores a file in the vault and then tries to delete it with full administrator rights. AWS refuses. The vault is in what AWS calls compliance mode. Until the lock expires, nobody can remove that evidence, including me." |

### Scene 5: One check, three frameworks (4:00 to 5:30)

| On screen | Say |
|---|---|
| `report.html`, top of page | "This is the report someone in compliance would read. At the top, a green banner confirms the evidence behind this page was verified when the page was made." |
| The four tiles | "**[Read from screen]** checks pass and **[read from screen]** fail. Most of the failures are deliberate. I planted weaknesses in the environment, such as a user with no MFA, a certificate with a weak key, and a storage bucket that could be made public. A tool that only ever says 'compliant' proves nothing. This one has to find what I hid." |
| Scroll to "What needs fixing". Stop on one finding | "Each finding names the exact resource, says why it matters in plain words, and lists the requirements it affects." |
| `3-one-check-three-frameworks.png`, then back to the report's framework tabs. Click PCI DSS, SOC 2, FedRAMP 20x | "This is the part that saves the most time. A check is written once. This one tests that everyone who can sign in has MFA. That one result answers PCI requirement 8.4.2, SOC 2 CC6.1, and a FedRAMP 20x indicator. Three frameworks, one piece of evidence, collected once." |

### Scene 6: PCI scope that checks itself (5:30 to 6:30)

| On screen | Say |
|---|---|
| Report, "PCI scope of the network" | "PCI scope is usually confirmed once a year, in a meeting. Here it's worked out on every run. Each part of the network carries a label that says what it's meant to be: card data, connected, or out of scope." |
| The highlighted row | "This column is the label. This column is what the firewall rules make it. The highlighted row is labelled out of scope, but it can reach the card database. So it's in scope, whether anyone meant it to be or not." |
| The drift card under the table | "It also compares the network with a baseline that a named person approved. Anything added or changed since then is listed here. This is PCI requirement 12.5.2, tested on every run." |

### Scene 7: FedRAMP 20x (6:30 to 7:30)

| On screen | Say |
|---|---|
| Report, "FedRAMP 20x Key Security Indicators" | "FedRAMP 20x is the new approach. It replaces long written narratives with 46 Key Security Indicators, and it expects proof that a machine can read." |
| The two tiles | "This project speaks to 16 of the 46. The other 30 need evidence a script can't see, such as policies, training records, and recovery tests. They're listed as not covered, so the gaps are in plain view." |
| Open one indicator | "For each indicator, this is FedRAMP's own wording. Then two statements: what the evidence establishes, and what it does not. I think that second statement matters most. It shows exactly where a person still has to make the call." |

### Scene 8: Stop a risky change before it happens (7:30 to 8:45)

| On screen | Say |
|---|---|
| `4-blocked-change.png` | "Everything so far finds problems after they exist. This part stops them from being created." |
| GitHub, the closed pull request "Let the reporting team query the card database" | "Here's a change someone proposed. It sounds reasonable. Let the reporting team query the card database." |
| Scroll to the checks box, the red X on Plan check | "GitHub checked it automatically. It signed in to AWS with a read-only identity, asked what the change would do, and judged the answer against eight rules." |
| Click through to the Plan check summary | "Blocked. The change would open the card data zone to the office network, and it would create an encryption key with rotation switched off. It names the rule and the resource." |
| Back on the pull request | "The merge button was disabled. No one had to notice the problem by hand. If the business does need to break a rule, there's a register of exceptions. Each one has a reason, an approver, and an expiry date." |

### Scene 9: It runs itself (8:45 to 9:15)

| On screen | Say |
|---|---|
| GitHub, Actions tab, "Collect evidence" runs | "All of this runs every morning without me. GitHub collects the evidence, grades it, and stores it in the vault." |
| Open one run's summary | "There are no AWS passwords or keys stored in GitHub. It proves who it is to AWS each time and gets access that expires within the hour." |

### Scene 10: What this is and is not (9:15 to 9:45)

| On screen | Say |
|---|---|
| You, on camera, or the README | "I want to be clear about the limits. This is a small demonstration, not a compliance programme. The mapping from checks to requirements is my own reading, and an assessor would want to discuss it. Passing these checks wouldn't make a company compliant." |
| Same | "What it does show is that evidence can be collected continuously, proven unaltered, and written once for three frameworks. The code, a full manual, and a sample report are on GitHub. Thanks for watching." |

## The short cut for LinkedIn

About 220 words, 90 seconds. Use clips you already recorded for the full video. Add captions, because most people watch without sound.

| Time | On screen | Say |
|---|---|---|
| 0:00 | The README's "old way" table | "Most compliance evidence is a screenshot in a folder. It's out of date the day it's taken, and nothing proves it's real." |
| 0:10 | `1-parts.png` | "I built a small fictional company in AWS and a system that collects its evidence automatically, straight from the source." |
| 0:20 | The tampering clip: edit a file, then `verify` fails | "Every file is fingerprinted. I edit the evidence to say a user has MFA when she doesn't, and it's caught." |
| 0:35 | The `test-lock` clip, on the word REFUSED | "The stored copy can't be deleted, even by an administrator." |
| 0:45 | The report's framework tabs being clicked | "Each check is written once and reported against PCI DSS, SOC 2, and FedRAMP 20x." |
| 0:58 | The highlighted row in the PCI scope table | "It works out PCI scope from the firewall rules, and flags a system that's labelled out of scope but can reach card data." |
| 1:10 | The blocked pull request, then the BLOCKED summary | "And it stops a risky change before it's made. This one would have opened the card database to the office network. It couldn't be merged." |
| 1:22 | The repository's front page | "Code, a plain-language manual, and a sample report are on GitHub. Link in the post." |

## After recording

- Watch it once with the sound off. If you can't follow it, add captions or slow down the screen changes.
- Check that no frame shows your email address, your AWS access portal address, or the contents of `terraform.tfvars`.
- Your 12-digit AWS account number appears in the report and the terminal. AWS does not treat it as a secret, and it is already visible in your public GitHub run summaries. Blur it if you would rather not show it.
