# How SecuGuard's evidence system fits together

Four pictures, each answering one question. GitHub draws them from the text in this file, so they stay in step with the project.

SecuGuard is a fictional company invented for this project.

## 1. What are the parts?

Terraform builds the environment. Collectors read it. Checks grade what the collectors wrote down. Everything is sealed and stored where it cannot be changed.

```mermaid
flowchart LR
    TF[Terraform<br/>blueprints] -->|builds| ENV
    subgraph ENV[SecuGuard AWS account]
        direction TB
        NET[Network in three zones:<br/>card data, connected, out of scope]
        RES[Users, roles, keys, certificates,<br/>storage, load balancer]
        MON[CloudTrail, flow logs,<br/>AWS Config, Security Hub]
    end
    ENV -->|asked directly,<br/>read-only| COL[9 collectors]
    COL -->|evidence files| CHK[26 checks]
    CHK --> KSI[FedRAMP 20x<br/>validation]
    CHK --> RPT[Reports: terminal,<br/>Markdown, web page]
    KSI --> RPT
    CHK -->|sealed run| VAULT[(Evidence vault:<br/>encrypted, versioned,<br/>locked)]
```

## 2. Why can the evidence be trusted?

Every file gets a fingerprint. The fingerprints go in a manifest. Each manifest records the fingerprint of the manifest before it, so the runs form a chain. Change any file in any run and the chain no longer adds up.

```mermaid
flowchart LR
    subgraph r1[Run 1]
        F1[Evidence files] -->|fingerprint of each| M1[Manifest 1]
    end
    subgraph r2[Run 2]
        F2[Evidence files] -->|fingerprint of each| M2[Manifest 2]
    end
    subgraph r3[Run 3]
        F3[Evidence files] -->|fingerprint of each| M3[Manifest 3]
    end
    M1 -->|its fingerprint is written into| M2
    M2 -->|its fingerprint is written into| M3
    M3 --> HEAD[Chain head in the vault]
    M1 --> LOCK[(Object Lock, compliance mode:<br/>nobody can delete or overwrite,<br/>not even an administrator)]
    M2 --> LOCK
    M3 --> LOCK
```

## 3. How does one check answer three frameworks?

A check is written once, against the evidence. It carries a list of the requirements it speaks to in each framework. The reports are three views of one set of results.

```mermaid
flowchart LR
    EV[identities.json<br/>evidence file] --> C[Check IAM-04:<br/>every user who can sign in has MFA]
    C --> P[PCI DSS 4.0.1<br/>requirement 8.4.2]
    C --> S[SOC 2<br/>CC6.1]
    C --> F[FedRAMP 20x<br/>KSI-IAM-APM]
```

## 4. How is a risky change stopped?

Nobody can change the main branch directly. A change is proposed as a pull request. GitHub signs in to AWS with a short-lived, read-only identity, asks Terraform what the change would do, and judges the answer against eight rules. A change that breaks a rule cannot be merged.

```mermaid
sequenceDiagram
    actor E as Engineer
    participant G as GitHub
    participant A as AWS (read-only role)
    participant R as Plan check, 8 rules
    E->>G: Opens a pull request
    G->>A: Signs in with a short-lived identity, no stored keys
    A-->>G: Current state of the environment
    G->>R: What would this change do?
    alt Breaks a rule and has no approved exception
        R-->>G: BLOCKED, with the rule and the resource
        G-->>E: Merge button disabled
    else Breaks nothing, or has an approved, unexpired exception
        R-->>G: Allowed
        G-->>E: Merge permitted
    end
```

## What runs where

| Thing | Where it runs | What it is allowed to do |
|---|---|---|
| Collectors, on your computer | Your computer, signed in through IAM Identity Center | Read configuration, write to the evidence vault |
| Collectors, daily | GitHub Actions, role `secuguard-evidence-collector` | Read configuration, write to the evidence vault. Usable only from the main branch. |
| Plan check on pull requests | GitHub Actions, role `secuguard-plan-checker` | Read only. Cannot change anything. Usable only from pull requests. |
| Terraform apply | Your computer | Build and change the environment |
