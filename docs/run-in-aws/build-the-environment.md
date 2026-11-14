# Build the environment

Use Terraform to build SecuGuard's environment in your AWS account.

**Time:** About 20 minutes

**Cost:** About $26 a month while the environment exists. To reduce or stop the cost, see [Manage costs and shut down](../maintain/manage-costs.md).

**Prerequisite:** [Create and secure an AWS account](create-an-aws-account.md)

## What Terraform builds

Terraform creates 81 resources in four groups.

| Group | Contents |
|---|---|
| Foundation | A private network with no internet connection, divided into three zones, the firewall rules between them, and the evidence vault |
| Planted weaknesses | Ten deliberate, harmless weaknesses for the checks to find |
| Monitoring | CloudTrail, VPC flow logs, AWS Config, and Security Hub |
| Terraform state | A storage bucket for Terraform's own records, used in [Block noncompliant changes](../automate/block-noncompliant-changes.md) |

### Network zones

Each zone carries a tag that declares where it sits in PCI scope.

| Zone | PCI scope tag | Represents |
|---|---|---|
| `cde` | `cde` | Systems that handle card data |
| `shared` | `connected` | Systems allowed to reach the cardholder data environment (CDE), which puts them in scope |
| `corporate` | `out-of-scope` | Office systems with no path to the CDE |

### Planted weaknesses

A check that only ever passes proves nothing, so the environment includes the kinds of problems that GRC teams find in real accounts.

| Area | Resource | Weakness | Found by |
|---|---|---|---|
| Network | A security group in the office zone | SSH is open to the internet | NET-01 |
| Network | A security group tagged out of scope | It can reach the card data zone on the database port | NET-02, SCP-02, SCP-03 |
| Network | A security group with no scope tag | Nobody has decided whether PCI DSS applies to it | SCP-01, SCP-03 |
| Encryption | An encryption key | Automatic rotation is off | CRY-01 |
| Storage | A storage bucket | It has no key of its own, and its public access protections are off | CRY-02, CRY-03 |
| Certificates | A certificate for `legacy-api.secuguard.example` | It has a 1024-bit key and expires 20 days after creation | CRY-04, CRY-05 |
| Load balancer | A load balancer named `secuguard-portal` | It accepts TLS 1.0 and 1.1, and its certificate is self-signed | CRY-06, CRY-07 |
| People | A user named `secuguard-dev-alice` | She can sign in with a password and has no MFA | IAM-04 |
| Machines | A service account named `secuguard-svc-reports` | It has administrator rights attached directly and an access key that has never been used | IAM-05, IAM-06 |
| Vendors | A role named `secuguard-legacy-vendor` | An outside account can use it with no added proof of identity | IAM-07 |

The planted weaknesses can't be exploited:

- **The users and the role can do nothing.** Each has a permissions boundary that denies every action, even if a password or key leaks.
- **The bucket is empty.** No setting makes it public. Only its protections are missing.
- **Nothing is reachable from the internet.** The network has no internet gateway, so the open SSH rule and the load balancer have no path in.

To build the environment without the planted weaknesses, add `planted_findings = false` to `terraform\terraform.tfvars` after you create that file.

## Build the environment

1. Sign in to AWS.

    ```powershell
    aws sso login --profile secuguard
    ```

2. Create your settings file.

    ```powershell
    Copy-Item terraform\terraform.tfvars.example terraform\terraform.tfvars
    ```

    The file tells Terraform which region and profile to use. The defaults are correct.

3. Initialize Terraform.

    ```powershell
    terraform -chdir=terraform init
    ```

    The output includes `Terraform has been successfully initialized!`

4. Check the plan.

    ```powershell
    secuguard plan-check
    ```

    A plan is Terraform's exact list of what it would create, change, or delete. This command asks Terraform for the plan and tests it against the project's eight rules.

    ```text
    Asking Terraform what it would change...
    Plan: 81 to add, 0 to change, 0 to destroy.
    Examined 81 planned changes against 8 rules.

    Accepted exceptions (7), listed in policy/exceptions.json:
      PLAN-01  aws_vpc_security_group_ingress_rule.planted_ssh_from_anywhere[0]
               opens SSH (port 22) to the whole internet
               accepted until 2027-01-31: Deliberate weakness for check NET-01 to find. ...

    ALLOWED. No planned change breaks a rule.
    ```

5. Apply the plan.

    ```powershell
    terraform -chdir=terraform apply tfplan
    ```

    This command applies exactly the plan that was checked. It takes three to five minutes. The output ends with `Apply complete! Resources: 81 added, 0 changed, 0 destroyed.` and a list of outputs that includes the name of your evidence vault:

    ```text
    evidence_bucket = "secuguard-evidence-123456789012"
    ```

If the apply stops with a timeout on the Security Hub standard, nothing is broken. See [Troubleshooting](../troubleshooting.md#terraform).

> [!NOTE]
> **Audit relevance:** Seven planted weaknesses break a rule. The plan is allowed only because each one has an entry in the exceptions register, `policy\exceptions.json`, with a reason, an approver, and an expiry date. After the expiry date, the same plan is blocked.

## Review the environment in the console

This procedure is optional.

1. Go to your access portal address, and then sign in.
2. In the search box, enter `VPC`, open it, and then select **Subnets**.

    Six subnets have names that start with `secuguard-`. Select one, and then select the **Tags** tab to see its `secuguard:pci-scope` tag.

3. In the search box, enter `S3`, and then open it.

    Select the bucket whose name starts with `secuguard-evidence-`, select the **Properties** tab, and then scroll to **Object Lock** to confirm that it's turned on.

## Next step

[Collect evidence and test the vault](collect-evidence.md)
