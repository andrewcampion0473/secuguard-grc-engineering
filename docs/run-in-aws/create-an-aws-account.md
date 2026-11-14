# Create and secure an AWS account

Open an AWS account, protect it, and connect your computer to it.

**Time:** About 45 minutes

**Prerequisites:**

- [Install the project](../get-started/install-the-project.md)
- An email address that isn't already tied to an AWS account
- A phone with an authenticator app, such as Microsoft Authenticator or Google Authenticator
- A credit or debit card

> [!WARNING]
> Create a new account for this project. Don't use an account that holds anything else, because the project creates deliberate weaknesses in the account it runs in.

AWS changes its console often. If a name in this manual doesn't match what you see, select the closest match.

## Create the account

AWS has two sign-up flows. Only the advanced flow creates an account that works for this project. The simplified flow creates an account fixed to one region with many security services unavailable.

1. Go to `https://signin.aws.amazon.com/signup?request_type=register`.

    Start from this address and not from the AWS home page, so that you get the advanced flow.

2. Enter an email address and an account name, such as `secuguard-grc`, and then select **Verify email address**.
3. Enter the code that AWS emails you, and then select **Verify**.
4. Create a password, and then select **Continue**.
5. For the account plan, select the paid plan.

    The free plan restricts services that this project needs. You're still charged only for what you use.

6. Enter your contact details, and then accept the customer agreement.
7. Enter your card details.
8. Enter the code that AWS sends to your phone.
9. For the support plan, select **Basic**, which is free.
10. Select **Complete sign up**.

    AWS emails you when the account is ready, usually within a few minutes.

11. Go to `https://console.aws.amazon.com`, and then sign in as the **root user** with the email address and password you created.

The top bar of the console shows a region name, such as **N. Virginia**, to the left of your account name. If you see **Manage projects** and **Manage team** and no region name, the account was created with the simplified flow. Sign out, and then repeat this procedure from step 1.

## Protect the root user

The root user can do anything to the account, including close it. Protect it with MFA, and then stop using it.

1. Select your account name in the upper-right corner, and then select **Security credentials**.
2. Under **Multi-factor authentication (MFA)**, select **Assign MFA device**.
3. Select **Authenticator app**, and then follow the prompts to scan the code with your phone.

Don't create access keys for the root user.

> [!NOTE]
> **Audit relevance:** Checks IAM-01 and IAM-02 test that the root user has MFA and no access keys. They pass because of this procedure.

## Set a spending alert

1. In the search box at the top of the console, enter `Budgets`, and then open **Budgets**.
2. Select **Create budget**.
3. Select **Use a template**, and then select **Monthly cost budget**.
4. Enter an amount of `50` and your email address.
5. Select **Create budget**.

The budget doesn't stop spending. It emails you if the month's bill is on track to pass the amount.

## Create an administrator user

Do all remaining work as a separate user, managed by IAM Identity Center, and not as the root user.

> [!IMPORTANT]
> IAM Identity Center is set up in the region that's selected when you turn it on. This project uses **US East (N. Virginia)**, `us-east-1`. Confirm the region before step 3.

1. In the top bar, select the region name, and then select **US East (N. Virginia)**.
2. In the search box, enter `IAM Identity Center`, and then open it.
3. Confirm that the top bar shows **N. Virginia**, and then select **Enable**. If you're asked, enable it with AWS Organizations.
4. Select **Users** > **Add user**. Enter a username, your email address, and your name, and then complete the prompts.
5. Open the invitation that AWS emails you. Accept it, set a password, and set up MFA.
6. In IAM Identity Center, select **Permission sets** > **Create permission set**.
7. Select **Predefined permission set** > **AdministratorAccess**, and then complete the prompts.
8. Select **AWS accounts**. Select the check box next to your account, and then select **Assign users or groups**.
9. Select your user, select the **AdministratorAccess** permission set, and then submit.
10. Select **Settings**. Under **AWS access portal URLs**, copy the **IPv4-only** address, which ends in `awsapps.com/start`.

    This address is your access portal. You sign in through it from now on, and you need it in the next procedure.

## Connect your computer to AWS

1. In PowerShell, run the following command.

    ```powershell
    aws configure sso
    ```

2. Answer the prompts.

    | Prompt | Answer |
    |---|---|
    | SSO session name | `secuguard` |
    | SSO start URL | Your access portal address |
    | SSO region | `us-east-1` |
    | SSO registration scopes | Press Enter to accept the default |

3. When your browser opens, sign in as the administrator user, and then approve the request.
4. Return to PowerShell, and then answer the remaining prompts.

    | Prompt | Answer |
    |---|---|
    | Account and role | If asked, your account and `AdministratorAccess` |
    | Default client Region | `us-east-1` |
    | CLI default output format | `json` |
    | Profile name | `secuguard` |

5. Confirm the connection.

    ```powershell
    aws sts get-caller-identity --profile secuguard
    ```

    The output shows a `UserId`, your 12-digit `Account` number, and an `Arn` that contains `AdministratorAccess`.

The sign-in lasts a few hours. When a command fails with a message about an expired token, sign in again.

```powershell
aws sso login --profile secuguard
```

## Next step

[Build the environment](build-the-environment.md)
