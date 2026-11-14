# Set up your computer

Install the five free programs the project uses.

| Program | Purpose | Needed for |
|---|---|---|
| Git | Downloads the project and tracks changes to it | All paths |
| Python | Runs the collectors and the checks | All paths |
| Visual Studio Code | Opens project files for reading and editing | All paths |
| Terraform | Builds the environment in AWS | Paths 2 and 3 |
| AWS CLI | Signs your computer in to AWS | Paths 2 and 3 |

**Time:** About 30 minutes

## Open PowerShell

PowerShell is the Windows terminal, a window where you enter commands. Every command in this manual runs in PowerShell.

1. Select **Start**.
2. Enter `PowerShell`.
3. Select **Windows PowerShell**.

To paste into PowerShell, press Ctrl+V or right-click inside the window.

## Install the programs

1. Run the following commands.

    ```powershell
    winget install --id Git.Git -e
    winget install --id Python.Python.3.13 -e
    winget install --id Hashicorp.Terraform -e
    winget install --id Amazon.AWSCLI -e
    winget install --id Microsoft.VisualStudioCode -e
    ```

2. If `winget` asks you to agree to its terms, enter `Y`.
3. If Windows asks whether to allow an installer to make changes, select **Yes**.
4. Close PowerShell, and then open a new PowerShell window.

    Newly installed programs aren't available until you open a new window.

## Verify the installation

Run each command.

```powershell
git --version
py --version
terraform -version
aws --version
```

Each command prints a version number, such as `git version 2.47.0.windows.1`. The exact numbers don't matter.

## Allow local scripts to run

Windows blocks a script that the project needs. Run this command once.

```powershell
Set-ExecutionPolicy -Scope CurrentUser -ExecutionPolicy RemoteSigned
```

If PowerShell asks you to confirm, enter `Y`.

This setting applies to your Windows user only. It allows scripts on your computer to run and continues to block unsigned scripts downloaded from the internet.

## Next step

[Install the project](install-the-project.md)
