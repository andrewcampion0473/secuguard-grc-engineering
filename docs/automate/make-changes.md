# Make and approve changes

After you [require the plan check](block-noncompliant-changes.md), the main branch accepts changes only through pull requests. Use this page each time you change the project.

## Make a change

In the commands, replace `my-change` with a short name for your change.

1. Create a branch.

    ```powershell
    git checkout -b my-change
    ```

2. Edit the files.
3. Commit the change, and then push the branch.

    ```powershell
    git add .
    git commit -m "Describe what changed"
    git push -u origin my-change
    ```

4. On GitHub, open a pull request, and then wait for **Tests** and **Plan check** to pass.
5. Select **Merge pull request**, and then select **Delete branch**.
6. Update your computer.

    ```powershell
    git checkout main
    git pull
    ```

7. If the change affects Terraform, apply it.

    ```powershell
    secuguard plan-check
    terraform -chdir=terraform apply tfplan
    ```

## Record an exception

When a rule must be set aside, record the decision in the exceptions register, `policy\exceptions.json`. Because the register is in the repository, adding or extending an exception goes through a pull request like any other change.

1. Open `policy\exceptions.json`.
2. Copy an existing entry, and then update its fields.

    | Field | Value |
    |---|---|
    | `address` | The one resource the exception covers |
    | `rule` | The one rule the resource is excused from |
    | `reason` | Why the risk is accepted |
    | `approved_by` | Who accepted the risk |
    | `expires` | The date the approval ends |

3. Follow [Make a change](#make-a-change) to propose and merge the exception.

After the `expires` date, the exception no longer applies, and the plan check blocks the change again.
