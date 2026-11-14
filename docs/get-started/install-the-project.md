# Install the project

Download the project from GitHub and install it in an isolated Python environment.

**Time:** About 10 minutes

**Prerequisite:** [Set up your computer](set-up-your-computer.md)

## Download the project

Run the following commands.

```powershell
mkdir $HOME\Projects -Force
cd $HOME\Projects
git clone https://github.com/andrewcampion0473/secuguard-grc-engineering.git
cd secuguard-grc-engineering
```

The prompt now ends with `secuguard-grc-engineering>`. This is the project folder. Run every command in this manual from this folder.

## Create the Python environment

A virtual environment keeps this project's Python packages separate from everything else on your computer.

1. Create the environment.

    ```powershell
    py -m venv .venv
    ```

    The command takes a few seconds and prints nothing.

2. Activate the environment.

    ```powershell
    .\.venv\Scripts\Activate.ps1
    ```

    `(.venv)` appears at the start of the prompt.

3. Install the project.

    ```powershell
    pip install -e ".[dev]"
    ```

    The last line of output starts with `Successfully installed`. The `secuguard` command is now available.

> [!IMPORTANT]
> Activate the environment each time you open a new PowerShell window. If `(.venv)` isn't at the start of the prompt, PowerShell can't find the `secuguard` command.

## Run the self-tests

```powershell
pytest
```

The output ends with a line that contains `passed` and reports no failures.

> [!NOTE]
> **Audit relevance:** These tests are the answer to "How do you know the automated checks work?" They confirm that every planted weakness is found, that an edited, added, or removed evidence file is detected, and that a check never reports a pass when its evidence is missing.

## Next step

[Run the project in practice mode](run-in-practice-mode.md)
