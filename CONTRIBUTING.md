# Contributing to WRAITH

Thank you for your interest in contributing to WRAITH. This document covers everything you need to get started — from setting up your environment to getting a pull request merged.

---

## Table of Contents

- [Code of Conduct](#code-of-conduct)
- [Getting Started](#getting-started)
- [Development Environment](#development-environment)
- [Branching Strategy](#branching-strategy)
- [Making Changes](#making-changes)
- [Commit Message Convention](#commit-message-convention)
- [Pull Request Process](#pull-request-process)
- [Reporting Bugs](#reporting-bugs)
- [Requesting Features](#requesting-features)
- [Style Guidelines](#style-guidelines)
- [Security Disclosures](#security-disclosures)

---

## Code of Conduct

By participating in this project you agree to uphold a respectful and inclusive environment. Harassment, discrimination, or abusive behavior of any kind will not be tolerated.

---

## Getting Started

1. **Fork** the repository to your own GitHub account.
2. **Clone** your fork locally:
   ```powershell
   git clone https://github.com/<your-username>/WRAITH.git
   cd WRAITH
   ```
3. Add the upstream remote so you can pull in future changes:
   ```powershell
   git remote add upstream https://github.com/Security-International-Group/WRAITH.git
   ```

---

## Development Environment

### Requirements

| Tool | Minimum Version |
|------|----------------|
| Windows | 10 / 11 (64-bit) |
| PowerShell | 5.1 or 7+ |
| Git | 2.40+ |

### First-time Setup

```powershell
# Install dependencies (adjust for your package manager / build system)
.\scripts\setup.ps1
```

> **Note:** All scripts should be run from a PowerShell terminal opened as **Administrator** unless otherwise noted.

---

## Branching Strategy

| Branch | Purpose |
|--------|---------|
| `main` | Stable, release-ready code |
| `dev` | Integration branch for in-progress work |
| `feature/<short-name>` | New features |
| `fix/<short-name>` | Bug fixes |
| `docs/<short-name>` | Documentation-only changes |

Always branch off `dev` for new work, not `main`:

```powershell
git checkout dev
git pull upstream dev
git checkout -b feature/your-feature-name
```

---

## Making Changes

- Keep changes focused. One pull request = one concern.
- Write or update tests for any logic you change.
- Run the full test suite before opening a PR:
  ```powershell
  .\scripts\test.ps1
  ```
- If your change touches the build system or CI pipeline, document why.

---

## Commit Message Convention

Follow [Conventional Commits](https://www.conventionalcommits.org/):

```
<type>(<scope>): <short summary>

[optional body]

[optional footer]
```

**Types:**

| Type | When to use |
|------|-------------|
| `feat` | New feature |
| `fix` | Bug fix |
| `docs` | Documentation only |
| `refactor` | Code restructure, no behavior change |
| `test` | Adding or fixing tests |
| `chore` | Build process, tooling, CI |
| `perf` | Performance improvement |

**Example:**
```
feat(agent): add stealthy process enumeration via NtQuerySystemInformation
```

---

## Pull Request Process

1. Ensure your branch is up to date with `dev`:
   ```powershell
   git fetch upstream
   git rebase upstream/dev
   ```
2. Push your branch:
   ```powershell
   git push origin feature/your-feature-name
   ```
3. Open a pull request against the `dev` branch — **not** `main`.
4. Fill out the PR template completely. Incomplete PRs may be closed without review.
5. At least **one approved review** is required before merge.
6. Resolve all review comments before requesting a re-review.
7. Squash commits if requested by a maintainer.

---

## Reporting Bugs

Open a [GitHub Issue](../../issues) and include:

- A clear, descriptive title.
- Steps to reproduce.
- Expected vs. actual behavior.
- Windows version, PowerShell version, and any relevant logs.
- Whether the issue is reproducible on a clean environment.

---

## Requesting Features

Open a GitHub Issue with the label `enhancement` and include:

- The problem you are trying to solve.
- Your proposed solution or approach.
- Any alternatives you considered.

Large feature proposals should be discussed in an issue **before** any code is written.

---

## Style Guidelines

- Follow the existing code style present in the file you are editing.
- PowerShell: use approved verbs (`Get-`, `Set-`, `Invoke-`, etc.), avoid aliases in scripts.
- Use `PascalCase` for functions and cmdlets, `camelCase` for local variables.
- Keep lines under **120 characters** where practical.
- No trailing whitespace. No unnecessary blank lines at the end of files.

---

## Security Disclosures

**Do not open a public issue for security vulnerabilities.**

Please report security issues privately to the maintainers via email or GitHub's private vulnerability reporting feature. We commit to acknowledging your report within **72 hours** and providing a resolution timeline.

---
