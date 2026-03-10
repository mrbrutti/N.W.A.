# GitHub Workflow

This repository uses an issue-driven workflow. Every implementation change must start from a GitHub issue and land through a pull request with local validation.

## Rules

1. Create or pick a GitHub issue before changing code.
2. Use a dedicated branch named `codex/<short-topic>` or an equivalent descriptive branch name.
3. Keep each branch and PR scoped to one issue, or one tightly related slice of an Epic.
4. Run the required validation locally before opening or updating the PR.
5. Open a PR immediately after the first push and link the issue with a closing keyword such as `Closes #123`.
6. Merge only after the PR is reviewed or otherwise accepted and the required local validation has been run for the final branch state.
7. Let the merge close the issue automatically. Do not close implementation issues by hand unless no code change is required.

## Required Validation

- `./scripts/validate-local.sh`

Add extra validation when the change touches a narrower subsystem, for example a focused smoke test, curl verification, or browser check.

## Recommended Issue Structure

- Use an Epic for large initiatives.
- Break Epics into work items that can realistically land in small PRs.
- Keep follow-up work in GitHub issues instead of burying it in PR comments.

## Pull Request Standard

Every PR should include:

- a short summary of the change
- the linked issue with a closing keyword
- the exact commands run for validation
- any residual risks or follow-up issues

## Merge Standard

Preferred merge mode:

- squash merge for feature work

Before merging:

- local validation has been run against the current branch tip
- the linked issue is present in the PR body
- the PR scope still matches the issue
