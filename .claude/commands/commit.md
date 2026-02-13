---
name: /commit
description: Smart commit workflow - analyze changes and generate conventional commit messages
usage: /commit [type]
example: /commit or /commit feat
---

# Smart Commit Workflow Command

When receiving `/commit [type]` command, follow these steps:

## Step 1: Analyze Changes
1. Run `git status` to see all changed files
2. Run `git diff` to see specific changes
3. Distinguish between staged and unstaged changes

## Step 2: Determine Commit Type
Auto-detect type based on changes (if user not specified):
- `test` - Test file changes
- `doc` - Documentation changes
- `chore` - Build, config, dependency related
- `feat` - New feature (default)
- `fix` - Bug fix
- `refactor` - Code refactoring
- `style` - Code style adjustments
- `perf` - Performance optimization

## Step 3: Determine Scope
Infer scope from file paths:
- `auth` - Authentication related
- `podcast` - Podcast related
- `chat` - Chat related
- `settings` - Settings related
- `user` - User related
- `api` - API related
- `models` - Data models related
- `services` - Service layer related
- `core` - Core functionality
- `ui` - UI components

## Step 4: Generate Commit Message
Follow [Conventional Commits](https://www.conventionalcommits.org/) format:
```
<type>[optional scope]: <description>

[optional body]
```

## Step 5: Wait for Confirmation
1. Display generated commit message
2. Ask user to confirm
3. Cancel if not accepted

## Step 6: Execute Commit
1. If unstaged changes exist, run `git add` first
2. Execute `git commit`
3. Display commit result

**IMPORTANT**: Do NOT include `Co-Authored-By:` in commit messages.

## Commit Message Format Reference
Based on project `cliff.toml` commit_parsers:

| Pattern | Group |
|---------|-------|
| `^feat` | 🚀 Features |
| `^fix` | 🐛 Bug Fixes |
| `^doc` | 📚 Documentation |
| `^perf` | ⚡ Performance |
| `^refactor` | 🚜 Refactor |
| `^style` | 🎨 Styling |
| `^test` | 🧪 Testing |
| `^chore` | ⚙️ Miscellaneous Tasks |

## Examples
Input: `/commit`
- Analyze changes: `frontend/lib/features/settings/...`
- Auto-detect type: `feat`
- Auto-detect scope: `settings`
- Generate: `feat(settings): add markdown rendering to update_dialog.dart, app_update_provider.dart`
- Execute commit after confirmation

Input: `/commit test`
- Specified type: `test`
- Generate: `test: add tests for update_dialog markdown rendering`
