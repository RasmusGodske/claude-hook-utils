# Hook Contracts

This document defines the exact input and output contracts for each hook type supported by `claude-hook-utils`.

## Table of Contents

- [Common Fields](#common-fields)
- [PreToolUse](#pretooluse)
- [PostToolUse](#posttooluse)
- [UserPromptSubmit](#userpromptsubmit)
- [SessionStart](#sessionstart)
- [Response Format](#response-format)

---

## Common Fields

All hook inputs share these base fields:

```python
@dataclass
class BaseHookInput:
    session_id: str           # Unique session identifier
    cwd: str                  # Current working directory
    hook_event_name: str      # "PreToolUse", "PostToolUse", etc.
    transcript_path: str      # Path to session transcript file
    permission_mode: str      # "default", "plan", etc.
```

**Raw JSON example:**

```json
{
  "session_id": "abc123-def456",
  "cwd": "/home/user/project",
  "hook_event_name": "PreToolUse",
  "transcript_path": "/home/user/.claude/projects/.../session.jsonl",
  "permission_mode": "default"
}
```

---

## PreToolUse

Runs **before** a tool executes. Can allow, deny, or modify the tool call.

### Input Contract

```python
@dataclass
class PreToolUseInput(BaseHookInput):
    # Inherited: session_id, cwd, hook_event_name, transcript_path, permission_mode

    tool_name: str            # "Write", "Edit", "Bash", "Read", etc.
    tool_input: dict          # Tool-specific parameters (see below)
    tool_use_id: str          # Unique identifier for this tool call
```

**Raw JSON example:**

```json
{
  "session_id": "abc123",
  "cwd": "/home/user/project",
  "hook_event_name": "PreToolUse",
  "transcript_path": "/home/user/.claude/...",
  "permission_mode": "default",
  "tool_name": "Write",
  "tool_input": {
    "file_path": "/home/user/project/app/Data/UserData.php",
    "content": "<?php\n\nclass UserData..."
  },
  "tool_use_id": "toolu_01ABC123..."
}
```

### Tool-Specific `tool_input` Schemas

#### Write Tool

```json
{
  "file_path": "/absolute/path/to/file",
  "content": "file contents here"
}
```

#### Edit Tool

```json
{
  "file_path": "/absolute/path/to/file",
  "old_string": "text to find",
  "new_string": "replacement text"
}
```

#### Bash Tool

```json
{
  "command": "npm run build",
  "description": "Build the project",
  "timeout": 60000
}
```

#### Read Tool

```json
{
  "file_path": "/absolute/path/to/file",
  "offset": 0,
  "limit": 1000
}
```

#### Glob Tool

```json
{
  "pattern": "**/*.php",
  "path": "/home/user/project"
}
```

#### Grep Tool

```json
{
  "pattern": "class.*Controller",
  "path": "/home/user/project",
  "include": "*.php"
}
```

#### WebFetch Tool

```json
{
  "url": "https://example.com",
  "prompt": "Extract the main content"
}
```

#### WebSearch Tool

```json
{
  "query": "laravel validation rules",
  "allowed_domains": ["laravel.com"],
  "blocked_domains": []
}
```

#### Task Tool (Subagent)

```json
{
  "description": "Research authentication patterns",
  "prompt": "Find how authentication is implemented...",
  "subagent_type": "general-purpose"
}
```

### Helper Methods

```python
class PreToolUseInput:
    def file_path_matches(self, *globs: str) -> bool:
        """
        Check if tool_input.file_path matches any of the provided glob patterns.

        Uses fnmatch-style patterns:
        - * matches any characters except /
        - ** matches any characters including /
        - ? matches single character

        Examples:
            input.file_path_matches('**/*.php')
            input.file_path_matches('**/app/Data/**/*.php', '**/app/Models/**/*.php')

        Returns False if file_path is not present in tool_input.
        """

    def file_path_excludes(self, *globs: str) -> bool:
        """
        Check if tool_input.file_path does NOT match any of the provided globs.

        Useful for "skip unless" patterns:
            if input.file_path_excludes('**/app/**'):
                return None  # Skip - not in app directory

        Returns True if file_path is not present in tool_input.
        """

    @property
    def file_path(self) -> str | None:
        """Get file_path from tool_input, or None if not present."""

    @property
    def content(self) -> str | None:
        """Get content from tool_input (Write tool), or None if not present."""

    @property
    def command(self) -> str | None:
        """Get command from tool_input (Bash tool), or None if not present."""

    @property
    def old_string(self) -> str | None:
        """Get old_string from tool_input (Edit tool), or None if not present."""

    @property
    def new_string(self) -> str | None:
        """Get new_string from tool_input (Edit tool), or None if not present."""
```

### Response Contract

```python
@dataclass
class PreToolUseResponse:
    decision: Literal["allow", "deny", "ask"]
    reason: str | None
    updated_input: dict | None  # Only valid with "allow"

    @staticmethod
    def allow(reason: str | None = None) -> PreToolUseResponse:
        """Allow tool execution. Optional reason shown to user."""

    @staticmethod
    def deny(reason: str) -> PreToolUseResponse:
        """
        Block tool execution.
        Reason is shown to Claude as feedback so it can adapt its approach.
        """

    @staticmethod
    def ask(reason: str) -> PreToolUseResponse:
        """
        Request user confirmation.
        Reason shown in the confirmation dialog.
        """

    def with_updated_input(self, **updates) -> PreToolUseResponse:
        """
        Modify tool_input before execution.

        Only valid with 'allow' decision.

        Example:
            PreToolUseResponse.allow().with_updated_input(
                file_path="/corrected/path.php"
            )
        """
```

**Output JSON (allow):**

```json
{
  "hookSpecificOutput": {
    "hookEventName": "PreToolUse",
    "permissionDecision": "allow",
    "permissionDecisionReason": "Validation passed"
  }
}
```

**Output JSON (deny):**

```json
{
  "hookSpecificOutput": {
    "hookEventName": "PreToolUse",
    "permissionDecision": "deny",
    "permissionDecisionReason": "Data classes must have #[TypeScript()] annotation"
  }
}
```

**Output JSON (allow with modified input):**

```json
{
  "hookSpecificOutput": {
    "hookEventName": "PreToolUse",
    "permissionDecision": "allow",
    "permissionDecisionReason": "Auto-corrected path",
    "updatedInput": {
      "file_path": "/corrected/path.php"
    }
  }
}
```

---

## PostToolUse

Runs **after** a tool completes. Useful for logging, metrics, or triggering follow-up actions.

### Input Contract

```python
@dataclass
class PostToolUseInput(BaseHookInput):
    # Inherited: session_id, cwd, hook_event_name, transcript_path, permission_mode

    tool_name: str            # "Write", "Edit", "Bash", etc.
    tool_input: dict          # Original tool parameters
    tool_use_id: str          # Same ID from PreToolUse
    tool_result: str          # Output/result from the tool
    tool_error: str | None    # Error message if tool failed
```

**Raw JSON example:**

```json
{
  "session_id": "abc123",
  "cwd": "/home/user/project",
  "hook_event_name": "PostToolUse",
  "tool_name": "Write",
  "tool_input": {
    "file_path": "/home/user/project/app/Data/UserData.php",
    "content": "<?php..."
  },
  "tool_use_id": "toolu_01ABC123...",
  "tool_result": "File written successfully",
  "tool_error": null
}
```

### Helper Methods

Same as PreToolUseInput, plus:

```python
class PostToolUseInput:
    @property
    def succeeded(self) -> bool:
        """True if tool completed without error."""

    @property
    def failed(self) -> bool:
        """True if tool encountered an error."""
```

### Response Contract

PostToolUse responses are primarily for logging/side effects. The tool has already executed.

```python
@dataclass
class PostToolUseResponse:
    # PostToolUse can add system messages but cannot change what happened

    @staticmethod
    def acknowledge() -> PostToolUseResponse:
        """Acknowledge the tool result (no action)."""

    @staticmethod
    def with_message(message: str) -> PostToolUseResponse:
        """Add a system message shown to the user."""
```

**Output JSON:**

```json
{
  "hookSpecificOutput": {
    "hookEventName": "PostToolUse"
  }
}
```

---

## UserPromptSubmit

Runs when the user submits a prompt, before Claude processes it.

### Input Contract

```python
@dataclass
class UserPromptSubmitInput(BaseHookInput):
    # Inherited: session_id, cwd, hook_event_name, transcript_path, permission_mode

    prompt: str               # The user's submitted prompt
```

**Raw JSON example:**

```json
{
  "session_id": "abc123",
  "cwd": "/home/user/project",
  "hook_event_name": "UserPromptSubmit",
  "prompt": "Add a login feature"
}
```

### Response Contract

```python
@dataclass
class UserPromptSubmitResponse:
    @staticmethod
    def allow() -> UserPromptSubmitResponse:
        """Allow the prompt to proceed."""

    @staticmethod
    def deny(reason: str) -> UserPromptSubmitResponse:
        """Block the prompt. Reason shown to user."""

    @staticmethod
    def with_modified_prompt(new_prompt: str) -> UserPromptSubmitResponse:
        """Modify the prompt before Claude sees it."""
```

---

## SessionStart

Runs when a Claude Code session begins.

### Input Contract

```python
@dataclass
class SessionStartInput(BaseHookInput):
    # Inherited: session_id, cwd, hook_event_name, transcript_path, permission_mode

    env_file: str             # Path to file for persisting environment variables
```

**Raw JSON example:**

```json
{
  "session_id": "abc123",
  "cwd": "/home/user/project",
  "hook_event_name": "SessionStart",
  "env_file": "/tmp/claude-env-abc123"
}
```

### Response Contract

```python
@dataclass
class SessionStartResponse:
    @staticmethod
    def acknowledge() -> SessionStartResponse:
        """Acknowledge session start."""

    @staticmethod
    def with_env_vars(vars: dict[str, str]) -> SessionStartResponse:
        """Set environment variables for the session."""
```

---

## Response Format

All responses follow the Claude Code `hookSpecificOutput` schema:

```json
{
  "hookSpecificOutput": {
    "hookEventName": "<hook type>",
    "permissionDecision": "allow" | "deny" | "ask",
    "permissionDecisionReason": "string",
    "updatedInput": { ... }
  }
}
```

### Additional Response Fields

These optional fields work across all hook types:

```json
{
  "continue": false,           // Stop Claude entirely
  "stopReason": "message",     // Shown when continue=false
  "suppressOutput": true,      // Hide stdout from transcript
  "systemMessage": "warning"   // Warning shown to user
}
```

### Exit Codes

| Exit Code | Behavior |
|-----------|----------|
| 0 | Success. JSON output parsed. No output = allow. |
| 2 | Blocking error. stdout ignored, stderr used as error message. |
| Other | Non-blocking error. Shown in verbose mode only. |

---

## Glob Pattern Syntax

The `file_path_matches()` and `file_path_excludes()` methods use glob patterns:

| Pattern | Matches |
|---------|---------|
| `*` | Any characters except `/` |
| `**` | Any characters including `/` (recursive) |
| `?` | Single character |
| `[abc]` | Character class |
| `[!abc]` | Negated character class |

**Examples:**

```python
# Match any PHP file
input.file_path_matches('**/*.php')

# Match Data classes specifically
input.file_path_matches('**/app/Data/**/*.php')

# Match multiple patterns
input.file_path_matches('**/*.vue', '**/*.ts', '**/*.tsx')

# Exclude vendor and node_modules
input.file_path_excludes('**/vendor/**', '**/node_modules/**')
```
