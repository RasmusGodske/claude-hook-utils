# claude-hook-utils

A Python utility package for building [Claude Code hooks](https://docs.anthropic.com/en/docs/claude-code/hooks) with minimal boilerplate.

## What Are Claude Code Hooks?

Claude Code hooks are custom scripts that run at specific points during Claude Code's execution. They allow you to:

- **Validate** tool calls before they execute (PreToolUse)
- **React** to tool results after execution (PostToolUse)
- **Intercept** user prompts before Claude sees them (UserPromptSubmit)
- **Initialize** state when a session starts (SessionStart)

## Why This Package?

Building Claude Code hooks involves repetitive boilerplate:
- Parsing JSON from stdin
- Validating input structure
- Formatting responses in the correct schema
- Handling errors gracefully

`claude-hook-utils` handles all of this, letting you focus on your validation logic.

## Design Philosophy

1. **One Pattern** - Extend `HookHandler`, override the hooks you need
2. **Type Safety** - Typed dataclasses for inputs, builder pattern for responses
3. **Explicit Control** - Helper methods on inputs, but you decide when to skip/allow/deny
4. **Multi-Hook Support** - One Python program can handle multiple hook types
5. **No Heavy Dependencies** - Core package has minimal dependencies; bring your own AI SDK if needed

## Installation

```bash
pip install claude-hook-utils
```

## Quick Start

```python
#!/usr/bin/env python3
"""Validate that Data classes have TypeScript annotation."""

from claude_hook_utils import HookHandler, PreToolUseInput, PreToolUseResponse

class DataClassValidator(HookHandler):
    def pre_tool_use(self, input: PreToolUseInput) -> PreToolUseResponse | None:
        # Skip if not a Data class file
        if not input.file_path_matches('**/app/Data/**/*.php'):
            return None

        # Check for required annotation
        if input.content and '#[TypeScript()]' not in input.content:
            return PreToolUseResponse.deny(
                "Data classes must have #[TypeScript()] annotation for type generation"
            )

        return PreToolUseResponse.allow()

if __name__ == "__main__":
    DataClassValidator().run()
```

Configure in `.claude/settings.json`:

```json
{
  "hooks": {
    "PreToolUse": [
      {
        "matcher": "Write|Edit",
        "hooks": [
          {
            "type": "command",
            "command": "python3 /path/to/data_class_validator.py"
          }
        ]
      }
    ]
  }
}
```

## Supported Hook Types

| Hook Type | When It Runs | Use Cases |
|-----------|--------------|-----------|
| `PreToolUse` | Before a tool executes | Validate file paths, check content, block dangerous operations |
| `PostToolUse` | After a tool completes | Log results, trigger follow-up actions, collect metrics |
| `UserPromptSubmit` | When user submits a prompt | Validate prompts, add context, enforce policies |
| `SessionStart` | When a Claude Code session begins | Initialize state, set environment variables |

## API Reference

### `HookHandler` Base Class

Extend this class and override the hooks you need:

```python
from claude_hook_utils import HookHandler

class MyHandler(HookHandler):
    def __init__(self):
        super().__init__()
        # Add any shared state here
        self._cache: dict = {}

    def pre_tool_use(self, input: PreToolUseInput) -> PreToolUseResponse | None:
        """Called before tool execution. Return None to skip."""
        return None

    def post_tool_use(self, input: PostToolUseInput) -> PostToolUseResponse | None:
        """Called after tool execution. Return None to skip."""
        return None

    def user_prompt_submit(self, input: UserPromptSubmitInput) -> UserPromptSubmitResponse | None:
        """Called when user submits a prompt. Return None to skip."""
        return None

    def session_start(self, input: SessionStartInput) -> SessionStartResponse | None:
        """Called when session starts. Return None to skip."""
        return None

if __name__ == "__main__":
    MyHandler().run()
```

### `PreToolUseInput`

Input for PreToolUse hooks:

```python
@dataclass
class PreToolUseInput:
    # Common fields
    session_id: str
    cwd: str
    hook_event_name: str  # Always "PreToolUse"

    # PreToolUse-specific
    tool_name: str        # "Write", "Edit", "Bash", etc.
    tool_input: dict      # Tool-specific parameters
    tool_use_id: str

    # Helper methods
    def file_path_matches(self, *globs: str) -> bool:
        """Check if tool_input.file_path matches any glob pattern."""

    def file_path_excludes(self, *globs: str) -> bool:
        """Check if tool_input.file_path does NOT match any glob pattern."""

    # Convenience properties
    @property
    def file_path(self) -> str | None:
        """Get file_path from tool_input (for Write/Edit/Read tools)."""

    @property
    def content(self) -> str | None:
        """Get content from tool_input (for Write tool)."""

    @property
    def command(self) -> str | None:
        """Get command from tool_input (for Bash tool)."""
```

### `PreToolUseResponse`

Response builder for PreToolUse hooks:

```python
class PreToolUseResponse:
    @staticmethod
    def allow(reason: str | None = None) -> PreToolUseResponse:
        """Allow the tool to execute."""

    @staticmethod
    def deny(reason: str) -> PreToolUseResponse:
        """Block the tool. Reason is shown to Claude as feedback."""

    @staticmethod
    def ask(reason: str) -> PreToolUseResponse:
        """Request user confirmation before proceeding."""

    def with_updated_input(self, **updates) -> PreToolUseResponse:
        """Modify tool_input before execution (only valid with allow)."""
```

### `HookLogger`

JSONL-based logging for easy debugging. Logs are organized by namespace (plugin name).

```python
from claude_hook_utils import HookHandler, HookLogger

class MyHandler(HookHandler):
    def __init__(self):
        # Logs to .claude/logs/my-plugin/hooks.jsonl
        super().__init__(
            logger=HookLogger.create_default("MyHandler", namespace="my-plugin")
        )

    def pre_tool_use(self, input: PreToolUseInput) -> PreToolUseResponse | None:
        # Session ID is automatically added from input
        self.logger.info("Checking file", file_path=input.file_path)
        # ... validation logic ...
        self.logger.decision("allow", reason="Validation passed")
        return PreToolUseResponse.allow()
```

**Log format (JSONL - one JSON object per line):**
```json
{"ts": "2025-01-04T10:15:23.456+00:00", "level": "INFO", "hook": "MyHandler", "namespace": "my-plugin", "session": "abc123", "msg": "Checking file", "file_path": "/path/to/file.php"}
{"ts": "2025-01-04T10:15:23.458+00:00", "level": "DECISION", "hook": "MyHandler", "namespace": "my-plugin", "session": "abc123", "msg": "decision=allow", "decision": "allow", "reason": "Validation passed"}
```

**Configuration:**
- Default location: `{cwd}/.claude/logs/{namespace}/hooks.jsonl`
- Without namespace: `{cwd}/.claude/logs/hooks.jsonl`
- Override directory with `CLAUDE_HOOK_LOG_DIR` env var
- Override namespace with `CLAUDE_HOOK_LOG_NAMESPACE` env var
- Session ID is automatically extracted from hook input

## Examples

### Validate Vue Component Structure

```python
class VueValidator(HookHandler):
    def pre_tool_use(self, input: PreToolUseInput) -> PreToolUseResponse | None:
        if not input.file_path_matches('**/*.vue'):
            return None

        content = input.content or ''

        # Check tag order: <script> before <template> before <style>
        script_pos = content.find('<script')
        template_pos = content.find('<template')
        style_pos = content.find('<style')

        if script_pos > template_pos or template_pos > style_pos:
            return PreToolUseResponse.deny(
                "Vue components must have tags in order: <script>, <template>, <style>"
            )

        # Check for setup lang="ts"
        if '<script setup lang="ts">' not in content:
            return PreToolUseResponse.deny(
                "Vue components must use <script setup lang=\"ts\">"
            )

        return PreToolUseResponse.allow()
```

### Validate Controller Location

```python
class ControllerValidator(HookHandler):
    def pre_tool_use(self, input: PreToolUseInput) -> PreToolUseResponse | None:
        if not input.file_path_matches('**/*Controller.php'):
            return None

        # Controllers must be in app/Http/Controllers/
        if not input.file_path_matches('**/app/Http/Controllers/**/*.php'):
            return PreToolUseResponse.deny(
                f"Controllers must be in app/Http/Controllers/. "
                f"Found: {input.file_path}"
            )

        return PreToolUseResponse.allow()
```

### Block FormRequest Usage (Suggest Data Class)

```python
class NoFormRequestValidator(HookHandler):
    def pre_tool_use(self, input: PreToolUseInput) -> PreToolUseResponse | None:
        if not input.file_path_matches('**/*Controller.php'):
            return None

        content = input.content or ''

        if 'FormRequest' in content:
            return PreToolUseResponse.deny(
                "Do not use FormRequest classes. Use Data classes instead. "
                "See: app/Data/ for examples."
            )

        return PreToolUseResponse.allow()
```

### Multi-Hook Handler (Pre + Post)

```python
class FileTracker(HookHandler):
    def __init__(self):
        super().__init__()
        self._pending_writes: set[str] = set()

    def pre_tool_use(self, input: PreToolUseInput) -> PreToolUseResponse | None:
        if input.tool_name == 'Write' and input.file_path:
            self._pending_writes.add(input.file_path)
            self.logger.info(f"Tracking write: {input.file_path}")
        return PreToolUseResponse.allow()

    def post_tool_use(self, input: PostToolUseInput) -> PostToolUseResponse | None:
        if input.tool_name == 'Write' and input.file_path:
            self._pending_writes.discard(input.file_path)
            self.logger.info(f"Write completed: {input.file_path}")
        return None
```

## Claude Code Hook Response Format

This package generates responses in the official `hookSpecificOutput` format:

```json
{
  "hookSpecificOutput": {
    "hookEventName": "PreToolUse",
    "permissionDecision": "deny",
    "permissionDecisionReason": "Your reason here"
  }
}
```

### Decision Options

| Decision | Effect |
|----------|--------|
| `allow` | Tool executes immediately, reason shown to user |
| `deny` | Tool blocked, reason shown to Claude (so it can adapt) |
| `ask` | User confirmation dialog shown |

### Modifying Tool Input

Use `with_updated_input()` to modify parameters before execution:

```python
def pre_tool_use(self, input: PreToolUseInput) -> PreToolUseResponse | None:
    # Auto-correct a common mistake
    if input.file_path and '/data/' in input.file_path:
        corrected = input.file_path.replace('/data/', '/Data/')
        return PreToolUseResponse.allow("Auto-corrected path").with_updated_input(
            file_path=corrected
        )
    return PreToolUseResponse.allow()
```

## Error Handling

The package handles errors gracefully:

- **Invalid JSON input**: Returns exit 0 (no output = allow)
- **Unknown hook type**: Returns None (skip)
- **Exception in handler**: Logged to stderr, returns exit 0 (fail open)

This "fail open" approach ensures your hooks don't block Claude Code if something goes wrong.

## Environment Variables

Claude Code provides these environment variables to hooks:

| Variable | Description |
|----------|-------------|
| `CLAUDE_PROJECT_DIR` | Absolute path to project root |
| `CLAUDE_CODE_REMOTE` | `"true"` if running in web environment |

This package uses:

| Variable | Description |
|----------|-------------|
| `CLAUDE_HOOK_LOG_DIR` | Override default log directory (default: `.claude/logs/{namespace}/`) |
| `CLAUDE_HOOK_LOG_NAMESPACE` | Override log namespace/subdirectory |

Access via `input.cwd` or `os.environ`.

## Extending for New Hook Types

To add support for a new hook type:

1. Create input dataclass in `inputs/`
2. Create response class in `responses/`
3. Add handler method to `HookHandler`
4. Add dispatch case in `HookHandler._dispatch()`

See existing implementations for patterns to follow.

## License

MIT
