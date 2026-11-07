# OmniPatch

OmniPatch is a headless CLI scaffold for security patch workflows.

Fresh clones use LF line endings for tracked text automatically; no local Git line-ending configuration is required.

## Development

```bash
uv sync
uv run omnipatch version
uv run omnipatch scan --repo . --json
```
