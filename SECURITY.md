# Security policy

## Reporting a vulnerability

Please **don't open a public issue** for security problems. Report them privately through
GitHub: open the repository's **Security** tab and choose **Report a vulnerability**.

Include what you found, how to reproduce it, and the impact you expect. You should get a
response within a week.

## Scope

memtaskman runs locally with the permissions of whoever starts it, and often elevated, to see
other users' processes. Of particular interest:

- Anything that makes memtaskman **read memory contents** of another process, or read model
  files beyond their header. It is designed to read only metadata.
- Network access beyond the documented localhost `GET /api/ps` request to Ollama, or any
  request sent to a non-local host.
- Output (`--json`, `record`, screenshots in `--privacy` mode) leaking more than documented.
- Crashes or hangs triggered by crafted files (GGUF headers) or crafted process metadata.

## Supported versions

Only the latest release receives fixes.
