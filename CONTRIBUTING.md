# Contributing to Mimick

Thanks for your interest in contributing to Mimick! Whether it's a bug report, feature idea, or code contribution — all input is appreciated.

## How to Contribute

### Reporting Bugs

Open an [issue](https://github.com/ceyhuncakir/mimick/issues) with:

- A clear description of the problem
- Steps to reproduce
- Expected vs actual behavior
- Mimick version and environment details (OS, Python version)

### Suggesting Features

Open an issue with the `feature` label. Describe the use case and why it would be valuable.

### Submitting a Pull Request

1. Fork the repository
2. Create a branch from `main` (`git checkout -b my-change`)
3. Make your changes
4. Run the existing tests to make sure nothing breaks
5. Submit a pull request against `main`

Keep PRs focused — one change per PR makes review faster.

### What to Work On

Check the [open issues](https://github.com/ceyhuncakir/mimick/issues) for things to pick up. Issues labeled `good first issue` are a good starting point.

## Development Setup

```bash
git clone https://github.com/ceyhuncakir/mimick.git
cd mimick
uv sync
uv run playwright install chromium
./install-tools.sh
```

## Code Style

- Follow the existing patterns in the codebase
- Keep changes minimal and focused
- Write clear commit messages

## Review Process

I review all PRs personally. I'll do my best to respond within a few days. If changes are needed, I'll leave comments — don't hesitate to ask questions.

## Security Issues

Do **not** open a public issue for security vulnerabilities. See [SECURITY.md](SECURITY.md) for how to report them.
