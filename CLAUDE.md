# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Commands
- Install dependencies: `pip install -e .`
- Run tool: `ari --access-key KEY --secret-key SECRET`
- Build package: `python -m build`
- Code linting: `pylint ari/*.py`
- Type checking: `mypy ari/*.py`
- Create distribution: `python -m build`
- Publish to PyPI: `twine upload dist/*`

## Code Style Guidelines
- **Imports**: Group imports by standard library, third-party, and project-specific
- **Formatting**: Follow PEP 8 conventions (4-space indentation)
- **Error Handling**: Use try/except blocks with specific exception types and logging
- **Naming**: Use snake_case for variables/functions and PascalCase for classes
- **Logging**: Use the logging module with appropriate levels (info, error, debug)
- **Documentation**: Include docstrings for classes and functions
- **AWS Resources**: Handle ClientError exceptions from boto3 calls
- **Database**: Use parameter binding for all SQL queries to prevent injection

When extending functionality, follow the existing patterns for adding new AWS service resource collectors.