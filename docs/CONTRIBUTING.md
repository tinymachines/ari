# Contributing to ARI

Thank you for your interest in contributing to AWS Resource Inventory (ARI)! This document provides guidelines and instructions for contributing to this project.

## Getting Started

1. **Fork the repository** on GitHub
2. **Clone your fork locally**:
   ```bash
   git clone git@github.com:yourusername/ari.git
   cd ari
   ```
3. **Set up development environment**:
   ```bash
   # Create a virtual environment
   python -m venv venv
   source venv/bin/activate  # On Windows: venv\Scripts\activate
   
   # Install the package in development mode with dev dependencies
   pip install -e ".[dev]"
   ```

## Development Workflow

1. **Create a branch** for your feature or bugfix:
   ```bash
   git checkout -b feature/your-feature-name
   ```

2. **Make your changes**:
   - Write code
   - Add or update tests
   - Update documentation

3. **Run tests and linting**:
   ```bash
   # Run tests
   pytest
   
   # Run linters
   pylint ari
   mypy ari
   ```

4. **Commit your changes** with a descriptive message:
   ```bash
   git add .
   git commit -m "Add feature: brief description of your changes"
   ```

5. **Push to your fork**:
   ```bash
   git push origin feature/your-feature-name
   ```

6. **Submit a pull request** from your fork to the main repository

## Adding Support for a New AWS Service

When adding support for a new AWS service:

1. Create a new method in `AWSInventory` class named `get_<service>_resources`
2. Use the boto3 client to gather resource information
3. Format resource data consistently with other services
4. Add the service name to `SERVICES_TO_CHECK` list
5. Update the `get_resources_by_service` method to handle the new service
6. Add tests for the new service

See existing service implementations for reference.

## Code Style

- Follow PEP 8 conventions
- Use 4 spaces for indentation (no tabs)
- Use descriptive names for variables, functions, and classes
- Include docstrings for all public functions, classes, and methods
- Handle exceptions with specific exception types and proper logging

## Testing

- Write unit tests for all new functionality
- Use pytest for testing
- Aim for high test coverage
- Mock AWS API calls to avoid requiring actual AWS credentials during tests

## Submitting Pull Requests

1. Ensure all tests pass
2. Update documentation if needed
3. Add your changes to the CHANGELOG.md under "Unreleased"
4. Submit a pull request with a clear description of the changes
5. Reference any related issues

## License

By contributing, you agree that your contributions will be licensed under the project's MIT License.