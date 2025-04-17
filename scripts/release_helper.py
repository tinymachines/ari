#!/usr/bin/env python3
"""
ARI Release Helper

A simple script to help with versioning and releases.
"""

import os
import re
import sys
import argparse
import datetime
from pathlib import Path

# Get the project root directory (assuming this script is in scripts/ directory)
SCRIPT_DIR = Path(os.path.dirname(os.path.abspath(__file__)))
PROJECT_ROOT = SCRIPT_DIR.parent

# File paths
INIT_FILE = PROJECT_ROOT / "ari" / "__init__.py"
CHANGELOG_FILE = PROJECT_ROOT / "CHANGELOG.md"


def get_current_version():
    """Get the current version from __init__.py"""
    with open(INIT_FILE, "r", encoding="utf-8") as f:
        init_content = f.read()
    
    version_match = re.search(r'__version__\s*=\s*["\']([^"\']+)["\']', init_content)
    if not version_match:
        print("Error: Could not find version in __init__.py")
        sys.exit(1)
    
    return version_match.group(1)


def update_version(version):
    """Update the version in __init__.py"""
    with open(INIT_FILE, "r", encoding="utf-8") as f:
        init_content = f.read()
    
    new_content = re.sub(
        r'__version__\s*=\s*["\']([^"\']+)["\']',
        f'__version__ = "{version}"',
        init_content
    )
    
    with open(INIT_FILE, "w", encoding="utf-8") as f:
        f.write(new_content)
    
    print(f"Updated version to {version} in {INIT_FILE}")


def update_changelog(version):
    """Update the CHANGELOG.md file with the new version"""
    with open(CHANGELOG_FILE, "r", encoding="utf-8") as f:
        changelog_content = f.read()
    
    today = datetime.date.today().isoformat()
    new_content = changelog_content.replace(
        "## [Unreleased]",
        f"## [Unreleased]\n\n## [{version}] - {today}"
    )
    
    with open(CHANGELOG_FILE, "w", encoding="utf-8") as f:
        f.write(new_content)
    
    print(f"Updated CHANGELOG.md with version {version}")


def main():
    parser = argparse.ArgumentParser(description="ARI Release Helper")
    parser.add_argument("--bump", choices=["major", "minor", "patch"], 
                        help="Bump the version (major, minor, or patch)")
    parser.add_argument("--version", help="Set a specific version")
    parser.add_argument("--get", action="store_true", help="Get the current version")
    args = parser.parse_args()
    
    current_version = get_current_version()
    
    if args.get:
        print(f"Current version: {current_version}")
        return
    
    if args.version:
        new_version = args.version
    elif args.bump:
        # Parse the current version
        try:
            major, minor, patch = map(int, current_version.split("."))
        except ValueError:
            print(f"Error: Invalid current version format: {current_version}")
            sys.exit(1)
        
        # Bump the version
        if args.bump == "major":
            new_version = f"{major + 1}.0.0"
        elif args.bump == "minor":
            new_version = f"{major}.{minor + 1}.0"
        elif args.bump == "patch":
            new_version = f"{major}.{minor}.{patch + 1}"
    else:
        parser.print_help()
        return
    
    # Update files
    update_version(new_version)
    update_changelog(new_version)
    
    print(f"\nReleased version {new_version}")
    print("\nNext steps:")
    print("1. Review changes to __init__.py and CHANGELOG.md")
    print("2. Git commit and tag:")
    print(f"   git add ari/__init__.py CHANGELOG.md")
    print(f'   git commit -m "Release version {new_version}"')
    print(f'   git tag -a v{new_version} -m "Version {new_version}"')
    print("3. Push to GitHub:")
    print("   git push origin main --tags")


if __name__ == "__main__":
    main()