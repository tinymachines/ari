from setuptools import setup, find_packages

with open("README.md", "r", encoding="utf-8") as fh:
    long_description = fh.read()

setup(
    name="ari",
    version="0.1.0",
    author="ARI Team",
    author_email="maintainer@example.com",
    description="AWS Resource Inventory and Service Mapper",
    long_description=long_description,
    long_description_content_type="text/markdown",
    url="https://github.com/yourusername/ari",
    packages=find_packages(include=['ari', 'scripts']),
    classifiers=[
        "Programming Language :: Python :: 3",
        "Programming Language :: Python :: 3.6",
        "Programming Language :: Python :: 3.7",
        "Programming Language :: Python :: 3.8",
        "Programming Language :: Python :: 3.9",
        "License :: OSI Approved :: MIT License",
        "Operating System :: OS Independent",
        "Development Status :: 3 - Alpha",
        "Topic :: System :: Systems Administration",
        "Topic :: Utilities",
    ],
    python_requires=">=3.6",
    install_requires=[
        "boto3>=1.17.0",
    ],
    extras_require={
        "dotenv": ["python-dotenv>=0.19.0"],
        "dev": [
            "pylint>=2.8.0",
            "mypy>=0.812",
            "build>=0.7.0",
            "twine>=3.4.1",
            "pytest>=6.2.5",
            "pytest-cov>=2.12.1",
            "black>=21.5b2",
        ],
    },
    entry_points={
        "console_scripts": [
            "ari=ari.cli:main",
            "ari-run=scripts.ari_run:main",
        ],
    },
    scripts=[
        "scripts/ari_wrapper.sh",
    ],
    include_package_data=True,
)