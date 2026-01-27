#!/usr/bin/env python3
"""Setup script for solodit-auditor package."""

from setuptools import setup, find_packages
from pathlib import Path

readme = Path(__file__).parent / "README.md"
long_description = readme.read_text() if readme.exists() else ""

setup(
    name="solodit-auditor",
    version="1.0.0",
    author="Security Auditor",
    description="Smart Contract Security Auditor powered by Cyfrin Solodit API",
    long_description=long_description,
    long_description_content_type="text/markdown",
    url="https://github.com/your-repo/solodit-auditor",
    packages=find_packages(),
    python_requires=">=3.8",
    install_requires=[
        "requests>=2.28.0",
    ],
    entry_points={
        "console_scripts": [
            "solodit-auditor=solodit_auditor.cli:main",
        ],
    },
    classifiers=[
        "Development Status :: 4 - Beta",
        "Intended Audience :: Developers",
        "Topic :: Security",
        "Topic :: Software Development :: Testing",
        "License :: OSI Approved :: MIT License",
        "Programming Language :: Python :: 3",
        "Programming Language :: Python :: 3.8",
        "Programming Language :: Python :: 3.9",
        "Programming Language :: Python :: 3.10",
        "Programming Language :: Python :: 3.11",
        "Programming Language :: Python :: 3.12",
    ],
    keywords="solidity, smart-contract, security, audit, ethereum, blockchain, web3",
)
