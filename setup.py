"""Azure Cost Optimizer - Setup configuration."""

from setuptools import setup, find_packages

with open("README.md", "r", encoding="utf-8") as f:
    long_description = f.read()

setup(
    name="azure-cost-optimizer",
    version="1.0.0",
    author="Akshaykumar Glasswala",
    author_email="akshaykumar@glasswala.com",
    description="Scan Azure subscriptions for cost savings, compliance gaps, and security anomalies",
    long_description=long_description,
    long_description_content_type="text/markdown",
    url="https://github.com/AkshaykumarGlasswala/azure-cost-optimizer",
    packages=find_packages(),
    python_requires=">=3.10",
    install_requires=[
        "azure-identity>=1.15.0",
        "azure-mgmt-compute>=30.0.0",
        "azure-mgmt-network>=25.0.0",
        "azure-mgmt-monitor>=6.0.0",
        "azure-mgmt-resource>=23.0.0",
        "azure-mgmt-policyinsights>=1.0.0",
        "azure-monitor-query>=1.2.0",
    ],
    extras_require={
        "web": ["flask>=3.0.0", "stripe>=8.0.0"],
        "dev": ["pytest>=8.0.0", "ruff>=0.3.0"],
    },
    entry_points={
        "console_scripts": [
            "azure-cost-optimizer=analyzer.cli:main",
        ],
    },
    classifiers=[
        "Development Status :: 4 - Beta",
        "Intended Audience :: System Administrators",
        "Intended Audience :: Developers",
        "License :: OSI Approved :: MIT License",
        "Programming Language :: Python :: 3",
        "Programming Language :: Python :: 3.10",
        "Programming Language :: Python :: 3.11",
        "Programming Language :: Python :: 3.12",
        "Topic :: System :: Systems Administration",
        "Topic :: Office/Business :: Financial",
    ],
    keywords="azure cost optimization cloud savings vm idle resources compliance security",
)
