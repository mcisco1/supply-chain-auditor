from setuptools import setup, find_packages

setup(
    name="supply-chain-auditor",
    version="1.0.0",
    description="Scans Python and Node.js codebases for dependency vulnerabilities using NVD, OSV, and GitHub Advisory databases.",
    author="Matthew",
    packages=find_packages(),
    python_requires=">=3.9",
    install_requires=[
        "requests>=2.31.0",
        "rich>=13.7.0",
        "packaging>=23.2",
        "toml>=0.10.2",
    ],
    entry_points={
        "console_scripts": [
            "sca-scan=scan:main",
        ],
    },
    include_package_data=True,
    package_data={"": ["templates/*.html"]},
    classifiers=[
        "Programming Language :: Python :: 3",
        "Topic :: Security",
        "Topic :: Software Development :: Quality Assurance",
    ],
)
