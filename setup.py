from setuptools import setup, find_packages

setup(
    name="jsanalsys",
    version="1.0.0",
    description="JavaScript Security Analyzer for Bug Bounty Hunters",
    author="Security Researcher",
    packages=find_packages(),
    install_requires=[
        "requests>=2.31.0",
        "httpx>=0.27.0",
        "beautifulsoup4>=4.12.0",
        "lxml>=5.1.0",
        "jsbeautifier>=1.15.1",
        "sqlalchemy>=2.0.0",
        "click>=8.1.7",
        "rich>=13.7.0",
        "pydantic>=2.5.0",
        "python-dotenv>=1.0.0",
        "tqdm>=4.66.0",
    ],
    entry_points={
        "console_scripts": [
            "jsanalsys=jsanalsys.cli:main",
        ],
    },
    python_requires=">=3.10",
)
