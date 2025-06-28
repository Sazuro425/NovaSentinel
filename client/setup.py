# setup.py

from setuptools import setup, find_packages

setup(
    name="NovaSentinel",
    version="0.1.0",
    description="Scan networks and devices for vulnerabilities",
    author="Oliveira Evan",
    packages=find_packages(),
    install_requires=[
        "python-dotenv",
        "dnspython",
        "scapy",
        "netifaces",
        "websockets",
        "asyncio",
        "python-nmap",
        "requests",
        "fpdf"       
    ],
    include_package_data=True,       
    python_requires=">=3.6",         
)
