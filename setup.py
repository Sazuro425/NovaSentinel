# setup.py

from setuptools import setup, find_packages

setup(
    name="NovaSentinel",
    version="0.1.0",
    description="Ton projet NovaSentinel",
    author="Ton Nom",
    packages=find_packages(),
    install_requires=[
        "python-dotenv",      
    ],
    include_package_data=True,       
    python_requires=">=3.6",         
)
