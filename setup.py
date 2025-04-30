# setup.py

from setuptools import setup, find_packages

setup(
    name="NovaSentinel",
    version="0.1.0",
    description="Ton projet NovaSentinel",
    author="Ton Nom",
    packages=find_packages(),        # va automatiquement inclure script et tous ses sous-packages
    install_requires=[
        "python-dotenv",            # si tu utilises python-dotenv
    ],
    include_package_data=True,       # si tu as des fichiers non-Python à embarquer
    python_requires=">=3.6",         # ou la version minimale que tu souhaites
)
