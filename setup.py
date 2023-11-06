from setuptools import setup, find_packages

setup(
    name="Pyne",
    version="2.0.0",
    description="Nessus Parser",
    author="Oliver Scotten",
    author_email="oliver@hopliteconsulting.com",
    packages=find_packages(),
    install_requires=[
        "alive_progress==3.1.4",
        "pyfiglet==1.0.2"
    ],
    entry_points={
        "console_scripts": [
            "pyne = pyne.pyne:setup",
        ],
    },
    package_data={"pyne": ["config/*"]}
)
