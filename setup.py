"""Install packages as defined in this file into the Python environment."""
import imp
import os
from setuptools import setup

here = os.path.abspath(os.path.dirname(__file__))
version_mod = imp.load_source('__tmp', os.path.join(here, 'authsignal/version.py'))

setup(
    name="authsignal",
    author="Authsignal",
    author_email="support@authsignal.com",
    url="https://www.authsignal.com",
    description="The Authsignal python server side signal SDK.",
    version=version_mod,
    packages=["authsignal"],
    install_requires=[
        "setuptools>=45.0",
        "requests>=2.28.1",
    ],
    classifiers=[
        "Programming Language :: Python :: 3.0",
        "Topic :: Utilities",
        "Intended Audience :: Developers",
        "License :: OSI Approved :: MIT License",
        "Topic :: Software Development :: Libraries :: Python Modules"
    ],
)