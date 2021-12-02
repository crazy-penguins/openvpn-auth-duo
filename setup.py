# -*- coding: utf-8 -*-
import os
import setuptools  # type: ignore

from openvpn_auth_duo._version import __version__

here = os.path.abspath(os.path.dirname(__file__))

# Get the long description from the README file
with open(os.path.join(here, "README.md"), encoding="utf-8") as f:
    long_description = f.read()

setuptools.setup(
    name="openvpn-auth-duo",
    version=__version__,
    entry_points={
        'console_scripts': [
            'openvpn-auth-duo = openvpn_auth_duo.cli:main',
        ],
    },
    license="MIT",
    author="crazy penguins",
    author_email="pshingavi@gmail.com,",
    description="openvpn-auth-duo connects to the openvpn management interface and handle the authentication "
    "against duo.",
    long_description=long_description,
    long_description_content_type="text/markdown",
    url="https://github.com/crazy-penguins/openvpn-auth-azure-ad",
    download_url="https://github.com/crazy-penguins/openvpn-auth-azure-ad/archive/v%s.tar.gz"
    % __version__,
    packages=setuptools.find_packages(),
    keywords=["OpenVPN", "AzureAD", "authentication", 'duo'],
    classifiers=[
        "Programming Language :: Python :: 3",
        "License :: OSI Approved :: MIT License",
        "Operating System :: OS Independent",
        "Development Status :: 5 - Production/Stable",
        "Environment :: Console",
        "Topic :: System :: Systems Administration :: Authentication/Directory",
    ],
    install_requires=[
        'msal~=1.4',
        'cacheout~=0.11',
        'ConfigArgParse~=1.2',
        'prometheus_client~=0.8',
        'concurrent-log-handler~=0.9',
        'duo-client',
    ],
    project_urls={
        "Changelog": "https://github.com/crazy-penguins/openvpn-auth-azure-ad/blob/v%s/CHANGELOG.md"
        % __version__,
        "Source": "https://github.com/crazy-penguins/openvpn-auth-azure-ad",
        "Bug Reports": "https://github.com/crazy-penguins/openvpn-auth-azure-ad/issues",
    },
)
