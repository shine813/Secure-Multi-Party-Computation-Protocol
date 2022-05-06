#!/usr/bin/env python
# -*- coding:utf-8 -*-
"""
@Version: 0.0.1
@Project: Secure-Multi-Party-Computation-Protocol
@Author: Zhan Shi
@Time  : 2022/5/6 11:43
@File: setup.py
@License: MIT
"""

import setuptools

with open("README.md", "r", encoding='utf-8') as fh:
    long_description = fh.read()

setuptools.setup(
    name="smpcp",
    version="0.0.1",
    author="Zhan Shi",
    author_email="phe.zshi@gmail.com",
    description="Secure Multi-Party Computation Protocol base on Partially Homomorphic Encryption for Python",
    long_description=long_description,
    long_description_content_type="text/markdown",
    url="https://github.com/shine813/Secure-Multi-Party-Computation-Protocol",
    packages=setuptools.find_packages(),
    classifiers=[
        "Programming Language :: Python :: 3",
        "License :: OSI Approved :: MIT License",
        "Operating System :: OS Independent",
    ],
)
