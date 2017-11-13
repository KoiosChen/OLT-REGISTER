from distutils.core import setup

PACKAGE = "telnet_device"
NAME = "telnet_device"
DESCRIPTION = "This package can be used to telnet HUAWEI MA5680T and ME60."
AUTHOR = "Koios Chen"
AUTHOR_EMAIL = "chjz1226@icloud.com"
URL = "https://github.com/KoiosChen/telnet_device"
VERSION = __import__(PACKAGE).__version__

setup(
    name=NAME,
    version=VERSION,
    description=DESCRIPTION,
    # long_description=read("README.md"),
    author=AUTHOR,
    author_email=AUTHOR_EMAIL,
    license="Apache License, Version 2.0",
    url=URL,
    packages=["telnet_device"],
    classifiers=[
        "Development Status :: 3 - Alpha",
        "Environment :: Web Environment",
        "Intended Audience :: Developers",
        "Operating System :: OS Independent",
        "Programming Language :: Python",
    ],
    zip_safe=False,
)
