import setuptools

with open("README.md", "r") as fh:
    long_description = fh.read()

setuptools.setup(
    name="python-tss-sdk",
    version="0.0.5",
    author="Adam Migus",
    author_email="adam@migus.org",
    description="The Thycotic Secret Server Python SDK",
    long_description=long_description,
    long_description_content_type="text/markdown",
    url="https://github.com/thycotic/python-tss-sdk",
    install_requires=["requests>=2.12.5"],
    packages=setuptools.find_packages(),
    classifiers=[
        "License :: OSI Approved :: Apache Software License",
        "Operating System :: OS Independent",
        "Programming Language :: Python :: 3",
    ],
    python_requires=">=3.6",
)
