import setuptools

with open("../README.md", "r", encoding="utf-8") as f:
    long_description = f.read()

setuptools.setup(
    name="watcherlab-ti-client-python",
    version="0.0.2",
    description="Watcherlab threat intelligence client",
    long_description=long_description,
    long_description_content_type="text/markdown",
    url="https://github.com/watcherlab/feed-client-python",
    author="watcherlab",
    author_email="service@watcherlab.com",
    classifiers=[
        "Development Status :: 3 - Alpha",
        "Intended Audience :: Developers",
        "Topic :: Software Development :: Build Tools",
        "License :: OSI Approved :: BSD License",
        "Programming Language :: Python :: 3.6",
        "Programming Language :: Python :: 3.7",
        "Programming Language :: Python :: 3.8",
        "Programming Language :: Python :: 3.9",
        "Programming Language :: Python :: 3.10",
    ],
    keywords="watcherlab threat intelligence feed",
    packages=setuptools.find_packages(),
    python_requires=">=3.6, <3.10",
    platforms="any",
    install_requires=[],
)
