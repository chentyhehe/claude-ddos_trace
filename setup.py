import os
from setuptools import find_packages, setup


def read_requirements(filename):
    """Read requirements.txt, skip comments and blank lines, keep environment markers."""
    filepath = os.path.join(os.path.dirname(__file__), filename)
    reqs = []
    with open(filepath, encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if line and not line.startswith("#"):
                reqs.append(line)
    return reqs


setup(
    name="ddos-trace",
    version="1.0.0",
    description="DDoS attack traceback analyzer based on NetFlow data",
    python_requires=">=3.6",
    package_dir={"": "src"},
    packages=find_packages(where="src"),
    install_requires=read_requirements("docs/deploy/requirements.txt"),
    extras_require={
        "hdbscan": ["hdbscan>=0.8.27,<0.8.29"],
        "dev": [
            "pytest>=6.2.5,<7.0",
            "pytest-cov>=2.12,<4.0",
        ],
    },
    entry_points={
        "console_scripts": [
            "ddos-trace=ddos_trace.__main__:main",
        ],
    },
    include_package_data=True,
    zip_safe=False,
)
