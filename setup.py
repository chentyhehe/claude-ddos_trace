from __future__ import absolute_import

import sys

from setuptools import find_packages, setup


PY36 = sys.version_info < (3, 7)


def build_install_requires():
    if PY36:
        return [
            "dataclasses>=0.8",
            "pandas>=1.1.5,<1.2",
            "numpy>=1.19.5,<1.20",
            "matplotlib>=3.3.4,<3.4",
            "scikit-learn>=0.24.2,<1.0",
            "clickhouse-driver>=0.2.5,<0.2.6",
            "pymysql>=0.9.3,<1.1",
            "fastapi>=0.63.0,<0.79",
            "uvicorn>=0.16.0,<0.17",
            "pyyaml>=5.4.1,<6.0.1",
        ]
    return [
        "pandas>=1.5.0",
        "numpy>=1.23.0",
        "matplotlib>=3.6.0",
        "scikit-learn>=1.2.0",
        "clickhouse-driver>=0.2.5",
        "pymysql>=1.1.0",
        "fastapi>=0.100.0",
        "uvicorn>=0.23.0",
        "pyyaml>=6.0",
    ]


def build_extras_require():
    if PY36:
        return {
            "hdbscan": ["hdbscan>=0.8.27,<0.8.29"],
            "dev": [
                "pytest>=6.2.5,<7.0",
                "pytest-cov>=2.12,<4.0",
            ],
        }
    return {
        "hdbscan": ["hdbscan>=0.8.29"],
        "dev": [
            "pytest>=7.0",
            "pytest-cov>=4.0",
        ],
    }


setup(
    name="ddos-trace",
    version="1.0.0",
    description="DDoS attack traceback analyzer based on NetFlow data",
    python_requires=">=3.6",
    package_dir={"": "src"},
    packages=find_packages(where="src"),
    install_requires=build_install_requires(),
    extras_require=build_extras_require(),
    entry_points={
        "console_scripts": [
            "ddos-trace=ddos_trace.__main__:main",
        ],
    },
    include_package_data=True,
    zip_safe=False,
)
