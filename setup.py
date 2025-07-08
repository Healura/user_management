from setuptools import setup, find_packages

setup(
    name="user-management-service",
    version="1.0.0",
    description="User Management Microservice for Voice Biomarker Healthcare Application",
    author="Your Team",
    packages=find_packages(where="src"),
    package_dir={"": "src"},
    python_requires=">=3.11",
    install_requires=[
        line.strip()
        for line in open("requirements.txt")
        if line.strip() and not line.startswith("#")
    ],
)