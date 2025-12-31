from setuptools import setup, find_packages

with open("README.md", "r", encoding="utf-8") as fh:
    long_description = fh.read()

setup(
    name='aphids-cli',
    version='1.2.3',
    author='Evan Magrann',
    author_email='admin@darksidesecurity.io',
    packages=find_packages()+['.'],
    include_package_data=True,
    python_requires='>=2.7',
    description='Aphids Interface for executing penetration testing tools.',
    long_description=long_description,
    long_description_content_type="text/markdown",
    url='https://www.github.com/darksidesecurity/aphids',
    project_urls = {
        "Bug Tracker": "https://www.github.com/darksidesecurity/aphids/issues"
    },
    license='GPL-3.0-or-later',
    install_requires=['requests', 'pyyaml'],
    keywords='pentest recon security appsec',
    entry_points={
        'console_scripts': [
            'aphids-cli=aphids:cli',
        ],
    },
)