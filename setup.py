from setuptools import setup

setup(
    name='Flask-Firebase',
    version='1.7',
    description='Google Firebase integration for Flask',
    packages=['flask_firebase'],
    include_package_data=True,
    install_requires=[
        'Flask>=0.11',
        'PyJWT>=1.4',
        'cryptography>=1.6',
        'requests>=2.12',
    ])
