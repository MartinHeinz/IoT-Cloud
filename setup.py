# -*- coding: utf-8 -*-

from setuptools import setup, find_packages


with open('README.md') as f:
    readme = f.read()

with open('LICENSE') as f:
    license = f.read()

setup(
    name='iot-cloud-cli',
    version='0.1.0',
    description='Privacy friendly framework for IoT Cloud',
    long_description=readme,
    author='Martin Heinz',
    author_email='martin7.heinz@gmail.com',
    url='',
    license=license,
    packages=find_packages(include=('client', 'client.user', 'client.device')),
    include_package_data=True,
    install_requires=[
        'Click',
        'requests',
        'cryptography',
        'tinydb',
        'paho-mqtt',
        'passlib',
        'scipy'
    ],
    entry_points='''
        [console_scripts]
        iot-cloud-cli=client.cli:cli
    ''',
)
