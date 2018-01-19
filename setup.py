import os
import re
import sys
import subprocess
from setuptools import setup, find_packages
from setuptools.command.build_ext import build_ext


class CMakeBuild(build_ext):

    def run(self):
        lib = "./lib/ed25519"
        cmake_args = [
            '.',
            "-DHASH=sha3_brainhub",
            "-DRANDOM=dev_urandom",
            "-DBUILD=SHARED",
            "-DTESTING=OFF"
        ]

        subprocess.check_call(['cmake', "."] + cmake_args, cwd=lib)
        subprocess.check_call(['make', '-j'], cwd=lib)

        build_ext.run(self)

setup(
    name='ed25519-python',
    version='0.0.1',
    author='Sonoko Mizuki',
    author_email='sonoko@mizuki.io',
    description='Python binding for ed25519',
    packages = find_packages(),
    cmdclass=dict(build_ext=CMakeBuild),
    zip_safe=False,
)
