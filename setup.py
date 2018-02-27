import os
import re
from glob import glob
import sys
import platform
import shutil
import subprocess
from distutils.version import LooseVersion
from setuptools import setup, find_packages, Extension
from setuptools.command.build_ext import build_ext


#python setup.py bdist_wheel
#twine upload dist/*.whl
#python setup.py sdist upload

# Cited by https://github.com/pybind/cmake_example/blob/master/setup.py

class CMakeExtension(Extension):
    def __init__(self, name, sourcedir=''):
        Extension.__init__(self, name, sources=[])
        self.sourcedir = os.path.abspath(sourcedir)


class CMakeBuild(build_ext):
    def run(self):
        try:
            out = subprocess.check_output(['cmake', '--version'])
        except OSError:
            raise RuntimeError("CMake must be installed to build the following extensions: " +
                               ", ".join(e.name for e in self.extensions))

        cmake_version = LooseVersion(re.search(r'version\s*([\d.]+)', out.decode()).group(1))
        if cmake_version < '3.0.0':
            raise RuntimeError("CMake >= 3.0.0 is required")

        for ext in self.extensions:
            self.build_extension(ext)

    def build_extension(self, ext):
        # Git submodule
        shutil.rmtree('lib/ed25519')
        subprocess.check_call(['git','clone','https://github.com/Warchant/ed25519.git','lib/ed25519'])

        extdir = os.path.abspath(os.path.dirname(self.get_ext_fullpath(ext.name)))
        cmake_args = ["-DCMAKE_LIBRARY_OUTPUT_DIRECTORY=" + extdir,
                      "-DHASH=sha3_brainhub",
                      "-DRANDOM=dev_urandom",
                      "-DBUILD=SHARED",
                      "-DTESTING=OFF"]

        build_args = []

        env = os.environ.copy()
        env['CXXFLAGS'] = '{} -DVERSION_INFO=\\"{}\\"'.format(env.get('CXXFLAGS', ''),
                                                              self.distribution.get_version())
        if not os.path.exists(self.build_temp):
            os.makedirs(self.build_temp)
        subprocess.check_call(['cmake', ext.sourcedir] + cmake_args, cwd=self.build_temp, env=env)
        subprocess.check_call(['cmake', '--build', '.'] + build_args, cwd=self.build_temp)
        subprocess.check_call(['cmake', '--build', '.'] + build_args, cwd=self.build_temp)

        # Move shared library to code's directory
        for f in glob('{}/libed25519*'.format(extdir)):
            shutil.copy(f, '{}/ed25519_python/'.format(extdir))

setup(
    name="ed25519-python",
    version="1.0.0",
    author="Sonoko Mizuki",
    author_email="sonoko@mizuki.io",
    ext_modules=[CMakeExtension("ed25519-python","lib/ed25519")],
    description="Python binding for ed25519",
    packages = find_packages(),
    cmdclass=dict(build_ext=CMakeBuild),
    zip_safe=False,
)

