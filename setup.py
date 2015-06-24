#!/usr/bin/env python

from distutils.core import setup

setup(name='isafw',
      version='0.1',
      description='Image Security analyser Framework',
      author='Elena Reshetova',
      author_email='elena.reshetova@intel.com',
      url='https://www.python.org/sigs/distutils-sig/',
      packages=['isafw', 'isaplugins'],
      package_dir={'isaplugins': 'isafw/isaplugins'},
      package_data={'isaplugins': ['configs/la/*']},
     )
