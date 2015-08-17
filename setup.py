#!/usr/bin/env python

from distutils.core import setup

setup(name='isafw',
      version='0.1',
      description='ISA FW',
      author='Elena Reshetova',
      author_email='elena.reshetova@intel.com',
      url='http://github.com/otcshare/isafw',
      packages=['isafw', 'isaplugins'],
      package_dir={'isaplugins': 'isafw/isaplugins'},
      package_data={'isaplugins': ['configs/la/*']},
     )
