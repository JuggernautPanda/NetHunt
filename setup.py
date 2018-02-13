#!/usr/bin/env python3
# -*- coding: utf-8 -*-
#  PwC:(NetHunt™)
#  setup.py
#  
#  Copyright 2018 raja <raja@raja-Inspiron-N5110>
#  
#  This program is free software; you can redistribute it and/or modify
#  it under the terms of the GNU General Public License as published by
#  the Free Software Foundation; either version 2 of the License, or
#  (at your option) any later version.
#  
#  This program is distributed in the hope that it will be useful,
#  but WITHOUT ANY WARRANTY; without even the implied warranty of
#  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
#  GNU General Public License for more details.
#  
#  You should have received a copy of the GNU General Public License
#  along with this program; if not, write to the Free Software
#  Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston,
#  MA 02110-1301, USA.

from setuptools import setup, find_packages
import os

data_files = [(d, [os.path.join(d, f) for f in files])
              for d, folders, files in os.walk(os.path.join('src', 'config'))]

setup(name='PwC:(NetHunt)',
      version='1.0',
      description='PwC:(NetHunt™): A NetFlow v9 parser and collector implemented in Python 3 for PwC. Tested with softflowd v0.9.9 on Ubuntu 16.04 LTS',
      author='G. Raja Sumant',
      author_email='grajasumant@gmail.com',
      packages=find_packages('src'),
      package_dir={'': 'src'},
      license='MIT'
)
