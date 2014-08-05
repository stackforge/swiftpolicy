#!/usr/bin/python
# This software is released under the MIT License.
#
# Copyright (c) 2014 Cloudwatt
#
# Permission is hereby granted, free of charge, to any person obtaining a copy
# of this software and associated documentation files (the "Software"),
# to deal in the Software without restriction, including without limitation
# the rights to use, copy, modify, merge, publish, distribute, sublicense,
# and/or sell copies of the Software, and to permit persons to whom the
# Software is furnished to do so, subject to the following conditions:
#
# The above copyright notice and this permission notice shall be included
# in all copies or substantial portions of the Software.
#
# THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
# IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
# FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
# AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
# LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING
# FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER
# DEALINGS IN THE SOFTWARE.

from setuptools import setup

import swiftpolicy


setup(name='swiftpolicy',
      version=swiftpolicy.version,
      description='Swift authentication/authorization middleware for keystone that uses "policy" file format.',
      author='CloudWatt',
      author_email='ala.rezmerita@cloudwatt.com',
      url='https://github.com/cloudwatt/swiftpolicy',
      packages=['swiftpolicy', 'swiftpolicy.openstack', 'swiftpolicy.openstack.common'],
      test_suite='tests',
      data_files=[('/etc/swift', ['policies/default.json']),],
      entry_points={'paste.filter_factory':
                    ['swiftpolicy=swiftpolicy.swiftpolicy:filter_factory']})
