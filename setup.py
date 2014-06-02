#!/usr/bin/python
# Copyright 2014 OpenStack, LLC.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#    http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

from setuptools import setup

import swiftpolicy


setup(name='swiftpolicy',
      version=swiftpolicy.version,
      description='Swift Policy Middleware',
      author='CloudWatt',
      author_email='nassim.babaci@cloudwatt.com',
      url='https://git.corp.cloudwatt.com/nassim.babaci/swiftpolicy',
      packages=['swiftpolicy', 'swiftpolicy.openstack', 'swiftpolicy.openstack.common'],
      requires=['swift(>=1.7)'],
      test_suite='tests',
      entry_points={'paste.filter_factory':
                    ['swiftpolicy=swiftpolicy.swiftpolicy:filter_factory']})
