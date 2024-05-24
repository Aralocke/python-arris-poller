#!/usr/bin/env python3

# Copyright 2020-2024 Daniel Weiner
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

import functools
from os.path import dirname, exists, join, realpath
import os
import sys


rootPath = realpath(join(__file__, os.pardir))
parentPath = dirname(rootPath)

if exists(join(parentPath, 'PyMonitorLib')):
    sys.path.insert(0, join(parentPath, 'PyMonitorLib'))

if exists(join(rootPath, 'commands')):
    sys.path.insert(0, rootPath)

from commands import Poller
from monitor.lib import Execute


if __name__ == '__main__':
    poller = Poller()
    Execute(functools.partial(Poller.Poll, poller),
            'devices',
            command='run')
