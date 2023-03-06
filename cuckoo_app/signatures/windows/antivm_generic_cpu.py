# -*- coding:utf-8 -*-
# Copyright (C) 2015 Optiv, Inc. (brad.spengler@optiv.com), Updated 2016 for Cuckoo 2.0
#
# This program is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program.  If not, see <http://www.gnu.org/licenses/>.

from lib.cuckoo.common.abstracts import Signature

class AntiVMCPU(Signature):
    name = "antivm_generic_cpu"
    #description = "Checks the CPU name from registry, possibly for anti-virtualization"
    description = u"利用注册表检测CPU名称，可能用于反虚拟化"
    severity = 3
    ttp = ["T1497"]
    categories = ["anti-vm"]
    authors = ["Optiv"]
    minimum = "2.0"

    regkeys_re = [
        ".*\\\\HARDWARE\\\\#description\\\\System\\\\CentralProcessor\\\\.*\\\\ProcessorNameString",
    ]

    def on_complete(self):
        for indicator in self.regkeys_re:
            for regkey in self.check_key(pattern=indicator, regex=True, all=True):
                self.mark_ioc("registry", regkey)

        return self.has_marks()
