# -*- coding:utf-8 -*-
# Copyright (C) 2016 Brad Spengler
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

class XenDetectKeys(Signature):
    name = "antivm_xen_keys"
    #description = "Detects Xen through the presence of a registry key"
    description = u"利用注册表项的存在检测Xen"
    severity = 3
    ttp = ["T1497"]
    categories = ["anti-vm"]
    authors = ["Brad Spengler"]
    minimum = "2.0"

    regkeys_re = [
        ".*\\\\SYSTEM\\\\(CurrentControlSet|ControlSet001)\\\\Enum\\\\ACPI\\\\XEN0000.*",
        ".*\\\\SYSTEM\\\\(CurrentControlSet|ControlSet001)\\\\Enum\\\\XEN.*",
        ".*\\\\HARDWARE\\\\ACPI\\\\(DSDT|FADT|RSDT)\\\\Xen.*",
    ]

    def on_complete(self):
        for indicator in self.regkeys_re:
            for regkey in self.check_key(pattern=indicator, regex=True, all=True):
                self.mark_ioc("registry", regkey)

        return self.has_marks()