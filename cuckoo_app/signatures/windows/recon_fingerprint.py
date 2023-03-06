# -*- coding:utf-8 -*-
# Copyright (C) 2012 Claudio "nex" Guarnieri (@botherder)
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

class Fingerprint(Signature):
    name = "recon_fingerprint"
    #description = "Collects information to fingerprint the system (MachineGuid, DigitalProductId, SystemBiosDate)"
    description = u"恶意收集信息，对系统进行指纹识别（ID、数码信息、系统时钟）"
    severity = 1
    ttp = ["T1005"]
    categories = ["recon"]
    authors = ["nex"]
    minimum = "2.0"

    indicators = [
        ".*\\\\MachineGuid$",
        ".*\\\\DigitalProductId$",
        ".*\\\\SystemBiosDate$",
        ".*Windows\\ NT\\\\CurrentVersion\\\\InstallDate$",
    ]

    def on_complete(self):
        for indicator in self.indicators:
            for regkey in self.check_key(pattern=indicator, regex=True, all=True):
                self.mark_ioc("registry", regkey)

        return self.has_marks()
