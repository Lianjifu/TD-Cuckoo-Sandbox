# -*- coding:utf-8 -*-
# Copyright (C) 2010-2015 Cuckoo Foundation.
# This file is part of Cuckoo Sandbox - http://www.cuckoosandbox.org
# This signature was contributed by RedSocks - http://redsocks.nl
# See the file 'docs/LICENSE' for copying permission.

from lib.cuckoo.common.abstracts import Signature

class rat_fexel_ip(Signature):
    name = "rat_fexel_ip"
    #description = "Connects to Fexel Backdoor IP 103.17.117.90" 
    description = u"连接Fexel后门IP：103.17.117.90"
    severity = 2
    ttp = ["T1016.001"]
    categories = ["rat"]
    authors = ["RedSocks"]
    minimum = "2.0"

    ipaddrs = [
        "103.17.117.90",
    ]

    def on_complete(self):
        for indicator in self.ipaddrs:
            if self.check_ip(pattern=indicator):
                self.mark_ioc("ipaddr", indicator)

        return self.has_marks()
