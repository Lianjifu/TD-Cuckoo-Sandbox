# -*- coding:utf-8 -*-
# Copyright (C) 2016 Justaguy @ Cybersprint B.V.
# This file is part of Cuckoo Sandbox - http://www.cuckoosandbox.org
# See the file 'docs/LICENSE' for copying permission.

import re

from lib.cuckoo.common.abstracts import Signature

class KovterBot(Signature):
    name = "bot_kovter"
    #description = "Performs HTTP requests like Kovter"
    description = u"恶意执行http请求（Kovter）"
    severity = 3
    ttp = ["T1204.001"]
    categories = ["http"]
    authors = ["Cybersprint"]
    minimum = "2.0"
    families = ["kovter"]

    def on_complete(self):
        for http in getattr(self, "get_net_http_ex", lambda: [])():
            if re.match("/counter/\\?id=", http["uri"]):
                self.mark_ioc("request", "%s %s://%s%s" % (
                    http["method"], http["protocol"], http["host"], http["uri"],
                ))

        return self.has_marks()
