# -*- coding:utf-8 -*-
# Copyright (C) 2010-2015 Cuckoo Foundation.
# This file is part of Cuckoo Sandbox - http://www.cuckoosandbox.org
# This signature was contributed by RedSocks - http://redsocks.nl
# See the file 'docs/LICENSE' for copying permission.

from lib.cuckoo.common.abstracts import Signature

class CloudFlare(Signature):
    name = "Cloudflare"
    #description = "Checks for Cloudflare connection"
    description = u"检测Cloudflare连接"
    severity = 2
    ttp = ["T1526"]
    categories = ["Cloudflare"]
    authors = ["RedSocks"]
    minimum = "2.0"

    domains = [
        "cloudflare.com",
    ]

    def on_complete(self):
        for indicator in self.domains:
            if self.check_domain(pattern=indicator):
                self.mark_ioc("domain", indicator)
                return True
