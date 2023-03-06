# -*- coding:utf-8 -*-
# Copyright (C) 2010-2015 Cuckoo Foundation.
# This file is part of Cuckoo Sandbox - http://www.cuckoosandbox.org
# This signature was contributed by RedSocks - http://redsocks.nl
# See the file 'docs/LICENSE' for copying permission.

from lib.cuckoo.common.abstracts import Signature

class UrkShortCN(Signature):
    name = "urlshortcn_checkip"
    #description = "Connects to Chinese URL Shortener, Possibly Malicious"
    description = u"连接中文网址索引可能存在恶意"
    severity = 2
    ttp = ["T1071.001"]
    categories = ["urlshort"]
    authors = ["RedSocks"]
    minimum = "2.0"

    domains = [
        "985.so",
    ]

    def on_complete(self):
        for indicator in self.domains:
            if self.check_domain(pattern=indicator):
                self.mark_ioc("domain", indicator)

        return self.has_marks()
