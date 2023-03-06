# -*- coding:utf-8 -*-
# Copyright (C) 2014 Optiv, Inc. (brad.spengler@optiv.com)
# Copyright (C) 2018 Cuckoo Foundation.
# This file is part of Cuckoo Sandbox - http://www.cuckoosandbox.org
# See the file 'docs/LICENSE' for copying permission.

from lib.cuckoo.common.abstracts import Signature

class ReadsUserAgent(Signature):
    name = "reads_user_agent"
    #description = "Reads the systems User Agent and subsequently performs requests"
    description = u"恶意读取用户代理并执行请求"
    authors = ["Cuckoo Technologies"]
    ttp = ["T1090"]
    severity = 2
    categories = ["stealth"]
    minimum = "2.0"

    filter_apinames = "ObtainUserAgentString", "InternetOpenA", "InternetOpenW"

    def __init__(self, *args, **kwargs):
        Signature.__init__(self, *args, **kwargs)
        self.queried_user_agent = False

    def on_call(self, call, process):
        api = call["api"]
        agent = call["arguments"]["user_agent"]
        if api == "ObtainUserAgentString":
            self.queried_user_agent = True
        elif self.queried_user_agent :
            self.mark_call()
            return True
