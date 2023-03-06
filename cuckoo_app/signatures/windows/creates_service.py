# -*- coding:utf-8 -*-
# Copyright (C) 2015-2018 Cuckoo Foundation.
# This file is part of Cuckoo Sandbox - http://www.cuckoosandbox.org
# See the file 'docs/LICENSE' for copying permission.

from lib.cuckoo.common.abstracts import Signature

class CreatesService(Signature):
    name = "creates_service"
    #description = "Creates a service" 
    description = u"恶意创建一个服务"
    severity = 2
    ttp = ["T1036.004"]
    categories = ["service", "persistence"]
    authors = ["Cuckoo Technologies", "Kevin Ross"]
    minimum = "2.0"

    filter_apinames = [
        "CreateServiceA", "CreateServiceW",
        "StartServiceA", "StartServiceW",
    ]

    def __init__(self, *args, **kwargs):
        Signature.__init__(self, *args, **kwargs)
        self.services = []
        self.startedservices = []

    def on_call(self, call, process):
        service_name = (call["arguments"].get("service_name") or "").lower()
        if call["api"] == "CreateServiceA" or call["api"] == "CreateServiceW":
            self.services.append(service_name)
            self.mark_call()

        elif call["api"] == "StartServiceA" or call["api"] == "StartServiceW":
            self.startedservices.append(service_name)

    def on_complete(self):
        for service in self.services:
            if service not in self.startedservices:
                # self.description = "Created a service where a service was also not started"
                self.description = u"创建了未启动服务的服务"
                self.severity = 3

        return self.has_marks()
