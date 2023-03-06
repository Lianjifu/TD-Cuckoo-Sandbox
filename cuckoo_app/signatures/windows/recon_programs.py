# -*- coding:utf-8 -*-
# Copyright (C) 2014 Optiv, Inc. (brad.spengler@optiv.com), Updated 2016 for cuckoo 2.0
# This file is part of Cuckoo Sandbox - http://www.cuckoosandbox.org
# See the file 'docs/LICENSE' for copying permission.

from lib.cuckoo.common.abstracts import Signature

class InstalledApps(Signature):
    name = "recon_programs"
    #description = "Collects information about installed applications"
    description = u"收集已安装应用程序信息"
    severity = 3
    ttp = ["T1005"]
    categories = ["recon"]
    authors = ["Optiv"]
    minimum = "2.0"

    filter_apinames = "RegQueryValueExA", "RegQueryValueExW"

    def on_call(self, call, process):
        keyname = call["arguments"]["regkey"]
        uninstall = "\\microsoft\\windows\\currentversion\\uninstall"
        if (keyname and uninstall in keyname.lower() and keyname.lower().endswith("displayname")):
            app = call["arguments"]["value"]
            if app:
                self.mark_call()

    def on_complete(self):
        return self.has_marks()

class QueriesInstalledApps(Signature):
    name = "queries_programs"
    #description = "Queries for potentially installed applications"
    description = u"查询可能已安装的应用进程"
    ttp = ["T1057"]
    severity = 2
    categories = ["recon"]
    authors = ["Kevin Ross"]
    minimum = "2.0"

    filter_apinames = "RegOpenKeyExA", "RegOpenKeyExW"

    def on_call(self, call, process):
        keyname = call["arguments"]["regkey"]
        uninstall = "\\microsoft\\windows\\currentversion\\uninstall"
        if (keyname and uninstall in keyname.lower()):
            self.mark_call()

    def on_complete(self):
        return self.has_marks()
