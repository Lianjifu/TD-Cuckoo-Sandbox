# -*- coding:utf-8 -*-
# Copyright (C) 2010-2015 Cuckoo Sandbox Developers.
# This file is part of Cuckoo Sandbox - http://www.cuckoosandbox.org
# See the file 'docs/LICENSE' for copying permission.

import re

from lib.cuckoo.common.abstracts import Signature

class HasWMI(Signature):
    name = "has_wmi"
    #description = "Executes one or more WMI queries"
    description = u"执行了一个或者多个WMI查询命令"
    severity = 2
    ttp = ["T1047"]
    categories = ["wmi"]
    authors = ["Cuckoo Technologies"]
    minimum = "2.0"

    blacklist = "(AntivirusProduct|FirewallProduct)"

    def on_complete(self):
        for query in self.get_wmi_queries():
            self.mark_ioc("wmi", query)

            if re.search(self.blacklist, query, re.I):
                self.severity = 3

        return self.has_marks()

class Win32ProcessCreate(Signature):
    ttp = ["T1047"]
    name = "win32_process_create"
    #description = "Uses WMI to create a new process"
    description = u"使用 WMI 创建新进程"
    severity = 4
    categories = ["wmi"]
    authors = ["Cuckoo Technologies"]
    minimum = "2.0"

    filter_apinames = [
        "IWbemServices_ExecMethod",
        "IWbemServices_ExecMethodAsync",
    ]

    def on_call(self, call, process):
        if call["arguments"]["class"] == "Win32_Process" and \
                call["arguments"]["method"] == "Create":
            self.mark_call()
            return True


class WMIAntiVM(Signature):
    name = "wmi_antivm"
    #description = "Executes one or more WMI queries which can be used to identify virtual machines"
    description = u"执行一个或多个可用于标识虚拟机的 WMI 查询"
    severity = 2
    categories = ["wmi", "anti-vm"]
    authors = ["Kevin Ross"]
    minimum = "2.0"
    ttp = ["T1497"]
    antivm = [
        "win32_processor",
        "win32_logicaldisk",
        "win32_bios",
        "win32_computersystem",
        "win32_physicalmemory",
        "deviceid",
        "win32_networkadapterconfiguration",
        "win32_nteventlogfile",
    ]

    def on_complete(self):
        for command in self.antivm:
            for query in self.get_wmi_queries():
                if command in query.lower():
                    self.mark_ioc("wmi", query)

        return self.has_marks()


class WMIPersistance(Signature):
    name = "wmi_persistance"
    #description = "Executes one or more WMI queries which can be used for persistance"
    description = u"执行一个或多个可用于持久性的 WMI 查询"
    severity = 3
    categories = ["persistance"]
    authors = ["Kevin Ross"]
    minimum = "2.0"
    ttp = ["T1047"]
    persistance = [
        "win32_startupcommand",
    ]

    def on_complete(self):
        for command in self.persistance:
            for query in self.get_wmi_queries():
                if command in query.lower():
                    self.mark_ioc("wmi", query)


        return self.has_marks()

class WMIService(Signature):
    name = "wmi_service"
    #description = "Executes one or more WMI queries which can be used to create or modify services"
    description = u"执行一个或多个可用于创建或修改服务的 WMI 查询"
    severity = 3
    categories = ["persistance"]
    authors = ["Kevin Ross"]
    minimum = "2.0"
    ttp = ["T1047"]

    persistance = [
        "win32_service",
    ]

    def on_complete(self):
        for command in self.persistance:
            for query in self.get_wmi_queries():
                if command in query.lower():
                    self.mark_ioc("wmi", query)

        return self.has_marks()
