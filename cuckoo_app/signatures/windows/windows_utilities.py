# -*- coding:utf-8 -*-
# Copyright (C) 2010-2015 Cuckoo Foundation.
# This file is part of Cuckoo Sandbox - http://www.cuckoosandbox.org
# See the file 'docs/LICENSE' for copying permission.

from lib.cuckoo.common.abstracts import Signature

utilities = [
    "at ",
    "at.exe",
    "attrib",
    "chcp",
    "del ",
    "del.exe",
    "dir ",
    "dir.exe",
    "driverquery",
    "erase ",
    "erase.exe",
    "fsutil",
    "getmac",
    "ipconfig",
    "nbtstat",
    "net ",
    "net.exe",
    "netsh",
    "netstat",
    "nslookup",
    "pathping",
    "ping ",
    "ping.exe",
    "qwinsta",
    "reg ",
    "reg.exe",
    "regsrv32",
    "route",
    "runas",
    "rwinsta",
    "sc ",
    "sc.exe",
    "schtasks",
    "shutdown",
    "sigverif",
    "systeminfo",
    "tasklist",
    "taskkill",
    "telnet",
    "whoami",
    "wmic",
    "wusa",
]

risk_utilities = [
    "bitsadmin",
    "cacls",
    "csvde",
    "dsquery",
    "icacls",
    "nltest",
    "rexec",
    "sdbinst",
    "volumeid",
    "vssadmin",
    "wevtutil",
    "whois",
    "xcacls",
]

sysinternals = [
    "accesschk",
    "accessenum",
    "adexplorer",
    "adinsight",
    "adrestore",
    "autologon",
    "autoruns",
    "bginfo",
    "bluescreen",
    "clockres",
    "contig",
    "coreinfo",
    "ctrl2cap",
    "debugview",
    "desktops",
    "disk2vhd",
    "diskext",
    "diskmon",
    "du ",
    "du.exe",
    "efsdump",
    "findlinks",
    "handle ",
    "handle.exe",
    "hex2dec",
    "junction",
    "ldmdump",
    "listdlls",
    "livekd",
    "loadorder",
    "logonsessions",
    "movefile",
    "notmyfault",
    "ntfsinfo",
    "pendmoves",
    "pipelist",
    "portmon",
    "procdump",
    "psexec",
    "psfile",
    "bginfo",
    "psgetsid",
    "psinfo",
    "pskill",
    "pslist",
    "psloggedon",
    "psloglist",
    "pspasswd",
    "psping",
    "psservice",
    "psshutdown",
    "pssuspend",
    "pstools",
    "rammap",
    "regdelnull",
    "ru ",
    "ru.exe",
    "regjump",
    "sdelete",
    "shareenum",
    "shellrunas",
    "sigcheck",
    "streams ",
    "streams.exe",
    "strings ",
    "strings.exe",
    "sync ",
    "sync.exe",
    "sysmon",
    "tcpview",
    "vmmap",
    "volumeid",
    "whois",
    "winobj",
    "zoomit",
]

class UsesWindowsUtilities(Signature):
    name = "uses_windows_utilities"
    #description = "Uses Windows utilities for basic Windows functionality"
    description = u"将 Windows 实用进程用于基本的 Windows 功能"
    severity = 2
    ttp = ["T1059.001"]
    categories = ["commands", "lateral"]
    authors = ["Cuckoo Technologies"]
    minimum = "2.0"
    references = ["http://blog.jpcert.or.jp/2016/01/windows-commands-abused-by-attackers.html"]

    def on_complete(self):
        for cmdline in self.get_command_lines():
            for utility in utilities:
                if utility in cmdline.lower():
                    self.mark_ioc("cmdline", cmdline)

        return self.has_marks()

class SuspiciousCommandTools(Signature):
    name = "suspicious_command_tools"
    #description = "Uses suspicious command line tools or Windows utilities"
    description = u"使用可疑的命令行工具或 Windows 实用进程"
    ttp = ["T1059.001"]
    severity = 3
    categories = ["commands", "lateral"]
    authors = ["Kevin Ross"]
    minimum = "2.0"

    def on_complete(self):
        for cmdline in self.get_command_lines():
            for utility in risk_utilities:
                if utility in cmdline.lower():
                    self.mark_ioc("cmdline", cmdline)

        return self.has_marks()

class SysInternalsToolsUsage(Signature):
    name = "sysinternals_tools_usage"
    #description = "Uses Sysinternals tools in order to add additional command line functionality"
    ttp = ["T1059.001"]
    description = u"使用系统内部工具添加额外的命令行功能"
    severity = 3
    categories = ["commands", "lateral"]
    authors = ["Kevin Ross"]
    minimum = "2.0"
    references = ["docs.microsoft.com/en-us/sysinternals/downloads/"]

    def on_complete(self):
        for cmdline in self.get_command_lines():
            for utility in sysinternals:
                if utility in cmdline.lower():
                    self.mark_ioc("cmdline", cmdline)

        return self.has_marks()

class AddsUser(Signature):
    name = "adds_user"
    ttp = ["T1136.001"]
    #description = "Uses windows command to add a user to the system"
    description = u"使用 windows 命令将用户添加到系统"
    severity = 2
    categories = ["commands"]
    authors = ["Kevin"]
    minimum = "2.0"

    def on_complete(self):
        for cmdline in self.get_command_lines():
                if cmdline.lower().startswith("net") and "user /add" in cmdline.lower():
                    self.mark_ioc("cmdline", cmdline)

        return self.has_marks()

class AddsUserAdmin(Signature):
    ttp = ["T1136.001"]
    name = "adds_user_admin"
    #description = "Uses windows command to add a user to the administrator group"
    description = u"使用 windows 命令将用户添加到管理员组"
    severity = 3
    categories = ["commands"]
    authors = ["Kevin"]
    minimum = "2.0"

    def on_complete(self):
        for cmdline in self.get_command_lines():
                if cmdline.lower().startswith("net") and "localgroup administrators" in cmdline.lower():
                    self.mark_ioc("cmdline", cmdline)

        return self.has_marks()
