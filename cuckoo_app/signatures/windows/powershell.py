# -*- coding:utf-8 -*-
# Copyright (C) 2015-2017 Cuckoo Foundation.
# This file is part of Cuckoo Sandbox - http://www.cuckoosandbox.org
# See the file 'docs/LICENSE' for copying permission.

import re

from lib.cuckoo.common.abstracts import Signature

class SuspiciousPowershell(Signature):
    name = "suspicious_powershell"
    #description = "Creates a suspicious Powershell process"
    description = u"创建Powershell进程"
    severity = 3
    ttp = ["T1543"]
    categories = ["script", "dropper", "downloader", "packer"]
    authors = ["Kevin Ross", "Cuckoo Technologies", "FDD"]
    minimum = "2.0"

    def on_complete(self):
        for cmdline in self.get_command_lines():
            lower = cmdline.lower()

            if "powershell" not in lower:
                continue

            epre = re.compile("\\-[e^]{1,2}[xecution]*[p^]{0,2}[olicy]*[\\s]+bypass")
            m = epre.search(lower)
            if m:
                self.mark(value="Attempts to bypass execution policy", option=m.group(0))

            epre = re.compile("\\-[e^]{1,2}[xecution]*[p^]{0,2}[olicy]*[\\s]+unrestricted")
            m = epre.search(lower)
            if m:
                self.mark(value="Attempts to bypass execution policy", option=m.group(0))

            nopre = re.compile("\\-nop[rofile]*")
            m = nopre.search(lower)
            if m:
                self.mark(value="Does not load current user profile", option=m.group(0))

            nolre = re.compile("\\-nol[og]*")
            m = nolre.search(lower)
            if m:
                self.mark(value="Hides the copyright banner when PowerShell launches", option=m.group(0))

            hiddenre = re.compile("\\-[w^]{1,2}[indowstyle^]*[\\s]+hidden")
            m = hiddenre.search(lower)
            if m:
                self.mark(value="Attempts to execute command with a hidden window", option=m.group(0))

            nonire = re.compile("\\-noni[nteraciv]*")
            m = nonire.search(lower)
            if m:
                self.mark(value="Prevents creating an interactive prompt for the user", option=m.group(0))

            if "downloadfile(" in lower:
                self.mark(value="Uses powershell to execute a file download from the command line")

        return self.has_marks()

class AmsiBypass(Signature):
    name = "amsi_bypass"
    #description = "Powershell script bypasses AMSI (Antimalware Scan Interface) by reporting a failure in AMSI initialization"
    description = u"Powershell 脚本通过报告 AMSI 初始化失败来绕过 AMSI（反恶意软件扫描接口）"
    severity = 5
    categories = ["script", "malware", "powershell", "amsi"]
    authors = ["FDD", "Cuckoo Technologies"]
    minimum = "2.0.4"
    ttp = ["T1059.001"]

    def on_yara(self, category, filepath, match):
        if match.name != "PowershellAMSI":
            return

        self.mark_ioc("function", match.string("fn1", 0))
        self.mark_ioc("function", match.string("fn2", 0))
        self.mark_ioc("function", match.string("fn3", 0))
        return True

class PowershellBitsTransfer(Signature):
    name = "powershell_bitstransfer"
    #description = "Powershell BITS Transfer detected (dropper malware)"
    description = u"检测到Powershell位传输（投放器恶意软件）"
    severity = 5
    categories = ["script", "dropper", "downloader", "malware", "powershell"]
    authors = ["FDD", "Cuckoo Technologies"]
    minimum = "2.0.4"
    ttp = ["T1059.001"]

    def on_yara(self, category, filepath, match):
        if match.name != "PowershellBitsTransfer":
            return

        self.mark_config({
            "family": "Powershell BITS Transfer Dropper",
            "url": match.string("Payload", 0),
        })
        return True

class PowershellDdiRc4(Signature):
    name = "powershell_ddi_rc4"
    #description = "Powershell downloads RC4 crypted data and executes it"
    description = u"Powershell下载RC4加密数据并执行它"
    severity = 5
    categories = ["script", "dropper", "downloader", "malware", "powershell"]
    authors = ["FDD", "Cuckoo Technologies"]
    minimum = "2.0.4"
    ttp = ["T1059.001"]

    def on_yara(self, category, filepath, match):
        if match.name != "PowershellDdiRc4":
            return

        host = match.string("Host", 0)
        path = match.string("Path", 0).strip("'")
        key = match.string("Key", 0)

        if "'" in key:
            key = key.split("'")[1]
        if '"' in key:
            key = key.split('"')[1]

        self.mark_config({
            "family": "Powershell DDI RC4 (downloader)",
            "url": "%s%s" % (host, path),
            "key": key,
        })
        return True

class PowershellDFSP(Signature):
    name = "powershell_dfsp"
    #description = "Powershell Downloader DFSP detected"
    description = u"检测到Powershell下载器 DFSP"
    severity = 5
    categories = ["script", "dropper", "downloader", "malware"]
    authors = ["FDD", "Cuckoo Technologies"]
    minimum = "2.0.4"
    ttp = ["T1059.001"]

    def on_yara(self, category, filepath, match):
        if match.name != "PowershellDFSP":
            return

        self.mark_config({
            "family": "Powershell Downloader DFSP",
            "url": match.string("Payload", 0),
        })
        return True


class PowershellDI(Signature):
    name = "powershell_di"
    #description = "Powershell script has download & invoke calls"
    description = u"Powershell 脚本具有下载和调用"
    severity = 1
    ttp = ["T1059.001"]
    categories = ["script", "dropper", "downloader", "malware", "powershell"]
    authors = ["FDD", "Cuckoo Technologies"]
    minimum = "2.0.4"

    def on_yara(self, category, filepath, match):
        if match.name != "PowershellDI":
            return

        for name in ("d1", "d2", "d3", "d4"):
            if name in match.offsets:
                url = match.string(name, 0)
                break

        if url.count('"') == 2:
            url = url.split('"')[1]
        elif url.count("'") == 2:
            url = url.split("'")[1]
        else:
            url = None

        if url:
            self.mark_config({
                "family": "Powershell Download & Invoke",
                "url": url,
            })
            return True


class PowershellDownload(Signature):
    name = "powershell_download"
    #description = "URL downloaded by powershell script"
    description = u"通过 Powershell 脚本下载的网址"
    severity = 2
    categories = ["downloader"]
    authors = ["FDD", "Cuckoo Technologies"]
    minimum = "2.0"
    ttp = ["T1059.001"]

    filter_apinames = [
        "recv",
    ]

    def on_call(self, call, process):
        if process["process_name"].lower() != "powershell.exe":
            return

        if call["arguments"]["buffer"]:
            self.mark_ioc("Data received", call["arguments"]["buffer"])

    def on_complete(self):
        return self.has_marks()

class PowershellEmpire(Signature):
    name = "powershell_empire"
    #description = "Powershell Empire detected"
    description = u"检测到Powershell Empire"
    severity = 5
    ttp = ["T1059.001"]
    categories = ["script", "dropper", "downloader", "malware"]
    authors = ["FDD", "Cuckoo Technologies"]
    minimum = "2.0.4"

    def on_yara(self, category, filepath, match):
        if match.name != "PowershellEmpire":
            return

        self.mark_config({
            "family": "Powershell Empire",

        })
        return True

class PowershellMeterpreter(Signature):
    name = "powershell_meterpreter"
    #description = "Meterpreter execution throught Powershell detected"
    description = u"检测到通过Powershell执行Meterpreter"
    severity = 5
    categories = ["script", "meterpreter", "powershell", "malware"]
    authors = ["FDD", "Cuckoo Technologies"]
    minimum = "2.0.4"
    ttp = ["T1059.001"]
    def on_yara(self, category, filepath, match):
        if match.name != "PowershellMeterpreter":
            return

        host = match.string("Host", 0).split()[1]
        port = match.string("Port", 0).split()[1]
        package = match.string("Package", 0)

        self.mark_config({
            "family": "Powershell Meterpreter",
            "url": "tcp://%s:%s" % (host, port),

            "type": package,
        })
        return True

class PowershellRequest(Signature):
    name = "powershell_request"
    #description = "Poweshell is sending data to a remote host"
    description = u"Poweshell 正在向远程主机发送数据"
    severity = 2
    categories = ["downloader"]
    authors = ["FDD", "Cuckoo Technologies"]
    minimum = "2.0"
    ttp = ["T1059.001"]
    filter_apinames = [
        "send",
    ]

    def on_call(self, call, process):
        if process["process_name"].lower() == "powershell.exe":

            self.mark_ioc("Data sent", call["arguments"]["buffer"])

    def on_complete(self):
        return self.has_marks()

class PowershellCcDns(Signature):
    name = "powershell_c2dns"
    #description = "Powershell C&C bot through DNS detected"
    description = u"检测到通过 DNS 的 Powershell C&C 机器人"
    severity = 5
    categories = ["script", "bot", "dns", "malware"]
    authors = ["FDD", "Cuckoo Technologies"]
    minimum = "2.0.4"
    ttp = ["T1059.001"]
    def on_yara(self, category, filepath, match):
        if match.name != "PowershellCcDns":
            return

        dns = match.string("DNS", 0).replace("nslookup -q=txt", "").strip()

        self.mark_config({
            "family": "Powershell DNS TXT Dropper",
            "url": dns,
        })
        return True

class PowershellUnicorn(Signature):
    name = "powershell_unicorn"
    #description = "A Powershell script generated using the unicorn technique (shellcode injection in powershell process) has been detected"
    description = u"检测到使用unicorn技术（Powershell 进程中的外壳代码注入）生成的 Powershell 脚本"
    severity = 5
    ttp = ["T1055"]
    categories = ["script", "dropper", "downloader", "malware"]
    authors = ["FDD", "Cuckoo Technologies"]
    minimum = "2.0.4"

    def on_yara(self, category, filepath, match):
        if match.name != "UnicornGen":
            return

        self.mark_config({
            "family": "Unicorn by trustedsec.com",
        })
        return True
