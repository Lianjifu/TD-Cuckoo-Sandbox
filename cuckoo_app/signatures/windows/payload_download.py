# -*- coding:utf-8 -*-
# Copyright (C) 2016 Kevin Ross. Also uses code from Will Metcalf
#
# This program is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program.  If not, see <http://www.gnu.org/licenses/>.

from lib.cuckoo.common.abstracts import Signature
import hashlib

class NetworkDocumentFile(Signature):
    name = "network_document_file"
    #description = "A document or script file initiated network communications indicative of a potential exploit or payload download"
    description = u"恶意脚本启动网络通信执行潜在利用或有效负载下载"
    severity = 3
    categories = ["exploit", "downloader"]
    authors = ["Kevin Ross", "Will Metcalf"]
    minimum = "2.0"

    def __init__(self, *args, **kwargs):
        Signature.__init__(self, *args, **kwargs)
        self.pname = []

    proc_list = [
        "wordview.exe", "winword.exe", "excel.exe", "powerpnt.exe",
        "outlook.exe", "acrord32.exe", "acrord64.exe", "wscript.exe",
        "mspub.exe", "powershell.exe",
    ]

    filter_apinames = [
        "InternetCrackUrlW", "InternetCrackUrlA", "URLDownloadToFileW",
        "URLDownloadToCacheFileW", "HttpOpenRequestW", "WSASend", "send"
    ]

    filter_analysistypes = "file"

    def on_call(self, call, process):
        pname = process["process_name"].lower()
        if pname in self.proc_list:
            if pname not in self.pname:
                self.pname.append(pname)
            self.mark_call()

    def on_complete(self):
        if len(self.pname) == 1:
            # self.description = "Network communications indicative of a potential document or script payload download was initiated by the process "
            self.description = u"指示潜在文档或脚本payload下载的网络通信由进程启动 "
            for pname in self.pname:
                self.description += pname
        elif len(self.pname) > 1:
            # self.description = "Network communications indicative of a potential document or script payload download was initiated by the processes "
            self.description = u"指示潜在文档或脚本payload下载的网络通信由进程启动 "
            self.description += ", ".join(self.pname)
        return self.has_marks()

class NetworkEXE(Signature):
    name = "network_downloader_exe"
    #description = "An executable file was downloaded"
    description = u"已下载可执行文档"
    severity = 2
    categories = ["exploit", "downloader"]
    authors = ["Kevin Ross", "Will Metcalf"]
    minimum = "2.0"

    def __init__(self, *args, **kwargs):
        Signature.__init__(self, *args, **kwargs)
        self.pname = []

    high_risk_proc = [
        "wordview.exe", "winword.exe", "excel.exe", "powerpnt.exe",
        "outlook.exe", "acrord32.exe", "acrord64.exe", "wscript.exe",
        "java.exe", "javaw.exe", "powershell.exe",
    ]

    filter_apinames = "recv", "InternetReadFile"

    def on_call(self, call, process):
        buf = call["arguments"]["buffer"]
        pname = process["process_name"].lower()
        if "MZ" in buf and "This program" in buf:
            if pname in self.high_risk_proc:
                self.severity = 3
            if pname not in self.pname:
                self.pname.append(pname)
            self.mark_call()

    def on_complete(self):
        if len(self.pname) == 1:
            # self.description = "An executable file was downloaded by the process  "
            self.description = u"进程下载了可执行文档  "
            for pname in self.pname:
                self.description += pname
        elif len(self.pname) > 1:
            # self.description = "An executable file was downloaded by the process  "
            self.description = u"进程下载了可执行文档 "
            self.description += ", ".join(self.pname)
        return self.has_marks()

class SuspiciousWriteEXE(Signature):
    name = "suspicious_write_exe"
    #description = "Wrote an executable file to disk"
    description = u"写入可执行文件到磁盘"
    severity = 3
    categories = ["exploit", "downloader", "virus"]
    authors = ["Will Metcalf", "Kevin Ross"]
    minimum = "2.0"

    def __init__(self, *args, **kwargs):
        Signature.__init__(self, *args, **kwargs)
        self.pname = []
        self.executed = False
        self.exes = []

    susp_proc_list = [
        "wordview.exe", "winword.exe", "excel.exe", "powerpnt.exe",
        "outlook.exe", "wscript.exe", "java.exe", "javaw.exe", "powershell.exe",
    ]

    filter_apinames = [
        "NtWriteFile", "CreateProcessInternalW", "ShellExecuteExW",
        "NtCreateFile", "NtWriteFile", "CreateProcessInternalW", "ShellExecuteExW",
    ]

    whitelist = [
        "\\Windows\\System32\\wscript.exe",
        "\\Windows\\hh.exe",
    ]

    def on_call(self, call, process):
        pname = process["process_name"].lower()
        if pname in self.susp_proc_list:
            if call["api"] == "NtWriteFile" and call["arguments"].get("filepath"):
                filepath = call["arguments"]["filepath"]
                buff = call["arguments"]["buffer"]
                if filepath.endswith(".exe") or (buff and len(buff) > 2 and buff.startswith("MZ") and "This program" in buff) and "powershell_ise.exe" not in filepath:
                    for white in self.whitelist:
                        if white in filepath:
                            return

                    if pname not in self.pname:
                        self.pname.append(pname)
                    if filepath not in self.exes:
                       self.exes.append(filepath)

            elif call["api"] == "NtCreateFile" and call["arguments"].get("filepath"):
                filepath = call["arguments"]["filepath"]
                if filepath.endswith(".exe") and "powershell_ise.exe" not in filepath:
                    for white in self.whitelist:
                        if white in filepath:
                            return

                    if pname not in self.pname:
                        self.pname.append(pname)
                    if filepath not in self.exes:
                        self.exes.append(filepath)

            elif call["api"] == "CreateProcessInternalW" or call["api"] == "ShellExecuteExW":
                filepath = call["arguments"]["filepath"]
                if filepath in self.exes and pname in self.pname:
                    self.executed = True

    def on_complete(self):
        if len(self.pname) == 1:
            for pname in self.pname:
                # self.description = "The process %s wrote an executable file to disk" % pname
                self.description = u"进程 %s 将可执行文档写入磁盘" % pname
                if self.executed:
                    # self.description += " which it then attempted to execute"
                    self.description += u" 然后它试图执行"
                    self.severity = 6
        elif len(self.pname) > 1:
            # self.description = "The processes %s wrote an executable file to disk" % ", ".join(self.pname)
            self.description = u"进程 %s 将可执行文档写入磁盘" % ", ".join(self.pname)
            if self.executed:
                # self.description += " which it then attempted to execute"
                self.description += u" 然后它试图执行"
                self.severity = 6
        for exe in self.exes:
            self.mark_ioc("file", exe)
        return self.has_marks()
