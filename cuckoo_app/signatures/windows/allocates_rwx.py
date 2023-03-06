# -*- coding:utf-8 -*-
# This file is part of Cuckoo Sandbox - http://www.cuckoosandbox.org
# See the file 'docs/LICENSE' for copying permission.

from lib.cuckoo.common.abstracts import Signature

class AllocatesRWX(Signature):
    name = "allocates_rwx"
    #description = "Allocates read-write-execute memory (usually to unpack itself)"
    description = u"授权分配读-写-执行内存（自行解包）"
    severity = 2
    ttp = ["T1222.001"]
    categories = ["unpacking"]
    authors = ["Cuckoo Technologies"]
    minimum = "2.0"

    filter_apinames = (
        "NtAllocateVirtualMemory", "NtProtectVirtualMemory",
        "VirtualAllocEx", "VirtualProtectEx",
    )
    process_handles = ["0xffffffff", "0xffffffffffffffff"]

    def on_call(self, call, process):
        proc_handle = call["arguments"]["process_handle"]

        if call["flags"]["protection"] == "PAGE_EXECUTE_READWRITE" and proc_handle in self.process_handles:
            self.mark_call()

    def on_complete(self):
        return self.has_marks()

class AllocatesExecuteRemoteProccess(Signature):
    name = "allocates_execute_remote_process"
    #description = "Allocates execute permission to another process indicative of possible code injection"
    description = u"授权分配执行权限给另一个可能存在代码注入的进程"
    ttp = ["T1222.001"]
    severity = 3
    categories = ["injection", "shellcode"]
    authors = ["Kevin Ross"]
    minimum = "2.0"

    filter_apinames = "NtAllocateVirtualMemory", "NtProtectVirtualMemory"
    process_handles = ["0xffffffff", "0xffffffffffffffff"]

    def on_call(self, call, process):
        protection = call["flags"]["protection"]
        proc_handle = call["arguments"]["process_handle"]
        if protection in ("PAGE_EXECUTE_READWRITE", "PAGE_EXECUTE", "PAGE_EXECUTE_WRITECOPY") and proc_handle not in self.process_handles:
            self.mark_call()

    def on_complete(self):
        return self.has_marks()
