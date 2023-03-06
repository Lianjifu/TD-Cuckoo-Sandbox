# -*- coding:utf-8 -*-
# Copyright (C) 2010-2015 Cuckoo Foundation.
# This file is part of Cuckoo Sandbox - http://www.cuckoosandbox.org
# This signature was contributed by RedSocks - http://redsocks.nl
# See the file 'docs/LICENSE' for copying permission.

from lib.cuckoo.common.abstracts import Signature

class VncMutexes(Signature):
    name = "vnc_mutexes"
    #description = "Creates VNC Remote Administration Tool Mutexes"
    description = u"创建VNC远程管理工具互斥锁"
    severity = 3
    ttp = ["T1133"]
    categories = ["rat"]
    families = ["vnc"]
    authors = ["RedSocks"]
    minimum = "2.0"

    mutexes_re = [
        ".*WinVNC_Win32_Instance_Mutex",
    ]

    def on_complete(self):
        for indicator in self.mutexes_re:
            match = self.check_mutex(pattern=indicator, regex=True)
            if match:
                self.mark_ioc("mutex", match)

        return self.has_marks()
