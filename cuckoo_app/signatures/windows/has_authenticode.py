# -*- coding:utf-8 -*-
# Copyright (C) 2010-2015 Cuckoo Sandbox Developers.
# This file is part of Cuckoo Sandbox - http://www.cuckoosandbox.org
# See the file 'docs/LICENSE' for copying permission.

from lib.cuckoo.common.abstracts import Signature

class HasAuthenticode(Signature):
    name = "has_authenticode"
    #description = "This executable is signed"
    description = u"可执行文件已授权"
    severity = 1
    ttp = ["T1222"]

    def on_complete(self):
        if self.get_results("static", {}).get("signature"):
            return True
