# -*- coding:utf-8 -*-
# Copyright (C) 2010-2015 Cuckoo Foundation.
# This file is part of Cuckoo Sandbox - http://www.cuckoosandbox.org
# See the file 'docs/LICENSE' for copying permission.

from lib.cuckoo.common.abstracts import Signature

class EvalJS(Signature):
    name = "js_eval"
    #description = "Executes javascript"
    description = u"执行JavaScript脚本文件"
    severity = 2
    categories = ["unpacking"]
    authors = ["Cuckoo Technologies"]
    minimum = "2.0"

    filter_apinames = "COleScript_Compile"

    def on_call(self, call, process):
        if call["arguments"]["type"] == "eval code":
            self.severity = 3
            # self.description = "Executed javascript and unpacks itself"
            self.description = u"执行 JavaScript 并自行解压缩"
        self.mark_call()
        return True
