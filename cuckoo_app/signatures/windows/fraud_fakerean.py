# -*- coding:utf-8 -*-
# Copyright (C) 2010-2015 Cuckoo Foundation.
# This file is part of Cuckoo Sandbox - http://www.cuckoosandbox.org
# This signature was contributed by RedSocks - http://redsocks.nl
# See the file 'docs/LICENSE' for copying permission.

from lib.cuckoo.common.abstracts import Signature

class FakeRean(Signature):
    name = "fraudtool_fakerean"
    #description = "Creates known FakeRean Fraudtool files, registry keys and/or mutexes" 
    description = u"创建已知的FakeRean欺诈工具文件、注册表以及互斥器"
    severity = 3
    ttp = ["T1204.002"]
    categories = ["fraudtool"]
    families = ["fakerean"]
    authors = ["RedSocks"]
    minimum = "2.0"

    mutexes_re = [
        ".*qcgce2mrvjq91kk1e7pnbb19m52fx1956jc03il0h",
    ]

    def on_complete(self):
        for indicator in self.mutexes_re:
            if self.check_mutex(pattern=indicator, regex=True):
                return True
