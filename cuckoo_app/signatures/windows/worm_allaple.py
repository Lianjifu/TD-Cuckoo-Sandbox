# -*- coding:utf-8 -*-
# Copyright (C) 2010-2015 Cuckoo Foundation.
# This file is part of Cuckoo Sandbox - http://www.cuckoosandbox.org
# This signature was contributed by RedSocks - http://redsocks.nl
# See the file 'docs/LICENSE' for copying permission.

from lib.cuckoo.common.abstracts import Signature

class WormAllaple(Signature):
    name = "worm_allaple"
    #description = "Creates known Allaple Worm files, registry keys and/or mutexes" 
    description = u"创建已知UAllaple蠕虫文件、注册表键以及互斥器"
    severity = 3
    ttp = ["T1204.002"]
    categories = ["worm"]
    families = ["allaple"]
    authors = ["RedSocks"]
    minimum = "2.0"

    mutexes_re = [
        ".*jhdheruhfrthkgjhtjkghjk5trh",
    ]

    def on_complete(self):
        for indicator in self.mutexes_re:
            mutex = self.check_mutex(pattern=indicator, regex=True)
            if mutex:
                self.mark_ioc("mutex", mutex)

        return self.has_marks()
