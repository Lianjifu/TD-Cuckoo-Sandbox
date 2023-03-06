# -*- coding:utf-8 -*-
# Copyright (C) 2010-2015 Cuckoo Foundation.
# This file is part of Cuckoo Sandbox - http://www.cuckoosandbox.org
# This signature was contributed by RedSocks - http://redsocks.nl
# See the file 'docs/LICENSE' for copying permission.

from lib.cuckoo.common.abstracts import Signature

class WormKolabc(Signature):
    name = "worm_kolabc"
    #description = "Creates known KolaBC Worm files, registry keys and/or mutexes"
    description = u"创建已知KolaBC蠕虫文件、注册表键以及互斥器"
    severity = 3
    ttp = ["T1204.002"]
    categories = ["worm"]
    families = ["kolabc"]
    authors = ["RedSocks"]
    minimum = "2.0"

    files_re = [
        "C:\\\\WINDOWSExplorer\\.exe",
        "C:\\\\WINDOWS\\\\Fonts\\\\unwise_\\.exe",
    ]

    def on_complete(self):
        for indicator in self.files_re:
            regkey = self.check_file(pattern=indicator, regex=True)
            if regkey:
                self.mark_ioc("file", regkey)

        return self.has_marks()
