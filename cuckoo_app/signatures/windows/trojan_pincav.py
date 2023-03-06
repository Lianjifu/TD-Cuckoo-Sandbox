# -*- coding:utf-8 -*-
# Copyright (C) 2010-2015 Cuckoo Foundation.
# This file is part of Cuckoo Sandbox - http://www.cuckoosandbox.org
# This signature was contributed by RedSocks - http://redsocks.nl
# See the file 'docs/LICENSE' for copying permission.

from lib.cuckoo.common.abstracts import Signature

class TrojanLethic(Signature):
    name = "trojan_pincav"
    #description = "Creates known Pincav Trojan Files, Registry Keys and/or Mutexes"
    description = u"创建已知Pincav木马文件、注册表键以及互斥器"
    severity = 3
    ttp = ["T1204.002"]
    categories = ["trojan"]
    families = ["pincav"]
    authors = ["RedSocks"]
    minimum = "2.0"

    mutexes_re = [
        ".*jK1dDfggS",
        ".*zBIYku2BMUdN9unB87sa2sa",
    ]
