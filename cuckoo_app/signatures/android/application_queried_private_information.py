# -*- coding:utf-8 -*-
# Copyright (C) Check Point Software Technologies LTD.

# This file is part of Cuckoo Sandbox - http://www.cuckoosandbox.org

# See the file 'docs/LICENSE' for copying permission.

from lib.cuckoo.common.abstracts import Signature

class AndroidPrivateInfoQuery(Signature):
    name = "application_queried_private_information"
    #description = "Application Queried Private Information (Dynamic)"
    description = u"应用查询私有信息(动态)"
    severity = 2
    categories = ["android"]
    authors = ["Check Point Software Technologies LTD"]
    minimum = "2.0"

    def on_complete(self):
        if "ContentResolver_queries" in self.get_droidmon():
            return True
