# -*- coding:utf-8 -*-
# Copyright (C) Check Point Software Technologies LTD.

# This file is part of Cuckoo Sandbox - http://www.cuckoosandbox.org

# See the file 'docs/LICENSE' for copying permission.

from lib.cuckoo.common.abstracts import Signature

class AndroidPhoneNumber(Signature):
    name = "application_queried_phone_number"
    #description = "Application Queried Phone Number (Dynamic)"
    description = u"应用查询电话手机号(动态)"
    severity = 1
    categories = ["android"]
    authors = ["Check Point Software Technologies LTD"]
    minimum = "2.0"

    def on_complete(self):
        if "getLine1Number" in self.get_droidmon("fingerprint"):
            return True
