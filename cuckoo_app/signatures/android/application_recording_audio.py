# -*- coding:utf-8 -*-
# Copyright (C) Check Point Software Technologies LTD.

# This file is part of Cuckoo Sandbox - http://www.cuckoosandbox.org

# See the file 'docs/LICENSE' for copying permission.

from lib.cuckoo.common.abstracts import Signature

class AndroidAudio(Signature):
    name = "application_recording_audio"
    #description = "Application Recording Audio (Dynamic)"
    description = u"应用录制音频(动态)"
    severity = 4
    categories = ["android"]
    authors = ["Check Point Software Technologies LTD"]
    minimum = "2.0"

    def on_complete(self):
        if "mediaRecorder" in self.get_droidmon("events"):
            return True
