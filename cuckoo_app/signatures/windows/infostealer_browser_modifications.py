# -*- coding:utf-8 -*-
# Copyright (C) 2015 Optiv, Inc. (brad.spengler@optiv.com), Updated 2016 for Cuckoo 2.0, Kevin Ross 2018
# This file is part of Cuckoo Sandbox - http://www.cuckoosandbox.org
# See the file 'docs/LICENSE' for copying permission.

from lib.cuckoo.common.abstracts import Signature

class DisablesSPDYFirefox(Signature):
    name = "disables_spdy_firefox"
    #description = "Attempts to disable SPDY support in Firefox to improve web infostealing capability"
    description = u"尝试禁用火狐浏览器中的SPDY支持以改进web信息窃取功能"
    severity = 3
    ttp = ["T1185"]
    categories = ["infostealer", "banker"]
    authors = ["Optiv"]
    minimum = "2.0"

    filter_apinames = [
        "NtWriteFile",
    ]

    def on_call(self, call, process):
        buf = call["arguments"]["buffer"]
        if "network.http.spdy.enabled" in buf and "false" in buf:
            self.mark_call()

    def on_complete(self):
        return self.has_marks()

class DisablesSPDYIE(Signature):
    name = "disables_spdy_ie"
    #description = "Attempts to disable SPDY support in Internet Explorer to improve web infostealing capability"
    description = u"尝试在 Internet Explorer 中禁用 SPDY 支持以提高 Web 信息窃取功能"
    severity = 3
    categories = ["infostealer", "banker"]
    authors = ["Kevin Ross"]
    minimum = "2.0"
    references = ["www.windows-security.org/65bb16b8e4a8cda95159541fcf31fcd7/allow-internet-explorer-to-use-the-spdy3-network-protocol"]

    filter_apinames = [
        "RegSetValueExA",
        "RegSetValueExW",
        "NtSetValueKey",
    ]

    def on_call(self, call, process):
        key = call['arguments'].get('regkey_r', '').lower()
        if key == '':
            key = call['arguments']['regkey'].split('\\')[-1]
        if key:
            if key == "enablespdy3_0" and call["arguments"]["value"] == 0:
                self.mark_call()

    def on_complete(self):
        return self.has_marks()

class DisablesSPDYChrome(Signature):
    name = "disables_spdy_chrome"
    #description = "Chrome has been executed without SPDY support to improve web infostealing capability"
    description = u"Chrome 已在没有 SPDY 支持的情况下执行，以提高网络信息窃取能力"
    severity = 3
    categories = ["infostealer", "banker"]
    authors = ["Kevin Ross"]
    minimum = "2.0"

    def on_complete(self):
        for cmdline in self.get_command_lines():
            if "chrome.exe" in cmdline.lower() and "--use-spdy=off" in cmdline.lower():
                    self.mark_ioc("cmdline", cmdline)

        return self.has_marks()

class ModifiesFirefoxConfiguration(Signature):
    name = "modifies_firefox_configuration"
    #description = "Modifies the Firefox configuration file"
    description = u"修改火狐浏览器配置文档"
    severity = 3
    categories = ["infostealer", "banker"]
    authors = ["Kevin Ross"]
    minimum = "2.0"

    filter_apinames = [
        "NtWriteFile",
    ]

    def on_call(self, call, process):
        if process["process_name"] != "firefox.exe":
            key = call["arguments"]["filepath"].lower()
            if key:
                if "\\mozilla\\firefox\\profiles\\" in key and  key.endswith("prefs.js"):
                    self.mark_call()

    def on_complete(self):
        return self.has_marks()

class DisablesIEHTTP2(Signature):
    name = "disables_ie_http2"
    #description = "Attempts to disable HTTP2 support in Internet Explorer or Edge to improve infostealing capability"
    description = u"尝试在 Internet Explorer 或 Edge 中禁用 HTTP2 支持以提高信息窃取功能"
    severity = 3
    categories = ["infostealer", "banker"]
    authors = ["Kevin Ross"]
    minimum = "2.0"

    http2keys = [
        "enablehttp2tls",
        "enablehttp2cleartext"
    ]

    filter_apinames = [
        "RegSetValueExA",
        "RegSetValueExW",
        "NtSetValueKey",
    ]


    def on_call(self, call, process):
        key = call['arguments'].get('regkey_r', '').lower()
        if key == '':
            key = call['arguments']['regkey'].split('\\')[-1]
        if key:
            for http2key in self.http2keys:
                if key == http2key and call["arguments"]["value"] == 0:
                    self.mark_call()

    def on_complete(self):
        return self.has_marks()
