# -*- coding:utf-8 -*-
# Copyright (C) 2017 Kevin Ross
#
# This program is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program.  If not, see <http://www.gnu.org/licenses/>.

from lib.cuckoo.common.abstracts import Signature

class PersistenceRegistryJavaScript(Signature):
    name = "persistence_registry_javascript"
    #description = "Used JavaScript in registry key value likely for persistance"
    description = u"恶意在注册表键值中使用JavaScript用于持久化"
    severity = 3
    ttp = ["T1547.001"]
    categories = ["persistence"]
    authors = ["Kevin Ross"]
    minimum = "2.0"
    evented = True

    filter_apinames = set(["RegSetValueExA", "RegSetValueExW", "NtSetValueKey"])

    def on_call(self, call, process):
        value = call["arguments"]["value"]
        if not isinstance(value, basestring):
            return
        if value and "javascript:" in value:
            self.mark_call()

    def on_complete(self):
        return self.has_marks()

class PersistenceRegistryEXE(Signature):
    name = "persistence_registry_exe"
    #description = "Stores an executable in the registry"
    description = u"在注册表中存储可执行文档"
    ttp = ["T1547.001"]
    severity = 3
    categories = ["persistence"]
    authors = ["Kevin Ross"]
    minimum = "2.0"
    evented = True

    filter_apinames = set(["RegSetValueExA", "RegSetValueExW", "NtSetValueKey"])

    def on_call(self, call, process):
        value = call["arguments"]["value"]
        if not isinstance(value, basestring):
            return
        if value.startswith("MZ"):
            self.mark_call()

    def on_complete(self):
        return self.has_marks()

class PersistenceRegistryPowershell(Signature):
    name = "persistence_registry_powershell"
    #description = "Stores PowerShell commands in the registry likely for persistence"
    ttp = ["T1547.001"]
    description = u"将 PowerShell 命令存储在注册表中，可能用于持久性"
    severity = 3
    categories = ["persistence"]
    authors = ["Kevin Ross"]
    minimum = "2.0"
    evented = True

    filter_apinames = set(["RegSetValueExA", "RegSetValueExW", "NtSetValueKey"])

    def on_call(self, call, process):
        value = call["arguments"]["value"]
        if not isinstance(value, basestring):
            return
        if "powershell " in value or "powershell.exe" in value:
            self.mark_call()

    def on_complete(self):
        return self.has_marks()
