# -*- coding:utf-8 -*-
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

class EncryptionKeys(Signature):
    name = "encryption_keys"
    #description = "Encryption keys have been identified in this analysis" 
    description = u"加密密钥已经在分析行为中被辨别"
    severity = 2
    minimum = "2.0"

    def on_complete(self):
        if self.get_results("static", {}).get("keys", []):
            return True