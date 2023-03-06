# -*- coding:utf-8 -*-
# Copyright (C) 2013 Claudio "nex" Guarnieri (@botherder)
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

class NetworkIRC(Signature):
    name = "network_irc"
    #description = "Connects to an IRC server, possibly part of a botnet"
    description = u"连接到一个IRC服务器，可能是某个僵尸网络的一部分"
    severity = 3
    categories = ["irc"]
    authors = ["nex"]
    minimum = "2.0"

    def on_complete(self):
        if self.get_net_irc():
            return True
