# -*- coding: utf-8 -*-
# Copyright (C) 2012-2013 Claudio Guarnieri.
# Copyright (C) 2014-2018 Cuckoo Foundation.
# This file is part of Cuckoo Sandbox - http://www.cuckoosandbox.org
# See the file 'docs/LICENSE' for copying permission.

import random
import re
import logging
import threading

from lib.common.abstracts import Auxiliary
from lib.common.defines import (
    KERNEL32, USER32, WM_GETTEXT, WM_GETTEXTLENGTH, WM_CLOSE, BM_CLICK,
    EnumWindowsProc, EnumChildProc, create_unicode_buffer,VK_CODE
)

log = logging.getLogger(__name__)

RESOLUTION = {
    "x": USER32.GetSystemMetrics(0),
    "y": USER32.GetSystemMetrics(1)
}

def click(hwnd):
    USER32.SetForegroundWindow(hwnd)
    KERNEL32.Sleep(1000)
    USER32.SendMessageW(hwnd, BM_CLICK, 0, 0)

def foreach_child(hwnd, lparam):
    # List of partial buttons labels to click.
    buttons = [
        "yes", "oui",u'是',
        "ok",u'确定',
        "i accept", u'我接受',"Accept",u"接受","accept",
        "next", "suivant", u'下一步',
        "new", "nouveau",
        "install", "installer", u'安装',
        "file", "fichier",
        "run", "start", "marrer", "cuter", u'运行',
        "extract",u'提取',
        "i agree", "accepte", u'我同意', u"同意"
        "enable", "activer", "accord", "valider",u'启用',
        "don't send", "ne pas envoyer",u'不发送',
        "don't save",u'不保存',u"不保存(N)",
        "continue", "continuer", u'继续',
        "personal", "personnel",u'个人'
        "scan", "scanner",u'扫描'
        "unzip", "dezip",
        "open", "ouvrir",u'打开'
        "close the program",u'关闭程序',
        "execute", "executer",u'执行',
        "launch", "lancer",u'启动',
        "save", "sauvegarder",u'保存',
        "download", "load", "charger",
        "end", "fin", "terminer",u'结束',u"保存(S)",
        "later",u'稍后',
        "finish",u'完成',
        "allow access", u'允许访问',
        "remind me later", u'以后提醒我',
    ]
    # List of complete button texts to click. These take precedence.
    buttons_complete = [
        "&Ja",  # E.g., Dutch Office Word 2013.
    ]

    # List of buttons labels to not click.
    dontclick = [
        "don't run",u"不运行",
        "i do not accept",u"我不同意","Don't Accept",u"不同意"
    ]

    classname = create_unicode_buffer(50)
    USER32.GetClassNameW(hwnd, classname, 50)
    # Check if the class of the child is button.
    if "button" in classname.value.lower():
        # Get the text of the button.
        length = USER32.SendMessageW(hwnd, WM_GETTEXTLENGTH, 0, 0)
        text = create_unicode_buffer(length + 1)
        USER32.SendMessageW(hwnd, WM_GETTEXT, length + 1, text)

        if text.value in buttons_complete:
            log.info("Found button %r, clicking it" % text.value)
            click(hwnd)
            return True

        # Check if the button is set as "clickable" and click it.
        textval = text.value.replace("&", "").lower()
        for button in buttons:
            if button in textval:
                for btn in dontclick:
                    if btn in textval:
                        break
                else:
                    log.info("Found button %r, clicking it" % text.value)
                    click(hwnd)

    # Recursively search for childs (USER32.EnumChildWindows).
    return True

# Callback procedure invoked for every enumerated window.
# Purpose is to close any office window
def get_office_window(hwnd, lparam):
    if USER32.IsWindowVisible(hwnd):
        text = create_unicode_buffer(1024)
        USER32.GetWindowTextW(hwnd, text, 1024)
        # TODO Would " - Microsoft (Word|Excel|PowerPoint)$" be better?
        if re.search("- (Microsoft|Word|Excel|PowerPoint)", text.value):
            USER32.SetForegroundWindow(hwnd)
            keybd_event_msg()
            USER32.SendNotifyMessageW(hwnd, WM_CLOSE, None, None)
            log.info("Closed Office window.")
    return True

# Callback procedure invoked for every enumerated window.
def foreach_window(hwnd, lparam):
    # If the window is visible, enumerate its child objects, looking
    # for buttons.
    if USER32.IsWindowVisible(hwnd):
        USER32.EnumChildWindows(hwnd, EnumChildProc(foreach_child), 0)
    return True

def move_mouse():
    x = random.randint(0, RESOLUTION["x"])
    y = random.randint(0, RESOLUTION["y"])

    # Originally was:
    # USER32.mouse_event(0x8000, x, y, 0, None)
    # Changed to SetCurorPos, since using GetCursorPos would not detect
    # the mouse events. This actually moves the cursor around which might
    # cause some unintended activity on the desktop. We might want to make
    # this featur optional.
    USER32.SetCursorPos(x, y)

def click_mouse():
    # Move mouse to top-middle position.
    USER32.SetCursorPos(RESOLUTION["x"] / 2, 0)
    # Mouse down.
    USER32.mouse_event(2, 0, 0, 0, None)
    KERNEL32.Sleep(50)
    # Mouse up.
    USER32.mouse_event(4, 0, 0, 0, None)

def keybd_event_msg():
    # Input keyboard key  PgDn
    # keyboard down
    string_word = "12343456778"
    for i in string_word: 
        # keyboard down
        USER32.keybd_event(VK_CODE[i], 0x1e, 0x0000, 0)
        # keyboard up
        USER32.keybd_event(VK_CODE[i], 0x1e, 0x0002, 0)
    USER32.keybd_event(VK_CODE["ctrl"], 0x1e, 0x0000, 0)
    USER32.keybd_event(VK_CODE["s"], 0x1e, 0x0000, 0)
    KERNEL32.Sleep(1000)
    log.info("keyboard key PgDn.")

def foreach_input_child(hwnd, lparam):
    # console input
    if USER32.IsWindowVisible(hwnd):
        text = create_unicode_buffer(1024)
        USER32.GetWindowTextW(hwnd, text, 1024)
        log.info("input child {}".format(text.value))
        if re.search(u"管理员",text.value):
            log.info("keyboard input 1")
            USER32.keybd_event(VK_CODE["1"], 0x1e, 0x0000, 0)
            USER32.keybd_event(VK_CODE["1"], 0x1e, 0x0002, 0)
            KERNEL32.Sleep(50)
            USER32.keybd_event(VK_CODE["enter"], 0x1e, 0x0000, 0)
            USER32.keybd_event(VK_CODE["enter"], 0x1e, 0x0002, 0)

    return True

def foreach_console_window(hwnd, lparam):
    # If the window is visible, enumerate its child objects, looking
    if USER32.IsWindowVisible(hwnd):
        USER32.EnumChildWindows(hwnd, EnumChildProc(foreach_input_child), 0)
    return True

class Human(threading.Thread, Auxiliary):
    """Human after all"""

    def __init__(self, options={}, analyzer=None):
        threading.Thread.__init__(self)
        Auxiliary.__init__(self, options, analyzer)
        self.do_run = True

    def stop(self):
        self.do_run = False

    def run(self):
        seconds = 0
        # Global disable flag.
        if "human" in self.options:
            self.do_move_mouse = int(self.options["human"])
            self.do_click_mouse = int(self.options["human"])
            self.do_click_buttons = int(self.options["human"])
            self.do_console_input = int(self.options["human"])
        else:
            self.do_move_mouse = True
            self.do_click_mouse = True
            self.do_click_buttons = True
            self.do_console_input = True

        # Per-feature enable or disable flag.
        if "human.move_mouse" in self.options:
            self.do_move_mouse = int(self.options["human.move_mouse"])

        if "human.click_mouse" in self.options:
            self.do_click_mouse = int(self.options["human.click_mouse"])

        if "human.click_buttons" in self.options:
            self.do_click_buttons = int(self.options["human.click_buttons"])

        while self.do_run:
            if seconds and not seconds % 60:
                USER32.EnumWindows(EnumWindowsProc(get_office_window), 0)

            if self.do_click_mouse:
                click_mouse()

            if self.do_move_mouse:
                move_mouse()

            if self.do_click_buttons:
                USER32.EnumWindows(EnumWindowsProc(foreach_window), 0)

            if seconds and not seconds % 30:
                USER32.EnumWindows(EnumWindowsProc(foreach_console_window), 0)

            KERNEL32.Sleep(1000)
            seconds += 1
