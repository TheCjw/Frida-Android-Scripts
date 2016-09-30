#!/usr/bin/env python
# -*- coding: utf-8 -*-
# Author: TheCjw<thecjw@live.com>
# Created on 2016.05.12

__author__ = "TheCjw"

import os
import time
import sys

import frida


def on_message(message, data):
    # print dir(message)
    # print(data)
    if message.has_key("payload"):
        print(message["payload"])


def get_process_pid(device, package_name):
    for p in device.enumerate_processes():
        if p.name == package_name:
            return p.pid
    return -1


def main():
    device = frida.get_device_manager().enumerate_devices()[-1]
    package_name = "com.tencent.tmgp.sgame"

    # find and kill process.
    pid = get_process_pid(device, package_name)
    if pid != -1:
        print("killing {0}".format(pid))
        device.kill(pid)
        time.sleep(0.3)

    os.system("adb shell am start -n {0}/{1}".format(package_name, "com.tencent.tmgp.sgame.SGameActivity"))
    time.sleep(0.2)

    pid = get_process_pid(device, package_name)
    if pid == -1:
        print("{0} is not found...".format(package_name))
        return

    session = None
    try:
        session = frida.get_device_manager().enumerate_devices()[-1].attach(pid)
        script_content = open("payload.js").read()
        script = session.create_script(script_content)
        script.on("message", on_message)
        script.load()
        sys.stdin.read()
    except KeyboardInterrupt as e:
        if session is not None:
            session.detach()
        sys.exit(0)


if __name__ == "__main__":
    main()
