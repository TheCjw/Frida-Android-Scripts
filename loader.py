#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# Author: TheCjw<thecjw@live.com>
# Created on 2016.11.08

__author__ = "TheCjw"

import os
import argparse
import time
import sys

import frida


def parse_args():
    parser = argparse.ArgumentParser()
    subparsers = parser.add_subparsers(help="commands")

    cmd_run = subparsers.add_parser("run",
                                    help="Restart package and inject Frida script.")
    cmd_run.set_defaults(command="run")
    cmd_run.add_argument("-p",
                         "--package",
                         type=str,
                         help="Package name of Android app")
    cmd_run.add_argument("-s",
                         "--script",
                         type=str,
                         default="payload.js",
                         help="Script to inject")
    args = parser.parse_args()

    return args


def on_message(message, data):
    if isinstance(message, dict):
        print(message)
    else:
        if message.has_key("payload"):
            print(message["payload"])


def get_application_name(device, identifier):
    for p in device.enumerate_applications():
        if p.identifier == identifier:
            return p.name


def get_process_pid(device, application_name):
    for p in device.enumerate_processes():
        if p.name == application_name:
            return p.pid
    return -1


def main():
    args = parse_args()
    if args.command == "run":
        script_file = args.script
        package_name = args.package

        if os.path.isabs(script_file) is False:
            script_file = os.path.abspath(script_file)

        device = frida.get_device_manager().enumerate_devices()[-1]

        pid = get_process_pid(device, package_name)
        if pid != -1:
            print("[+] killing {0}".format(pid))
            device.kill(pid)
            time.sleep(0.3)

        # Pause for 3s.
        os.system(r"adb shell su -c \"echo 4 > /data/data/{0}/files/.pause\"".format(package_name))
        os.system(r"adb shell monkey -p {0} -c android.intent.category.LAUNCHER 1".format(package_name))

        pid = -1
        for i in range(10):
            pid = get_process_pid(device, package_name)
            if pid != -1:
                break
            time.sleep(0.1)

        if pid == -1:
            print("[-] Run package {0} failed.".format(package_name))
            return

        print("[+] Injecting {0} to {1}({2})".format(script_file, package_name, pid))

        session = None
        try:
            session = frida.get_device_manager().enumerate_devices()[-1].attach(pid)
            script_content = open(script_file).read()
            # Update some consts.
            script_content = script_content.replace("__PACKAGE_NAME__", package_name)
            script = session.create_script(script_content)
            script.on("message", on_message)
            script.load()
            sys.stdin.read()
        except KeyboardInterrupt as e:
            if session is not None:
                session.detach()
            sys.exit(0)

    else:
        pass


if __name__ == "__main__":
    main()
