#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# Author: TheCjw<thecjw@live.com>
# Created on 2016.11.08

__author__ = "TheCjw"

import argparse
import locale
import os
import platform
import shutil
import subprocess
import sys
import time
from datetime import datetime

import frida

import colorlog
from colorlog import ColoredFormatter

handler = colorlog.StreamHandler()

formatter = ColoredFormatter(
    "%(log_color)s[%(asctime)s] [%(levelname)s]%(reset)s %(message)s",
    datefmt="%H:%M:%S",
    reset=True,
    log_colors={
        "DEBUG": "cyan",
        "INFO": "green",
        "WARNING": "yellow",
        "ERROR": "red",
        "CRITICAL": "red,bg_white",
    }
)

handler.setFormatter(formatter)

logger = colorlog.getLogger("loader")
logger.addHandler(handler)
logger.level = 10  # DEBUG


class MyArgParser(object):
    def __init__(self):
        self.frida = shutil.which("frida")
        self.frida_compile = self.__node_script_path__("frida-compile")
        self.temp_script_path = os.path.join(os.path.dirname(__file__), "out")

        parser = argparse.ArgumentParser(
            description="A frida script loader for Android/iOS app",
            usage=f"""{os.path.basename(__file__)} <command> [<args>]

""")

        parser.add_argument("command", help="Subcommand to run")

        if len(sys.argv) == 1:
            parser.print_help()
            sys.exit(1)

        args = parser.parse_args(sys.argv[1:2])
        if not hasattr(self, args.command):
            logger.error(f"Unrecognized command: {args.command}")
            parser.print_help()
            sys.exit(1)

        getattr(self, args.command)()

    @staticmethod
    def exec_command(*args):
        """

        :param args:
        :return:
        """
        p = subprocess.Popen(args,
                             stdout=subprocess.PIPE,
                             stderr=subprocess.PIPE)
        _stdout, _stderr = p.communicate()
        if p.returncode != 0:
            logger.error(f"stderr:\n{_stderr.decode('utf-8')}")
            raise RuntimeError(f"exec_command {args[0]} failed.")

        return _stdout.decode("utf-8")

    @staticmethod
    def __start_session__(device, pid, script_content):
        """
        :return:
        """
        session = None
        try:
            session = device.attach(pid)
            script = session.create_script(script_content)
            script.load()
            sys.stdin.read()
        except KeyboardInterrupt:
            if session is not None:
                session.detach()
            logger.error("user aborted")

        print(f"[*] Shutting down at {datetime.now().strftime('%H:%M:%S')}")

    @staticmethod
    def __node_script_path__(name):
        """
        get node.js module from dev dir.
        :param name:
        :return:
        """
        build_os = platform.system().lower()
        suffix = ".cmd" if build_os == "windows" else ""
        return os.path.abspath(os.path.join(sys.path[0], "node_modules",
                                            ".bin", name + suffix))

    @staticmethod
    def __get_application_name__(device, identifier):
        """
        :param device:
        :param identifier:
        :return:
        """
        for p in device.enumerate_applications():
            if p.identifier == identifier:
                return p.name

    @staticmethod
    def __get_process_pid__(device, application_name):
        """
        :param device:
        :param application_name:
        :return:
        """
        for p in device.enumerate_processes():
            if p.name == application_name:
                return p.pid
        return -1

    def __compile_javascript__(self, src, dst):
        """
        Using frida-compile convert ES6 script to ES5 script
        :param src:
        :param dst:
        :return:
        """
        logger.info(f"Compiling {os.path.basename(src)} file with frida-compile.")
        self.exec_command(self.frida_compile, src, "-o", dst)

    def __spawn_and_inject__(self, package_name, script_path):
        """
        :param package_name:
        :param script_path:
        :return:
        """
        print(f"[*] Staring at {datetime.now().strftime('%H:%M:%S')}")

        if os.path.isabs(script_path) is False:
            script_path = os.path.abspath(script_path)

        output_script = os.path.join(self.temp_script_path,
                                     os.path.basename(script_path))
        self.__compile_javascript__(script_path, output_script)

        script_content = open(output_script, encoding="utf-8").read()
        script_content = script_content.replace("__PACKAGE_NAME__", package_name)

        device = frida.get_usb_device()

        pid = self.__get_process_pid__(device, package_name)
        if pid != -1:
            device.kill(package_name)
            time.sleep(0.1)

        self.exec_command("adb", "shell", "monkey", "-p",
                          package_name, "-c", "android.intent.category.LAUNCHER", "1")

        pid = -1
        for i in range(15):
            pid = self.__get_process_pid__(device, package_name)
            if pid != -1:
                break
            time.sleep(0.05)

        if pid == -1:
            logger.error(f"Run package {package_name} failed.")
            return

        logger.info(f"Injecting {os.path.basename(script_path)} to {package_name}({pid})")

        self.__start_session__(device, pid, script_content)

    def spawn(self):
        """
        Spawn a new process with package name, then inject frida script.
        :return:
        """
        parser = argparse.ArgumentParser(
            description="Spawn a new process with package and inject script.")
        parser.add_argument("-p",
                            "--package",
                            type=str,
                            help="Package name of app",
                            required=True)
        parser.add_argument("-s",
                            "--script",
                            type=str,
                            help="Script to inject",
                            required=True)
        args = parser.parse_args(sys.argv[2:])
        self.__spawn_and_inject__(args.package, args.script)

    def inject(self):
        """
        Inject a frida script to a running process.
        :return:
        """
        raise NotImplementedError


def main():
    MyArgParser()


if __name__ == "__main__":
    main()
