"use strict";

// Copy from http://stackoverflow.com/a/4673436/3026513
if (!String.prototype.format) {
  String.prototype.format = function () {
    var args = arguments;
    return this.replace(/{(\d+)}/g, function (match, number) {
      return typeof args[number] != 'undefined' ?
        args[number] :
        match;
    });
  };
}

console.log("[*] Frida {0} on {1}".format(Frida.version, Process.arch));