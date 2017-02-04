"use strict";

if (!String.prototype.startsWith) {
  String.prototype.startsWith = function (str) {
    return !this.indexOf(str);
  }
}
