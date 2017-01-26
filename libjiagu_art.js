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

const PACKAGE_NAME = "__PACKAGE_NAME__";
const APP_FILES_PATH = "/data/data/{0}/files".format(PACKAGE_NAME);

try {

  const LIBJIAGU = "libjiagu_64.so";
  const LIBZ = "libz.so"
  const Z_OK = 0;

  const libz_uncompress = Module.findExportByName(LIBZ, "uncompress");

  /*
  ZEXTERN int ZEXPORT uncompress OF((Bytef *dest,   uLongf *destLen,
                                   const Bytef *source, uLong sourceLen));
   */
  Interceptor.attach(libz_uncompress, {
    onEnter: function (args) {
      this.dest = args[0];
      this.destLen = args[1];
      this.source = args[2];
      this.sourceLen = args[3];
    },
    onLeave: function (retval) {

      // Return value is not Z_OK.
      if (!retval.isNull())
        return;

      let caller = this.returnAddress.sub(1);
      let module = Process.getModuleByAddress(caller);

      if (module.name === LIBJIAGU) {
        console.log("[*] libz::uncompress is calling from {0}.".format(module.name));
        let destLen = Memory.readULong(this.destLen);
        console.log("[*] dest/destLen: {0}, {1}".format(this.dest, destLen));
        console.log("[*] source/sourceLen: {0}, {1}".format(this.source, this.sourceLen));

        console.log(hexdump(this.dest, {
          offset: 0,
          length: 0x30,
          header: true,
          ansi: true
        }));

        let output_path = "{0}/{1}".format(APP_FILES_PATH, "unpacked_libjiagu.so");
        let out = new File(output_path, "wb");
        out.write(Memory.readByteArray(this.dest, destLen));
        out.close();
        console.log("[*] Saved to {0}\n".format(output_path));
      }
    }
  });

} catch (error) {
  console.log(error);
}