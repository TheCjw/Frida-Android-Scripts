"use strict";

require("./lib/common");

(function () {

  console.log(`[*] Current frida verison: ${Frida.version} on ${Process.arch}\n`);

  const PACKAGE_NAME = "__PACKAGE_NAME__";
  const APP_FILES_PATH = `/data/data/${PACKAGE_NAME}/files`;

  const LIBZ = "libz.so";
  const LIBC = "libc.so";
  const LIBART = "libart.so";
  const DEX_MAGIC = 0x0A786564;

  /**
   * 
   * @param {*} address 
   */
  const writeDexToFile = function (address) {
    try {
      let dex_size = Memory.readU32(address.add(0x20));
      let file_name = `${APP_FILES_PATH}/unpacked_${address}_${dex_size.toString(0x10)}.dex`;
      console.log(`[*] Writing dex to ${file_name}`);
      let out = new File(file_name, "wb");
      out.write(Memory.readByteArray(address, dex_size));
      out.close();
    } catch (e) {
      console.log(`[-] ${e}`);
    }
  };

  try {

    // ...and ART runtime only.
    if (!Process.findModuleByName(LIBART)) {
      console.log("[-] This script is compatible with ART runtime ONLY.");
      return;
    }

    if (Process.pointerSize !== 4) {
      console.log("[-] This script is compatible with 32bit process ONLY.");
      return;
    }

    let libart_DexFile_OpenFile_hook = (function () {
      const _address = Module.findExportByName(LIBART,
        "_ZN3art7DexFile8OpenFileEiPKcbPNSt3__112basic_stringIcNS3_11char_traitsIcEENS3_9allocatorIcEEEE");
      let _listener = null;

      return {
        attach: function () {
          _listener = Interceptor.attach(_address, {
            onEnter: function (args) {
              console.log(`[*] Enter art::DexFile::OpenFile`);
              let fd = args[1];
              let location = Memory.readUtf8String(args[2]);

              console.log(`[*] Loading dex from ${location}`);
            },
            onLeave: function (retval) {
              console.log(`[*] Leaving art::DexFile::OpenFile\n`);
            }
          });
        },
        detach: function () {
          _listener.detach();
        }
      };
    })();

    libart_DexFile_OpenFile_hook.attach();

  } catch (e) {
    console.log(`[-] ${e}`);
    // exit.
  }
})();