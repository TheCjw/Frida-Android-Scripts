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

    let libart_DexFile_OpenMemory_hook = (function () {
      const _address = Module.findExportByName(LIBART,
        "_ZN3art7DexFile10OpenMemoryEPKhjRKNSt3__112basic_stringIcNS3_11char_traitsIcEENS3_9allocatorIcEEEEjPNS_6MemMapEPKNS_10OatDexFileEPS9_");
      let _listener = null;

      return {
        attach: function () {
          _listener = Interceptor.attach(_address, {
            onEnter: function (args) {
              console.log(`[*] Enter art::DexFile::OpenMemory`);

              let base = args[1];
              let size = args[2].toInt32();
              let location_checksum = args[4].toInt32();

              // Tested on 32bit System only, std::string + 8 = raw_string.
              let location = Memory.readUtf8String(
                Memory.readPointer(args[3].add(0x2 * Process.pointerSize)));

              if (location.indexOf(PACKAGE_NAME) === -1) {
                console.log(`[-] Not dynamic loaded dex(${location}), ignore.`);
                return;
              }

              console.log(`[*] Loading dex from ${location}`);
              console.log(`[*] base ${base}, size ${size.toString(0x10)}, checksum ${args[4]}`);
              console.log(hexdump(base, {
                offset: 0,
                length: 0x20,
                header: true,
                ansi: true
              }));

              writeDexToFile(base);
            },
            onLeave: function (retval) {
              console.log(`[*] Leaving art::DexFile::OpenMemory\n`);
            }
          });
        },
        detach: function () {
          _listener.detach();
        }
      };
    })();

    libart_DexFile_OpenMemory_hook.attach();

  } catch (e) {
    console.log(`[-] ${e}`);
    // exit.
  }
})();