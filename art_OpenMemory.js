"use strict";

require("./lib/common");

(function () {

  console.log(`[*] Current frida verison: ${Frida.version} on ${Process.arch}\n`);

  const PACKAGE_NAME = "__PACKAGE_NAME__";
  const APP_FILES_PATH = `/data/data/${PACKAGE_NAME}/files`;

  const LIBJIAGU = "libjiagu";
  const LIBZ = "libz.so";
  const LIBC = "libc.so";
  const LIBART = "libart.so";
  const DEX_MAGIC = 0x0A786564;
  const POINTER_SIZE = Process.pointerSize;

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

    if (POINTER_SIZE !== 4) {
      console.log("[-] This script is compatible with 32bit process ONLY.");
      return;
    }

    /**
     * For tracing...
     */
    let libart_OpenDexFilesFromOat_hook = (function () {
      const _address = Module.findExportByName(LIBART, "_ZN3art11ClassLinker19OpenDexFilesFromOatEPKcS2_PNSt3__16vectorINS3_12basic_stringIcNS3_11char_traitsIcEENS3_9allocatorIcEEEENS8_ISA_EEEE");
      let _listener = null;

      return {
        /**
         * std::vector<std::unique_ptr<const DexFile>> ClassLinker::OpenDexFilesFromOat(
         * const char* dex_location, const char* oat_location,
         * std::vector<std::string>* error_msgs)
         */
        attach: function () {
          _listener = Interceptor.attach(_address, {
            onEnter: function (args) {
              // OpenDexFilesFromOat is a Class Method.
              let dex_location = Memory.readUtf8String(args[2]);
              let oat_location = Memory.readUtf8String(args[3]);
              // console.log(`[*] OpenDexFilesFromOat: ${dex_location} ${oat_location}`);
            },
            onLeave: function (retval) {}
          });
        },
        detach: function () {
          _listener.detach();
        }
      };
    })();

    /**
     * Yeah, I found this function, finally.
     */
    let libart_OpenMemory_hook = (function () {
      const _address = Module.findExportByName(LIBART, "_ZN3art7DexFile10OpenMemoryEPKhjRKNSt3__112basic_stringIcNS3_11char_traitsIcEENS3_9allocatorIcEEEEjPNS_6MemMapEPKNS_10OatDexFileEPS9_");
      let _listener = null;
      let _loaded_dex_checksums = [];

      return {
        attach: function () {
          /** std::unique_ptr<const DexFile> DexFile::OpenMemory(const uint8_t* base,
                                                   size_t size,
                                                   const std::string& location,
                                                   uint32_t location_checksum,
                                                   MemMap* mem_map,
                                                   const OatDexFile* oat_dex_file,
                                                   std::string* error_msg)*/
          _listener = Interceptor.attach(_address, {
            onEnter: function (args) {
              console.log(`[*] Enter art::DexFile::OpenMemory`);

              let base = args[1];
              let size = args[2].toInt32();
              let std_str_location = args[3];
              let location_checksum = args[4].toInt32();

              // Tested on 32bit System only, std::string + 8 = raw_string.
              let location = Memory.readUtf8String(
                Memory.readPointer(std_str_location.add(0x2 * POINTER_SIZE)));
              
              // 
              if (location.indexOf(PACKAGE_NAME) === -1) {
                console.log(`[-] Not dynamic loaded dex, ignore.`);
                return;
              }

              console.log(`[*] Loading dex from ${location}`);

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

    libart_OpenDexFilesFromOat_hook.attach();
    libart_OpenMemory_hook.attach();

  } catch (e) {
    console.log(`[-] ${e}`);
    // exit.
  }
})();