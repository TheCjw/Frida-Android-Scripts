"use strict";

require("./lib/common");

const PACKAGE_NAME = "__PACKAGE_NAME__";
const APP_FILES_PATH = `/data/data/${PACKAGE_NAME}/files`;

try {

  const LIBJIAGU = "libjiagu";
  const LIBZ = "libz.so";
  const LIBC = "libc.so";
  const LIBART = "libart.so";

  var libc_mmap_hook = (function () {
    const _address = Module.findExportByName(LIBC, "mmap");
    var _listener = null;

    return {
      attach: function () {
        _listener = Interceptor.attach(_address, {
          onLeave: function (retval) {}
        });
      },
      detach: function () {
        _listener.detach();
      }
    };
  })();

  var libc_gettimeofday_hook = (function () {
    const _address = Module.findExportByName(LIBC, "gettimeofday");
    var _listener = null;

    return {
      attach: function () {
        _listener = Interceptor.attach(_address, {
          onEnter: function (args) {
            try {
              let range = Process.findRangeByAddress(this.returnAddress);

              if (!range.file) {
                _listener.detach();
                console.log("[*] Phase 2 starting...");
                console.log(`[*] Internal libjiagu.so range: ${range.base} - ${range.size.toString(0x10)}`);

                Memory.protect(range.base, range.size, "rwx");

                // TODO: 
              }

            } catch (error) {
              //
            }
          }
        });
      },
      detach: function () {
        _listener.detach();
      }
    };
  })();

  var libc_open_hook = (function () {
    const _address = Module.findExportByName(LIBC, "open");
    var _listener = null;

    return {
      attach: function () {
        _listener = Interceptor.attach(_address, {
          onEnter: function (args) {
            // let path = Memory.readUtf8String(args[0]);
          },
          onLeave: function (retval) {}
        });
      },
      detach: function () {
        _listener.detach();
      }
    };
  })();

  var libz_uncompress_hook = (function () {
    const _address = Module.findExportByName(LIBZ, "uncompress");
    var _listener = null;

    return {
      attach: function () {
        /*
        ZEXTERN int ZEXPORT uncompress OF((Bytef *dest,   uLongf *destLen,
                                          const Bytef *source, uLong sourceLen));
        */
        _listener = Interceptor.attach(_address, {
          onEnter: function (args) {

            let module = Process.getModuleByAddress(this.returnAddress);
            this.is_call_from_libjiagu = module.name.startsWith(LIBJIAGU);

            if (!this.is_call_from_libjiagu)
              return;

            // Save args.
            this.dest = args[0];
            this.destLen = args[1];
            this.source = args[2];
            this.sourceLen = args[3];

            console.log(`[*] libz#uncompress is calling from ${this.returnAddress}(${module.name}).`);
          },
          onLeave: function (retval) {

            // Return value is not Z_OK.
            if (!retval.isNull())
              return;

            if (!this.is_call_from_libjiagu)
              return;

            let destLen = Memory.readULong(this.destLen);
            console.log(`[*] dest/destLen: ${this.dest}, ${destLen.toString(0x10)}`);
            console.log(`[*] source/sourceLen: ${this.source}, ${this.sourceLen}`);

            console.log(hexdump(this.dest, {
              offset: 0,
              length: 0x30,
              header: true,
              ansi: true
            }));

            let output_path = `${APP_FILES_PATH}/unpacked_libjiagu.so`;
            let out = new File(output_path, "wb");
            out.write(Memory.readByteArray(this.dest, destLen));
            out.close();
            console.log(`[*] Save uncompressed so to ${output_path}.`);

            _listener.detach();

            // Phase 2 start.
            libc_gettimeofday_hook.attach();
          }
        });
      },
      detach: function () {
        _listener.detach();
      }
    };
  })();

  // Phase 1 start.
  libz_uncompress_hook.attach();

} catch (e) {
  console.log(`[-] Exception: ${e}`);
}
