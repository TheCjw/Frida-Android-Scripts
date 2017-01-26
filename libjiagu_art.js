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

  const LIBJIAGU = "libjiagu";
  const LIBZ = "libz.so";
  const LIBC = "libc.so";

  const allocated_address = [];
  var current_stage = 0;

  const isCallFromAllocatedMemory = function (address) {
    try {
      Process.findModuleByAddress(address);
      return false;
    } catch (error) {
      return true;
    }
  };

  var libc_mmap_hook = (function () {
    const libc_mmap = Module.findExportByName(LIBC, "mmap");
    var _listener = null;

    return {
      attach: function () {
        _listener = Interceptor.attach(libc_mmap, {
          onLeave: function (retval) {
            allocated_address.push(retval.toString());
          }
        });
      },
      detach: function () {
        _listener.detach();
      }
    };
  })();

  var libc_gettimeofday_hook = (function () {
    const libc_gettimeofday = Module.findExportByName(LIBC, "gettimeofday");
    var _listener = null;

    return {
      attach: function () {
        _listener = Interceptor.attach(libc_gettimeofday, {
          onLeave: function (retval) {
            if (!isCallFromAllocatedMemory())
              return;

            switch (current_stage) {
              case 0:
                libc_mmap_hook.attach();
                current_stage = 1;
                break;

              case 1:
                if (allocated_address.length === 0)
                  break;

                libc_mmap_hook.detach();
                libc_gettimeofday_hook.detach();

                current_stage = 2; // 

                console.log("[*] Finished, with {0} address log.".format(allocated_address.length));

                allocated_address.forEach(function (address) {
                  try {
                    let p = new NativePointer(address);
                    if (Memory.readU32(p) === 0)
                      return;

                    console.log(hexdump(p, {
                      offset: 0,
                      length: 0x30,
                      header: true,
                      ansi: true
                    }));
                  } catch (error) {
                    // Ignore invalid ptr.
                  }
                });

                break;

              default:
                break;
            }
          }
        });
      },
      detach: function () {
        _listener.detach();
      }
    };
  })();

  var libz_uncompress_hook = (function () {
    const libz_uncompress = Module.findExportByName(LIBZ, "uncompress");
    var _listener = null;

    return {
      attach: function () {
        /*
        ZEXTERN int ZEXPORT uncompress OF((Bytef *dest,   uLongf *destLen,
                                   const Bytef *source, uLong sourceLen));
        */
        _listener = Interceptor.attach(libz_uncompress, {
          onEnter: function (args) {

            let caller = this.returnAddress.sub(1);
            let module = Process.getModuleByAddress(caller);

            this.is_call_from_libjiagu = module.name.indexOf(LIBJIAGU) !== -1;

            if (!this.is_call_from_libjiagu)
              return;

            // Save args.
            this.dest = args[0];
            this.destLen = args[1];
            this.source = args[2];
            this.sourceLen = args[3];

            console.log("[*] libz#uncompress is calling from {0}({1}).".format(caller, module.name));

            // Arch64 infinite loop
            // Memory.protect(module.base.add(0x5264), 4096, 'rwx');
            // Memory.writeUInt(module.base.add(0x5264), 0x14000000);
          },
          onLeave: function (retval) {

            // Return value is not Z_OK.
            if (!retval.isNull())
              return;

            if (!this.is_call_from_libjiagu)
              return;

            let destLen = Memory.readULong(this.destLen);
            console.log("[*] dest/destLen: {0}, {1}".format(this.dest, destLen.toString(0x10)));
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
            console.log("[*] Save uncompressed so to {0}.".format(output_path));

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

} catch (error) {
  console.log(error);
}