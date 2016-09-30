(function() {
    "use strict";

    // Copy from https://stackoverflow.com/questions/951021/what-do-i-do-if-i-want-a-javascript-version-of-sleep
    function sleep(time) {
        return new Promise((resolve) => setTimeout(resolve, time));
    }

    // Waiting for libmono loading.

    var libmono_base = null;
    while (true) {
        sleep(100);
        libmono_base = Module.findBaseAddress("libmono.so");
        if (libmono_base != null) {
            break;
        }
    }

    console.log("libmono base address: " + libmono_base);

    // https://github.com/mono/mono/blob/0e97e079fa6f90c2bf864d315a2e2c8bf8ca7410/mono/metadata/image.c#L1272
    // mono_image_open_from_data_internal (char *data,
    // guint32 data_len,
    // gboolean need_copy,
    // MonoImageOpenStatus *status,
    // gboolean refonly,
    // gboolean metadata_only,
    // const char *name)
    var func_mono_image_open_from_data_with_name = new NativeFunction(
        Module.findExportByName("libmono.so", "mono_image_open_from_data_with_name"), "pointer", ["pointer", "uint32", "uint32", "pointer", "uint32", "uint32", "pointer"]);
    console.log("mono_image_open_from_data_with_name: " + func_mono_image_open_from_data_with_name);

    try {
        Interceptor.attach(func_mono_image_open_from_data_with_name, {
            onEnter: function(args) {
                try {
                    let ptr_assembly_name = Memory.readUtf8String(args[5]);
                    console.log(ptr_assembly_name);
                    if (ptr_assembly_name.indexOf("Assembly-CSharp.dll") != -1) {
                        this.data = args[0];
                        this.size = args[1];
                    }
                } catch (e) {
                    console.log(e);
                }
            },
            onLeave: function(retval) {
                try {
                    if (this.data != null) {
                        console.log(this.data + " " + this.size);
                        var out = new File("/sdcard/holyshit.dll", "wb");
                        out.write(Memory.readByteArray(this.data, this.size.toInt32()));
                        out.close();
                    }
                } catch (e) {
                    console.log(e);
                }
            }
        });
    } catch (e) {
        console.log(e);
    }
})();
