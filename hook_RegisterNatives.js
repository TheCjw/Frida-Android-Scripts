"use strict";

require("./lib/common");

(function () {

  console.log(`[*] Current frida verison: ${Frida.version} on ${Process.arch}\n`);

  const PACKAGE_NAME = "__PACKAGE_NAME__";
  const APP_FILES_PATH = `/data/data/${PACKAGE_NAME}/files`;

  const adjustFunctionAddress = function (address) {
    // Check thumb mode or ARM mode.
    try {
      // Still unstable.
      Instruction.parse(address);
    } catch (e) {
      // Thumb mode here.
      address = address.add(1);
    }
    return address;
  };

  const func_ArtMethod_RegisterNative =
    Module.findExportByName("libart.so", "_ZN3art9ArtMethod14RegisterNativeEPKvb");

  console.log(`[*] ArtMethod::RegisterNative addr: ${func_ArtMethod_RegisterNative}`);

  Interceptor.attach(func_ArtMethod_RegisterNative, {
    onEnter: function (args) {
      let artMethod = args[0];
      let native_method = args[1];
      let is_fast = args[2];

      try {
        let module = Process.getModuleByAddress(native_method);
      } catch (e) {
        // Parse Art Method here.

        let method = {
          "declaring_class_": Memory.readPointer(Memory.readPointer(artMethod.add(Process.pointerSize * 0))),
          "dex_cache_resolved_methods_": Memory.readPointer(artMethod.add(Process.pointerSize * 1)),
          "dex_cache_resolved_types_": Memory.readPointer(artMethod.add(Process.pointerSize * 2)),
          "access_flags_": Memory.readUInt(artMethod.add(Process.pointerSize * 3)),
          "dex_code_item_offset_": Memory.readUInt(artMethod.add(Process.pointerSize * 4)),
          "dex_method_index_": Memory.readUInt(artMethod.add(Process.pointerSize * 5)),
          "method_index_": Memory.readUInt(artMethod.add(Process.pointerSize * 6)),
          "entry_point_from_interpreter_": Memory.readPointer(artMethod.add(Process.pointerSize * 7)),
          "entry_point_from_jni_": Memory.readPointer(artMethod.add(Process.pointerSize * 8)),
          "entry_point_from_quick_compiled_code_": Memory.readPointer(artMethod.add(Process.pointerSize * 9)),
        };

        let r1 = Process.findRangeByAddress(native_method);
        let offset = native_method.sub(r1.base);
        console.log(`[*] Register ${artMethod} to ${native_method}, offset ${offset}, id ${method["dex_method_index_"]}`);
      }
    },
    onLeave: function (retval) {}
  });

})();