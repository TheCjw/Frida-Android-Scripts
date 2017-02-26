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

  const call_function_symbol = "__dl__ZN6soinfo13call_functionEPKcPFvvE";
  let call_function_ptr = adjustFunctionAddress(
    DebugSymbol.getFunctionByName(call_function_symbol));

  console.log(`[*] Found ${call_function_symbol} at ${call_function_ptr}`);

  Interceptor.attach(call_function_ptr, {
    // http://androidxref.com/6.0.0_r5/xref/bionic/linker/linker.cpp#2219
    // void soinfo::call_function(const char* function_name __unused, linker_function_t function) {
    onEnter: function (args) {
      this.function_address = args[2];
      if (!this.function_address)
        return;

      let range = Process.findRangeByAddress(this.function_address);
      // range.file would not be null.

      // Tested On TXLegu, ARM mode arm32 lib.
      if (range.file.path.indexOf("libshella") === -1)
         return;

      // Tested On Ijiami, Thumb mode arm32 lib.
      // if (range.file.path.indexOf("libexec") === -1)
      //   return;

      try {

        console.log(`[*] Calling ${this.function_address} at ${range.file.path}`);
        let patch_address = this.function_address;
        let infinite_loop_bytes;

        if (this.function_address.toInt32() & 1) {
          // Target function at thumb mode.
          patch_address = patch_address.sub(1);
          // Thumb mode infinite loop opcode: 0xFE, 0xE7
          infinite_loop_bytes = [0xFE, 0xE7];
        } else {
          // Target function at ARM/ARM64 mode.
          infinite_loop_bytes =
            Process.pointerSize == 4 ? [0xFE, 0xFF, 0xFF, 0xEA] : [0x00, 0x00, 0x00, 0x14];
        }

        console.log(`[*] Restore func(${this.function_address}) header with IDAPython:\n` +
          `    PatchDword(GetRegValue("PC"), 0x${Memory.readU32(patch_address).toString(0x10)})`);

        Memory.protect(patch_address, Process.pageSize, "rwx");
        Memory.writeByteArray(patch_address, infinite_loop_bytes);

        Interceptor.detachAll();

        console.log(`[*] Finished. Attach with IDAPro and continue.`);

      } catch (e) {
        console.log(`[-] ${e}`);
      }
    },
    onLeave: function (retval) {
      // TODO:
    }
  });
})();