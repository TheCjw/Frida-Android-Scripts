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
      console.log(`[*] Calling ${this.function_address} at ${range.file.path}`);

      // TODO:
      //  - Patch function_address to infinite loop then use IDA Pro to attach.
    },
    onLeave: function (retval) {
      // TODO:
    }
  });
})();