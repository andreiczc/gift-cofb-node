#include "wrapper.hpp"
#include <nan.h>

using Nan::GetFunction;
using Nan::New;
using Nan::Set;
using v8::FunctionTemplate;
using v8::String;

NAN_MODULE_INIT(InitAll) {
  Set(target, New<String>("encrypt").ToLocalChecked(),
      GetFunction(New<FunctionTemplate>(Encrypt)).ToLocalChecked());

  Set(target, New<String>("decrypt").ToLocalChecked(),
      GetFunction(New<FunctionTemplate>(Decrypt)).ToLocalChecked());
}

NODE_MODULE(addon, InitAll)