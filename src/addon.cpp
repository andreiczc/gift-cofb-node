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
}

NODE_MODULE(addon, InitAll)