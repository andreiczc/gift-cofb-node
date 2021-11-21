#include "gift_cofb.h"
#include <memory>
#include <nan.h>

extern "C" {
#include "crypto_utils.h"
}

#include "cipher.hpp"
#include "wrapper.hpp"

NAN_METHOD(Encrypt) {
  if (info.Length() != 4 || !info[0]->IsString() || !info[1]->IsString() ||
      !info[2]->IsString() || !info[3]->IsString()) {
    return Nan::ThrowError(Nan::New("Encrypt was called with the wrong number "
                                    "of args. Expected 4 Strings!")
                               .ToLocalChecked());
  }

  const auto isolate = info.GetIsolate();
  const auto context = isolate->GetCurrentContext();

  const auto plaintextV8 = info[0]->ToString(context).ToLocalChecked();
  const auto plaintextHex =
      std::unique_ptr<char[]>(new char[plaintextV8->Length()]);
  plaintextV8->WriteUtf8(isolate, plaintextHex.get());

  const auto plaintextLength = plaintextV8->Length() / 2;
  const auto plaintext = std::unique_ptr<byte[]>(new byte[plaintextLength]);
  ascii2byte(plaintextHex.get(), plaintext.get());

  const auto keyV8 = info[1]->ToString(context).ToLocalChecked();
  const auto keyHex = std::unique_ptr<char[]>(new char[keyV8->Length()]);
  keyV8->WriteUtf8(isolate, keyHex.get());

  const auto key = std::unique_ptr<byte[]>(new byte[BLOCK_SIZE]);
  ascii2byte(keyHex.get(), key.get());

  const auto nonceV8 = info[2]->ToString(context).ToLocalChecked();
  const auto nonceHex = std::unique_ptr<char[]>(new char[nonceV8->Length()]);
  nonceV8->WriteUtf8(isolate, nonceHex.get());

  const auto nonce = std::unique_ptr<byte[]>(new byte[BLOCK_SIZE]);
  ascii2byte(nonceHex.get(), nonce.get());

  const auto adV8 = info[3]->ToString(context).ToLocalChecked();
  const auto adHex = std::unique_ptr<char[]>(new char[adV8->Length()]);

  const auto adLength = adV8->Length() / 2;
  const auto ad = std::unique_ptr<byte[]>(new byte[adLength]);
  ascii2byte(adHex.get(), ad.get());

  const auto ciphertext =
      std::unique_ptr<byte[]>(new byte[plaintextLength + BLOCK_SIZE]);
  auto ciphertextLength = 0ull;

  crypto_aead_encrypt(ciphertext.get(), &ciphertextLength, plaintext.get(),
                      plaintextLength, ad.get(), adLength, nonce.get(),
                      key.get());

  const auto returnString = v8::String::NewFromUtf8(isolate, "abc");

  info.GetReturnValue().Set(returnString);
}