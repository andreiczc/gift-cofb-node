#include "gift_cofb.h"
#include "v8.h"
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
  if (keyV8->Length() != BLOCK_SIZE * 2) {
    return Nan::ThrowError(
        Nan::New("Key should have 16 bytes!").ToLocalChecked());
  }

  const auto keyHex = std::unique_ptr<char[]>(new char[keyV8->Length()]);
  keyV8->WriteUtf8(isolate, keyHex.get());

  const auto key = std::unique_ptr<byte[]>(new byte[BLOCK_SIZE]);
  ascii2byte(keyHex.get(), key.get());

  const auto nonceV8 = info[2]->ToString(context).ToLocalChecked();
  if (nonceV8->Length() != BLOCK_SIZE * 2) {
    return Nan::ThrowError(
        Nan::New("Nonce should have 16 bytes!").ToLocalChecked());
  }

  const auto nonceHex = std::unique_ptr<char[]>(new char[nonceV8->Length()]);
  nonceV8->WriteUtf8(isolate, nonceHex.get());

  const auto nonce = std::unique_ptr<byte[]>(new byte[BLOCK_SIZE]);
  ascii2byte(nonceHex.get(), nonce.get());

  const auto adV8 = info[3]->ToString(context).ToLocalChecked();
  if (adV8->Length() > BLOCK_SIZE * 2) {
    return Nan::ThrowError(
        Nan::New("Additional data can't be larger than 16 bytes")
            .ToLocalChecked());
  }

  const auto adHex = std::unique_ptr<char[]>(new char[adV8->Length()]);

  const auto adLength = adV8->Length() / 2;
  const auto ad = std::unique_ptr<byte[]>(new byte[adLength]);
  ascii2byte(adHex.get(), ad.get());

  const auto ciphertext = encrypt(plaintext.get(), plaintextLength, ad.get(),
                                  adLength, nonce.get(), key.get());

  const auto ciphertextHex =
      std::unique_ptr<char[]>(new char[(plaintextLength + BLOCK_SIZE) * 2]);
  byte2ascii(ciphertext.get(), plaintextLength + BLOCK_SIZE,
             ciphertextHex.get());

  const auto returnString =
      v8::String::NewFromUtf8(isolate, ciphertextHex.get());

  info.GetReturnValue().Set(returnString);
}

NAN_METHOD(Decrypt) {
  if (info.Length() != 4 || !info[0]->IsString() || !info[1]->IsString() ||
      !info[2]->IsString() || !info[3]->IsString()) {
    return Nan::ThrowError(Nan::New("Encrypt was called with the wrong number "
                                    "of args. Expected 4 Strings!")
                               .ToLocalChecked());
  }

  const auto isolate = info.GetIsolate();
  const auto context = isolate->GetCurrentContext();

  const auto ciphertextV8 = info[0]->ToString(context).ToLocalChecked();
  const auto ciphertextHex =
      std::unique_ptr<char[]>(new char[ciphertextV8->Length()]);
  ciphertextV8->WriteUtf8(isolate, ciphertextHex.get());

  const auto ciphertextLength = ciphertextV8->Length() / 2;
  const auto ciphertext = std::unique_ptr<byte[]>(new byte[ciphertextLength]);
  ascii2byte(ciphertextHex.get(), ciphertext.get());

  const auto keyV8 = info[1]->ToString(context).ToLocalChecked();
  if (keyV8->Length() != BLOCK_SIZE * 2) {
    return Nan::ThrowError(
        Nan::New("Key should have 16 bytes!").ToLocalChecked());
  }

  const auto keyHex = std::unique_ptr<char[]>(new char[keyV8->Length()]);
  keyV8->WriteUtf8(isolate, keyHex.get());

  const auto key = std::unique_ptr<byte[]>(new byte[BLOCK_SIZE]);
  ascii2byte(keyHex.get(), key.get());

  const auto nonceV8 = info[2]->ToString(context).ToLocalChecked();
  if (nonceV8->Length() != BLOCK_SIZE * 2) {
    return Nan::ThrowError(
        Nan::New("Nonce should have 16 bytes!").ToLocalChecked());
  }

  const auto nonceHex = std::unique_ptr<char[]>(new char[nonceV8->Length()]);
  nonceV8->WriteUtf8(isolate, nonceHex.get());

  const auto nonce = std::unique_ptr<byte[]>(new byte[BLOCK_SIZE]);
  ascii2byte(nonceHex.get(), nonce.get());

  const auto adV8 = info[3]->ToString(context).ToLocalChecked();
  if (adV8->Length() > BLOCK_SIZE * 2) {
    return Nan::ThrowError(
        Nan::New("Additional data can't be larger than 16 bytes")
            .ToLocalChecked());
  }

  const auto adHex = std::unique_ptr<char[]>(new char[adV8->Length()]);

  const auto adLength = adV8->Length() / 2;
  const auto ad = std::unique_ptr<byte[]>(new byte[adLength]);
  ascii2byte(adHex.get(), ad.get());

  const auto plaintext = decrypt(ciphertext.get(), ciphertextLength, ad.get(),
                                 adLength, nonce.get(), key.get());
  const auto plaintextHex =
      std::unique_ptr<char[]>(new char[(ciphertextLength - BLOCK_SIZE) * 2]);
  byte2ascii(plaintext.get(), ciphertextLength - BLOCK_SIZE,
             plaintextHex.get());

  const auto returnString =
      v8::String::NewFromUtf8(isolate, plaintextHex.get());

  info.GetReturnValue().Set(returnString);
}