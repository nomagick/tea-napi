#include <napi.h>
#include <cstdio>
#include <cstdint>

static uint32_t DELTA = 0x9e3779b9;

static size_t TEA_BLOCK_LEN = 8;
static size_t TEA_KEY_LEN = 16;

static void tea_encrypt(uint32_t *v, uint32_t *k, size_t iter) {
    uint32_t v0 = v[0], v1 = v[1], sum = 0, i;           /* set up */
    uint32_t k0 = k[0], k1 = k[1], k2 = k[2], k3 = k[3];   /* cache key */
    for (i = 0; i < iter; i++) {                       /* basic cycle start */
        sum += DELTA;
        v0 += ((v1 << 4) + k0) ^ (v1 + sum) ^ ((v1 >> 5) + k1);
        v1 += ((v0 << 4) + k2) ^ (v0 + sum) ^ ((v0 >> 5) + k3);
    }                                              /* end cycle */
    v[0] = v0;
    v[1] = v1;
}

static void tea_decrypt(uint32_t *v, uint32_t *k, size_t iter) {
    uint32_t v0 = v[0], v1 = v[1], sum = DELTA * iter, i;  /* set up */
    uint32_t k0 = k[0], k1 = k[1], k2 = k[2], k3 = k[3];   /* cache key */
    for (i = 0; i < iter; i++) {                         /* basic cycle start */
        v1 -= ((v0 << 4) + k2) ^ (v0 + sum) ^ ((v0 >> 5) + k3);
        v0 -= ((v1 << 4) + k0) ^ (v1 + sum) ^ ((v1 >> 5) + k1);
        sum -= DELTA;
    }                                              /* end cycle */
    v[0] = v0;
    v[1] = v1;
}

static Napi::Value TeaDecrypt(const Napi::CallbackInfo &info) {
    if (info.Length() != 3) {
        Napi::Error::New(info.Env(), "Expected exactly three argument")
                .ThrowAsJavaScriptException();
        return info.Env().Undefined();
    }
    if (!info[0].IsBuffer()) {
        Napi::Error::New(info.Env(), "Expected first param (value) a Buffer")
                .ThrowAsJavaScriptException();
        return info.Env().Undefined();
    }
    if (!info[1].IsBuffer()) {
        Napi::Error::New(info.Env(), "Expected second param (key) a Buffer")
                .ThrowAsJavaScriptException();
        return info.Env().Undefined();
    }
    if (info[1].As<Napi::Buffer<uint8_t>>().ByteLength() < TEA_KEY_LEN) {
        Napi::Error::New(info.Env(), "Expected second param (key) to be a Buffer at least 16 bytes")
                .ThrowAsJavaScriptException();
        return info.Env().Undefined();
    }
    if (!info[2].IsNumber() && info[2].As<Napi::Number>().Uint32Value() > 0) {
        Napi::Error::New(info.Env(), "Expected third param (iter) an Integer")
                .ThrowAsJavaScriptException();
        return info.Env().Undefined();
    }

    Napi::Buffer<uint8_t> valueBuf = info[0].As<Napi::Buffer<uint8_t>>();
    Napi::Buffer<uint32_t> keyBuf = info[1].As<Napi::Buffer<uint32_t>>();
    size_t iter = info[2].As<Napi::Number>().Uint32Value();

    uint32_t tmp[2] = {0};
    uint32_t key[4] = {0};

    const size_t cnt = valueBuf.ByteLength() / TEA_BLOCK_LEN;

    const uint8_t *rawData = valueBuf.Data();
    const uint32_t *rawKey = keyBuf.Data();

    memcpy((uint32_t *) key, rawKey, TEA_KEY_LEN);

    for (size_t i = 0; i < cnt; ++i) {
        memcpy((uint8_t *) tmp, rawData + i * TEA_BLOCK_LEN, TEA_BLOCK_LEN);
        tea_decrypt(tmp, key, iter);
        memcpy((uint8_t *) rawData + (i * TEA_BLOCK_LEN), tmp, TEA_BLOCK_LEN);
    }

    return valueBuf;
}


static Napi::Value TeaEncrypt(const Napi::CallbackInfo &info) {
    if (info.Length() != 3) {
        Napi::Error::New(info.Env(), "Expected exactly three argument")
                .ThrowAsJavaScriptException();
        return info.Env().Undefined();
    }
    if (!info[0].IsBuffer()) {
        Napi::Error::New(info.Env(), "Expected first param (value) a Buffer")
                .ThrowAsJavaScriptException();
        return info.Env().Undefined();
    }
    if (!info[1].IsBuffer()) {
        Napi::Error::New(info.Env(), "Expected second param (key) a Buffer")
                .ThrowAsJavaScriptException();
        return info.Env().Undefined();
    }
    if (info[1].As<Napi::Buffer<uint8_t>>().ByteLength() < TEA_KEY_LEN) {
        Napi::Error::New(info.Env(), "Expected second param (key) to be a Buffer at least 16 bytes")
                .ThrowAsJavaScriptException();
        return info.Env().Undefined();
    }
    if (!info[2].IsNumber() && info[2].As<Napi::Number>().Uint32Value() > 0) {
        Napi::Error::New(info.Env(), "Expected third param (iter) an Integer")
                .ThrowAsJavaScriptException();
        return info.Env().Undefined();
    }

    Napi::Buffer<uint8_t> valueBuf = info[0].As<Napi::Buffer<uint8_t>>();
    Napi::Buffer<uint32_t> keyBuf = info[1].As<Napi::Buffer<uint32_t>>();
    size_t iter = info[2].As<Napi::Number>().Uint32Value();

    uint32_t tmp[2] = {0};
    uint32_t key[4] = {0};

    const size_t cnt = valueBuf.ByteLength() / TEA_BLOCK_LEN;

    const uint8_t *rawData = valueBuf.Data();
    const uint32_t *rawKey = keyBuf.Data();

    memcpy((uint32_t *) key, rawKey, TEA_KEY_LEN);

    for (size_t i = 0; i < cnt; ++i) {
        memcpy((uint8_t *) tmp, rawData + i * TEA_BLOCK_LEN, TEA_BLOCK_LEN);
        tea_encrypt(tmp, key, iter);
        memcpy((uint8_t *) rawData + (i * TEA_BLOCK_LEN), tmp, TEA_BLOCK_LEN);
    }

    return valueBuf;
}


static Napi::Object Init(Napi::Env env, Napi::Object exports) {
    exports["teaDecrypt"] = Napi::Function::New(env, TeaDecrypt);
    exports["teaEncrypt"] = Napi::Function::New(env, TeaEncrypt);

    exports["TEA_BLOCK_LEN"] = Napi::Number::New(env, TEA_BLOCK_LEN);
    exports["TEA_KEY_LEN"] = Napi::Number::New(env, TEA_KEY_LEN);

    return exports;
}

NODE_API_MODULE(NODE_GYP_MODULE_NAME, Init);
