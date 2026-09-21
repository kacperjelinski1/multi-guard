#include <iostream>
#include <cassert>
#include <cstring>
#include <string>
#include <vector>

extern "C" {
#include "../src/core/tweetnacl.h"
void randombytes(unsigned char *, unsigned long long) {}
}

// Standalone verify function matching Ed25519.cpp
static bool ed25519_verify(const std::string &message,
                           const std::vector<unsigned char> &signature,
                           const std::vector<unsigned char> &publicKey)
{
    if (signature.size() != 64 || publicKey.size() != 32) return false;
    size_t mlen = message.size();
    size_t smlen = 64 + mlen;
    std::vector<unsigned char> sm(smlen);
    memcpy(sm.data(), signature.data(), 64);
    if (mlen > 0) memcpy(sm.data() + 64, message.data(), mlen);
    std::vector<unsigned char> mOut(smlen);
    unsigned long long mlenOut = 0;
    int ret = crypto_sign_open(mOut.data(), &mlenOut, sm.data(), smlen, publicKey.data());
    return (ret == 0 && mlenOut == mlen);
}

static std::vector<unsigned char> hexToBytes(const std::string &hex) {
    std::vector<unsigned char> bytes;
    for (size_t i = 0; i < hex.length(); i += 2) {
        std::string byteString = hex.substr(i, 2);
        unsigned char byte = (unsigned char)strtol(byteString.c_str(), NULL, 16);
        bytes.push_back(byte);
    }
    return bytes;
}

int main() {
    std::cout << "[TEST] Running Ed25519 C++ verification tests..." << std::endl;

    // Test vector from test_tokens.env:
    std::string pubHex = "d47e820c392cece42ede2c2926369b5d9218f9cfdef4c2112117bb3613a7b373";
    std::string tokenAv = "eyJsaWQiOiJsaWMtYXYtMDAxIiwicGlkIjoiOTg0M2Q1ZmQtZjA5MC00NTM0LTlkMzItZDY2YjY0OTk5YWNiIiwicGxuIjoibXVsdGktZ3VhcmQtYXYtMTJtIiwic3RzIjoiYWN0aXZlIiwiZGlkIjoiVEVTVC1NQUNISU5FLUdVSUQtMDAxIiwiaWF0IjoxNzg5OTkwNzM4LCJleHAiOjE3OTI1ODI3MzgsInZ1biI6MTc5MjU4MjczOCwiZ3JjIjowLCJuY2UiOiJ0ZXN0LW5vbmNlLTEyMzQ1IiwiZnByIjoiMjZmNDNhMTcxODQ4OGU3YyJ9.r5Cr9l27z6A5CpSZ3Yn7_J5hek4-dKKqrV20jmFTZ8nyqQL7t5tJ284PogH6kKzte6WhVfMezaruhFaQMEheAA";

    size_t dotPos = tokenAv.find('.');
    assert(dotPos != std::string::npos);
    std::string payloadB64 = tokenAv.substr(0, dotPos);
    std::string sigB64 = tokenAv.substr(dotPos + 1);

    // base64url decode sig
    // sigB64: r5Cr9l27z6A5CpSZ3Yn7_J5hek4-dKKqrV20jmFTZ8nyqQL7t5tJ284PogH6kKzte6WhVfMezaruhFaQMEheAA
    // In raw hex (from Go test):
    auto pubKey = hexToBytes(pubHex);

    // We can decode base64url:
    std::string s = sigB64;
    for (char &c : s) {
        if (c == '-') c = '+';
        else if (c == '_') c = '/';
    }
    while (s.size() % 4 != 0) s.push_back('=');

    // Decode base64
    const std::string b64Chars = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    std::vector<unsigned char> sigBytes;
    int val = 0, valb = -8;
    for (unsigned char c : s) {
        if (c == '=') break;
        size_t idx = b64Chars.find(c);
        if (idx == std::string::npos) continue;
        val = (val << 6) + idx;
        valb += 6;
        if (valb >= 0) {
            sigBytes.push_back((val >> valb) & 0xFF);
            valb -= 8;
        }
    }

    assert(sigBytes.size() == 64);
    assert(pubKey.size() == 32);

    // Test 1: Valid signature
    bool valid = ed25519_verify(payloadB64, sigBytes, pubKey);
    assert(valid == true);
    std::cout << "  [PASS] Test 1: Valid Ed25519 signature verified successfully." << std::endl;

    // Test 2: Tampered payload
    std::string tamperedPayload = payloadB64;
    tamperedPayload[10] ^= 0x01;
    bool tamperedValid = ed25519_verify(tamperedPayload, sigBytes, pubKey);
    assert(tamperedValid == false);
    std::cout << "  [PASS] Test 2: Tampered payload rejected as invalid." << std::endl;

    // Test 3: Tampered signature
    std::vector<unsigned char> tamperedSig = sigBytes;
    tamperedSig[0] ^= 0xFF;
    bool tamperedSigValid = ed25519_verify(payloadB64, tamperedSig, pubKey);
    assert(tamperedSigValid == false);
    std::cout << "  [PASS] Test 3: Tampered signature rejected as invalid." << std::endl;

    std::cout << "[SUCCESS] All Ed25519 C++ unit tests passed!" << std::endl;
    return 0;
}
