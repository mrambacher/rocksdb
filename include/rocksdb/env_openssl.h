//  copyright (c) 2011-present, Facebook, Inc.  All rights reserved.
//  This source code is licensed under both the GPLv2 (found in the
//  COPYING file in the root directory) and Apache 2.0 License
//  (found in the LICENSE.Apache file in the root directory).

//
// env_encryption.cc copied to this file then modified.

#pragma once

#ifdef ROCKSDB_OPENSSL_AES_CTR
#ifndef ROCKSDB_LITE

#include <openssl/aes.h>
#include <openssl/evp.h>
#include <openssl/rand.h>

#include <algorithm>
#include <cctype>
#include <iostream>
#include <map>

#include "env.h"
#include "rocksdb/env_encryption.h"
#include "util/mutexlock.h"
#endif

namespace ROCKSDB_NAMESPACE {
class UnixLibCrypto;

#ifndef ROCKSDB_LITE

class ShaDescription {
public:
  static Status Create(const std::string& descriptor, ShaDescription *sha);
  static Status Create(const uint8_t* desc, size_t size, ShaDescription *sha);

  ShaDescription() {
    memset(desc, 0, EVP_MAX_MD_SIZE);
    len = 0;
  }

  ShaDescription(const ShaDescription& rhs) { *this = rhs; }

  ShaDescription& operator=(const ShaDescription& rhs) {
    memcpy(desc, rhs.desc, sizeof(desc));
    len = rhs.len;
    return *this;
  }

  ShaDescription(const uint8_t* _desc, size_t _len) {
    assert(_len <= EVP_MAX_MD_SIZE);
    memset(desc, 0, EVP_MAX_MD_SIZE);
    memcpy(desc, _desc, _len);
    len = _len;
  }

  // see AesCtrKey destructor below.  This data is not really
  //  essential to clear, but trying to set pattern for future work.
  // goal is to explicitly remove desc from memory once no longer needed
  ~ShaDescription() {
    memset(desc, 0, EVP_MAX_MD_SIZE);
    len = 0;
  }

  bool operator<(const ShaDescription& rhs) const {
    return memcmp(desc, rhs.desc, EVP_MAX_MD_SIZE) < 0;
  }

  bool operator==(const ShaDescription& rhs) const {
    return 0 == memcmp(desc, rhs.desc, EVP_MAX_MD_SIZE) && len == rhs.len;
  }
  std::string ToString() const;
  uint8_t desc[EVP_MAX_MD_SIZE];
  size_t  len;
};

struct AesCtrKey {
  uint8_t key[EVP_MAX_KEY_LENGTH];
  size_t  len;
  static Status Create(const uint8_t* key_in, size_t key_len, AesCtrKey *aes_key);
  
  AesCtrKey() { memset(key, 0, EVP_MAX_KEY_LENGTH); }

  AesCtrKey(const uint8_t* key_in, size_t key_len)  {
    assert(key_len <= EVP_MAX_KEY_LENGTH);
    memset(key, 0, EVP_MAX_KEY_LENGTH);
    if (key_len <= EVP_MAX_KEY_LENGTH) {
      memcpy(key, key_in, key_len);
      len = key_len;
    }
  }

  // see Writing Solid Code, 2nd edition
  //   Chapter 9, page 321, Managing Secrets in Memory ... bullet 4 "Scrub the
  //   memory"
  // Not saying this is essential or effective in initial implementation since
  // current
  //  usage model loads all keys at start and only deletes them at shutdown. But
  //  does establish presidence.
  // goal is to explicitly remove key from memory once no longer needed
  ~AesCtrKey() {
    memset(key, 0, EVP_MAX_KEY_LENGTH);
    len = 0;
  }

  bool operator==(const AesCtrKey& rhs) const {
    return (0 == memcmp(key, rhs.key, EVP_MAX_KEY_LENGTH)) &&
      (len == rhs.len);
  }
  std::string ToString() const;
};

// code tests for 64 character hex string to yield 32 byte binary key
std::shared_ptr<AesCtrKey> NewAesCtrKey(const std::string& hex_key_str);

class SslAesCtrEncryptionProvider : public EncryptionProvider {
 public:
  explicit SslAesCtrEncryptionProvider(const std::shared_ptr<UnixLibCrypto>& crypto);

  size_t GetPrefixLength() const override;
  const char *Name() const override;

  Status AddCipher(const std::string& descriptor, const char* cipher, size_t cipher_len, bool for_write) override;
  Status CreateNewPrefix(const std::string& /*fname*/, char* prefix,
                         size_t prefixLength) const override;

  Status CreateCipherStream(
      const std::string& /*fname*/, const EnvOptions& /*options*/,
      Slice& /*prefix*/,
      std::unique_ptr<BlockAccessCipherStream>* /*result*/) override;
 protected:
  Status TEST_Initialize() override;
  std::shared_ptr<UnixLibCrypto> crypto_;
  std::map<ShaDescription, AesCtrKey> read_keys_;
  ShaDescription write_key_;
  mutable port::RWMutex key_lock_;
};

#endif  // ROCKSDB_LITE

}  // namespace ROCKSDB_NAMESPACE

#endif  // ROCKSDB_OPENSSL_AES_CTR
