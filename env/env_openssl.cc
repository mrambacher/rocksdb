//  Copyright (c) 2011-present, Facebook, Inc.  All rights reserved.
//  This source code is licensed under both the GPLv2 (found in the
//  COPYING file in the root directory) and Apache 2.0 License
//  (found in the LICENSE.Apache file in the root directory).

//
//  env_encryption.cc copied to this file then modified.

#include <algorithm>
#include <cctype>
#include <iostream>
#include <mutex>

#include "env/env_openssl_impl.h"
#include "monitoring/perf_context_imp.h"
#include "port/port.h"
#include "util/aligned_buffer.h"
#include "util/coding.h"
#include "util/library_loader.h"
#include "util/mutexlock.h"
#include "util/random.h"

namespace ROCKSDB_NAMESPACE {
#ifdef ROCKSDB_OPENSSL_AES_CTR
#ifndef ROCKSDB_LITE

const std::shared_ptr<UnixLibCrypto> & GetCrypto() {
  static std::once_flag crypto_loaded;
  static std::shared_ptr<UnixLibCrypto> crypto_shared;
  
  std::call_once(crypto_loaded,
                 []() { crypto_shared = std::make_shared<UnixLibCrypto>(); });
  return crypto_shared;
}

// reuse cipher context between calls to Encrypt & Decrypt
static void do_nothing(EVP_CIPHER_CTX*){};
thread_local static std::unique_ptr<EVP_CIPHER_CTX, void (*)(EVP_CIPHER_CTX*)>
    aes_context(nullptr, &do_nothing);

Status ShaDescription::Create(const uint8_t* desc, size_t len, ShaDescription *sha) {
  if (len > EVP_MAX_MD_SIZE) {
    return Status::InvalidArgument("Size is too big");
  } else {
    memset(sha->desc, 0, EVP_MAX_MD_SIZE);
    memcpy(sha->desc, desc, len);
    sha->len = len;
    return Status::OK();
  }
}

std::string ShaDescription::ToString() const {
  Slice s(reinterpret_cast<const char*>(desc), len);
  return s.ToString(true);
}

Status ShaDescription::Create(const std::string& key_desc, ShaDescription* result) {
  auto & crypto = GetCrypto();  // ensure libcryto available

  if (! crypto->IsValid()) {
    return Status::NotSupported("Could not load crypto libraries");
  } else if (key_desc.length() <= 0) {
    return Status::InvalidArgument("Key descriptor too short");
  } else {
    memset(result->desc, 0, EVP_MAX_MD_SIZE);
    std::unique_ptr<EVP_MD_CTX, void (*)(EVP_MD_CTX*)> context(
        crypto->EVP_MD_CTX_new(), crypto->EVP_MD_CTX_free_ptr());

    int ret_val = crypto->EVP_DigestInit_ex(context.get(), crypto->EVP_sha1(), nullptr);
    if (ret_val == 1) {
      ret_val = crypto->EVP_DigestUpdate(context.get(), key_desc.c_str(), key_desc.length());
    }
    if (ret_val == 1) {
      unsigned len;
      ret_val = crypto->EVP_DigestFinal_ex(context.get(), result->desc, &len);
      if (ret_val == 1) {
        result->len = static_cast<size_t>(len);
      }
    }
    if (ret_val == 1) {
      return Status::OK();
    } else {
      return Status::OK(); //**MJR: TODO: What code should be returned?
    }
  }
}

Status AesCtrKey::Create(const uint8_t * cipher, size_t cipher_len, AesCtrKey *result) {
  memset(result->key, 0, EVP_MAX_KEY_LENGTH);
  if (cipher_len <= EVP_MAX_KEY_LENGTH) {
    memcpy(result->key, cipher, cipher_len);
    result->len = cipher_len;
    return Status::OK();
  } else {
    return Status::InvalidArgument("Key too long");
  }   
}

std::string AesCtrKey::ToString() const {
  Slice s(reinterpret_cast<const char*>(key), len);
  return s.ToString(true);
}
  
#ifdef MJR 
AesCtrKey::AesCtrKey(const std::string& key_str) : valid(false) {
  GetCrypto();  // ensure libcryto available
  memset(key, 0, EVP_MAX_KEY_LENGTH);

  // simple parse:  must be 64 characters long and hexadecimal values
  if (64 == key_str.length()) {
    auto bad_pos = key_str.find_first_not_of("abcdefABCDEF0123456789");
    if (std::string::npos == bad_pos) {
      for (size_t idx = 0, idx2 = 0; idx < key_str.length(); idx += 2, ++idx2) {
        std::string hex_string(key_str.substr(idx, 2));
        key[idx2] = std::stoul(hex_string, 0, 16);
      }
      valid = true;
    }
  }
}
#endif // MJR
 
Status AESBlockAccessCipherStream::CreateCipherStream(const AesCtrKey& key,
                                                       const uint8_t nonce[],
                                                       std::unique_ptr<BlockAccessCipherStream>* result) {
  const auto & crypto = GetCrypto();
  if (crypto->IsValid()) {
    result->reset(new AESBlockAccessCipherStream(crypto, key, nonce));
    return Status::OK();
  } else {
    return Status::NotSupported("libcrypto not available for encryption/decryption.");
  }
}

void AESBlockAccessCipherStream::BigEndianAdd128(uint8_t* buf, uint64_t value) {
  uint8_t *sum, *addend, *carry, pre, post;

  sum = buf + 15;

  if (port::kLittleEndian) {
    addend = (uint8_t*)&value;
  } else {
    addend = (uint8_t*)&value + 7;
  }

  // future:  big endian could be written as uint64_t add
  for (int loop = 0; loop < 8 && value; ++loop) {
    pre = *sum;
    *sum += *addend;
    post = *sum;
    --sum;
    value >>= 8;

    carry = sum;
    // carry?
    while (post < pre && buf <= carry) {
      pre = *carry;
      *carry += 1;
      post = *carry;
      --carry;
    }
  }  // for
}

// "data" is assumed to be aligned at AES_BLOCK_SIZE or greater
Status AESBlockAccessCipherStream::Encrypt(uint64_t file_offset, char* data,
                                           size_t data_size) {
  Status status;
  if (0 < data_size) {
    int ret_val, out_len;
    ALIGN16 uint8_t iv[AES_BLOCK_SIZE];
    uint64_t block_index = file_offset / BlockSize();
    
    // make a context once per thread
    if (!aes_context) {
      aes_context =
        std::unique_ptr<EVP_CIPHER_CTX, void (*)(EVP_CIPHER_CTX*)>(
                crypto_->EVP_CIPHER_CTX_new(),
                crypto_->EVP_CIPHER_CTX_free_ptr());
    }
    
    memcpy(iv, nonce_, AES_BLOCK_SIZE);
    BigEndianAdd128(iv, block_index);
    
    ret_val = crypto_->EVP_EncryptInit_ex(
                                          aes_context.get(), crypto_->EVP_aes_256_ctr(), nullptr,
                                          key_.key, iv);
    if (1 == ret_val) {
      out_len = 0;
      ret_val = crypto_->EVP_EncryptUpdate(
                                           aes_context.get(), (unsigned char*)data, &out_len,
                                           (unsigned char*)data, (int)data_size);
      
      if (1 == ret_val && (int)data_size == out_len) {
        // this is a soft reset of aes_context per man pages
        uint8_t temp_buf[AES_BLOCK_SIZE];
        out_len = 0;
        ret_val = crypto_->EVP_EncryptFinal_ex(aes_context.get(),
                                               temp_buf, &out_len);
        
        if (1 != ret_val || 0 != out_len) {
          status = Status::InvalidArgument(
                                           "EVP_EncryptFinal_ex failed: ",
                                           (1 != ret_val) ? "bad return value" : "output length short");
        }
      } else {
        status = Status::InvalidArgument("EVP_EncryptUpdate failed: ",
                                         (int)data_size == out_len
                                         ? "bad return value"
                                         : "output length short");
      }
    } else {
      status = Status::InvalidArgument("EVP_EncryptInit_ex failed.");
    }
  }
  return status;
}

// Decrypt one or more (partial) blocks of data at the file offset.
//  Length of data is given in data_size.
//  CTR Encrypt and Decrypt are synonyms.  Using Encrypt calls here to reduce
//   count of symbols loaded from libcrypto.
Status AESBlockAccessCipherStream::Decrypt(uint64_t file_offset, char* data,
                                           size_t data_size) {
  // Calculate block index
  size_t block_size = BlockSize();
  uint64_t block_index = file_offset / block_size;
  size_t block_offset = file_offset % block_size;
  size_t remaining = data_size;
  size_t prefix_size = 0;
  uint8_t temp_buf[block_size];

  Status status;
  ALIGN16 uint8_t iv[AES_BLOCK_SIZE];
  int out_len = 0, ret_val;

  // make a context once per thread
  if (!aes_context) {
    aes_context = std::unique_ptr<EVP_CIPHER_CTX,
                                  void (*)(EVP_CIPHER_CTX*)>(
                                                             crypto_->EVP_CIPHER_CTX_new(),
                                                             crypto_->EVP_CIPHER_CTX_free_ptr());
  }

  memcpy(iv, nonce_, AES_BLOCK_SIZE);
  BigEndianAdd128(iv, block_index);
  
  ret_val = crypto_->EVP_EncryptInit_ex(aes_context.get(), crypto_->EVP_aes_256_ctr(), nullptr,
                                        key_.key, iv);
  if (1 == ret_val) {
    // handle uneven block start
    if (0 != block_offset) {
      prefix_size = block_size - block_offset;
      if (data_size < prefix_size) {
        prefix_size = data_size;
      }
      
      memcpy(temp_buf + block_offset, data, prefix_size);
      out_len = 0;
      ret_val = crypto_->EVP_EncryptUpdate(aes_context.get(), temp_buf, &out_len, temp_buf, (int)block_size);

      if (1 != ret_val || (int)block_size != out_len) {
        status = Status::InvalidArgument("EVP_EncryptUpdate failed 1: ",
                                         (int)block_size == out_len
                                         ? "bad return value"
                                         : "output length short");
      } else {
        memcpy(data, temp_buf + block_offset, prefix_size);
      }
    }
    
    // all remaining data, even block size not required
    remaining -= prefix_size;
    if (status.ok() && remaining) {
      out_len = 0;
      ret_val = crypto_->EVP_EncryptUpdate(
            aes_context.get(), (uint8_t*)data + prefix_size, &out_len,
            (uint8_t*)data + prefix_size, (int)remaining);
      
      if (1 != ret_val || (int)remaining != out_len) {
        status = Status::InvalidArgument("EVP_EncryptUpdate failed 2: ",
                                           (int)remaining == out_len
                                         ? "bad return value"
                                         : "output length short");
      }
    }
    
    // this is a soft reset of aes_context per man pages
    out_len = 0;
    ret_val = crypto_->EVP_EncryptFinal_ex(aes_context.get(), temp_buf,
                                           &out_len);
    
    if (1 != ret_val || 0 != out_len) {
      status = Status::InvalidArgument("EVP_EncryptFinal_ex failed.");
    }
  } else {
    status = Status::InvalidArgument("EVP_EncryptInit_ex failed.");
  }
  return status;
}

SslAesCtrEncryptionProvider::SslAesCtrEncryptionProvider(const std::shared_ptr<UnixLibCrypto>& crypto)
  : crypto_(crypto) {
}
  
Status SslAesCtrEncryptionProvider::TEST_Initialize() {
// this key is from
// https://nvlpubs.nist.gov/nistpubs/Legacy/SP/nistspecialpublication800-38a.pdf,
//  example F.5.5
  static uint8_t key256[] = {0x60, 0x3d, 0xeb, 0x10, 0x15, 0xca, 0x71, 0xbe,
                             0x2b, 0x73, 0xae, 0xf0, 0x85, 0x7d, 0x77, 0x81,
                             0x1f, 0x35, 0x2c, 0x07, 0x3b, 0x61, 0x08, 0xd7,
                             0x2d, 0x98, 0x10, 0xa3, 0x09, 0x14, 0xdf, 0xf4};
  return AddCipher("Test Key Name", (char*) key256, sizeof(key256), true);
}
  
const char* SslAesCtrEncryptionProvider::Name() const {
  return "SSL-AES-CTR";
}
  
Status SslAesCtrEncryptionProvider::AddCipher(const std::string& descriptor, const char* cipher,
                                          size_t cipher_len, bool for_write) {
  AesCtrKey key;
  ShaDescription sha1;

  const uint8_t *bytes = reinterpret_cast<const uint8_t*>(cipher);
  Status s = AesCtrKey::Create(bytes, cipher_len, &key);
  if (s.ok()) {
    s = ShaDescription::Create(descriptor, &sha1);
  }
  if (s.ok()) {
    WriteLock lock(&key_lock_);    
    if (for_write) {
      write_key_ = sha1;
    }
    read_keys_[sha1] = key;
  }
  return s;
}

Status SslAesCtrEncryptionProvider::CreateNewPrefix(const std::string& /*fname*/,
                                                char* prefix,
                                                size_t prefixLength) const {
  Status s = Status::OK();;
  if (sizeof(PrefixVersion0) <= prefixLength) {
    ReadLock lock(&key_lock_);    
    const auto & iter = read_keys_.find(write_key_);
    if (iter == read_keys_.end()) {
      s = Status::NotFound("No key for write");
    } else {
      memcpy(prefix, kEncryptMarker, sizeof(EncryptMarker));
      PrefixVersion0* pf = reinterpret_cast<PrefixVersion0*>(prefix + sizeof(EncryptMarker));
      memcpy(pf->descriptor, write_key_.desc, sizeof(write_key_.desc));
      int ret_val = crypto_->RAND_bytes((unsigned char*)&pf->nonce, AES_BLOCK_SIZE);
      if (1 != ret_val) {
        s = Status::NotSupported("RAND_bytes failed");
      }
    }
  } else {
    s = Status::NotSupported("Prefix size needs to be 28 or more");
  }
  return s;
}

size_t SslAesCtrEncryptionProvider::GetPrefixLength() const {
  return sizeof(PrefixVersion0)  + sizeof(EncryptMarker);
}

Status SslAesCtrEncryptionProvider::CreateCipherStream(
      const std::string& /*fname*/, const EnvOptions& /*options*/,
      Slice& prefix,
      std::unique_ptr<BlockAccessCipherStream>* result) {
  const auto pv0 = reinterpret_cast<const PrefixVersion0*>(prefix.data() + sizeof(EncryptMarker));
  ShaDescription desc(pv0->descriptor, EVP_MAX_MD_SIZE);
  ReadLock lock(&key_lock_);
  const auto & iter = read_keys_.find(desc);
  printf("Looking for read key [%s] found=%d\n", desc.ToString().c_str(), iter != read_keys_.end());
  if (iter != read_keys_.end()) {
    result->reset(new AESBlockAccessCipherStream(crypto_, iter->second, pv0->nonce));
    return Status::OK();
  } else {
    return Status::NotFound("Key not found");
  }
}

#endif  // ROCKSDB_LITE
#endif  // ROCKSDB_OPENSSL_AES_CTR

Status CreateSslAesCtrProvider(const ConfigOptions& /*config_options*/,
                               const std::string& /*value*/,
                               std::shared_ptr<EncryptionProvider>* provider) {
  provider->reset();
#ifdef ROCKSDB_LITE
  return Status::NotSupported("SSL not supported in LITE mode");
#endif // ROCKSDB_LITE
#ifndef ROCKSDB_OPENSSL_AES_CTR
  return Status::NotSupported("SSL not supported in LITE mode");
#else
  auto & crypto = GetCrypto();
  if (crypto->IsValid()) {
    provider->reset(new SslAesCtrEncryptionProvider(crypto));
    return Status::OK();
  } else {
    return Status::NotSupported("Could not load crypt libraries");
  }
#endif  // ROCKSDB_OPENSSL_AES_CTR
}
}  // namespace ROCKSDB_NAMESPACE

