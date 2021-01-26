//  Copyright (c) 2011-present, Facebook, Inc.  All rights reserved.
//  This source code is licensed under both the GPLv2 (found in the
//  COPYING file in the root directory) and Apache 2.0 License
//  (found in the LICENSE.Apache file in the root directory).
//
// Copyright (c) 2011 The LevelDB Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file. See the AUTHORS file for names of contributors.
//
// Logger implementation that can be shared by all environments
// where enough posix functionality is available.

#pragma once
#include <algorithm>
#include <stdio.h>
#include "port/sys_time.h"
#include <time.h>
#include <fcntl.h>

#ifdef OS_LINUX
#ifndef FALLOC_FL_KEEP_SIZE
#include <linux/falloc.h>
#endif
#endif

#include <atomic>

#include "logging/file_logger.h"
#include "rocksdb/env.h"

namespace ROCKSDB_NAMESPACE {
class SystemClock;

class PosixLogger : public FileLogger {
 private:
  FILE* file_;
  uint64_t (*gettid_)();  // Return the thread id for the current thread
  int fd_;

 protected:
  Status CloseLocked() override {
    int ret = fclose(file_);
    if (ret) {
      return IOError("Unable to close log file", "", ret);
    }
    return Status::OK();
  }

  Status FlushLocked() override {
    fflush(file_);
    return Status::OK();
  }

  Status WriteLocked(const char* data, size_t size) override {
#ifdef ROCKSDB_FALLOCATE_PRESENT
    const int kDebugLogChunkSize = 128 * 1024;

    // If this write would cross a boundary of kDebugLogChunkSize
    // space, pre-allocate more space to avoid overly large
    // allocations from filesystem allocsize options.
    const size_t log_size = log_size_;
    const size_t last_allocation_chunk =
        ((kDebugLogChunkSize - 1 + log_size) / kDebugLogChunkSize);
    const size_t desired_allocation_chunk =
        ((kDebugLogChunkSize - 1 + log_size + size) / kDebugLogChunkSize);
    if (last_allocation_chunk != desired_allocation_chunk) {
      fallocate(
          fd_, FALLOC_FL_KEEP_SIZE, 0,
          static_cast<off_t>(desired_allocation_chunk * kDebugLogChunkSize));
    }
#endif

    size_t sz = fwrite(data, 1, size, file_);
    if (sz > 0) {
      return Status::OK();
    } else {
      return Status::IOError("Failed to write posix logger");
    }
  }

  uint64_t GetThreadID() const override { return gettid_(); }

 public:
  PosixLogger(FILE* f, uint64_t (*gettid)(),
              const std::shared_ptr<SystemClock>& clock,
              const InfoLogLevel log_level = InfoLogLevel::ERROR_LEVEL)
      : FileLogger(clock, log_level),
        file_(f),
        gettid_(gettid),
        fd_(fileno(f)) {}

  ~PosixLogger() override { Close().PermitUncheckedError(); }

  static const char* kName() { return "PosixLogger"; }
  const char* Name() const override { return kName(); }
};

}  // namespace ROCKSDB_NAMESPACE
