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

#include <stdint.h>
#include <windows.h>

#include "logging/file_logger.h"

namespace ROCKSDB_NAMESPACE {
class SystemClock;

namespace port {
class WinLogger : public ROCKSDB_NAMESPACE::FileLogger {
 public:
  WinLogger(uint64_t (*gettid)(), const std::shared_ptr<SystemClock>& clock,
            HANDLE file,
            const InfoLogLevel log_level = InfoLogLevel::ERROR_LEVEL);

  virtual ~WinLogger();

  WinLogger(const WinLogger&) = delete;

  WinLogger& operator=(const WinLogger&) = delete;
  const char* Name() const override { return "WindowsLogger"; }

 protected:
  virtual uint64_t GetThreadID() const override;
  virtual Status FlushLocked() override;
  virtual Status WriteLocked(const char* data, size_t size) override;
  virtual Status CloseLocked() override;

 private:
  HANDLE file_;
  uint64_t (*gettid_)();  // Return the thread id for the current thread
};
}

}  // namespace ROCKSDB_NAMESPACE
