//  Copyright (c) 2011-present, Facebook, Inc.  All rights reserved.
//  This source code is licensed under both the GPLv2 (found in the
//  COPYING file in the root directory) and Apache 2.0 License
//  (found in the LICENSE.Apache file in the root directory).
//
// Copyright (c) 2011 The LevelDB Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file. See the AUTHORS file for names of contributors.
//
// Logger implementation that uses custom Env object for logging.

#pragma once

#include <time.h>

#include <atomic>
#include <memory>

#include "file/writable_file_writer.h"
#include "logging/file_logger.h"
#include "port/sys_time.h"
#include "rocksdb/slice.h"

namespace ROCKSDB_NAMESPACE {

class EnvLogger : public FileLogger {
 public:
  EnvLogger(std::unique_ptr<FSWritableFile>&& writable_file,
            const std::string& fname, const EnvOptions& options, Env* env,
            InfoLogLevel log_level = InfoLogLevel::ERROR_LEVEL)
      : FileLogger(env->GetSystemClock(), log_level),
        file_(std::move(writable_file), fname, options, env->GetSystemClock()),
        env_(env) {}

  const char* Name() const override { return "EnvLogger"; }

  ~EnvLogger() override { Close().PermitUncheckedError(); }

 protected:
  Status FlushLocked() override { return file_.Flush(); }

  Status CloseLocked() override {
    Status status = file_.Close();
    if (status.ok()) {
      return status;
    } else {
      return Status::IOError(
          "Close of log file failed with error:" +
          (status.getState() ? std::string(status.getState()) : std::string()));
    }
  }

  Status WriteLocked(const char* data, size_t size) override {
    return file_.Append(Slice(data, size));
  }

  uint64_t GetThreadID() const override { return env_->GetThreadID(); }

 private:
  WritableFileWriter file_;
  Env* env_;
};

}  // namespace ROCKSDB_NAMESPACE
