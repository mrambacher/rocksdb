// Copyright (c) 2011-present, Facebook, Inc.  All rights reserved.
//  This source code is licensed under both the GPLv2 (found in the
//  COPYING file in the root directory) and Apache 2.0 License
//  (found in the LICENSE.Apache file in the root directory).
// Copyright (c) 2011 The LevelDB Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file. See the AUTHORS file for names of contributors.
//
// An Env is an interface used by the rocksdb implementation to access
// operating system functionality like the filesystem etc.  Callers
// may wish to provide a custom Env object when opening a database to
// get fine gain control; e.g., to rate limit file system operations.
//
// All Env implementations are safe for concurrent access from
// multiple threads without any external synchronization.

#pragma once

#include <limits>
#include <memory>

#include "rocksdb/rocksdb_namespace.h"
#include "rocksdb/status.h"

#if defined(__GNUC__) || defined(__clang__)
#define ROCKSDB_PRINTF_FORMAT_ATTR(format_param, dots_param) \
  __attribute__((__format__(__printf__, format_param, dots_param)))
#else
#define ROCKSDB_PRINTF_FORMAT_ATTR(format_param, dots_param)
#endif

namespace ROCKSDB_NAMESPACE {
class Env;
class Logger;

enum InfoLogLevel : unsigned char {
  DEBUG_LEVEL = 0,
  INFO_LEVEL,
  WARN_LEVEL,
  ERROR_LEVEL,
  FATAL_LEVEL,
  HEADER_LEVEL,
  NUM_INFO_LOG_LEVELS,
};

extern void LogFlush(const std::shared_ptr<Logger>& info_log);

extern void Log(const InfoLogLevel log_level,
                const std::shared_ptr<Logger>& info_log, const char* format,
                ...) ROCKSDB_PRINTF_FORMAT_ATTR(3, 4);

// a set of log functions with different log levels.
extern void Header(const std::shared_ptr<Logger>& info_log, const char* format,
                   ...) ROCKSDB_PRINTF_FORMAT_ATTR(2, 3);
extern void Debug(const std::shared_ptr<Logger>& info_log, const char* format,
                  ...) ROCKSDB_PRINTF_FORMAT_ATTR(2, 3);
extern void Info(const std::shared_ptr<Logger>& info_log, const char* format,
                 ...) ROCKSDB_PRINTF_FORMAT_ATTR(2, 3);
extern void Warn(const std::shared_ptr<Logger>& info_log, const char* format,
                 ...) ROCKSDB_PRINTF_FORMAT_ATTR(2, 3);
extern void Error(const std::shared_ptr<Logger>& info_log, const char* format,
                  ...) ROCKSDB_PRINTF_FORMAT_ATTR(2, 3);
extern void Fatal(const std::shared_ptr<Logger>& info_log, const char* format,
                  ...) ROCKSDB_PRINTF_FORMAT_ATTR(2, 3);

// Log the specified data to *info_log if info_log is non-nullptr.
// The default info log level is InfoLogLevel::INFO_LEVEL.
extern void Log(const std::shared_ptr<Logger>& info_log, const char* format,
                ...) ROCKSDB_PRINTF_FORMAT_ATTR(2, 3);

extern void LogFlush(Logger* info_log);

extern void Log(const InfoLogLevel log_level, Logger* info_log,
                const char* format, ...) ROCKSDB_PRINTF_FORMAT_ATTR(3, 4);

// The default info log level is InfoLogLevel::INFO_LEVEL.
extern void Log(Logger* info_log, const char* format, ...)
    ROCKSDB_PRINTF_FORMAT_ATTR(2, 3);

// a set of log functions with different log levels.
extern void Header(Logger* info_log, const char* format, ...)
    ROCKSDB_PRINTF_FORMAT_ATTR(2, 3);
extern void Debug(Logger* info_log, const char* format, ...)
    ROCKSDB_PRINTF_FORMAT_ATTR(2, 3);
extern void Info(Logger* info_log, const char* format, ...)
    ROCKSDB_PRINTF_FORMAT_ATTR(2, 3);
extern void Warn(Logger* info_log, const char* format, ...)
    ROCKSDB_PRINTF_FORMAT_ATTR(2, 3);
extern void Error(Logger* info_log, const char* format, ...)
    ROCKSDB_PRINTF_FORMAT_ATTR(2, 3);
extern void Fatal(Logger* info_log, const char* format, ...)
    ROCKSDB_PRINTF_FORMAT_ATTR(2, 3);

// An interface for writing log messages.
class Logger {
 public:
  size_t kDoNotSupportGetLogFileSize = (std::numeric_limits<size_t>::max)();

  explicit Logger(const InfoLogLevel log_level = InfoLogLevel::INFO_LEVEL)
      : closed_(false), log_level_(log_level) {}
  // No copying allowed
  Logger(const Logger&) = delete;
  void operator=(const Logger&) = delete;

  virtual ~Logger();

  static const char* Type() { return "Logger"; }

  // The name of this logger class.  Implementations should override this method
  virtual const char* Name() const { return ""; }

  // Close the log file. Must be called before destructor. If the return
  // status is NotSupported(), it means the implementation does cleanup in
  // the destructor
  virtual Status Close();

  // Write a header to the log file with the specified format
  // It is recommended that you log all header information at the start of the
  // application. But it is not enforced.
  virtual void LogHeader(const char* format, va_list ap) {
    // Default implementation does a simple INFO level log write.
    // Please override as per the logger class requirement.
    Logv(InfoLogLevel::INFO_LEVEL, format, ap);
  }

  // Write an entry to the log file with the specified format.
  //
  // Users who override the `Logv()` overload taking `InfoLogLevel` do not need
  // to implement this, unless they explicitly invoke it in
  // `Logv(InfoLogLevel, ...)`.
  virtual void Logv(const char* /* format */, va_list /* ap */) {
    assert(false);
  }

  // Write an entry to the log file with the specified log level
  // and format.  Any log with level under the internal log level
  // of *this (see @SetInfoLogLevel and @GetInfoLogLevel) will not be
  // printed.
  virtual void Logv(const InfoLogLevel log_level, const char* format,
                    va_list ap);

  virtual size_t GetLogFileSize() const { return kDoNotSupportGetLogFileSize; }
  // Flush to the OS buffers
  virtual void Flush() {}
  virtual InfoLogLevel GetInfoLogLevel() const { return log_level_; }
  virtual void SetInfoLogLevel(const InfoLogLevel log_level) {
    log_level_ = log_level;
  }

  // If you're adding methods here, remember to add them to LoggerWrapper too.

 protected:
  virtual Status CloseImpl();
  bool closed_;

 private:
  InfoLogLevel log_level_;
};

class LoggerWrapper : public Logger {
 public:
  explicit LoggerWrapper(Logger* target) : target_(target) {}

  Status Close() override { return target_->Close(); }
  void LogHeader(const char* format, va_list ap) override {
    return target_->LogHeader(format, ap);
  }
  void Logv(const char* format, va_list ap) override {
    return target_->Logv(format, ap);
  }
  void Logv(const InfoLogLevel log_level, const char* format,
            va_list ap) override {
    return target_->Logv(log_level, format, ap);
  }
  size_t GetLogFileSize() const override { return target_->GetLogFileSize(); }
  void Flush() override { return target_->Flush(); }
  InfoLogLevel GetInfoLogLevel() const override {
    return target_->GetInfoLogLevel();
  }
  void SetInfoLogLevel(const InfoLogLevel log_level) override {
    return target_->SetInfoLogLevel(log_level);
  }

 private:
  Logger* target_;
};

// Returns an instance of logger that can be used for storing informational
// messages.
// This is a factory method for EnvLogger declared in logging/env_logging.h
Status NewEnvLogger(const std::string& fname, Env* env,
                    std::shared_ptr<Logger>* result);

}  // namespace ROCKSDB_NAMESPACE
