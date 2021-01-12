// Copyright (c) 2011-present, Facebook, Inc.  All rights reserved.
//  This source code is licensed under both the GPLv2 (found in the
//  COPYING file in the root directory) and Apache 2.0 License
//  (found in the LICENSE.Apache file in the root directory).
// Copyright (c) 2011 The LevelDB Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file. See the AUTHORS file for names of contributors.

#pragma once
#include <rocksdb/rocksdb_namespace.h>
#include <rocksdb/status.h>
#include <stdint.h>

#include <memory>

#ifdef _WIN32
// Windows API macro interference
#undef GetCurrentTime
#endif

namespace ROCKSDB_NAMESPACE {
struct ConfigOptions;

// A SystemClock is an interface used by the rocksdb implementation to access
// operating system time-related functionality.
class SystemClock {
 public:
  virtual ~SystemClock() {}

  static const char* Type() { return "SystemClock"; }

  // Creates and configures a new SystemClock from the input options and id.
  // MJR static Status CreateFromString(const ConfigOptions& config_options,
  // MJR                               const std::string& id,
  // MJR                               std::shared_ptr<SystemClock>* clock);

  // The name of this system clock
  virtual const char* Name() const = 0;

  // Return a default SystemClock suitable for the current operating
  // system.
  static const std::shared_ptr<SystemClock>& Default();

  // Returns the number of micro-seconds since some fixed point in time.
  // It is often used as system time such as in GenericRateLimiter
  // and other places so a port needs to return system time in order to work.
  virtual uint64_t NowMicros() = 0;

  // Returns the number of nano-seconds since some fixed point in time. Only
  // useful for computing deltas of time in one run.
  // Default implementation simply relies on NowMicros.
  // In platform-specific implementations, NowNanos() should return time points
  // that are MONOTONIC.
  virtual uint64_t NowNanos() { return NowMicros() * 1000; }

  // 0 indicates not supported.
  virtual uint64_t NowCPUNanos() { return 0; }

  // Sleep/delay the thread for the prescribed number of micro-seconds.
  virtual void SleepForMicroseconds(int micros) = 0;

  // Get the number of seconds since the Epoch, 1970-01-01 00:00:00 (UTC).
  // Only overwrites *unix_time on success.
  virtual Status GetCurrentTime(int64_t* unix_time) = 0;

  // Converts seconds-since-Jan-01-1970 to a printable string
  virtual std::string TimeToString(uint64_t time) = 0;
};

// Wrapper class for a SystemClock.  Redirects all methods (except Name)
// of the SystemClock interface to the target/wrapped class.
class SystemClockWrapper : public SystemClock {
 public:
  SystemClockWrapper(const std::shared_ptr<SystemClock>& t) : target_(t) {}

  uint64_t NowMicros() override { return target_->NowMicros(); }

  uint64_t NowNanos() override { return target_->NowNanos(); }

  // 0 indicates not supported.
  uint64_t NowCPUNanos() override { return target_->NowCPUNanos(); }

  // Sleep/delay the thread for the prescribed number of micro-seconds.
  virtual void SleepForMicroseconds(int micros) override {
    return target_->SleepForMicroseconds(micros);
  }

  // Get the number of seconds since the Epoch, 1970-01-01 00:00:00 (UTC).
  // Only overwrites *unix_time on success.
  Status GetCurrentTime(int64_t* unix_time) override {
    return target_->GetCurrentTime(unix_time);
  }

  // Converts seconds-since-Jan-01-1970 to a printable string
  std::string TimeToString(uint64_t time) override {
    return target_->TimeToString(time);
  }

 protected:
  std::shared_ptr<SystemClock> target_;
};

}  // end namespace ROCKSDB_NAMESPACE
