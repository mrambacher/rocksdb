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

#if defined(OS_WIN)

#include "port/win/win_logger.h"

#include <fcntl.h>
#include <stdio.h>
#include <time.h>

#include <algorithm>
#include <atomic>

#include "monitoring/iostats_context_imp.h"
#include "port/sys_time.h"
#include "port/win/env_win.h"
#include "port/win/io_win.h"
#include "rocksdb/env.h"
#include "rocksdb/system_clock.h"

namespace ROCKSDB_NAMESPACE {

namespace port {

WinLogger::WinLogger(uint64_t (*gettid)(),
                     const std::shared_ptr<SystemClock>& clock, HANDLE file,
                     const InfoLogLevel log_level)
    : FileLogger(log_level, clock), file_(file), gettid_(gettid) {
  assert(file_ != NULL);
  assert(file_ != INVALID_HANDLE_VALUE);
}

WinLogger::~WinLogger() { Close().PermitUncheckedError(); }

Status WinLogger::CloseLocked() {
  Status s;
  if (INVALID_HANDLE_VALUE != file_) {
    BOOL ret = FlushFileBuffers(file_);
    if (ret == 0) {
      auto lastError = GetLastError();
      s = IOErrorFromWindowsError("Failed to flush LOG on Close() ", lastError);
    }
    ret = CloseHandle(file_);
    // On error the return value is zero
    if (ret == 0 && s.ok()) {
      auto lastError = GetLastError();
      s = IOErrorFromWindowsError("Failed to flush LOG on Close() ", lastError);
    }
    file_ = INVALID_HANDLE_VALUE;
  }
  return s;
}

Status WinLogger::FlushLocked() {
  assert(file_ != INVALID_HANDLE_VALUE);
  // With Windows API writes go to OS buffers directly so no fflush needed
  // unlike with C runtime API. We don't flush all the way to disk
  // for perf reasons.
  return Status::OK();
}

uint64_t WinLogger::GetThreadID() const { return (*gettid_)(); }

Status WinLogger::WriteLocked(const char* data, size_t size) {
  return DebugWriter(data, static_cast<int>(size));
  assert(file_ != INVALID_HANDLE_VALUE);
  DWORD bytesWritten = 0;
  BOOL ret =
      WriteFile(file_, data, static_cast<DWORD>(size), &bytesWritten, NULL);
  if (ret == FALSE) {
    return Status::IOError("Failed to write to Windows Logger: ",
                           GetWindowsErrSz(GetLastError()));
  } else {
    assert((bytesWritten == write_size) || (ret == FALSE));
    return Status::OK();
  }
}

}  // namespace ROCKSDB_NAMESPACE

#endif
