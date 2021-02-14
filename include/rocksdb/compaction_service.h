// Copyright (c) 2019-present, Rockset, Inc.  All rights reserved.
// This source code is licensed under both the GPLv2 (found in the
// COPYING file in the root directory) and Apache 2.0 License
// (found in the LICENSE.Apache file in the root directory).

#pragma once

#include <stdint.h>

#include <climits>
#include <vector>

#include "rocksdb/customizable.h"
#include "rocksdb/options.h"
#include "rocksdb/types.h"

// An EXPERIMENTAL feature to allow alternative CompactionService
// policies to be implemented.  A future derivative of this interface
// could be used, for example, to offload a compaction job to a remote
// process.
//
// This feature is an EXPERIMENTAL work in progress and is subject to
// change in a future release
namespace ROCKSDB_NAMESPACE {
class Slice;

struct CompactionJobInfo;
struct ConfigOptions;
struct FileOptions;

// The input parameters for a compaction service request.
// The fields in this structure are EXPERIMENTAL and subject to change as the
// interface is refined.
struct CompactionServiceOptions : CompactionOptions {
 public:
  // The name of the column family
  std::string column_family_name;

  // List of existing snapshots in the db
  std::vector<SequenceNumber> existing_snapshots;

  // List of input files of the compaction
  std::vector<std::string> input_files;

  // The level to which the files are compacted into
  int output_level;

  // If specified, this will be the first key in the compaction output
  Slice* begin = nullptr;

  // If specified, this will be the last key in the compaction output
  Slice* end = nullptr;
};

// The CompactionService performs the underlying compaction operations.
// Instances of this service take in a set of files to be compacted,
// perform the compaction, and return the results.
// The CompactionService is EXPERIMENTAL and subject to change in a future
// release
class CompactionService : public Customizable {
 public:
  virtual ~CompactionService() {}
  static const char* Type() { return "CompactionService"; }

  // Returns the name of this compaction service.
  virtual const char* Name() const = 0;
  // Starts a compaction job using the supplied parameters.
  // This method starts or schedules the compaction and returns a "job_id"
  // that can be used to manage the job.
  //
  // If an implementation does not support the specified options, it can
  // return "Status::NotSupported", in which case the default compaction service
  // will attempt the job.
  virtual Status Start(const CompactionServiceOptions& compaction_options,
                       const Options& options, std::string* job_id) = 0;

  // Cancels a compaction job that is currently running.
  // This method can be used to abort a manual compaction or to
  // indicate that the job should be terminated when the database is being
  // shutdown.
  virtual Status Cancel(const std::string& job_id) = 0;

  // Waits for the specified compaction job to complete.  Returns the results
  // of this compaction.
  virtual Status WaitForComplete(const std::string& job_id,
                                 CompactionJobInfo* compaction_job_info) = 0;

  // Install files that were generated by a pluggable compaction request into
  // the local database.
  virtual Status DownloadFile(const FileOptions& options,
                              const std::string& remote_path,
                              const std::string& local_path) = 0;
  virtual std::vector<Status> DownloadFiles(
      const FileOptions& options, const std::vector<std::string>& remote_paths,
      const std::vector<std::string>& local_paths);
};
}  // namespace ROCKSDB_NAMESPACE
