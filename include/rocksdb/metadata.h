// Copyright (c) 2011-present, Facebook, Inc.  All rights reserved.
//  This source code is licensed under both the GPLv2 (found in the
//  COPYING file in the root directory) and Apache 2.0 License
//  (found in the LICENSE.Apache file in the root directory).

#pragma once

#include <stdint.h>

#include <limits>
#include <string>
#include <vector>

#include "rocksdb/options.h"
#include "rocksdb/types.h"

namespace ROCKSDB_NAMESPACE {
struct BlobMetaData;
struct ColumnFamilyMetaData;
struct LevelMetaData;
struct SstFileMetaData;

// The metadata that describes a column family.
struct ColumnFamilyMetaData {
  ColumnFamilyMetaData() : size(0), file_count(0), name("") {}
  ColumnFamilyMetaData(const std::string& _name, uint64_t _size,
                       const std::vector<LevelMetaData>&& _levels)
      : size(_size), name(_name), levels(_levels) {}

  // The size of this column family in bytes, which is equal to the sum of
  // the file size of its "levels".
  uint64_t size;
  // The number of files in this column family.
  size_t file_count;
  // The name of the column family.
  std::string name;
  // The metadata of all levels in this column family.
  std::vector<LevelMetaData> levels;

  // The total size of all blob files
  uint64_t blob_file_size = 0;
  // The number of blob files in this column family.
  size_t blob_file_count = 0;
  // The name of the column family.
  std::vector<BlobMetaData> blob_files;
};

// The metadata that describes a level.
struct LevelMetaData {
  LevelMetaData(int _level, uint64_t _size,
                const std::vector<SstFileMetaData>&& _files)
      : level(_level), size(_size), files(_files) {}

  // The level which this meta data describes.
  const int level;
  // The size of this level in bytes, which is equal to the sum of
  // the file size of its "files".
  const uint64_t size;
  // The metadata of all sst files in this level.
  const std::vector<SstFileMetaData> files;
};

// The metadata that describes a SST file.
struct SstFileMetaData {
  SstFileMetaData()
      : size(0),
        file_number(0),
        smallest_seqno(0),
        largest_seqno(0),
        num_reads_sampled(0),
        being_compacted(false),
        num_entries(0),
        num_deletions(0),
        temperature(Temperature::kUnknown),
        oldest_blob_file_number(0),
        oldest_ancester_time(0),
        file_creation_time(0) {}

  SstFileMetaData(const std::string& _file_name, uint64_t _file_number,
                  const std::string& _path, size_t _size,
                  SequenceNumber _smallest_seqno, SequenceNumber _largest_seqno,
                  const std::string& _smallestkey,
                  const std::string& _largestkey, uint64_t _num_reads_sampled,
                  bool _being_compacted, Temperature _temperature,
                  uint64_t _oldest_blob_file_number,
                  uint64_t _oldest_ancester_time, uint64_t _file_creation_time,
                  std::string& _file_checksum,
                  std::string& _file_checksum_func_name)
      : size(_size),
        name(_file_name),
        file_number(_file_number),
        db_path(_path),
        smallest_seqno(_smallest_seqno),
        largest_seqno(_largest_seqno),
        smallestkey(_smallestkey),
        largestkey(_largestkey),
        num_reads_sampled(_num_reads_sampled),
        being_compacted(_being_compacted),
        num_entries(0),
        num_deletions(0),
        temperature(_temperature),
        oldest_blob_file_number(_oldest_blob_file_number),
        oldest_ancester_time(_oldest_ancester_time),
        file_creation_time(_file_creation_time),
        file_checksum(_file_checksum),
        file_checksum_func_name(_file_checksum_func_name) {}

  // File size in bytes.
  size_t size;
  // The name of the file.
  std::string name;
  // The id of the file.
  uint64_t file_number;
  // The full path where the file locates.
  std::string db_path;

  SequenceNumber smallest_seqno;  // Smallest sequence number in file.
  SequenceNumber largest_seqno;   // Largest sequence number in file.
  std::string smallestkey;        // Smallest user defined key in the file.
  std::string largestkey;         // Largest user defined key in the file.
  uint64_t num_reads_sampled;     // How many times the file is read.
  bool being_compacted;  // true if the file is currently being compacted.

  uint64_t num_entries;
  uint64_t num_deletions;

  // This feature is experimental and subject to change.
  Temperature temperature;

  uint64_t oldest_blob_file_number;  // The id of the oldest blob file
                                     // referenced by the file.
  // An SST file may be generated by compactions whose input files may
  // in turn be generated by earlier compactions. The creation time of the
  // oldest SST file that is the compaction ancestor of this file.
  // The timestamp is provided SystemClock::GetCurrentTime().
  // 0 if the information is not available.
  //
  // Note: for TTL blob files, it contains the start of the expiration range.
  uint64_t oldest_ancester_time;
  // Timestamp when the SST file is created, provided by
  // SystemClock::GetCurrentTime(). 0 if the information is not available.
  uint64_t file_creation_time;

  // The checksum of a SST file, the value is decided by the file content and
  // the checksum algorithm used for this SST file. The checksum function is
  // identified by the file_checksum_func_name. If the checksum function is
  // not specified, file_checksum is "0" by default.
  std::string file_checksum;

  // The name of the checksum function used to generate the file checksum
  // value. If file checksum is not enabled (e.g., sst_file_checksum_func is
  // null), file_checksum_func_name is UnknownFileChecksumFuncName, which is
  // "Unknown".
  std::string file_checksum_func_name;
};

// The full set of metadata associated with each SST file.
struct LiveFileMetaData : SstFileMetaData {
  std::string column_family_name;  // Name of the column family
  int level;                       // Level at which this file resides.
  LiveFileMetaData() : column_family_name(), level(0) {}
};

// The MetaData that describes a Blob file
struct BlobMetaData {
  BlobMetaData()
      : blob_file_number(0),
        blob_file_size(0),
        total_blob_count(0),
        total_blob_bytes(0),
        garbage_blob_count(0),
        garbage_blob_bytes(0) {}

  BlobMetaData(uint64_t _file_number, const std::string& _file_name,
               const std::string& _file_path, uint64_t _file_size,
               uint64_t _total_blob_count, uint64_t _total_blob_bytes,
               uint64_t _garbage_blob_count, uint64_t _garbage_blob_bytes,
               const std::string& _file_checksum,
               const std::string& _file_checksum_func_name)
      : blob_file_number(_file_number),
        blob_file_name(_file_name),
        blob_file_path(_file_path),
        blob_file_size(_file_size),
        total_blob_count(_total_blob_count),
        total_blob_bytes(_total_blob_bytes),
        garbage_blob_count(_garbage_blob_count),
        garbage_blob_bytes(_garbage_blob_bytes),
        checksum_method(_file_checksum),
        checksum_value(_file_checksum_func_name) {}
  uint64_t blob_file_number;
  std::string blob_file_name;
  std::string blob_file_path;
  uint64_t blob_file_size;
  uint64_t total_blob_count;
  uint64_t total_blob_bytes;
  uint64_t garbage_blob_count;
  uint64_t garbage_blob_bytes;
  std::string checksum_method;
  std::string checksum_value;
};

// Metadata returned as output from ExportColumnFamily() and used as input to
// CreateColumnFamiliesWithImport().
struct ExportImportFilesMetaData {
  std::string db_comparator_name;       // Used to safety check at import.
  std::vector<LiveFileMetaData> files;  // Vector of file metadata.
};
}  // namespace ROCKSDB_NAMESPACE
