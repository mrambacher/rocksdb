// Copyright (c) Facebook, Inc. and its affiliates. All Rights Reserved.
// Copyright (c) 2011 The LevelDB Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file. See the AUTHORS file for names of contributors.

#include <memory>

#include "options/customizable_helper.h"
#include "rocksdb/compaction_filter.h"
#include "rocksdb/options.h"
#include "utilities/compaction_filters/remove_emptyvalue_compactionfilter.h"

namespace ROCKSDB_NAMESPACE {
#ifndef ROCKSDB_LITE
static int RegisterBuiltinCompactionFilters(ObjectLibrary& library,
                                            const std::string& /*arg*/) {
  library.Register<const CompactionFilter>(
      RemoveEmptyValueCompactionFilter::kClassName(),
      [](const std::string& /*uri*/,
         std::unique_ptr<const CompactionFilter>* /*guard*/,
         std::string* /*errmsg*/) {
        return new RemoveEmptyValueCompactionFilter();
      });
  return 1;
}
static std::once_flag load_once;
#endif  // ROCKSDB_LITE
Status CompactionFilter::CreateFromString(const ConfigOptions& config_options,
                                          const std::string& value,
                                          const CompactionFilter** result) {
#ifndef ROCKSDB_LITE
  std::call_once(load_once, [&]() {
    RegisterBuiltinCompactionFilters(*(ObjectLibrary::Default().get()), "");
  });
#endif  // ROCKSDB_LITE
  CompactionFilter* filter = const_cast<CompactionFilter*>(*result);
  Status status = LoadStaticObject<CompactionFilter>(config_options, value,
                                                     nullptr, &filter);
  if (status.ok()) {
    *result = const_cast<CompactionFilter*>(filter);
  }
  return status;
}

Status CompactionFilterFactory::CreateFromString(
    const ConfigOptions& config_options, const std::string& value,
    std::shared_ptr<CompactionFilterFactory>* result) {
#ifndef ROCKSDB_LITE
  std::call_once(load_once, [&]() {
    RegisterBuiltinCompactionFilters(*(ObjectLibrary::Default().get()), "");
  });
#endif  // ROCKSDB_LITE
  Status status = LoadSharedObject<CompactionFilterFactory>(
      config_options, value, nullptr, result);
  return status;
}
}  // namespace ROCKSDB_NAMESPACE