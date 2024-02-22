#pragma once

#include <cstddef>

enum PresubmitResponse {
	kPRLocalError,
	kPRRemoteError,
	kPRDontUpload,
	kPRUploadCrashDumpAndMetadata,
	kPRUploadMetadataOnly,
};


PresubmitResponse PresubmitCrashDump(const char* path, char* tokenBuffer, size_t tokenBufferSize);