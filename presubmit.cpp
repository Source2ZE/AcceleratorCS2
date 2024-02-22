#include "presubmit.h"
#include "extension.h"


#if defined _LINUX
#include "client/linux/handler/exception_handler.h"
#include "common/linux/linux_libc_support.h"
#include "third_party/lss/linux_syscall_support.h"
#include "common/linux/http_upload.h"
#include "common/linux/dump_symbols.h"

#include <dirent.h>
#include <unistd.h>
#else
#include "client/windows/handler/exception_handler.h"
#include "common/windows/http_upload.h"
#endif

#include <sstream>
#include <codecvt>

#include "common/path_helper.h"
#include "common/using_std_string.h"
#include "google_breakpad/processor/basic_source_line_resolver.h"
#include "google_breakpad/processor/minidump_processor.h"
#include "google_breakpad/processor/process_state.h"
#include "processor/simple_symbol_supplier.h"
#include "processor/stackwalk_common.h"
#include <google_breakpad/processor/call_stack.h>
#include <google_breakpad/processor/stack_frame.h>
#include <processor/pathname_stripper.h>

extern std::string g_UserId;
extern AcceleratorCS2 g_AcceleratorCS2;
extern std::string g_serverId;
extern char dumpStoragePath[512];

class ClogInhibitor
{
	std::streambuf* saved_clog = nullptr;

public:
	ClogInhibitor() {
		saved_clog = std::clog.rdbuf();
		std::clog.rdbuf(nullptr);
	}

	~ClogInhibitor() {
		std::clog.rdbuf(saved_clog);
	}
};

#ifdef _LINUX
#include <paths.h>

class StderrInhibitor
{
	FILE* saved_stderr = nullptr;

public:
	StderrInhibitor() {
		saved_stderr = fdopen(dup(fileno(stderr)), "w");
		if (freopen(_PATH_DEVNULL, "w", stderr)) {
			// If it fails, not a lot we can (or should) do.
			// Add this brace section to silence gcc warnings.
		}
	}

	~StderrInhibitor() {
		fflush(stderr);
		dup2(fileno(saved_stderr), fileno(stderr));
		fclose(saved_stderr);
	}
};
#endif

bool UploadSymbolFile(const google_breakpad::CodeModule* _module, std::string presubmitToken);

PresubmitResponse PresubmitCrashDump(const char* path, char* tokenBuffer, size_t tokenBufferSize)
{
	google_breakpad::ProcessState processState;
	google_breakpad::ProcessResult processResult;
	google_breakpad::MinidumpProcessor minidumpProcessor(nullptr, nullptr);

	{
		ClogInhibitor clogInhibitor;
		processResult = minidumpProcessor.Process(path, &processState);
	}

	if (processResult != google_breakpad::PROCESS_OK) {
		return kPRLocalError;
	}

	std::string os_short = "";
	std::string cpu_arch = "";
	if (processState.system_info()) {
		os_short = processState.system_info()->os_short;
		if (os_short.empty()) {
			os_short = processState.system_info()->os;
		}
		cpu_arch = processState.system_info()->cpu;
		ConMsg("%s arch\n", cpu_arch.c_str());
	}


	int requestingThread = processState.requesting_thread();
	if (requestingThread == -1) {
		requestingThread = 0;
	}

	const google_breakpad::CallStack* stack = processState.threads()->at(requestingThread);
	if (!stack) {
		return kPRLocalError;
	}

	int frameCount = stack->frames()->size();
	if (frameCount > 1024) {
		frameCount = 1024;
	}

	std::ostringstream summaryStream;
	summaryStream << "2|" << std::to_string(processState.time_date_stamp()) << "|" << os_short << "|" << cpu_arch << "|" << std::to_string(processState.crashed()) << "|" << processState.crash_reason() << "|" << std::hex << processState.crash_address() << std::dec << "|" << std::to_string(requestingThread);

	std::map<const google_breakpad::CodeModule*, unsigned int> moduleMap;

	unsigned int moduleCount = processState.modules() ? processState.modules()->module_count() : 0;
	for (unsigned int moduleIndex = 0; moduleIndex < moduleCount; ++moduleIndex) {
		auto module = processState.modules()->GetModuleAtIndex(moduleIndex);
		moduleMap[module] = moduleIndex;

		auto debugFile = google_breakpad::PathnameStripper::File(module->debug_file());
		auto debugIdentifier = module->debug_identifier();

		summaryStream << "|M|" << debugFile << "|" << debugIdentifier;
	}

	for (int frameIndex = 0; frameIndex < frameCount; ++frameIndex) {
		auto frame = stack->frames()->at(frameIndex);

		int moduleIndex = -1;
		auto moduleOffset = frame->ReturnAddress();
		if (frame->module) {
			moduleIndex = moduleMap[frame->module];
			moduleOffset -= frame->module->base_address();
		}

		summaryStream << "|F|" << std::to_string(moduleIndex) << "|" << std::hex << moduleOffset << std::dec;
	}

	auto summaryLine = summaryStream.str();

#ifdef WIN32
	std::wstring_convert<std::codecvt_utf8<wchar_t>, wchar_t> strconverter;
	std::map<std::wstring, std::wstring> params;
	std::map<std::wstring, std::wstring> files;

	params[L"UserID"] = strconverter.from_bytes(g_UserId).c_str();
	params[L"ExtensionVersion"] = strconverter.from_bytes(g_AcceleratorCS2.GetVersion()) + L" [AcceleratorCS2 Build]";
	params[L"ServerID"] = strconverter.from_bytes(g_serverId).c_str();
	params[L"CrashSignature"] = strconverter.from_bytes(summaryLine).c_str();

	std::wstring res;
	int res_code;
	bool success = google_breakpad::HTTPUpload::SendMultipartPostRequest(L"http://crash.limetech.org/submit", params, files, nullptr, &res, &res_code);

	std::string resAscii = strconverter.to_bytes(res);
#else
	std::map<std::string, std::string> params;
	std::map<std::string, std::string> files;

	params["UserID"] = g_UserId;
	params["ExtensionVersion"] = std::string(g_AcceleratorCS2.GetVersion()) + " [AcceleratorCS2 Build]";
	params["ServerID"] = g_serverId;
	params["CrashSignature"] = summaryLine;

	ConMsg("signature %s\n", summaryLine.c_str());

	std::string resAscii;
	long int res_code;
	bool success = google_breakpad::HTTPUpload::SendRequest("http://crash.limetech.org/submit", params, files, "", "", "", &resAscii, &res_code, nullptr);
#endif

	// RESPONSE EXAMPLE: Y|NNNYYYYNNNNNYYYYYYNNNNNNNY|3d6193b79d332048ed6e59557452b7fc
	// 1 - response state (Y/N/M)
	// 2 - List of modules, one character per module, Y (upload) or N (don't upload)
	// 3 - Presubmit ID


	if (!success) {
		ConMsg("Presubmit failed: %s (%i)\n", resAscii.c_str(), res_code);
		return kPRRemoteError;
	}


	ConMsg("Presubmit response: %s\n", resAscii.c_str());

	if (resAscii.length() < 2) {
		return kPRLocalError;
	}

	if (resAscii[0] == 'E') {
		ConMsg("Presubmit error: %s (%i)\n", resAscii.c_str(), res_code);
		return kPRRemoteError;
	}

	PresubmitResponse presubmitResponse = kPRRemoteError;
	if (resAscii[0] == 'Y') presubmitResponse = kPRUploadCrashDumpAndMetadata;
	else if (resAscii[0] == 'N') presubmitResponse = kPRDontUpload;
	else if (resAscii[0] == 'M') presubmitResponse = kPRUploadMetadataOnly;
	else return kPRRemoteError;

	if (resAscii[1] != '|') {
		ConMsg("Response delimiter missing\n");
		return kPRRemoteError;
	}

	auto idPos = resAscii.find('|', 2);
	if (idPos == std::string::npos) {
		ConMsg("Presubmit ID missing\n");
		return kPRRemoteError;
	}

	auto moduleList = resAscii.substr(2, idPos - 2);
	auto presubmitId = resAscii.substr(idPos + 1);

	ConMsg("Presubmit ID: %s\n", presubmitId.c_str());
	ConMsg("Module list: %s\n", moduleList.c_str());

	if (tokenBuffer)
	{
		strncpy(tokenBuffer, presubmitId.c_str(), tokenBufferSize);
		tokenBuffer[tokenBufferSize - 1] = 0;
	}

	if (moduleList.length() != moduleCount) {
		ConMsg("Module list length mismatch\n");
		return kPRRemoteError;
	}


	if (moduleCount > 0)
	{
		for (unsigned int moduleIndex = 0; moduleIndex < moduleCount; ++moduleIndex) {
			bool submitSymbols = false;
			bool submitBinary = (resAscii[2 + moduleIndex] == 'U');
#ifdef _LINUX
			submitSymbols = (resAscii[2 + moduleIndex] == 'Y');
#endif

			if (!submitBinary && !submitSymbols)
				continue;

			auto _module = processState.modules()->GetModuleAtIndex(moduleIndex);

			if (submitSymbols)
			{
				UploadSymbolFile(_module, presubmitId);
			}
		}
	}
}

#ifdef _LINUX
bool UploadSymbolFile(const google_breakpad::CodeModule* _module, std::string presubmitToken)
{
	auto debugFile = _module->debug_file();
	std::string vdsoOutputPath = "";

	if (debugFile == "linux-gate.so") {
		FILE* auxvFile = fopen("/proc/self/auxv", "rb");
		if (auxvFile) {
			char vdsoOutputPathBuffer[512];
			vdsoOutputPath = dumpStoragePath;

			while (!feof(auxvFile)) {
				int auxvEntryId = 0;
				fread(&auxvEntryId, sizeof(auxvEntryId), 1, auxvFile);
				long auxvEntryValue = 0;
				fread(&auxvEntryValue, sizeof(auxvEntryValue), 1, auxvFile);

				if (auxvEntryId == 0) break;
				if (auxvEntryId != 33) continue; // AT_SYSINFO_EHDR

				Elf32_Ehdr* vdsoHdr = (Elf32_Ehdr*)auxvEntryValue;
				auto vdsoSize = vdsoHdr->e_shoff + (vdsoHdr->e_shentsize * vdsoHdr->e_shnum);
				void* vdsoBuffer = malloc(vdsoSize);
				memcpy(vdsoBuffer, vdsoHdr, vdsoSize);

				FILE* vdsoFile = fopen(vdsoOutputPath.c_str(), "wb");
				if (vdsoFile) {
					fwrite(vdsoBuffer, 1, vdsoSize, vdsoFile);
					fclose(vdsoFile);
					debugFile = vdsoOutputPath;
				}

				free(vdsoBuffer);
				break;
			}

			fclose(auxvFile);
		}
	}

	if (debugFile[0] != '/') {
		return false;
	}

	ConMsg("Uploading symbol file: %s\n", debugFile.c_str());

	auto debugFileDir = google_breakpad::DirName(debugFile);
	std::vector<string> debug_dirs{
		debugFileDir,
		debugFileDir + "/.debug",
		"/usr/lib/debug" + debugFileDir,
	};

	std::ostringstream outputStream;
	google_breakpad::DumpOptions options(ALL_SYMBOL_DATA, true, true);

	{
		StderrInhibitor stdrrInhibitor;

		if (!WriteSymbolFile(debugFile, debugFile, "Linux", debug_dirs, options, outputStream)) {
			outputStream.str("");
			outputStream.clear();

			// Try again without debug dirs.
			if (!WriteSymbolFile(debugFile, debugFile, "Linux", {}, options, outputStream)) {
				ConMsg("Failed to process symbol file\n");
				return false;
			}
		}
	}

	auto output = outputStream.str();

	if (debugFile == vdsoOutputPath) {
		unlink(vdsoOutputPath.c_str());
	}

	std::map<std::string, std::string> params;
	std::map<std::string, std::string> files;

	params["UserID"] = g_UserId;
	params["ExtensionVersion"] = std::string(g_AcceleratorCS2.GetVersion()) + " [AcceleratorCS2 Build]";
	params["ServerID"] = g_serverId;

	if(!presubmitToken.empty())
		params["PresubmitToken"] = presubmitToken;

	files["symbol_file"] = output;

	std::string resAscii;
	long int res_code;
	bool success = google_breakpad::HTTPUpload::SendRequest("http://crash.limetech.org/symbols/submit", params, files, "", "", "", &resAscii, &res_code, nullptr);

	ConMsg("Upload response: %s\n", resAscii.c_str());
	return success;
}
#endif