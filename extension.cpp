#include "extension.h"

#if defined _LINUX
#include "client/linux/handler/exception_handler.h"
#include "common/linux/linux_libc_support.h"
#include "third_party/lss/linux_syscall_support.h"

#include <dirent.h>
#include <unistd.h>
#else
#include "client/windows/handler/exception_handler.h"
#endif

#include <sys/stat.h>
#include <stdio.h>
#include <stdlib.h>
#include <signal.h>
#include <limits>
#include <filesystem>
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

#include <entity2/entitysystem.h>
#if defined WIN32
#include <corecrt_io.h>
#endif

AcceleratorCS2 g_AcceleratorCS2;
PLUGIN_EXPOSE(AcceleratorCS2, g_AcceleratorCS2);

char crashMap[256];
char crashGamePath[512];
char crashCommandLine[1024];
char dumpStoragePath[512];

CGameEntitySystem *GameEntitySystem()
{
	return nullptr;
}

class GameSessionConfiguration_t { };
SH_DECL_HOOK3_void(IServerGameDLL, GameFrame, SH_NOATTRIB, 0, bool, bool, bool);
SH_DECL_HOOK3_void(INetworkServerService, StartupServer, SH_NOATTRIB, 0, const GameSessionConfiguration_t&, ISource2WorldSession*, const char*);

google_breakpad::ExceptionHandler* exceptionHandler = nullptr;

void signal_safe_hex_print(int num)
{
	if (num > 15) {
		signal_safe_hex_print(num / 16);
	}
	char c = "0123456789ABCDEF"[num % 16];
#if defined _LINUX
	sys_write(STDOUT_FILENO, &c, 1);
#else
	write(fileno(stdout), &c, 1);
#endif
}

#if defined _LINUX
void (*SignalHandler)(int, siginfo_t*, void*);
const int kExceptionSignals[] = { SIGSEGV, SIGABRT, SIGFPE, SIGILL, SIGBUS };
const int kNumHandledSignals = std::size(kExceptionSignals);

static bool dumpCallback(const google_breakpad::MinidumpDescriptor& descriptor, void* context, bool succeeded)
{
	if (succeeded)
		sys_write(STDOUT_FILENO, "Wrote minidump to: ", 19);
	else
		sys_write(STDOUT_FILENO, "Failed to write minidump to: ", 29);

	sys_write(STDOUT_FILENO, descriptor.path(), my_strlen(descriptor.path()));
	sys_write(STDOUT_FILENO, "\n", 1);

	if (!succeeded)
		return succeeded;

	my_strlcpy(dumpStoragePath, descriptor.path(), sizeof(dumpStoragePath));
	my_strlcat(dumpStoragePath, ".txt", sizeof(dumpStoragePath));

	int extra = sys_open(dumpStoragePath, O_WRONLY | O_CREAT, S_IRUSR | S_IWUSR);
	if (extra == -1)
	{
		sys_write(STDOUT_FILENO, "Failed to open metadata file!\n", 30);
		return succeeded;
	}

	sys_write(extra, "-------- CONFIG BEGIN --------", 30);
	sys_write(extra, "\nMap=", 5);
	sys_write(extra, crashMap, my_strlen(crashMap));
	sys_write(extra, "\nGamePath=", 10);
	sys_write(extra, crashGamePath, my_strlen(crashGamePath));
	sys_write(extra, "\nCommandLine=", 13);
	sys_write(extra, crashCommandLine, my_strlen(crashCommandLine));
	sys_write(extra, "\n-------- CONFIG END --------\n", 30);
	sys_write(extra, "\n", 1);

	google_breakpad::scoped_ptr<google_breakpad::SimpleSymbolSupplier> symbolSupplier;
	google_breakpad::BasicSourceLineResolver resolver;
	google_breakpad::MinidumpProcessor minidump_processor(symbolSupplier.get(), &resolver);

	// Increase the maximum number of threads and regions.
	google_breakpad::MinidumpThreadList::set_max_threads(std::numeric_limits<uint32_t>::max());
	google_breakpad::MinidumpMemoryList::set_max_regions(std::numeric_limits<uint32_t>::max());
	// Process the minidump.
	google_breakpad::Minidump miniDump(descriptor.path());
	if (!miniDump.Read())
	{
		sys_write(STDOUT_FILENO, "Failed to read minidump\n", 24);
	}
	else
	{
		google_breakpad::ProcessState processState;
		if (minidump_processor.Process(&miniDump, &processState) != google_breakpad::PROCESS_OK)
		{
			sys_write(STDOUT_FILENO, "MinidumpProcessor::Process failed\n", 34);
		}
		else
		{
			int requestingThread = processState.requesting_thread();
			if (requestingThread == -1) {
				requestingThread = 0;
			}

			const google_breakpad::CallStack* stack = processState.threads()->at(requestingThread);
			int frameCount = stack->frames()->size();
			if (frameCount > 15) {
				frameCount = 15;
			}

			//std::ostringstream stream;

			sys_write(STDOUT_FILENO, "\n", 1);
			for (int frameIndex = 0; frameIndex < frameCount; ++frameIndex) {
				auto frame = stack->frames()->at(frameIndex);

				auto moduleOffset = frame->ReturnAddress();
				if (frame->module) {
					auto moduleFile = google_breakpad::PathnameStripper::File(frame->module->code_file());
					moduleOffset -= frame->module->base_address();
					sys_write(STDOUT_FILENO, moduleFile.c_str(), moduleFile.size());
					sys_write(STDOUT_FILENO, " (0x", 4);
					signal_safe_hex_print(moduleOffset);
					sys_write(STDOUT_FILENO, ")\n", 2);
				}
				else {
					sys_write(STDOUT_FILENO, "unknown (0x", 11);
					signal_safe_hex_print(moduleOffset);
					sys_write(STDOUT_FILENO, ") \n", 3);
				}
			}

			//sys_write(STDOUT_FILENO, stream.str().c_str(), stream.str().length());

			freopen(dumpStoragePath, "a", stdout);
			PrintProcessState(processState, true, false, &resolver);
			fflush(stdout);
		}
	}

	sys_close(extra);

	return succeeded;
}
#else
void* vectoredHandler = NULL;

LONG CALLBACK BreakpadVectoredHandler(_In_ PEXCEPTION_POINTERS ExceptionInfo)
{
	switch (ExceptionInfo->ExceptionRecord->ExceptionCode)
	{
	case EXCEPTION_ACCESS_VIOLATION:
	case EXCEPTION_INVALID_HANDLE:
	case EXCEPTION_ARRAY_BOUNDS_EXCEEDED:
	case EXCEPTION_DATATYPE_MISALIGNMENT:
	case EXCEPTION_ILLEGAL_INSTRUCTION:
	case EXCEPTION_INT_DIVIDE_BY_ZERO:
	case EXCEPTION_STACK_OVERFLOW:
	case 0xC0000409: // STATUS_STACK_BUFFER_OVERRUN
	case 0xC0000374: // STATUS_HEAP_CORRUPTION
		break;
	case 0: // Valve use this for Sys_Error.
		if ((ExceptionInfo->ExceptionRecord->ExceptionFlags & EXCEPTION_NONCONTINUABLE) == 0)
			return EXCEPTION_CONTINUE_SEARCH;
		break;
	default:
		return EXCEPTION_CONTINUE_SEARCH;
	}

	if (exceptionHandler->WriteMinidumpForException(ExceptionInfo))
	{
		// Stop the handler thread from deadlocking us.
		delete exceptionHandler;

		// Stop Valve's handler being called.
		ExceptionInfo->ExceptionRecord->ExceptionCode = EXCEPTION_BREAKPOINT;

		return EXCEPTION_EXECUTE_HANDLER;
	}
	else {
		return EXCEPTION_CONTINUE_SEARCH;
	}
}

std::string ws2s(const std::wstring& wstr)
{
	using convert_typeX = std::codecvt_utf8<wchar_t>;
	std::wstring_convert<convert_typeX, wchar_t> converterX;

	return converterX.to_bytes(wstr);
}

static bool dumpCallback(const wchar_t* dump_path,
	const wchar_t* minidump_id,
	void* context,
	EXCEPTION_POINTERS* exinfo,
	MDRawAssertionInfo* assertion,
	bool succeeded)
{
	if (!succeeded) {
		printf("Failed to write minidump to: %ls\\%ls.dmp\n", dump_path, minidump_id);
		return succeeded;
	}

	sprintf(dumpStoragePath, "%ls\\%ls.dmp.txt", dump_path, minidump_id);

	FILE* extra = fopen(dumpStoragePath, "wb");
	if (!extra) {
		printf("Failed to open metadata file!\n");
		return succeeded;
	}

	fprintf(extra, "-------- CONFIG BEGIN --------");
	fprintf(extra, "\nMap=%s", crashMap);
	fprintf(extra, "\nGamePath=%s", crashGamePath);
	fprintf(extra, "\nCommandLine=%s", crashCommandLine);
	fprintf(extra, "\n-------- CONFIG END --------\n");
	fprintf(extra, "\n");

	google_breakpad::scoped_ptr<google_breakpad::SimpleSymbolSupplier> symbolSupplier;
	google_breakpad::BasicSourceLineResolver resolver;
	google_breakpad::MinidumpProcessor minidump_processor(symbolSupplier.get(), &resolver);

	// Increase the maximum number of threads and regions.
#undef max
	google_breakpad::MinidumpThreadList::set_max_threads(std::numeric_limits<uint32_t>::max());
	google_breakpad::MinidumpMemoryList::set_max_regions(std::numeric_limits<uint32_t>::max());
	// Process the minidump.
	std::wstring widestr = std::wstring(dump_path) + L"\\" + std::wstring(minidump_id) + L".dmp";
	google_breakpad::Minidump miniDump(ws2s(widestr));
	if (!miniDump.Read())
	{
		printf("Failed to read minidump\n");
	}
	else
	{
		google_breakpad::ProcessState processState;
		if (minidump_processor.Process(&miniDump, &processState) != google_breakpad::PROCESS_OK)
		{
			printf("MinidumpProcessor::Process failed\n");
		}
		else
		{
			freopen(dumpStoragePath, "a", stdout);
			PrintProcessState(processState, true, false, &resolver);
			fflush(stdout);
		}
	}

	fclose(extra);

	return succeeded;
}
#endif

bool AcceleratorCS2::Load(PluginId id, ISmmAPI* ismm, char* error, size_t maxlen, bool late)
{
	PLUGIN_SAVEVARS();

	GET_V_IFACE_CURRENT(GetServerFactory, g_pSource2Server, ISource2Server, SOURCE2SERVER_INTERFACE_VERSION);
	GET_V_IFACE_CURRENT(GetEngineFactory, g_pNetworkServerService, INetworkServerService, NETWORKSERVERSERVICE_INTERFACE_VERSION);

	strncpy(crashGamePath, ismm->GetBaseDir(), sizeof(crashGamePath) - 1);
	ismm->Format(dumpStoragePath, sizeof(dumpStoragePath), "%s/addons/accelerator_local/dumps", ismm->GetBaseDir());

	std::filesystem::create_directory(dumpStoragePath);

#if defined _LINUX
	google_breakpad::MinidumpDescriptor descriptor(dumpStoragePath);
	exceptionHandler = new google_breakpad::ExceptionHandler(descriptor, NULL, dumpCallback, NULL, true, -1);

	struct sigaction oact;
	sigaction(SIGSEGV, NULL, &oact);
	SignalHandler = oact.sa_sigaction;

	SH_ADD_HOOK(IServerGameDLL, GameFrame, g_pSource2Server, SH_MEMBER(this, &AcceleratorCS2::GameFrame), true);
#else
	wchar_t* buf = new wchar_t[sizeof(dumpStoragePath)];
	size_t num_chars = mbstowcs(buf, dumpStoragePath, sizeof(dumpStoragePath));

	exceptionHandler = new google_breakpad::ExceptionHandler(
		std::wstring(buf, num_chars), NULL, dumpCallback, NULL, google_breakpad::ExceptionHandler::HANDLER_ALL,
		static_cast<MINIDUMP_TYPE>(MiniDumpWithUnloadedModules | MiniDumpWithFullMemoryInfo), static_cast<const wchar_t*>(NULL), NULL);

	vectoredHandler = AddVectoredExceptionHandler(0, BreakpadVectoredHandler);

	delete buf;
#endif

	SH_ADD_HOOK(INetworkServerService, StartupServer, g_pNetworkServerService, SH_MEMBER(this, &AcceleratorCS2::StartupServer), true);

	strncpy(crashCommandLine, CommandLine()->GetCmdLine(), sizeof(crashCommandLine) - 1);

	if (late)
		StartupServer({}, nullptr, nullptr);

	return true;
}

bool AcceleratorCS2::Unload(char* error, size_t maxlen)
{
#if defined _LINUX
	SH_REMOVE_HOOK(IServerGameDLL, GameFrame, g_pSource2Server, SH_MEMBER(this, &AcceleratorCS2::GameFrame), true);
#endif
	SH_REMOVE_HOOK(INetworkServerService, StartupServer, g_pNetworkServerService, SH_MEMBER(this, &AcceleratorCS2::StartupServer), true);

	delete exceptionHandler;

	return true;
}

#if defined _LINUX

void AcceleratorCS2::GameFrame(bool simulating, bool bFirstTick, bool bLastTick)
{
	bool weHaveBeenFuckedOver = false;
	struct sigaction oact;

	for (int i = 0; i < kNumHandledSignals; ++i)
	{
		sigaction(kExceptionSignals[i], NULL, &oact);

		if (oact.sa_sigaction != SignalHandler)
		{
			weHaveBeenFuckedOver = true;
			break;
		}
	}

	if (!weHaveBeenFuckedOver)
		return;

	struct sigaction act;
	memset(&act, 0, sizeof(act));
	sigemptyset(&act.sa_mask);

	for (int i = 0; i < kNumHandledSignals; ++i)
		sigaddset(&act.sa_mask, kExceptionSignals[i]);

	act.sa_sigaction = SignalHandler;
	act.sa_flags = SA_ONSTACK | SA_SIGINFO;

	for (int i = 0; i < kNumHandledSignals; ++i)
		sigaction(kExceptionSignals[i], &act, NULL);
}

#endif

void AcceleratorCS2::StartupServer(const GameSessionConfiguration_t& config, ISource2WorldSession*, const char*)
{
	strncpy(crashMap, g_pNetworkServerService->GetIGameServer()->GetMapName(), sizeof(crashMap) - 1);
}

const char* AcceleratorCS2::GetLicense()
{
	return "GPLv3";
}

const char* AcceleratorCS2::GetVersion()
{
	return "1.0.0";
}

const char* AcceleratorCS2::GetDate()
{
	return __DATE__;
}

const char* AcceleratorCS2::GetLogTag()
{
	return "AcceleratorCS2";
}

const char* AcceleratorCS2::GetAuthor()
{
	return "Poggu, Phoenix (˙·٠●Феникс●٠·˙), Asher Baker (asherkin)";
}

const char* AcceleratorCS2::GetDescription()
{
	return "Crash Handler";
}

const char* AcceleratorCS2::GetName()
{
	return "AcceleratorCS2";
}

const char* AcceleratorCS2::GetURL()
{
	return "https://github.com/Source2ZE/AcceleratorCS2";
}