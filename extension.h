#pragma once
#include "khook.hpp"
#include <ISmmPlugin.h>
#include <igameevents.h>
#include <iserver.h>

class AcceleratorCS2 : public ISmmPlugin, public IMetamodListener
{
public:
	bool Load(PluginId id, ISmmAPI* ismm, char* error, size_t maxlen, bool late);
	bool Unload(char* error, size_t maxlen);
public:
	const char* GetAuthor();
	const char* GetName();
	const char* GetDescription();
	const char* GetURL();
	const char* GetLicense();
	const char* GetVersion();
	const char* GetDate();
	const char* GetLogTag();
public: // Hooks
	KHook::Return<void> GameFrame(IServerGameDLL* pThis, bool simulating, bool bFirstTick, bool bLastTick);
	KHook::Return<void> StartupServer(INetworkServerService* pThis, const GameSessionConfiguration_t& config, ISource2WorldSession*, const char*);
};