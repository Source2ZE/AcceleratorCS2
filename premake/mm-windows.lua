files {
	path.join(SDK_PATH, "tier0_perproject", "convar.cpp"),
}

links {
	path.join(SDK_PATH, "lib", "public", "win64", "tier0.lib"),
	path.join(SDK_PATH, "lib", "public", "win64", "interfaces.lib"),
	path.join(SDK_PATH, "lib", "public", "win64", "mathlib.lib")
}

includedirs {
	_MAIN_SCRIPT_DIR,
	-- sdk
	SDK_PATH,
	path.join(SDK_PATH, "thirdparty", "protobuf-3.21.8", "src"),
	path.join(SDK_PATH, "common"),
	path.join(SDK_PATH, "game", "shared"),
	path.join(SDK_PATH, "public"),
	path.join(SDK_PATH, "public", "mathlib"),
	path.join(SDK_PATH, "public", "tier0"),
	path.join(SDK_PATH, "public", "entity2"),
	-- metamod
	path.join(MM_PATH, "core"),
	path.join(MM_PATH, "third_party", "khook", "include"),
}

defines {
	"COMPILER_MSVC",
	"COMPILER_MSVC64",
	"PLATFORM_64BITS",
	"X64BITS",
	"WIN32",
	"WINDOWS",
	"CRT_SECURE_NO_WARNINGS",
	"CRT_SECURE_NO_DEPRECATE",
	"CRT_NONSTDC_NO_DEPRECATE"
}

characterset "MBCS"