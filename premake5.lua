include("premake/utils")

SDK_PATH = os.getenv("HL2SDKCS2")
MM_PATH = os.getenv("MMSOURCE112")
local breakpadPath = "vendor/breakpad/src"

if(SDK_PATH == nil) then
	error("INVALID HL2SDK PATH")
end

if(MM_PATH == nil) then
	error("INVALID METAMOD PATH")
end

workspace "AcceleratorCS2"
	configurations { "Debug", "Release" }
	platforms {
		"win64",
		"linux64"
	}
	location "build"
	include("premake/breakpad")

project "AcceleratorCS2"
	kind "SharedLib"
	language "C++"
	targetdir "bin/%{cfg.buildcfg}"
	location "build/AcceleratorCS2"
	visibility  "Hidden"
	targetprefix ""

	files { "*.h", "*.cpp" }

	vpaths {
		["Headers/*"] = "**.h",
		["Sources/*"] = "**.cpp"
	}

	filter "configurations:Debug"
		defines { "DEBUG" }
		symbols "On"

	filter "configurations:Release"
		defines { "NDEBUG" }
		optimize "On"

	filter "system:windows"
		cppdialect "c++20"
		include("premake/mm-windows.lua")

	filter "system:linux"
		cppdialect "c++2a"
		include("premake/mm-linux.lua")
		links { "pthread", "z"}
		linkoptions { '-static-libstdc++', '-static-libgcc' }
		disablewarnings { "register" }

		includedirs {
			path.join(_MAIN_SCRIPT_DIR, "breakpad-config", "linux"),
		}

		files {
			path.join(breakpadPath, "common", "dwarf_cfi_to_module.cc"),
			path.join(breakpadPath, "common", "dwarf_cu_to_module.cc"),
			path.join(breakpadPath, "common", "dwarf_line_to_module.cc"),
			path.join(breakpadPath, "common", "dwarf_range_list_handler.cc"),
			path.join(breakpadPath, "common", "language.cc"),
			path.join(breakpadPath, "common", "module.cc"),
			path.join(breakpadPath, "common", "path_helper.cc"),
			path.join(breakpadPath, "common", "stabs_reader.cc"),
			path.join(breakpadPath, "common", "stabs_to_module.cc"),
			path.join(breakpadPath, "common", "dwarf", "bytereader.cc"),
			path.join(breakpadPath, "common", "dwarf", "dwarf2diehandler.cc"),
			path.join(breakpadPath, "common", "dwarf", "dwarf2reader.cc"),
			path.join(breakpadPath, "common", "dwarf", "elf_reader.cc"),
			path.join(breakpadPath, "common", "linux", "crc32.cc"),
			path.join(breakpadPath, "common", "linux", "dump_symbols.cc"),
			path.join(breakpadPath, "common", "linux", "elf_symbols_to_module.cc"),
			path.join(breakpadPath, "common", "linux", "breakpad_getcontext.S")
		}

	filter {}

	links {
		"breakpad",
		"breakpad-client",
		"libdisasm"
	}

	defines { "META_IS_SOURCE2", "HAVE_CONFIG_H", "HAVE_STDINT_H", "_ITERATOR_DEBUG_LEVEL=0" }

	vectorextensions "sse"
	strictaliasing "Off"

	flags { "MultiProcessorCompile", "Verbose" }
	pic "On"

	includedirs {
		path.join("vendor", "breakpad", "src"),
		path.join("vendor", "fmt", "include"),
	}