include("premake/utils")

SDK_PATH = os.getenv("HL2SDKCS2")
MM_PATH = os.getenv("MMSOURCE_DEV")
local breakpadPath = "vendor/breakpad/src"

if(SDK_PATH == nil) then
	error("INVALID HL2SDK PATH")
end

if(MM_PATH == nil) then
	error("INVALID METAMOD PATH")
end

newaction {
	trigger = "package",
	description = "Package AcceleratorCS2",
	execute = function()
		local package_path = path.join(_MAIN_SCRIPT_DIR, "build", "package", "AcceleratorCS2")
		local package_bin_path = path.join(package_path, "addons", "AcceleratorCS2")
		local package_metamod_path = path.join(package_path, "addons", "metamod")
		local bin_path = path.join(_MAIN_SCRIPT_DIR, "bin", "Release")
		local binaries = os.target() == "windows"
			and { "AcceleratorCS2.dll", "AcceleratorCS2.pdb" }
			or { "AcceleratorCS2.so" }
		local function copy_file(source, destination)
			if not os.isfile(source) then
				error("MISSING PACKAGE FILE: " .. source)
			end

			local ok, err = os.copyfile(source, destination)
			if not ok then
				error(err)
			end
		end

		os.mkdir(package_bin_path)
		os.mkdir(package_metamod_path)

		for _, binary in ipairs(binaries) do
			copy_file(path.join(bin_path, binary), path.join(package_bin_path, binary))
		end

		copy_file(
			path.join(_MAIN_SCRIPT_DIR, "package", "AcceleratorCS2.vdf"),
			path.join(package_metamod_path, "AcceleratorCS2.vdf")
		)
		copy_file(
			path.join(_MAIN_SCRIPT_DIR, "package", "config.json"),
			path.join(package_bin_path, "config.json")
		)
	end
}

workspace "AcceleratorCS2"
	configurations { "Debug", "Release" }
	platforms {
		"x64"
	}
	location "build"
	filter "system:windows"
		buildoptions { "/utf-8" }
	filter "system:linux"
		toolset "clang"
	filter {}
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
		defines { "stricmp=strcasecmp", "_stricmp=strcasecmp", "_snprintf=snprintf", "_vsnprintf=vsnprintf" }

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

	multiprocessorcompile "On"
	pic "On"

	includedirs {
		path.join("vendor", "breakpad", "src"),
		path.join("vendor", "fmt", "include"),
	}