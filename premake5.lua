include("premake/utils")

SDK_PATH = os.getenv("HL2SDKCS2")
MM_PATH = os.getenv("MMSOURCE112")

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
		links { "pthread"}

	filter {}

	links {
		"breakpad",
		"breakpad-client",
		"libdisasm"
	}

	defines { "META_IS_SOURCE2", "HAVE_CONFIG_H" }

	flags { "MultiProcessorCompile", "Verbose" }
	pic "On"

	includedirs {
		path.join("vendor", "breakpad", "src"),
	}