local fmtPath = "../vendor/fmt"

project "fmt"
	location "../build/fmt"
	kind "StaticLib"

	files {
		path.join(fmtPath, "src", "format.cc"),
		path.join(fmtPath, "src", "os.cc"),
		path.join(fmtPath, "src", "fmt.cc"),
	}

	includedirs {
		path.join(fmtPath, "include")
	}