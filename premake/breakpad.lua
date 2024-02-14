if(_ACTION ~= nil) then
	local commands = {
		"cd ../vendor/breakpad",
		"git clean -fdx",
		"git reset --hard"
	}

	os.execute(table.concat(commands, " && "))

	commands = {
		"cd ../vendor/breakpad",
	}

	local files = os.matchfiles("../patches/*.patch");
	for _, patch in ipairs(files) do
		table.insert(commands, "git apply --reject ../" .. patch)
	end

	os.execute(table.concat(commands, " && "))
end

local breakpadPath = "../vendor/breakpad/src"

project "breakpad"
	location "../build/breakpad"
	kind "StaticLib"

	files {
		path.join(breakpadPath, "processor", "basic_code_modules.cc"),
		path.join(breakpadPath, "processor", "basic_source_line_resolver.cc"),
		path.join(breakpadPath, "processor", "call_stack.cc"),
		path.join(breakpadPath, "processor", "cfi_frame_info.cc"),
		path.join(breakpadPath, "processor", "convert_old_arm64_context.cc"),
		path.join(breakpadPath, "processor", "disassembler_x86.cc"),
		path.join(breakpadPath, "processor", "dump_context.cc"),
		path.join(breakpadPath, "processor", "dump_object.cc"),
		path.join(breakpadPath, "processor", "exploitability.cc"),
		path.join(breakpadPath, "processor", "exploitability_linux.cc"),
		path.join(breakpadPath, "processor", "exploitability_win.cc"),
		path.join(breakpadPath, "processor", "fast_source_line_resolver.cc"),
		path.join(breakpadPath, "processor", "logging.cc"),
		path.join(breakpadPath, "processor", "microdump.cc"),
		path.join(breakpadPath, "processor", "microdump_processor.cc"),
		path.join(breakpadPath, "processor", "minidump.cc"),
		path.join(breakpadPath, "processor", "minidump_processor.cc"),
		path.join(breakpadPath, "processor", "module_comparer.cc"),
		path.join(breakpadPath, "processor", "module_serializer.cc"),
		path.join(breakpadPath, "processor", "pathname_stripper.cc"),
		path.join(breakpadPath, "processor", "process_state.cc"),
		path.join(breakpadPath, "processor", "proc_maps_linux.cc"),
		path.join(breakpadPath, "processor", "simple_symbol_supplier.cc"),
		path.join(breakpadPath, "processor", "source_line_resolver_base.cc"),
		path.join(breakpadPath, "processor", "stack_frame_cpu.cc"),
		path.join(breakpadPath, "processor", "stack_frame_symbolizer.cc"),
		path.join(breakpadPath, "processor", "stackwalk_common.cc"),
		path.join(breakpadPath, "processor", "stackwalker.cc"),
		path.join(breakpadPath, "processor", "stackwalker_amd64.cc"),
		path.join(breakpadPath, "processor", "stackwalker_arm.cc"),
		path.join(breakpadPath, "processor", "stackwalker_arm64.cc"),
		path.join(breakpadPath, "processor", "stackwalker_address_list.cc"),
		path.join(breakpadPath, "processor", "stackwalker_mips.cc"),
		path.join(breakpadPath, "processor", "stackwalker_ppc.cc"),
		path.join(breakpadPath, "processor", "stackwalker_ppc64.cc"),
		path.join(breakpadPath, "processor", "stackwalker_riscv.cc"),
		path.join(breakpadPath, "processor", "stackwalker_riscv64.cc"),
		path.join(breakpadPath, "processor", "stackwalker_sparc.cc"),
		path.join(breakpadPath, "processor", "stackwalker_x86.cc"),
		path.join(breakpadPath, "processor", "symbolic_constants_win.cc"),
		path.join(breakpadPath, "processor", "tokenize.cc")
	}

	includedirs {
		breakpadPath
	}

	pic "On"

	defines { "HAVE_CONFIG_H" }

	filter "system:linux"
		files {
			path.join(breakpadPath, "common", "linux", "scoped_pipe.cc"),
			path.join(breakpadPath, "common", "linux", "scoped_tmpfile.cc"),
			path.join(breakpadPath, "processor", "disassembler_objdump.cc")
		}

		includedirs {
			path.join(_MAIN_SCRIPT_DIR, "breakpad-config", "linux")
		}

	filter "system:windows"
		includedirs {
			path.join(_MAIN_SCRIPT_DIR, "breakpad-config", "windows")
		}

project "breakpad-client"
	location "../build/breakpad-client"
	kind "StaticLib"
	language "c"

	files {
		path.join(breakpadPath, "common", "convert_UTF.cc"),
		path.join(breakpadPath, "common", "string_conversion.cc"),
	}

	pic "On"

	defines { "HAVE_CONFIG_H" }

	includedirs {
		breakpadPath
	}

	filter "system:linux"
		files {
			path.join(breakpadPath, "client", "minidump_file_writer.cc"),
			path.join(breakpadPath, "client", "linux", "crash_generation", "crash_generation_client.cc"),
			path.join(breakpadPath, "client", "linux", "crash_generation", "crash_generation_server.cc"),
			path.join(breakpadPath, "client", "linux", "dump_writer_common", "thread_info.cc"),
			path.join(breakpadPath, "client", "linux", "dump_writer_common", "ucontext_reader.cc"),
			path.join(breakpadPath, "client", "linux", "handler", "exception_handler.cc"),
			path.join(breakpadPath, "client", "linux", "handler", "minidump_descriptor.cc"),
			path.join(breakpadPath, "client", "linux", "log", "log.cc"),
			path.join(breakpadPath, "client", "linux", "microdump_writer", "microdump_writer.cc"),
			path.join(breakpadPath, "client", "linux", "minidump_writer", "linux_core_dumper.cc"),
			path.join(breakpadPath, "client", "linux", "minidump_writer", "linux_dumper.cc"),
			path.join(breakpadPath, "client", "linux", "minidump_writer", "linux_ptrace_dumper.cc"),
			path.join(breakpadPath, "client", "linux", "minidump_writer", "minidump_writer.cc"),
			path.join(breakpadPath, "client", "linux", "minidump_writer", "pe_file.cc"),
			path.join(breakpadPath, "common", "linux", "elf_core_dump.cc"),
			path.join(breakpadPath, "common", "linux", "elfutils.cc"),
			path.join(breakpadPath, "common", "linux", "file_id.cc"),
			path.join(breakpadPath, "common", "linux", "guid_creator.cc"),
			path.join(breakpadPath, "common", "linux", "linux_libc_support.cc"),
			path.join(breakpadPath, "common", "linux", "memory_mapped_file.cc"),
			path.join(breakpadPath, "common", "linux", "safe_readlink.cc")
		}

		includedirs {
			path.join(_MAIN_SCRIPT_DIR, "breakpad-config", "linux")
		}

	filter "system:windows"
		files {
			path.join(breakpadPath, "client", "windows", "crash_generation", "client_info.cc"),
			path.join(breakpadPath, "client", "windows", "crash_generation", "crash_generation_client.cc"),
			path.join(breakpadPath, "client", "windows", "crash_generation", "crash_generation_server.cc"),
			path.join(breakpadPath, "client", "windows", "crash_generation", "minidump_generator.cc"),
			path.join(breakpadPath, "client", "windows", "handler", "exception_handler.cc"),
			path.join(breakpadPath, "common", "windows", "guid_string.cc")
		}

		includedirs {
			path.join(_MAIN_SCRIPT_DIR, "breakpad-config", "windows")
		}

	filter {}

project "libdisasm"
	location "../build/libdisasm"
	kind "StaticLib"
	language "c"

	files {
		path.join(breakpadPath, "third_party", "libdisasm", "ia32_implicit.c"),
		path.join(breakpadPath, "third_party", "libdisasm", "ia32_insn.c"),
		path.join(breakpadPath, "third_party", "libdisasm", "ia32_invariant.c"),
		path.join(breakpadPath, "third_party", "libdisasm", "ia32_modrm.c"),
		path.join(breakpadPath, "third_party", "libdisasm", "ia32_opcode_tables.c"),
		path.join(breakpadPath, "third_party", "libdisasm", "ia32_operand.c"),
		path.join(breakpadPath, "third_party", "libdisasm", "ia32_reg.c"),
		path.join(breakpadPath, "third_party", "libdisasm", "ia32_settings.c"),
		path.join(breakpadPath, "third_party", "libdisasm", "x86_disasm.c"),
		path.join(breakpadPath, "third_party", "libdisasm", "x86_format.c"),
		path.join(breakpadPath, "third_party", "libdisasm", "x86_imm.c"),
		path.join(breakpadPath, "third_party", "libdisasm", "x86_insn.c"),
		path.join(breakpadPath, "third_party", "libdisasm", "x86_misc.c"),
		path.join(breakpadPath, "third_party", "libdisasm", "x86_operand_list.c")
	}

	pic "On"

	defines { "HAVE_CONFIG_H" }

	includedirs {
		breakpadPath
	}

	filter "system:linux"
		includedirs {
			path.join(_MAIN_SCRIPT_DIR, "breakpad-config", "linux")
		}

	filter "system:windows"
		includedirs {
			path.join(_MAIN_SCRIPT_DIR, "breakpad-config", "windows")
		}
