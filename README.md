# AcceleratorCS2

A fork of [AcceleratorLocal](https://github.com/komashchenko/AcceleratorLocal) which is a fork of [asherkin's accelerator](https://github.com/asherkin/accelerator) using Premake with Linux and Windows support.

## Configuration

The configuration file is located at `AcceleratorCS2/config.json`. It contains a `MinidumpAccountSteamId64` field for you to specify your steamid64. This allows you to view full details for your crash dumps on [Throttle](https://crash.limetech.org/).

## Possible conflicts with CounterStrikeSharp

### Windows startup crash

**You must run the server with `-DoNotPreloadDLLs` startup parameter if running Accelerator with CS# on Windows.** The engine loops over every single loaded dll and tries to read an address in every single page of memory. This causes access violations for the .NET binaries that Accelerator catches and handles (dumps and quits).

### Uncaught C# exceptions crashing

If any C# plugin code throws an exception that isn't caught (e.g. no `try`/`catch` handling), Accelerator will catch and handle it (dumps and quits). This is generally easy to spot, because the top function in the stack trace will be `memfd:doublemapper (deleted)`. **Running Accelerator with CS# plugins that do not take this into account will introduce new "crashes" that would not happen otherwise.**