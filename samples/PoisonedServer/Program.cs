// Entry point so the deliberately poisoned sample is runnable (F5 / dotnet run). The runtime behavior
// is beside the point — what matters is that *building* this project surfaces mcp-guard's findings
// (the MCPGxxx warnings) in the build output and the Problems panel.
System.Console.WriteLine("PoisonedServer: a deliberately poisoned MCP server fixture.");
System.Console.WriteLine("Build this project to see mcp-guard's MCPGxxx findings in the build output.");