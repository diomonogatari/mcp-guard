; Unshipped analyzer release
; https://github.com/dotnet/roslyn-analyzers/blob/main/src/Microsoft.CodeAnalysis.Analyzers/ReleaseTrackingAnalyzers.Help.md

### New Rules

Rule ID | Category | Severity | Notes
--------|----------|----------|-------
MCPG003 | Security | Warning  | MCP tool description references a sensitive credential artifact.
MCPG004 | Security | Warning  | MCP tool description directs data to an external destination.
MCPG005 | Security | Warning  | MCP tool description contains an ANSI/terminal escape sequence.
