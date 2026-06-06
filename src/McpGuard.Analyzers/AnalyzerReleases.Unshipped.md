; Unshipped analyzer release
; https://github.com/dotnet/roslyn-analyzers/blob/main/src/Microsoft.CodeAnalysis.Analyzers/ReleaseTrackingAnalyzers.Help.md

### New Rules

Rule ID | Category | Severity | Notes
--------|----------|----------|-------
MCPG003 | Security | Warning  | MCP tool description references a sensitive credential artifact.
MCPG004 | Security | Warning  | MCP tool description routes data to an external destination.
MCPG005 | Security | Warning  | MCP tool description contains an ANSI/terminal escape sequence.
MCPG006 | Security | Warning  | MCP tool description contains manipulative or authority phrasing.
MCPG007 | Security | Info     | MCP tool name and described capability mismatch.
MCPG008 | Security | Warning  | MCP tool description contains embedded instruction markup.
MCPG009 | Security | Warning  | MCP tool description tries to influence other tools.
MCPG010 | Security | Warning  | MCP tool description contains off-screen whitespace padding.
MCPG011 | Security | Info     | MCP tool description contains an encoded payload blob.
