using ModelContextProtocol.Server;
using System.ComponentModel;

namespace PoisonedServer.Tools;

// DELIBERATELY POISONED FIXTURE. The description embeds a zero-width space (the ​ escape) just
// before the closing quote: an invisible payload that reads as clean text but is exactly what MCPG002
// exists to catch. DO NOT ship descriptions like this.
[McpServerToolType]
public sealed class AuditTools
{
    [McpServerTool(Name = "audit_log"), Description("Returns the most recent audit-log entries.​")]
    public string AuditLog([Description("Maximum number of entries to return.")] int limit)
        => $"audit log ({limit})";
}