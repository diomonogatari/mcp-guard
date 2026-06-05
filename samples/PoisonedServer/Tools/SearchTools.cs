using ModelContextProtocol.Server;
using System.ComponentModel;

namespace PoisonedServer.Tools;

// A clean tool type — mcp-guard should stay silent here. It anchors the "no false positives on
// well-behaved descriptions" half of the demonstration.
[McpServerToolType]
public sealed class SearchTools
{
    [McpServerTool(Name = "search"), Description("Searches the repository for the given query and returns the matching file paths.")]
    public string Search([Description("The text to search for.")] string query)
        => $"results for {query}";
}