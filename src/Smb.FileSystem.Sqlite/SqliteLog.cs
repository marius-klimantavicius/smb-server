using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Logging.Abstractions;

namespace Smb.FileSystem.Sqlite;

public static class SqliteLog
{
    public static ILogger Logger { get; set; } = NullLogger.Instance;

    internal static readonly AsyncLocal<bool> Suppress = new AsyncLocal<bool>();

    public static void ExecuteNonQuery(string commandText)
    {
        if (!Suppress.Value)
            Logger.LogDebug("ExecuteNonQuery: {CommandText}", commandText);
    }

    public static void Query(string commandText)
    {
        if (!Suppress.Value)
            Logger.LogDebug("Query: {CommandText}", commandText);
    }

    public static void Error(string message)
    {
        if (!Suppress.Value)
            Logger.LogError("Error: {Message}", message);
    }
}
