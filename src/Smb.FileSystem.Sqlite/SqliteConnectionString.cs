// Permission is hereby granted, free of charge, to any person obtaining a copy
// of this software and associated documentation files (the "Software"), to deal
// in the Software without restriction, including without limitation the rights
// to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
// copies of the Software, and to permit persons to whom the Software is
// furnished to do so, subject to the following conditions:
//
// The above copyright notice and this permission notice shall be included in
// all copies or substantial portions of the Software.
//
// THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
// IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
// FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
// AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
// LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
// OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
// THE SOFTWARE.
//

using System.Data.Common;
using System.Globalization;
using System.Runtime.CompilerServices;

namespace Smb.FileSystem.Sqlite;

public class SqliteConnectionString
{
    private const string DateTimeSqliteDefaultFormat = "yyyy'-'MM'-'dd'T'HH':'mm':'ss'.'fff";

    public string? UniqueKey { get; }
    public string DatabasePath { get; }
    public bool StoreDateTimeAsTicks { get; }
    public bool StoreTimeSpanAsTicks { get; }
    public string DateTimeStringFormat { get; }
    public DateTimeStyles DateTimeStyle { get; }
    public SqliteOpenFlags OpenFlags { get; }
    public string? VfsName { get; }

    public SqliteConnectionString(string connectionString)
        : this(Parse(connectionString))
    {
    }

    public SqliteConnectionString(string databasePath, bool storeDateTimeAsTicks)
        : this(databasePath, SqliteOpenFlags.Create | SqliteOpenFlags.ReadWrite, storeDateTimeAsTicks)
    {
    }

    public SqliteConnectionString(string databasePath, bool storeDateTimeAsTicks, string? vfsName = null)
        : this(databasePath, SqliteOpenFlags.Create | SqliteOpenFlags.ReadWrite, storeDateTimeAsTicks, vfsName)
    {
    }

    public SqliteConnectionString(string databasePath, SqliteOpenFlags openFlags, bool storeDateTimeAsTicks, string? vfsName = null, string dateTimeStringFormat = DateTimeSqliteDefaultFormat, bool storeTimeSpanAsTicks = true)
    {
        UniqueKey = $"{databasePath}_{(uint)openFlags:X8}";
        StoreDateTimeAsTicks = storeDateTimeAsTicks;
        StoreTimeSpanAsTicks = storeTimeSpanAsTicks;
        DateTimeStringFormat = dateTimeStringFormat;
        DateTimeStyle = "o".Equals(DateTimeStringFormat, StringComparison.OrdinalIgnoreCase) || "r".Equals(DateTimeStringFormat, StringComparison.OrdinalIgnoreCase) ? DateTimeStyles.RoundtripKind : DateTimeStyles.None;
        OpenFlags = openFlags;
        VfsName = vfsName;

        DatabasePath = databasePath;
    }

    private SqliteConnectionString(ParsedConnectionString connectionString)
        : this(
            connectionString.DatabasePath,
            connectionString.OpenFlags,
            connectionString.StoreDateTimeAsTicks,
            connectionString.VfsName,
            connectionString.DateTimeStringFormat,
            connectionString.StoreTimeSpanAsTicks)
    {
    }

    private static ParsedConnectionString Parse(string connectionString)
    {
        ArgumentNullException.ThrowIfNull(connectionString);

        if (!connectionString.Contains('='))
        {
            return new ParsedConnectionString(
                connectionString,
                SqliteOpenFlags.Create | SqliteOpenFlags.ReadWrite,
                storeDateTimeAsTicks: true,
                vfsName: null,
                DateTimeSqliteDefaultFormat,
                storeTimeSpanAsTicks: true);
        }

        var builder = new DbConnectionStringBuilder { ConnectionString = connectionString };
        string? databasePath = null;
        var openFlags = SqliteOpenFlags.Create | SqliteOpenFlags.ReadWrite;
        var storeDateTimeAsTicks = true;
        var storeTimeSpanAsTicks = true;
        var dateTimeStringFormat = DateTimeSqliteDefaultFormat;
        string? vfsName = null;

        foreach (string key in builder.Keys)
        {
            var value = (string)builder[key];
            switch (NormalizeKey(key))
            {
                case "data source":
                case "datasource":
                case "filename":
                    databasePath = value;
                    break;
                case "mode":
                    openFlags = SetMode(openFlags, value);
                    break;
                case "cache":
                    openFlags = SetCache(openFlags, value);
                    break;
                case "mutex":
                    openFlags = SetMutex(openFlags, value);
                    break;
                case "flags":
                case "open flags":
                case "openflags":
                    if (!Enum.TryParse(value, ignoreCase: true, out SqliteOpenFlags parsedOpenFlags))
                        ThrowInvalidConnectionStringValue(key, value);

                    openFlags = parsedOpenFlags;
                    break;
                case "store datetime as ticks":
                case "storedatetimeasticks":
                    if (!bool.TryParse(value, out storeDateTimeAsTicks))
                        ThrowInvalidConnectionStringValue(key, value);

                    break;
                case "store timespan as ticks":
                case "storetimespanasticks":
                    if (!bool.TryParse(value, out storeTimeSpanAsTicks))
                        ThrowInvalidConnectionStringValue(key, value);

                    break;
                case "datetime string format":
                case "datetimestringformat":
                    dateTimeStringFormat = value;
                    break;
                case "vfs":
                case "vfs name":
                case "vfsname":
                    vfsName = value;
                    break;
                default:
                    throw new ArgumentException($"Keyword not supported: '{key}'.", nameof(connectionString));
            }
        }

        if (databasePath is null)
            throw new ArgumentException("Connection string must contain a Data Source or Filename keyword.", nameof(connectionString));

        return new ParsedConnectionString(
            databasePath,
            openFlags,
            storeDateTimeAsTicks,
            vfsName,
            dateTimeStringFormat,
            storeTimeSpanAsTicks);
    }

    private static string NormalizeKey(string key) => key.Trim().ToLowerInvariant();

    private static SqliteOpenFlags SetMode(SqliteOpenFlags openFlags, string value)
    {
        const SqliteOpenFlags modeFlags = SqliteOpenFlags.ReadOnly | SqliteOpenFlags.ReadWrite | SqliteOpenFlags.Create | SqliteOpenFlags.Memory;
        openFlags &= ~modeFlags;

        return value.ToLowerInvariant() switch
        {
            "readonly" => openFlags | SqliteOpenFlags.ReadOnly,
            "readwrite" => openFlags | SqliteOpenFlags.ReadWrite,
            "readwritecreate" => openFlags | SqliteOpenFlags.ReadWrite | SqliteOpenFlags.Create,
            "memory" => openFlags | SqliteOpenFlags.ReadWrite | SqliteOpenFlags.Create | SqliteOpenFlags.Memory,
            _ => ThrowInvalidConnectionStringValue("Mode", value),
        };
    }

    private static SqliteOpenFlags SetCache(SqliteOpenFlags openFlags, string value)
    {
        openFlags &= ~(SqliteOpenFlags.SharedCache | SqliteOpenFlags.PrivateCache);

        return value.ToLowerInvariant() switch
        {
            "default" => openFlags,
            "shared" => openFlags | SqliteOpenFlags.SharedCache,
            "private" => openFlags | SqliteOpenFlags.PrivateCache,
            _ => ThrowInvalidConnectionStringValue("Cache", value),
        };
    }

    private static SqliteOpenFlags SetMutex(SqliteOpenFlags openFlags, string value)
    {
        openFlags &= ~(SqliteOpenFlags.NoMutex | SqliteOpenFlags.FullMutex);

        return value.ToLowerInvariant() switch
        {
            "default" => openFlags,
            "no" or "nomutex" => openFlags | SqliteOpenFlags.NoMutex,
            "full" or "fullmutex" => openFlags | SqliteOpenFlags.FullMutex,
            _ => ThrowInvalidConnectionStringValue("Mutex", value),
        };
    }

    [MethodImpl(MethodImplOptions.NoInlining)]
    private static SqliteOpenFlags ThrowInvalidConnectionStringValue(string key, string value) =>
        throw new ArgumentException($"Invalid value '{value}' for connection string keyword '{key}'.");

    private struct ParsedConnectionString
    {
        public string DatabasePath { get; init; }
        public SqliteOpenFlags OpenFlags { get; init; }
        public bool StoreDateTimeAsTicks { get; init; }
        public string? VfsName { get; init; }
        public string DateTimeStringFormat { get; init; }
        public bool StoreTimeSpanAsTicks { get; init; }

        public ParsedConnectionString(string databasePath,
            SqliteOpenFlags openFlags,
            bool storeDateTimeAsTicks,
            string? vfsName,
            string dateTimeStringFormat,
            bool storeTimeSpanAsTicks)
        {
            DatabasePath = databasePath;
            OpenFlags = openFlags;
            StoreDateTimeAsTicks = storeDateTimeAsTicks;
            VfsName = vfsName;
            DateTimeStringFormat = dateTimeStringFormat;
            StoreTimeSpanAsTicks = storeTimeSpanAsTicks;
        }
    }
}