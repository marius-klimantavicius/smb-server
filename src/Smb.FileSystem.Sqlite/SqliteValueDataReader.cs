using System.Diagnostics.CodeAnalysis;
using System.Globalization;
using System.Runtime.CompilerServices;
using System.Runtime.InteropServices.Marshalling;
using static Managed.Database.Sqlite;
using DateTime = System.DateTime;

namespace Smb.FileSystem.Sqlite;

public unsafe struct SqliteValueDataReader : ISqliteDataReader, IDisposable
{
    private readonly SqliteConnection _connection;
    internal readonly sqlite3_stmt* _statement;

    private Dictionary<string, int>? _aliasMapping;
    private Dictionary<TableColumnName, int>? _tableColumnMapping;

    public readonly int FieldCount => sqlite3_column_count(_statement);

    public SqliteValueDataReader(SqliteConnection connection, sqlite3_stmt* statement)
    {
        _connection = connection;
        _statement = statement;
    }

    public void Dispose()
    {
        var s = _statement;
        this = default;

        if (s != null)
            sqlite3_finalize(s);
    }

    public readonly void Close()
    {
        if (_statement != null)
            sqlite3_finalize(_statement);
    }

    public readonly bool Read()
    {
        var result = sqlite3_step(_statement);
        if (result == SQLITE_ROW)
            return true;
        if (result == SQLITE_DONE)
            return false;

        SqliteException.ThrowIfNotOk(result, _connection.Handle);
        return false;
    }

    public readonly string GetColumnName(int ordinal)
    {
        return GetString(sqlite3_column_name(_statement, ordinal))!;
    }

    public readonly SqliteColumnType GetColumnType(int ordinal)
    {
        return (SqliteColumnType)sqlite3_column_type(_statement, ordinal);
    }

    public readonly object? GetValue(int ordinal)
    {
        var type = GetColumnType(ordinal);
        return type switch
        {
            SqliteColumnType.Integer => GetInt64(ordinal),
            SqliteColumnType.Float => GetDouble(ordinal),
            SqliteColumnType.Text => GetString(ordinal),
            SqliteColumnType.Blob => GetBlob(ordinal),
            SqliteColumnType.Null => null,
            _ => GetString(ordinal),
        };
    }

    public readonly bool IsDBNull(int ordinal)
    {
        return sqlite3_column_type(_statement, ordinal) == (int)SqliteColumnType.Null;
    }

    public readonly string? GetString(int ordinal)
    {
        if (sqlite3_column_type(_statement, ordinal) == (int)SqliteColumnType.Null)
            return null;

        return GetString(sqlite3_column_text(_statement, ordinal));
    }

    public readonly long GetInt64(int ordinal)
    {
        return sqlite3_column_int64(_statement, ordinal);
    }

    public readonly long? GetNullableInt64(int ordinal)
    {
        if (sqlite3_column_type(_statement, ordinal) == (int)SqliteColumnType.Null)
            return null;

        return sqlite3_column_int64(_statement, ordinal);
    }

    public readonly int GetInt32(int ordinal)
    {
        return sqlite3_column_int(_statement, ordinal);
    }

    public readonly int? GetNullableInt32(int ordinal)
    {
        if (sqlite3_column_type(_statement, ordinal) == (int)SqliteColumnType.Null)
            return null;

        return sqlite3_column_int(_statement, ordinal);
    }

    public readonly DateTime GetDateTime(int ordinal)
    {
        if (_connection.StoreDateTimeAsTicks)
        {
            var ticks = sqlite3_column_int64(_statement, ordinal);
            return new DateTime(ticks, DateTimeKind.Utc);
        }

        var s = GetString(sqlite3_column_text(_statement, ordinal));
        if (DateTime.TryParseExact(s, _connection.DateTimeStringFormat, CultureInfo.InvariantCulture, _connection.DateTimeStyle, out var result))
            return result.Kind == DateTimeKind.Utc ? result : DateTime.SpecifyKind(result, DateTimeKind.Utc);

        return default;
    }

    public readonly DateTime? GetNullableDateTime(int ordinal)
    {
        if (IsDBNull(ordinal))
            return null;

        return GetDateTime(ordinal);
    }

    public readonly TimeSpan GetTimeSpan(int ordinal)
    {
        if (_connection.StoreTimeSpanAsTicks)
        {
            var ticks = sqlite3_column_int64(_statement, ordinal);
            return new TimeSpan(ticks);
        }

        var s = GetString(sqlite3_column_text(_statement, ordinal));
        if (TimeSpan.TryParseExact(s, "c", CultureInfo.InvariantCulture, TimeSpanStyles.None, out var result))
            return result;

        return TimeSpan.Zero;
    }

    public readonly TimeSpan? GetNullableTimeSpan(int ordinal)
    {
        if (IsDBNull(ordinal))
            return null;

        return GetTimeSpan(ordinal);
    }

    public readonly char GetChar(int ordinal)
    {
        var s = GetString(sqlite3_column_text(_statement, ordinal));
        if (!string.IsNullOrEmpty(s))
            return s[0];

        return (char)0;
    }

    public readonly char? GetNullableChar(int ordinal)
    {
        if (sqlite3_column_type(_statement, ordinal) == (int)SqliteColumnType.Null)
            return null;

        var s = GetString(sqlite3_column_text(_statement, ordinal));
        if (!string.IsNullOrEmpty(s))
            return s[0];

        return null;
    }

    public readonly double GetDouble(int ordinal)
    {
        return sqlite3_column_double(_statement, ordinal);
    }

    public readonly double? GetNullableDouble(int ordinal)
    {
        if (sqlite3_column_type(_statement, ordinal) == (int)SqliteColumnType.Null)
            return null;

        return sqlite3_column_double(_statement, ordinal);
    }

    public readonly decimal GetDecimal(int ordinal)
    {
        return (decimal)sqlite3_column_double(_statement, ordinal);
    }

    public readonly decimal? GetNullableDecimal(int ordinal)
    {
        if (sqlite3_column_type(_statement, ordinal) == (int)SqliteColumnType.Null)
            return null;

        return (decimal)sqlite3_column_double(_statement, ordinal);
    }

    public readonly Guid GetGuid(int ordinal)
    {
        var value = GetString(ordinal);
        if (string.IsNullOrEmpty(value))
            return Guid.Empty;

        return Guid.Parse(value);
    }

    public readonly Guid? GetNullableGuid(int ordinal)
    {
        var value = GetString(ordinal);
        if (string.IsNullOrEmpty(value))
            return null;

        return Guid.Parse(value);
    }

    public readonly byte[]? GetBlob(int ordinal)
    {
        if (sqlite3_column_type(_statement, ordinal) == (int)SqliteColumnType.Null)
            return null;

        var ptr = sqlite3_column_blob(_statement, ordinal);
        if (ptr == null)
            return Array.Empty<byte>();

        var count = sqlite3_column_bytes(_statement, ordinal);
        if (count == 0)
            return Array.Empty<byte>();

        var result = new byte[count];
        new Span<byte>(ptr, count).CopyTo(result);
        return result;
    }

    public readonly bool GetBoolean(int ordinal)
    {
        var columnType = sqlite3_column_type(_statement, ordinal);
        if (columnType == (int)SqliteColumnType.Null)
            return false;

        if (columnType == (int)SqliteColumnType.Integer)
            return sqlite3_column_int64(_statement, ordinal) != 0;

        if (columnType == (int)SqliteColumnType.Text)
        {
            var s = GetString(sqlite3_column_text(_statement, ordinal));
            if ("yes".Equals(s, StringComparison.OrdinalIgnoreCase) ||
                "y".Equals(s, StringComparison.OrdinalIgnoreCase) ||
                "true".Equals(s, StringComparison.OrdinalIgnoreCase) ||
                "t".Equals(s, StringComparison.OrdinalIgnoreCase) ||
                "1".Equals(s, StringComparison.OrdinalIgnoreCase))
                return true;
        }

        return false;
    }

    public readonly bool? GetNullableBoolean(int ordinal)
    {
        var columnType = sqlite3_column_type(_statement, ordinal);
        if (columnType == (int)SqliteColumnType.Null)
            return null;

        if (columnType == (int)SqliteColumnType.Integer)
            return sqlite3_column_int64(_statement, ordinal) != 0;

        if (columnType == (int)SqliteColumnType.Text)
        {
            var s = GetString(sqlite3_column_text(_statement, ordinal));
            if ("yes".Equals(s, StringComparison.OrdinalIgnoreCase) ||
                "y".Equals(s, StringComparison.OrdinalIgnoreCase) ||
                "true".Equals(s, StringComparison.OrdinalIgnoreCase) ||
                "t".Equals(s, StringComparison.OrdinalIgnoreCase) ||
                "1".Equals(s, StringComparison.OrdinalIgnoreCase))
                return true;

            if ("no".Equals(s, StringComparison.OrdinalIgnoreCase) ||
                "n".Equals(s, StringComparison.OrdinalIgnoreCase) ||
                "false".Equals(s, StringComparison.OrdinalIgnoreCase) ||
                "f".Equals(s, StringComparison.OrdinalIgnoreCase) ||
                "0".Equals(s, StringComparison.OrdinalIgnoreCase))
                return false;
        }

        return null;
    }

    private static string? GetString(byte* value)
    {
        if (value == null)
            return null;

        return Utf8StringMarshaller.ConvertToManaged(value);
    }

    public int GetOrdinal(string name)
    {
        if (_aliasMapping == null)
        {
            _aliasMapping = new Dictionary<string, int>(StringComparer.OrdinalIgnoreCase);
            var columnCount = sqlite3_column_count(_statement);
            for (var i = 0; i < columnCount; i++)
            {
                var columnName = GetString(sqlite3_column_name(_statement, i));
                if (!string.IsNullOrEmpty(columnName))
                    _aliasMapping[columnName] = i;
            }
        }

        if (_aliasMapping.TryGetValue(name, out var ordinal))
            return ordinal;

        Throw(name);
        return -1;

        [DoesNotReturn]
        [MethodImpl(MethodImplOptions.NoInlining)]
        static void Throw(string name) => throw new IndexOutOfRangeException($"Column alias '{name}' does not exist in the result set (this overload requires \"AS\" alias otherwise the result is undefined).");
    }

    public int GetOrdinal(string tableName, string columnName)
    {
        EnsureColumnMapping();

        var key = new TableColumnName { TableName = tableName, ColumnName = columnName };
        if (_tableColumnMapping.TryGetValue(key, out var ordinal))
            return ordinal;

        Throw(tableName, columnName);
        return -1;

        [DoesNotReturn]
        [MethodImpl(MethodImplOptions.NoInlining)]
        static void Throw(string tableName, string columnName) => throw new IndexOutOfRangeException($"Column '{tableName}.{columnName}' does not exist in the result set.");
    }

    [MemberNotNull(nameof(_tableColumnMapping))]
    private void EnsureColumnMapping()
    {
        if (_tableColumnMapping != null)
            return;

        _tableColumnMapping = new Dictionary<TableColumnName, int>();
        var columnCount = sqlite3_column_count(_statement);
        for (var i = 0; i < columnCount; i++)
        {
            var tableName = GetString(sqlite3_column_table_name(_statement, i))!;
            var columnName = GetString(sqlite3_column_origin_name(_statement, i))!;
            _tableColumnMapping[new TableColumnName { TableName = tableName, ColumnName = columnName }] = i;
        }
    }

    private struct TableColumnName : IEquatable<TableColumnName>
    {
        public string TableName { get; init; }
        public string ColumnName { get; init; }

        public bool Equals(TableColumnName other)
        {
            return string.Equals(TableName, other.TableName, StringComparison.OrdinalIgnoreCase) &&
                string.Equals(ColumnName, other.ColumnName, StringComparison.OrdinalIgnoreCase);
        }

        public override bool Equals(object? obj)
        {
            return obj is TableColumnName other && Equals(other);
        }

        public override int GetHashCode()
        {
            var hashCode = new HashCode();
            hashCode.Add(TableName, StringComparer.OrdinalIgnoreCase);
            hashCode.Add(ColumnName, StringComparer.OrdinalIgnoreCase);
            return hashCode.ToHashCode();
        }

        public static bool operator ==(TableColumnName left, TableColumnName right)
        {
            return left.Equals(right);
        }

        public static bool operator !=(TableColumnName left, TableColumnName right)
        {
            return !left.Equals(right);
        }
    }
}

public readonly struct SqliteValueDataReader<TReader, TRow> : IDisposable
    where TReader : ISqliteRowReader<TRow>
{
    public SqliteValueDataReader Reader { get; }

    public SqliteValueDataReader(SqliteValueDataReader reader)
    {
        Reader = reader;
    }

    public void Dispose()
    {
        Reader.Dispose();
    }

    public bool TryRead([NotNullWhen(true)] out TRow? value)
    {
        if (Reader.Read())
        {
            value = TReader.Read(Reader)!;
            return true;
        }

        value = default;
        return false;
    }
}