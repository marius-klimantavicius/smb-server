namespace Smb.FileSystem.Sqlite;

public interface ISqliteDataReader
{
    int FieldCount { get; }

    bool Read();

    string GetColumnName(int ordinal);
    SqliteColumnType GetColumnType(int ordinal);
    bool IsDBNull(int ordinal);
    string? GetString(int ordinal);
    long GetInt64(int ordinal);
    long? GetNullableInt64(int ordinal);
    int GetInt32(int ordinal);
    int? GetNullableInt32(int ordinal);
    DateTime GetDateTime(int ordinal);
    DateTime? GetNullableDateTime(int ordinal);
    TimeSpan GetTimeSpan(int ordinal);
    TimeSpan? GetNullableTimeSpan(int ordinal);
    char GetChar(int ordinal);
    char? GetNullableChar(int ordinal);
    double GetDouble(int ordinal);
    double? GetNullableDouble(int ordinal);
    decimal GetDecimal(int ordinal);
    decimal? GetNullableDecimal(int ordinal);
    Guid GetGuid(int ordinal);
    Guid? GetNullableGuid(int ordinal);
    byte[]? GetBlob(int ordinal);
    bool GetBoolean(int ordinal);
    bool? GetNullableBoolean(int ordinal);

    int GetOrdinal(string name);
    int GetOrdinal(string tableName, string columnName);

    public object? GetValue(int ordinal)
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

    // These overloads require "AS" and alias, this is because sqlite3_column_name:
    //    The name of a result column is the value of the "AS" clause for that column, if there is an AS clause.
    //    If there is no AS clause then the name of the column is unspecified and may change from one release of SQLite to the next.
    public bool IsDBNull(string name)
    {
        var ordinal = GetOrdinal(name);
        return IsDBNull(ordinal);
    }

    public string? GetString(string name)
    {
        var ordinal = GetOrdinal(name);
        return GetString(ordinal);
    }

    public long GetInt64(string name)
    {
        var ordinal = GetOrdinal(name);
        return GetInt64(ordinal);
    }

    public long? GetNullableInt64(string name)
    {
        var ordinal = GetOrdinal(name);
        return GetNullableInt64(ordinal);
    }

    public int GetInt32(string name)
    {
        var ordinal = GetOrdinal(name);
        return GetInt32(ordinal);
    }

    public int? GetNullableInt32(string name)
    {
        var ordinal = GetOrdinal(name);
        return GetNullableInt32(ordinal);
    }

    public DateTime GetDateTime(string name)
    {
        var ordinal = GetOrdinal(name);
        return GetDateTime(ordinal);
    }

    public DateTime? GetNullableDateTime(string name)
    {
        var ordinal = GetOrdinal(name);
        return GetNullableDateTime(ordinal);
    }

    public TimeSpan GetTimeSpan(string name)
    {
        var ordinal = GetOrdinal(name);
        return GetTimeSpan(ordinal);
    }

    public TimeSpan? GetNullableTimeSpan(string name)
    {
        var ordinal = GetOrdinal(name);
        return GetNullableTimeSpan(ordinal);
    }

    public char GetChar(string name)
    {
        var ordinal = GetOrdinal(name);
        return GetChar(ordinal);
    }

    public char? GetNullableChar(string name)
    {
        var ordinal = GetOrdinal(name);
        return GetNullableChar(ordinal);
    }

    public double GetDouble(string name)
    {
        var ordinal = GetOrdinal(name);
        return GetDouble(ordinal);
    }

    public double? GetNullableDouble(string name)
    {
        var ordinal = GetOrdinal(name);
        return GetNullableDouble(ordinal);
    }

    public decimal GetDecimal(string name)
    {
        var ordinal = GetOrdinal(name);
        return GetDecimal(ordinal);
    }

    public decimal? GetNullableDecimal(string name)
    {
        var ordinal = GetOrdinal(name);
        return GetNullableDecimal(ordinal);
    }

    public Guid GetGuid(string name)
    {
        var ordinal = GetOrdinal(name);
        return GetGuid(ordinal);
    }

    public Guid? GetNullableGuid(string name)
    {
        var ordinal = GetOrdinal(name);
        return GetNullableGuid(ordinal);
    }

    public byte[]? GetBlob(string name)
    {
        var ordinal = GetOrdinal(name);
        return GetBlob(ordinal);
    }

    public bool GetBoolean(string name)
    {
        var ordinal = GetOrdinal(name);
        return GetBoolean(ordinal);
    }

    public bool? GetNullableBoolean(string name)
    {
        var ordinal = GetOrdinal(name);
        return GetNullableBoolean(ordinal);
    }

    public bool IsDBNull(string tableName, string columnName)
    {
        var ordinal = GetOrdinal(tableName, columnName);
        return IsDBNull(ordinal);
    }

    public string? GetString(string tableName, string columnName)
    {
        var ordinal = GetOrdinal(tableName, columnName);
        return GetString(ordinal);
    }

    public long GetInt64(string tableName, string columnName)
    {
        var ordinal = GetOrdinal(tableName, columnName);
        return GetInt64(ordinal);
    }

    public long? GetNullableInt64(string tableName, string columnName)
    {
        var ordinal = GetOrdinal(tableName, columnName);
        return GetNullableInt64(ordinal);
    }

    public int GetInt32(string tableName, string columnName)
    {
        var ordinal = GetOrdinal(tableName, columnName);
        return GetInt32(ordinal);
    }

    public int? GetNullableInt32(string tableName, string columnName)
    {
        var ordinal = GetOrdinal(tableName, columnName);
        return GetNullableInt32(ordinal);
    }

    public DateTime GetDateTime(string tableName, string columnName)
    {
        var ordinal = GetOrdinal(tableName, columnName);
        return GetDateTime(ordinal);
    }

    public DateTime? GetNullableDateTime(string tableName, string columnName)
    {
        var ordinal = GetOrdinal(tableName, columnName);
        return GetNullableDateTime(ordinal);
    }

    public TimeSpan GetTimeSpan(string tableName, string columnName)
    {
        var ordinal = GetOrdinal(tableName, columnName);
        return GetTimeSpan(ordinal);
    }

    public TimeSpan? GetNullableTimeSpan(string tableName, string columnName)
    {
        var ordinal = GetOrdinal(tableName, columnName);
        return GetNullableTimeSpan(ordinal);
    }

    public char GetChar(string tableName, string columnName)
    {
        var ordinal = GetOrdinal(tableName, columnName);
        return GetChar(ordinal);
    }

    public char? GetNullableChar(string tableName, string columnName)
    {
        var ordinal = GetOrdinal(tableName, columnName);
        return GetNullableChar(ordinal);
    }

    public double GetDouble(string tableName, string columnName)
    {
        var ordinal = GetOrdinal(tableName, columnName);
        return GetDouble(ordinal);
    }

    public double? GetNullableDouble(string tableName, string columnName)
    {
        var ordinal = GetOrdinal(tableName, columnName);
        return GetNullableDouble(ordinal);
    }

    public decimal GetDecimal(string tableName, string columnName)
    {
        var ordinal = GetOrdinal(tableName, columnName);
        return GetDecimal(ordinal);
    }

    public decimal? GetNullableDecimal(string tableName, string columnName)
    {
        var ordinal = GetOrdinal(tableName, columnName);
        return GetNullableDecimal(ordinal);
    }

    public Guid GetGuid(string tableName, string columnName)
    {
        var ordinal = GetOrdinal(tableName, columnName);
        return GetGuid(ordinal);
    }

    public Guid? GetNullableGuid(string tableName, string columnName)
    {
        var ordinal = GetOrdinal(tableName, columnName);
        return GetNullableGuid(ordinal);
    }

    public byte[]? GetBlob(string tableName, string columnName)
    {
        var ordinal = GetOrdinal(tableName, columnName);
        return GetBlob(ordinal);
    }

    public bool GetBoolean(string tableName, string columnName)
    {
        var ordinal = GetOrdinal(tableName, columnName);
        return GetBoolean(ordinal);
    }

    public bool? GetNullableBoolean(string tableName, string columnName)
    {
        var ordinal = GetOrdinal(tableName, columnName);
        return GetNullableBoolean(ordinal);
    }
}