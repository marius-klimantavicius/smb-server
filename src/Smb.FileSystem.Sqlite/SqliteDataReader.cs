using static Managed.Database.Sqlite;

namespace Smb.FileSystem.Sqlite;

public unsafe partial class SqliteDataReader : ISqliteDataReader, IDisposable
{
    private readonly bool _ownsStatement;
    private SqliteValueDataReader _reader;

    public int FieldCount => _reader.FieldCount;

    public SqliteDataReader(SqliteConnection connection, sqlite3_stmt* statement, bool ownsStatement)
    {
        _reader = new SqliteValueDataReader(connection, statement);
        _ownsStatement = ownsStatement;
    }

    ~SqliteDataReader()
    {
        Dispose(false);
    }

    public void Dispose()
    {
        Dispose(true);
        GC.SuppressFinalize(this);
    }

    protected virtual void Dispose(bool _)
    {
        var s = _reader._statement;
        _reader = default;
        if (s != null)
        {
            if (_ownsStatement)
                sqlite3_finalize(s);
            else
                sqlite3_reset(s);
        }
    }

    public bool Read() => _reader.Read();

    public string GetColumnName(int ordinal) => _reader.GetColumnName(ordinal);

    public SqliteColumnType GetColumnType(int ordinal) => _reader.GetColumnType(ordinal);

    public object? GetValue(int ordinal) => _reader.GetValue(ordinal);

    public bool IsDBNull(int ordinal) => _reader.IsDBNull(ordinal);

    public string? GetString(int ordinal) => _reader.GetString(ordinal);

    public long GetInt64(int ordinal) => _reader.GetInt64(ordinal);

    public long? GetNullableInt64(int ordinal) => _reader.GetNullableInt64(ordinal);

    public int GetInt32(int ordinal) => _reader.GetInt32(ordinal);

    public int? GetNullableInt32(int ordinal) => _reader.GetNullableInt32(ordinal);

    public System.DateTime GetDateTime(int ordinal) => _reader.GetDateTime(ordinal);

    public System.DateTime? GetNullableDateTime(int ordinal) => _reader.GetNullableDateTime(ordinal);

    public TimeSpan GetTimeSpan(int ordinal) => _reader.GetTimeSpan(ordinal);

    public TimeSpan? GetNullableTimeSpan(int ordinal) => _reader.GetNullableTimeSpan(ordinal);

    public char GetChar(int ordinal) => _reader.GetChar(ordinal);

    public char? GetNullableChar(int ordinal) => _reader.GetNullableChar(ordinal);

    public double GetDouble(int ordinal) => _reader.GetDouble(ordinal);

    public double? GetNullableDouble(int ordinal) => _reader.GetNullableDouble(ordinal);

    public decimal GetDecimal(int ordinal) => _reader.GetDecimal(ordinal);

    public decimal? GetNullableDecimal(int ordinal) => _reader.GetNullableDecimal(ordinal);

    public Guid GetGuid(int ordinal) => _reader.GetGuid(ordinal);

    public Guid? GetNullableGuid(int ordinal) => _reader.GetNullableGuid(ordinal);

    public byte[]? GetBlob(int ordinal) => _reader.GetBlob(ordinal);

    public bool GetBoolean(int ordinal) => _reader.GetBoolean(ordinal);

    public bool? GetNullableBoolean(int ordinal) => _reader.GetNullableBoolean(ordinal);

    public int GetOrdinal(string name) => _reader.GetOrdinal(name);

    public int GetOrdinal(string tableName, string columnName) => _reader.GetOrdinal(tableName, columnName);
}