namespace Smb.FileSystem.Sqlite;

public struct SqliteScalarInt64 : ISqliteRowReader<SqliteScalarInt64>, ISqliteRowReader<SqliteScalarInt64?>
{
    public long Value { get; }

    public static SqliteScalarInt64 Read<TReader>(TReader reader)
        where TReader : ISqliteDataReader, allows ref struct
    {
        return reader.GetInt64(0);
    }

    static SqliteScalarInt64? ISqliteRowReader<SqliteScalarInt64?>.Read<TReader>(TReader reader)
    {
        if (reader.IsDBNull(0))
            return null;

        return Read(reader);
    }

    public SqliteScalarInt64(long value)
    {
        Value = value;
    }

    public static implicit operator SqliteScalarInt64(long value) => new SqliteScalarInt64(value);
    public static implicit operator long(SqliteScalarInt64 rowId) => rowId.Value;
    public static implicit operator SqliteScalarInt64?(long? value) => value.HasValue ? new SqliteScalarInt64(value.Value) : null;
    public static implicit operator long?(SqliteScalarInt64? rowId) => rowId?.Value;
}