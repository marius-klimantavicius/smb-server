namespace Smb.FileSystem.Sqlite;

/// <summary>
/// Scalar int32 row reader for COUNT queries in trace storage.
/// </summary>
public struct SqliteScalarInt32 : ISqliteRowReader<SqliteScalarInt32>, ISqliteRowReader<SqliteScalarInt32?>
{
    public int Value { get; }

    public static SqliteScalarInt32 Read<TReader>(TReader reader)
        where TReader : ISqliteDataReader, allows ref struct
    {
        return reader.GetInt32(0);
    }

    static SqliteScalarInt32? ISqliteRowReader<SqliteScalarInt32?>.Read<TReader>(TReader reader)
    {
        if (reader.IsDBNull(0))
            return null;

        return Read(reader);
    }

    public SqliteScalarInt32(int value)
    {
        Value = value;
    }

    public static implicit operator SqliteScalarInt32(int value) => new SqliteScalarInt32(value);
    public static implicit operator int(SqliteScalarInt32 scalar) => scalar.Value;
    public static implicit operator SqliteScalarInt32?(int? value) => value.HasValue ? new SqliteScalarInt32(value.Value) : null;
    public static implicit operator int?(SqliteScalarInt32? rowId) => rowId?.Value;
}