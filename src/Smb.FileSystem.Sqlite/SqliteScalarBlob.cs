namespace Smb.FileSystem.Sqlite;

public struct SqliteScalarBlob : ISqliteRowReader<SqliteScalarBlob>
{
    public byte[]? Value { get; }

    public static SqliteScalarBlob Read<TReader>(TReader reader)
        where TReader : ISqliteDataReader, allows ref struct
    {
        return reader.GetBlob(0);
    }

    public SqliteScalarBlob(byte[]? value)
    {
        Value = value;
    }

    public static implicit operator SqliteScalarBlob(byte[]? value) => new SqliteScalarBlob(value);
    public static implicit operator byte[]?(SqliteScalarBlob rowId) => rowId.Value;
}