namespace Smb.FileSystem.Sqlite;

public struct SqliteScalarString : ISqliteRowReader<SqliteScalarString>
{
    public string? Value { get; }

    public static SqliteScalarString Read<TReader>(TReader reader)
        where TReader : ISqliteDataReader, allows ref struct
    {
        return reader.GetString(0);
    }

    public SqliteScalarString(string? value)
    {
        Value = value;
    }

    public static implicit operator SqliteScalarString(string? value) => new SqliteScalarString(value);
    public static implicit operator string?(SqliteScalarString rowId) => rowId.Value;
}