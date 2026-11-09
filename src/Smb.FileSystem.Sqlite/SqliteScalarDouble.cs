namespace Smb.FileSystem.Sqlite;

public struct SqliteScalarDouble : ISqliteRowReader<SqliteScalarDouble>, ISqliteRowReader<SqliteScalarDouble?>
{
    public double Value { get; }

    public static SqliteScalarDouble Read<TReader>(TReader reader)
        where TReader : ISqliteDataReader, allows ref struct
    {
        return reader.GetDouble(0);
    }

    public SqliteScalarDouble(double value)
    {
        Value = value;
    }

    static SqliteScalarDouble? ISqliteRowReader<SqliteScalarDouble?>.Read<TReader>(TReader reader)
    {
        if (reader.IsDBNull(0))
            return null;
        
        return Read(reader);
    }

    public static implicit operator SqliteScalarDouble(double value) => new SqliteScalarDouble(value);
    public static implicit operator double(SqliteScalarDouble rowId) => rowId.Value;
    public static implicit operator SqliteScalarDouble?(double? value) => value.HasValue ? new SqliteScalarDouble(value.Value) : null;
    public static implicit operator double?(SqliteScalarDouble? rowId) => rowId?.Value;
}