namespace Smb.FileSystem.Sqlite;

public interface ISqliteRowReader<out T>
{
    public static abstract T Read<TReader>(TReader reader)
        where TReader : ISqliteDataReader, allows ref struct;
}