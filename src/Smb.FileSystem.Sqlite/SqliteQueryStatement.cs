namespace Smb.FileSystem.Sqlite;

public unsafe class SqliteQueryStatement<TArguments, TRowReader, TRow> : SqlitePreparedStatement
    where TRowReader : ISqliteRowReader<TRow>
{
    private readonly SqliteBindStatement<TArguments> _bind;

    public SqliteQueryStatement(SqliteConnection connection, string commandText, SqliteBindStatement<TArguments> bind, bool initialize = false)
        : base(connection, commandText, initialize)
    {
        _bind = bind;
    }

    public IEnumerable<TRow> Query(TArguments arguments)
    {
        Initialize();

        _bind(new SqliteStatementBinder(Connection, Statement), arguments);

        return Enumerate(new SqliteDataReader(Connection, Statement, ownsStatement: false));

        static IEnumerable<TRow> Enumerate(SqliteDataReader reader)
        {
            using (reader)
            {
                while (reader.Read())
                    yield return TRowReader.Read(reader);
            }
        }
    }
    
    public TRow? QueryFirstOrDefault(TArguments arguments)
    {
        Initialize();

        _bind(new SqliteStatementBinder(Connection, Statement), arguments);

        using var reader = new SqliteDataReader(Connection, Statement, ownsStatement: false);
        if (reader.Read())
            return TRowReader.Read(reader);

        return default;
    }
}