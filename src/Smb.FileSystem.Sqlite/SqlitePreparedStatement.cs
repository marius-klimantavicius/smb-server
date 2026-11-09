using System.Diagnostics;
using static Managed.Database.Sqlite;

namespace Smb.FileSystem.Sqlite;

public unsafe class SqlitePreparedStatement : IDisposable
{
    private readonly string _commandText;

    private bool _isInitialized;
    private SqliteConnection _connection;
    private sqlite3_stmt* _statement;

    protected SqliteConnection Connection => _connection;
    protected sqlite3_stmt* Statement => _statement;

    public string CommandText => _commandText;

    public SqlitePreparedStatement(SqliteConnection connection, string commandText, bool initialize = false)
    {
        _connection = connection;
        _commandText = commandText;

        if (initialize)
            Initialize();
    }

    public void Dispose()
    {
        var s = _statement;
        _statement = null;
        _connection = null!;
        if (_isInitialized && s != null)
            sqlite3_finalize(s);
    }

    protected void Initialize()
    {
        ObjectDisposedException.ThrowIf(_isInitialized && _statement == null, this);

        if (!_isInitialized)
        {
            _isInitialized = true;

            fixed (sqlite3_stmt** ptr = &_statement)
            {
                var result = sqlite3_prepare_v2(_connection.Handle, _commandText, ptr);
                SqliteException.ThrowIfNotOk(result, _connection.Handle);
            }

            SqliteLog.ExecuteNonQuery($"PREPARE: {_commandText}");
        }


        Debug.Assert(Statement != null);
    }
}
