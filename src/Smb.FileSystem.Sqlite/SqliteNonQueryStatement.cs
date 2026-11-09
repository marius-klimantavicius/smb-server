using System.Runtime.InteropServices.Marshalling;
using Sqlite3 = Managed.Database.Sqlite;

namespace Smb.FileSystem.Sqlite;

public unsafe class SqliteNonQueryStatement : SqlitePreparedStatement
{
    public SqliteNonQueryStatement(SqliteConnection connection, string commandText, bool initialize = false)
        : base(connection, commandText, initialize)
    {
    }

    public int ExecuteNonQuery()
    {
        Initialize();

        var result = Sqlite3.sqlite3_step(Statement);
        if (result == Sqlite3.SQLITE_DONE || result == Sqlite3.SQLITE_ROW)
        {
            var rowsAffected = Sqlite3.sqlite3_changes(Connection.Handle);
            Sqlite3.sqlite3_reset(Statement);
            return rowsAffected;
        }

        if (result == Sqlite3.SQLITE_ERROR)
        {
            var messagePtr = Sqlite3.sqlite3_errmsg(Connection.Handle);
            var message = messagePtr == null ? "" : Utf8StringMarshaller.ConvertToManaged(messagePtr) ?? "";
            Sqlite3.sqlite3_reset(Statement);
            SqliteException.Throw(result, message);
        }

        Sqlite3.sqlite3_reset(Statement);
        SqliteException.ThrowIfNotOk(result, Connection.Handle);
        return 0;
    }
}

public unsafe class SqliteNonQueryStatement<TArguments> : SqlitePreparedStatement
    where TArguments: allows ref struct
{
    private readonly SqliteBindStatement<TArguments> _bind;

    public SqliteNonQueryStatement(SqliteConnection connection, string commandText, SqliteBindStatement<TArguments> bind, bool initialize = false)
        : base(connection, commandText, initialize)
    {
        _bind = bind;
    }

    public int ExecuteNonQuery(TArguments arguments)
    {
        Initialize();

        _bind(new SqliteStatementBinder(Connection, Statement), arguments);

        var result = Sqlite3.sqlite3_step(Statement);
        if (result == Sqlite3.SQLITE_DONE || result == Sqlite3.SQLITE_ROW)
        {
            var rowsAffected = Sqlite3.sqlite3_changes(Connection.Handle);
            Sqlite3.sqlite3_reset(Statement);
            return rowsAffected;
        }

        if (result == Sqlite3.SQLITE_ERROR)
        {
            var messagePtr = Sqlite3.sqlite3_errmsg(Connection.Handle);
            var message = messagePtr == null ? "" : Utf8StringMarshaller.ConvertToManaged(messagePtr) ?? "";
            Sqlite3.sqlite3_reset(Statement);
            SqliteException.Throw(result, message);
        }

        Sqlite3.sqlite3_reset(Statement);
        SqliteException.ThrowIfNotOk(result, Connection.Handle);
        return 0;
    }
}

public unsafe class SqliteRefNonQueryStatement<TArguments> : SqlitePreparedStatement
    where TArguments : allows ref struct
{
    private readonly SqliteRefBindStatement<TArguments> _bind;

    public SqliteRefNonQueryStatement(SqliteConnection connection, string commandText, SqliteRefBindStatement<TArguments> bind, bool initialize = false)
        : base(connection, commandText, initialize)
    {
        _bind = bind;
    }

    public int ExecuteNonQuery(ref TArguments arguments)
    {
        Initialize();

        _bind(new SqliteStatementBinder(Connection, Statement), ref arguments);

        var result = Sqlite3.sqlite3_step(Statement);
        if (result == Sqlite3.SQLITE_DONE || result == Sqlite3.SQLITE_ROW)
        {
            var rowsAffected = Sqlite3.sqlite3_changes(Connection.Handle);
            Sqlite3.sqlite3_reset(Statement);
            return rowsAffected;
        }

        if (result == Sqlite3.SQLITE_ERROR)
        {
            var messagePtr = Sqlite3.sqlite3_errmsg(Connection.Handle);
            var message = messagePtr == null ? "" : Utf8StringMarshaller.ConvertToManaged(messagePtr) ?? "";
            Sqlite3.sqlite3_reset(Statement);
            SqliteException.Throw(result, message);
        }

        Sqlite3.sqlite3_reset(Statement);
        SqliteException.ThrowIfNotOk(result, Connection.Handle);
        return 0;
    }
}