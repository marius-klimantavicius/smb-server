//
// Copyright (c) 2009-2024 Krueger Systems, Inc.
//
// Permission is hereby granted, free of charge, to any person obtaining a copy
// of this software and associated documentation files (the "Software"), to deal
// in the Software without restriction, including without limitation the rights
// to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
// copies of the Software, and to permit persons to whom the Software is
// furnished to do so, subject to the following conditions:
//
// The above copyright notice and this permission notice shall be included in
// all copies or substantial portions of the Software.
//
// THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
// IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
// FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
// AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
// LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
// OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
// THE SOFTWARE.
//

using System.Globalization;
using System.Runtime.InteropServices.Marshalling;
using System.Security.Cryptography;
using static Managed.Database.Sqlite;

namespace Smb.FileSystem.Sqlite;

public unsafe class SqliteConnection : IDisposable
{
    private bool _open;

    private SqliteNonQueryStatement? _beingTransaction;
    private SqliteNonQueryStatement? _commit;
    private SqliteNonQueryStatement? _rollback;

    public string DatabasePath { get; private set; }
    public int LibVersionNumber { get; private set; }
    public sqlite3* Handle { get; private set; }
    public bool StoreDateTimeAsTicks { get; private set; }
    public bool StoreTimeSpanAsTicks { get; private set; }
    public string DateTimeStringFormat { get; private set; }
    internal DateTimeStyles DateTimeStyle { get; private set; }

    public long LastInsertRowId => Handle != null! ? sqlite3_last_insert_rowid(Handle) : -1;

    private int _transactionDepth;

    public TimeSpan BusyTimeout
    {
        get;
        set
        {
            field = value;
            if (Handle != null!)
                sqlite3_busy_timeout(Handle, (int)field.TotalMilliseconds);
        }
    }

    public SqliteConnection(string connectionString) : this(new SqliteConnectionString(connectionString)) { }

    public SqliteConnection(SqliteConnectionString connectionString)
    {
        ArgumentNullException.ThrowIfNull(connectionString);

        DatabasePath = connectionString.DatabasePath ?? throw new InvalidOperationException("DatabasePath must be specified");
        LibVersionNumber = sqlite3_libversion_number();

        var handle = default(sqlite3*);
        var r = sqlite3_open_v2(connectionString.DatabasePath, &handle, (int)connectionString.OpenFlags, connectionString.VfsName);

        Handle = handle;
        SqliteException.ThrowIfNotOk(r, $"Could not open database file: {DatabasePath} ({r})");

        _open = true;

        StoreDateTimeAsTicks = connectionString.StoreDateTimeAsTicks;
        StoreTimeSpanAsTicks = connectionString.StoreTimeSpanAsTicks;
        DateTimeStringFormat = connectionString.DateTimeStringFormat;
        DateTimeStyle = connectionString.DateTimeStyle;

        BusyTimeout = TimeSpan.FromSeconds(1.0);
    }

    ~SqliteConnection()
    {
        Dispose(false);
    }

    public void Dispose()
    {
        Dispose(true);
        GC.SuppressFinalize(this);
    }

    public ValueTask DisposeAsync()
    {
        Dispose();
        return ValueTask.CompletedTask;
    }

    public void Close()
    {
        Dispose(true, canThrow: true);
    }

    private void Dispose(bool disposing, bool canThrow = false)
    {
        var useClose2 = LibVersionNumber >= 3007014;

        if (_open && Handle != null!)
        {
            try
            {
                if (disposing)
                {
                    _beingTransaction?.Dispose();
                    _commit?.Dispose();
                    _rollback?.Dispose();

                    var r = sqlite3_wal_checkpoint_v2(Handle, null, SQLITE_CHECKPOINT_TRUNCATE, null, null);
                    if (canThrow)
                        SqliteException.ThrowIfNotOk(r, Handle);

                    r = useClose2 ? sqlite3_close_v2(Handle) : sqlite3_close(Handle);
                    if (canThrow)
                        SqliteException.ThrowIfNotOk(r, Handle);
                }
                else
                {
                    _ = useClose2 ? sqlite3_close_v2(Handle) : sqlite3_close(Handle);
                }
            }
            finally
            {
                Handle = null!;
                _open = false;
            }
        }
    }

    public void EnableWriteAheadLogging()
    {
        ExecuteNonQuery("PRAGMA journal_mode=WAL");
        ExecuteNonQuery("PRAGMA synchronous=NORMAL");
    }

    public void BeginTransaction()
    {
        if (Interlocked.CompareExchange(ref _transactionDepth, 1, 0) == 0)
        {
            try
            {
                _beingTransaction ??= new SqliteNonQueryStatement(this, "BEGIN TRANSACTION");
                _beingTransaction.ExecuteNonQuery();
            }
            catch (SqliteException ex) when
            (
                ex.Result == SQLITE_IOERR ||
                ex.Result == SQLITE_FULL ||
                ex.Result == SQLITE_BUSY ||
                ex.Result == SQLITE_NOMEM ||
                ex.Result == SQLITE_INTERRUPT
            )
            {
                RollbackTo(null, true);
                throw;
            }
            catch
            {
                Interlocked.Decrement(ref _transactionDepth);
                throw;
            }
        }
        else
        {
            SqliteException.Throw(SQLITE_ERROR, "Cannot begin a transaction while already in a transaction.");
        }
    }

    public void Commit()
    {
        if (Interlocked.Exchange(ref _transactionDepth, 0) != 0)
        {
            try
            {
                _commit ??= new SqliteNonQueryStatement(this, "COMMIT");
                _commit.ExecuteNonQuery();
            }
            catch
            {
                try
                {
                    _rollback ??= new SqliteNonQueryStatement(this, "ROLLBACK");
                    _rollback.ExecuteNonQuery();
                }
                catch
                {
                    // rollback can fail in all sorts of wonderful version-dependent ways. Let's just hope for the best
                }

                throw;
            }
        }
    }

    public void SaveTransactionPoint()
    {
        var depth = Interlocked.Increment(ref _transactionDepth) - 1;
        var statement = $"SAVEPOINT S{RandomNumberGenerator.GetInt32(short.MaxValue)}D{depth}";

        try
        {
            ExecuteNonQuery(statement);
        }
        catch (SqliteException ex) when
        (
            ex.Result == SQLITE_IOERR ||
            ex.Result == SQLITE_FULL ||
            ex.Result == SQLITE_BUSY ||
            ex.Result == SQLITE_NOMEM ||
            ex.Result == SQLITE_INTERRUPT
        )
        {
            RollbackTo(null, true);
            throw;
        }
        catch
        {
            Interlocked.Decrement(ref _transactionDepth);
            throw;
        }
    }

    public void Rollback()
    {
        RollbackTo(null, false);
    }

    public void RollbackTo(string savepoint)
    {
        RollbackTo(savepoint, false);
    }

    public void Release(string savepoint)
    {
        try
        {
            DoSavePointExecute(savepoint, "RELEASE ");
        }
        catch (SqliteException ex)
        {
            if (ex.Result == SQLITE_BUSY)
            {
                try
                {
                    _rollback ??= new SqliteNonQueryStatement(this, "ROLLBACK");
                    _rollback.ExecuteNonQuery();
                }
                catch
                {
                    // rollback can fail in all sorts of wonderful version-dependent ways. Let's just hope for the best
                }
            }

            throw;
        }
    }

    private void RollbackTo(string? savepoint, bool noThrow)
    {
        try
        {
            if (string.IsNullOrEmpty(savepoint))
            {
                if (Interlocked.Exchange(ref _transactionDepth, 0) > 0)
                {
                    _rollback ??= new SqliteNonQueryStatement(this, "ROLLBACK");
                    _rollback.ExecuteNonQuery();
                }
            }
            else
            {
                DoSavePointExecute(savepoint, "ROLLBACK TO ");
            }
        }
        catch (SqliteException) when (noThrow)
        {
            // Don't throw
        }
    }

    private void DoSavePointExecute(string savepoint, string cmd)
    {
        // Validate the savepoint
        var firstLen = savepoint.IndexOf('D');
        if (firstLen >= 2 && savepoint.Length > firstLen + 1)
        {
            if (int.TryParse(savepoint.AsSpan(firstLen + 1), out var depth))
            {
                if (0 <= depth && depth < _transactionDepth)
                {
                    Volatile.Write(ref _transactionDepth, depth);
                    ExecuteNonQuery(cmd + savepoint);
                    return;
                }
            }
        }

        throw new ArgumentException("savePoint is not valid, and should be the result of a call to SaveTransactionPoint.", nameof(savepoint));
    }

    public int ExecuteNonQuery(string commandText)
    {
        SqliteLog.ExecuteNonQuery(commandText);

        if (!_open)
            SqliteException.Throw(SQLITE_ERROR, "Cannot execute commands on unopened database");

        // Use SQLite's parser tail, so comments and quoted semicolons remain SQL.
        // This overload has no bindings; parameterized readers prepare one statement.
        var changes = 0;
        fixed (char* start = commandText)
        {
            var cursor = start;
            var end = start + commandText.Length;
            while (cursor < end)
            {
                sqlite3_stmt* statement = null;
                void* tail = null;
                try
                {
                    var result = sqlite3_prepare16_v2(Handle, cursor, checked((int)(end - cursor) * sizeof(char)), &statement, &tail);
                    SqliteException.ThrowIfNotOk(result, Handle);
                    if (statement != null)
                    {
                        do
                        {
                            result = sqlite3_step(statement);
                        } while (result == SQLITE_ROW);

                        if (result != SQLITE_DONE)
                            SqliteException.ThrowIfNotOk(result, Handle);

                        changes += sqlite3_changes(Handle);
                    }

                    if ((char*)tail <= cursor)
                        break;

                    cursor = (char*)tail;
                }
                finally
                {
                    if (statement != null)
                        sqlite3_finalize(statement);
                }
            }
        }

        return changes;
    }

    public int ExecuteNonQuery(SqliteCommandText commandText)
    {
        if (!_open)
            SqliteException.Throw(SQLITE_ERROR, "Cannot execute commands on unopened database");

        var commandTextValue = commandText.ToStringAndClear();
        SqliteLog.ExecuteNonQuery(commandTextValue);

        var statement = default(sqlite3_stmt*);
        var result = sqlite3_prepare_v2(Handle, commandTextValue, &statement);
        try
        {
            SqliteException.ThrowIfNotOk(result, Handle);

            commandText.BindAndClear(this, statement);

            result = sqlite3_step(statement);
            sqlite3_finalize(statement);
            statement = null!;

            if (result == SQLITE_DONE || result == SQLITE_ROW)
                return sqlite3_changes(Handle);

            SqliteException.ThrowIfNotOk(result, Handle);
            return -1;
        }
        finally
        {
            if (statement != null)
                sqlite3_finalize(statement);
        }
    }

    public SqliteDataReader ExecuteReader(string commandText)
    {
        SqliteLog.Query(commandText);

        var statement = default(sqlite3_stmt*);
        var result = sqlite3_prepare_v2(Handle, commandText, &statement);
        SqliteException.ThrowIfNotOk(result, Handle);

        return new SqliteDataReader(this, statement, ownsStatement: true);
    }

    public SqliteDataReader ExecuteReader<TArguments>(string commandText, SqliteBindStatement<TArguments> bind, TArguments arguments)
        where TArguments : allows ref struct
    {
        SqliteLog.Query(commandText);

        var statement = default(sqlite3_stmt*);
        var result = sqlite3_prepare_v2(Handle, commandText, &statement);
        SqliteException.ThrowIfNotOk(result, Handle);

        try
        {
            bind(new SqliteStatementBinder(this, statement), arguments);
            return new SqliteDataReader(this, statement, ownsStatement: true);
        }
        catch
        {
            sqlite3_finalize(statement);
            throw;
        }
    }

    public SqliteDataReader ExecuteReader<TArguments>(string commandText, SqliteRefBindStatement<TArguments> bind, ref TArguments arguments)
        where TArguments : allows ref struct
    {
        SqliteLog.Query(commandText);

        var statement = default(sqlite3_stmt*);
        var result = sqlite3_prepare_v2(Handle, commandText, &statement);
        SqliteException.ThrowIfNotOk(result, Handle);

        bind(new SqliteStatementBinder(this, statement), ref arguments);

        return new SqliteDataReader(this, statement, ownsStatement: true);
    }

    public SqliteDataReader ExecuteReader(SqliteCommandText commandText)
    {
        var commandTextValue = commandText.ToStringAndClear();
        SqliteLog.Query(commandTextValue);

        var statement = default(sqlite3_stmt*);
        var result = sqlite3_prepare_v2(Handle, commandTextValue, &statement);
        SqliteException.ThrowIfNotOk(result, Handle);

        commandText.BindAndClear(this, statement);

        return new SqliteDataReader(this, statement, ownsStatement: true);
    }

    public SqliteValueDataReader ExecuteValueReader(string commandText)
    {
        SqliteLog.Query(commandText);

        var statement = default(sqlite3_stmt*);
        var result = sqlite3_prepare_v2(Handle, commandText, &statement);
        SqliteException.ThrowIfNotOk(result, Handle);

        return new SqliteValueDataReader(this, statement);
    }

    public SqliteValueDataReader ExecuteValueReader<TArguments>(string commandText, SqliteBindStatement<TArguments> bind, TArguments arguments)
        where TArguments : allows ref struct
    {
        SqliteLog.Query(commandText);

        var statement = default(sqlite3_stmt*);
        var result = sqlite3_prepare_v2(Handle, commandText, &statement);
        SqliteException.ThrowIfNotOk(result, Handle);

        bind(new SqliteStatementBinder(this, statement), arguments);

        return new SqliteValueDataReader(this, statement);
    }

    public SqliteValueDataReader ExecuteValueReader<TArguments>(string commandText, SqliteRefBindStatement<TArguments> bind, ref TArguments arguments)
        where TArguments : allows ref struct
    {
        SqliteLog.Query(commandText);

        var statement = default(sqlite3_stmt*);
        var result = sqlite3_prepare_v2(Handle, commandText, &statement);
        SqliteException.ThrowIfNotOk(result, Handle);

        bind(new SqliteStatementBinder(this, statement), ref arguments);

        return new SqliteValueDataReader(this, statement);
    }

    public SqliteValueDataReader ExecuteValueReader(SqliteCommandText commandText)
    {
        var commandTextValue = commandText.ToStringAndClear();
        SqliteLog.Query(commandTextValue);

        var statement = default(sqlite3_stmt*);
        var result = sqlite3_prepare_v2(Handle, commandTextValue, &statement);
        SqliteException.ThrowIfNotOk(result, Handle);

        commandText.BindAndClear(this, statement);

        return new SqliteValueDataReader(this, statement);
    }

    public SqliteValueDataReader<TRow, TRow> Query<TRow>(string commandText)
        where TRow : ISqliteRowReader<TRow> =>
        Query<TRow, TRow>(commandText);

    public SqliteValueDataReader<TRow, TRow> Query<TRow>(SqliteCommandText commandText)
        where TRow : ISqliteRowReader<TRow> =>
        Query<TRow, TRow>(commandText);

    public SqliteValueDataReader<TReader, TRow> Query<TReader, TRow>(string commandText)
        where TReader : ISqliteRowReader<TRow>
    {
        SqliteLog.Query(commandText);

        var statement = default(sqlite3_stmt*);
        var result = sqlite3_prepare_v2(Handle, commandText, &statement);
        SqliteException.ThrowIfNotOk(result, this);

        return new SqliteValueDataReader<TReader, TRow>(new SqliteValueDataReader(this, statement));
    }

    public SqliteValueDataReader<TReader, TRow> Query<TReader, TRow>(SqliteCommandText commandText)
        where TReader : ISqliteRowReader<TRow>
    {
        var commandTextValue = commandText.ToStringAndClear();
        SqliteLog.Query(commandTextValue);

        var statement = default(sqlite3_stmt*);
        var result = sqlite3_prepare_v2(Handle, commandTextValue, &statement);
        SqliteException.ThrowIfNotOk(result, Handle);

        commandText.BindAndClear(this, statement);

        return new SqliteValueDataReader<TReader, TRow>(new SqliteValueDataReader(this, statement));
    }

    public SqliteValueDataReader<TReader, TRow> Query<TReader, TRow, TArguments>(string commandText, SqliteBindStatement<TArguments> bind, TArguments arguments)
        where TReader : ISqliteRowReader<TRow>
        where TArguments : allows ref struct
    {
        SqliteLog.Query(commandText);

        var statement = default(sqlite3_stmt*);
        var result = sqlite3_prepare_v2(Handle, commandText, &statement);
        SqliteException.ThrowIfNotOk(result, Handle);

        bind(new SqliteStatementBinder(this, statement), arguments);

        return new SqliteValueDataReader<TReader, TRow>(new SqliteValueDataReader(this, statement));
    }

    public SqliteValueDataReader<TReader, TRow> Query<TReader, TRow, TArguments>(string commandText, SqliteRefBindStatement<TArguments> bind, ref TArguments arguments)
        where TReader : ISqliteRowReader<TRow>
        where TArguments : allows ref struct
    {
        SqliteLog.Query(commandText);

        var statement = default(sqlite3_stmt*);
        var result = sqlite3_prepare_v2(Handle, commandText, &statement);
        SqliteException.ThrowIfNotOk(result, Handle);

        bind(new SqliteStatementBinder(this, statement), ref arguments);

        return new SqliteValueDataReader<TReader, TRow>(new SqliteValueDataReader(this, statement));
    }

    public TRow? QueryFirstOrDefault<TRow>(string commandText)
        where TRow : ISqliteRowReader<TRow> =>
        QueryFirstOrDefault<TRow, TRow>(commandText);

    public TRow? QueryFirstOrDefault<TRow>(SqliteCommandText commandText)
        where TRow : ISqliteRowReader<TRow> =>
        QueryFirstOrDefault<TRow, TRow>(commandText);

    public TRow? QueryFirstOrDefault<TReader, TRow>(string commandText)
        where TReader : ISqliteRowReader<TRow>
    {
        SqliteLog.Query(commandText);

        var statement = default(sqlite3_stmt*);
        var result = sqlite3_prepare_v2(Handle, commandText, &statement);
        SqliteException.ThrowIfNotOk(result, this);

        using var reader = new SqliteValueDataReader(this, statement);
        if (reader.Read())
            return TReader.Read(reader);

        return default;
    }

    public TRow? QueryFirstOrDefault<TReader, TRow>(SqliteCommandText commandText)
        where TReader : ISqliteRowReader<TRow>
    {
        var commandTextValue = commandText.ToStringAndClear();
        SqliteLog.Query(commandTextValue);

        var statement = default(sqlite3_stmt*);
        var result = sqlite3_prepare_v2(Handle, commandTextValue, &statement);
        SqliteException.ThrowIfNotOk(result, Handle);

        commandText.BindAndClear(this, statement);

        using var reader = new SqliteValueDataReader(this, statement);
        if (reader.Read())
            return TReader.Read(reader);

        return default;
    }

    public SqliteDynamicQueryResult QueryDynamic(string commandText)
    {
        SqliteLog.Query(commandText);

        var statement = default(sqlite3_stmt*);
        var result = sqlite3_prepare_v2(Handle, commandText, &statement);
        SqliteException.ThrowIfNotOk(result, Handle);

        using var reader = new SqliteDataReader(this, statement, ownsStatement: true);

        string[]? columnNames = null;
        var rows = new List<object?[]>();

        while (reader.Read())
        {
            if (columnNames == null)
            {
                columnNames = new string[reader.FieldCount];
                for (var i = 0; i < reader.FieldCount; i++)
                    columnNames[i] = reader.GetColumnName(i);
            }

            var row = new object?[reader.FieldCount];
            for (var i = 0; i < reader.FieldCount; i++)
                row[i] = reader.GetValue(i);
            rows.Add(row);
        }

        // If no rows, still get column names
        if (columnNames == null && reader.FieldCount > 0)
        {
            columnNames = new string[reader.FieldCount];
            for (var i = 0; i < reader.FieldCount; i++)
                columnNames[i] = reader.GetColumnName(i);
        }

        var changes = sqlite3_changes(Handle);
        return new SqliteDynamicQueryResult(columnNames ?? [], rows, changes);
    }

    public static void Backup(SqliteConnection destination, string destinationDatabase, SqliteConnection source, string sourceDatabase)
    {
        var backup = default(sqlite3_backup*);

        scoped var destinationDatabaseMarshaller = new Utf8StringMarshaller.ManagedToUnmanagedIn();
        scoped var sourceDatabaseMarshaller = new Utf8StringMarshaller.ManagedToUnmanagedIn();
        try
        {
            destinationDatabaseMarshaller.FromManaged(destinationDatabase, stackalloc byte[Utf8StringMarshaller.ManagedToUnmanagedIn.BufferSize]);
            sourceDatabaseMarshaller.FromManaged(sourceDatabase, stackalloc byte[Utf8StringMarshaller.ManagedToUnmanagedIn.BufferSize]);

            backup = sqlite3_backup_init(destination.Handle, destinationDatabaseMarshaller.ToUnmanaged(), source.Handle, sourceDatabaseMarshaller.ToUnmanaged());

            if (backup == null)
                SqliteException.Throw(SQLITE_ERROR, $"SQLite snapshot failed: {SqliteException.ErrorMessage(destination)}");

            var result = sqlite3_backup_step(backup, -1);
            if (result != SQLITE_DONE)
                SqliteException.Throw(result, $"SQLite snapshot step failed: {SqliteException.ErrorMessage(destination)}");

            result = sqlite3_backup_finish(backup);
            if (result != SQLITE_OK)
                SqliteException.Throw(result, $"SQLite snapshot finish failed: {SqliteException.ErrorMessage(destination)}");

            backup = null;
        }
        finally
        {
            destinationDatabaseMarshaller.Free();
            sourceDatabaseMarshaller.Free();

            if (backup != null)
                sqlite3_backup_finish(backup);
        }
    }
}
