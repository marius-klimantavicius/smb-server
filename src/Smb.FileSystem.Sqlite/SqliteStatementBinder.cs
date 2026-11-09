using System.Globalization;
using System.Runtime.CompilerServices;
using static Managed.Database.Sqlite;

namespace Smb.FileSystem.Sqlite;

public readonly unsafe struct SqliteStatementBinder
{
    private readonly SqliteConnection _connection;
    private readonly sqlite3_stmt* _statement;

    public SqliteStatementBinder(SqliteConnection connection, sqlite3_stmt* statement)
    {
        _connection = connection;
        _statement = statement;
    }

    public int GetParameterIndex(string name)
    {
        scoped var marshaller = new System.Runtime.InteropServices.Marshalling.Utf8StringMarshaller.ManagedToUnmanagedIn();
        try
        {
            marshaller.FromManaged(name, stackalloc byte[System.Runtime.InteropServices.Marshalling.Utf8StringMarshaller.ManagedToUnmanagedIn.BufferSize]);
            var index = sqlite3_bind_parameter_index(_statement, marshaller.ToUnmanaged());
            if (index == 0) throw new System.ArgumentException("Unknown SQLite parameter: " + name, nameof(name));
            return index;
        }
        finally { marshaller.Free(); }
    }

    [MethodImpl(MethodImplOptions.AggressiveInlining)]
    public void SetString(int index, string? value)
    {
        if (value == null)
            SqliteException.ThrowIfNotOk(sqlite3_bind_null(_statement, index), _connection);
        else
            SqliteException.ThrowIfNotOk(sqlite3_bind_text16(_statement, index, value), _connection);
    }

    [MethodImpl(MethodImplOptions.AggressiveInlining)]
    public void SetBlob(int index, byte[]? value)
    {
        if (value == null)
            SqliteException.ThrowIfNotOk(sqlite3_bind_null(_statement, index), _connection);
        else
            SqliteException.ThrowIfNotOk(sqlite3_bind_blob(_statement, index, value), _connection);
    }

    [MethodImpl(MethodImplOptions.AggressiveInlining)]
    public void SetInt64(int index, long value)
    {
        SqliteException.ThrowIfNotOk(sqlite3_bind_int64(_statement, index, value), _connection);
    }

    [MethodImpl(MethodImplOptions.AggressiveInlining)]
    public void SetInt64(int index, long? value)
    {
        if (value == null)
            SqliteException.ThrowIfNotOk(sqlite3_bind_null(_statement, index), _connection);
        else
            SqliteException.ThrowIfNotOk(sqlite3_bind_int64(_statement, index, value.GetValueOrDefault()), _connection);
    }

    [MethodImpl(MethodImplOptions.AggressiveInlining)]
    public void SetInt32(int index, int value)
    {
        SqliteException.ThrowIfNotOk(sqlite3_bind_int(_statement, index, value), _connection);
    }

    [MethodImpl(MethodImplOptions.AggressiveInlining)]
    public void SetInt32(int index, int? value)
    {
        if (value == null)
            SqliteException.ThrowIfNotOk(sqlite3_bind_null(_statement, index), _connection);
        else
            SqliteException.ThrowIfNotOk(sqlite3_bind_int(_statement, index, value.GetValueOrDefault()), _connection);
    }

    [MethodImpl(MethodImplOptions.AggressiveInlining)]
    public void SetDateTime(int index, System.DateTime value)
    {
        var utc = SqliteCommandBinding.NormalizeDateTime(value);
        if (_connection.StoreDateTimeAsTicks)
        {
            SqliteException.ThrowIfNotOk(sqlite3_bind_int64(_statement, index, utc.Ticks), _connection);
        }
        else
        {
            var s = utc.ToString(_connection.DateTimeStringFormat, CultureInfo.InvariantCulture);
            SqliteException.ThrowIfNotOk(sqlite3_bind_text16(_statement, index, s), _connection);
        }
    }

    [MethodImpl(MethodImplOptions.AggressiveInlining)]
    public void SetDateTime(int index, System.DateTime? value)
    {
        if (value == null)
        {
            SqliteException.ThrowIfNotOk(sqlite3_bind_null(_statement, index), _connection);
        }
        else
        {
            var utc = SqliteCommandBinding.NormalizeDateTime(value.GetValueOrDefault());
            if (_connection.StoreDateTimeAsTicks)
            {
                SqliteException.ThrowIfNotOk(sqlite3_bind_int64(_statement, index, utc.Ticks), _connection);
            }
            else
            {
                var s = utc.ToString(_connection.DateTimeStringFormat, CultureInfo.InvariantCulture);
                SqliteException.ThrowIfNotOk(sqlite3_bind_text16(_statement, index, s), _connection);
            }
        }
    }

    [MethodImpl(MethodImplOptions.AggressiveInlining)]
    public void SetChar(int index, char value)
    {
        SqliteException.ThrowIfNotOk(sqlite3_bind_text16(_statement, index, value), _connection);
    }

    [MethodImpl(MethodImplOptions.AggressiveInlining)]
    public void SetChar(int index, char? value)
    {
        if (value == null)
        {
            SqliteException.ThrowIfNotOk(sqlite3_bind_null(_statement, index), _connection);
        }
        else
        {
            var actualValue = value.GetValueOrDefault();
            SqliteException.ThrowIfNotOk(sqlite3_bind_text16(_statement, index, actualValue), _connection);
        }
    }

    [MethodImpl(MethodImplOptions.AggressiveInlining)]
    public void SetDecimal(int index, decimal value)
    {
        SqliteException.ThrowIfNotOk(sqlite3_bind_double(_statement, index, (double)value), _connection);
    }

    [MethodImpl(MethodImplOptions.AggressiveInlining)]
    public void SetDecimal(int index, decimal? value)
    {
        if (value == null)
            SqliteException.ThrowIfNotOk(sqlite3_bind_null(_statement, index), _connection);
        else
            SqliteException.ThrowIfNotOk(sqlite3_bind_double(_statement, index, (double)value.GetValueOrDefault()), _connection);
    }
}