using System.Diagnostics.CodeAnalysis;
using System.Runtime.CompilerServices;
using System.Runtime.InteropServices.Marshalling;
using static Managed.Database.Sqlite;

namespace Smb.FileSystem.Sqlite;

public unsafe class SqliteException : Exception
{
    public int Result { get; private set; }

    private SqliteException(int r, byte* message) : base(message == null ? null : Utf8StringMarshaller.ConvertToManaged(message))
    {
        Result = r;
    }

    private SqliteException(int r, string message) : base(message)
    {
        Result = r;
    }

    [DoesNotReturn]
    public static void Throw(int result, string message) =>
        throw new SqliteException(result, message);

    [MethodImpl(MethodImplOptions.AggressiveInlining)]
    public static void ThrowIfNotOk(int result, SqliteConnection connection) =>
        ThrowIfNotOk(result, connection.Handle);

    [MethodImpl(MethodImplOptions.AggressiveInlining)]
    public static void ThrowIfNotOk(int result, sqlite3* connectionHandle)
    {
        if (result != SQLITE_OK)
            Throw(result, connectionHandle);

        return;

        [MethodImpl(MethodImplOptions.NoInlining)]
        static void Throw(int result, sqlite3* connectionHandle) => throw new SqliteException(result, sqlite3_errmsg(connectionHandle));
    }

    [MethodImpl(MethodImplOptions.AggressiveInlining)]
    public static void ThrowIfNotOk(int result, [InterpolatedStringHandlerArgument(nameof(result))] MessageInterpolatedStringHandler message)
    {
        if (result != SQLITE_OK)
            Throw(result, message.ToStringAndClear());

        return;

        [MethodImpl(MethodImplOptions.NoInlining)]
        static void Throw(int result, string message) => throw new SqliteException(result, message);
    }

    public static string ErrorMessage(SqliteConnection connection)
    {
        var errorPtr = sqlite3_errmsg(connection.Handle);
        if (errorPtr == null)
            return string.Empty;

        return Utf8StringMarshaller.ConvertToManaged(errorPtr) ?? "";
    }

    [InterpolatedStringHandler]
    public ref struct MessageInterpolatedStringHandler
    {
        private DefaultInterpolatedStringHandler _handler;

        public MessageInterpolatedStringHandler(int literalLength, int formattedCount, int result, out bool append)
        {
            append = result != SQLITE_OK;

            if (append)
                _handler = new DefaultInterpolatedStringHandler(literalLength, formattedCount);
        }

        public string ToStringAndClear() => _handler.ToStringAndClear();

        public void AppendLiteral(string value) => _handler.AppendLiteral(value);

        public void AppendFormatted<T>(T value) => _handler.AppendFormatted(value);

        public void AppendFormatted<T>(T value, string? format) => _handler.AppendFormatted(value, format);

        public void AppendFormatted<T>(T value, int alignment) => _handler.AppendFormatted(value, alignment);

        public void AppendFormatted<T>(T value, int alignment, string? format) => _handler.AppendFormatted(value, alignment, format);

        public void AppendFormatted(scoped ReadOnlySpan<char> value) => _handler.AppendFormatted(value);

        // ReSharper disable once MethodOverloadWithOptionalParameter
        public void AppendFormatted(scoped ReadOnlySpan<char> value, int alignment = 0, string? format = null) => _handler.AppendFormatted(value, alignment, format);

        public void AppendFormatted(string? value) => _handler.AppendFormatted(value);

        // ReSharper disable once MethodOverloadWithOptionalParameter
        public void AppendFormatted(string? value, int alignment = 0, string? format = null) => _handler.AppendFormatted(value, alignment, format);

        public void AppendFormatted(object? value, int alignment = 0, string? format = null) => _handler.AppendFormatted(value, alignment, format);
    }
}