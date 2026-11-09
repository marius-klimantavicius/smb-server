using System.Runtime.InteropServices.Marshalling;

namespace Managed.Database;

public static unsafe partial class Sqlite
{
    public static int sqlite3_open_v2(string databasePath, sqlite3** db, int connectionFlags, string? vfsName)
    {
        scoped var databasePathMarshaller = new Utf8StringMarshaller.ManagedToUnmanagedIn();
        scoped var vfsNameMarshaller = new Utf8StringMarshaller.ManagedToUnmanagedIn();

        try
        {
            databasePathMarshaller.FromManaged(databasePath, stackalloc byte[Utf8StringMarshaller.ManagedToUnmanagedIn.BufferSize]);
            vfsNameMarshaller.FromManaged(vfsName, stackalloc byte[Utf8StringMarshaller.ManagedToUnmanagedIn.BufferSize]);

            return sqlite3_open_v2(databasePathMarshaller.ToUnmanaged(), db, connectionFlags, vfsNameMarshaller.ToUnmanaged());
        }
        finally
        {
            databasePathMarshaller.Free();
            vfsNameMarshaller.Free();
        }
    }

    public static int sqlite3_prepare_v2(sqlite3* db, string statementText, sqlite3_stmt** statement)
    {
        fixed (char* statementPtr = statementText)
            return sqlite3_prepare16_v2(db, statementPtr, statementText.Length * sizeof(char), statement, null);
    }

    public static int sqlite3_bind_text16(sqlite3_stmt* statement, int index, string value)
    {
        fixed (char* ptr = value)
            return sqlite3_bind_text16(statement, index, ptr, value.Length * sizeof(char), SQLITE_TRANSIENT);
    }

    public static int sqlite3_bind_text16(sqlite3_stmt* statement, int index, int c)
    {
        return sqlite3_bind_text16(statement, index, &c, sizeof(char), SQLITE_TRANSIENT);
    }

    public static int sqlite3_bind_blob(sqlite3_stmt* statement, int index, ReadOnlySpan<byte> value)
    {
        // A null pointer means SQL NULL even when the byte count is zero.
        if (value.IsEmpty) return sqlite3_bind_zeroblob(statement, index, 0);
        fixed (byte* ptr = value)
            return sqlite3_bind_blob(statement, index, ptr, value.Length, SQLITE_TRANSIENT);
    }
}