using System;
using System.IO;
using Smb.FileSystem.Sqlite;
using Managed.Database;

namespace Smb.Testing;

public static class SqliteEngineProof
{
    public static void Print(TextWriter output)
    {
        using var db = new SqliteConnection(new SqliteConnectionString(":memory:", true));
        using var reader = db.ExecuteReader("SELECT sqlite_version(),sqlite_source_id()");
        Check.That(reader.Read(), "engine identity row");
        Check.Equal(Sqlite.SQLITE_VERSION, reader.GetString(0)!, "compiled engine version");
        Check.Equal(Sqlite.SQLITE_SOURCE_ID, reader.GetString(1)!, "compiled engine source ID");
        Check.Equal(Sqlite.SQLITE_VERSION_NUMBER, db.LibVersionNumber, "compiled version number");
        output.WriteLine($"SQLITE_ENGINE implementation=Managed.Database.Sqlite framework=Ews.Common.Sqlite version={reader.GetString(0)} number={db.LibVersionNumber} source_id={reader.GetString(1)}");
    }
}
