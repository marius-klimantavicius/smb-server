using Smb.FileSystem.Sqlite;
using Smb.Testing;
using static Managed.Database.Sqlite;

internal static class SqliteEngineTests
{
    public static IEnumerable<(string Name, Func<Task> Run)> Cases()
    {
        yield return ("sqlite.engine.transaction-error", () => Run(TransactionError));
        yield return ("sqlite.engine.tails", () => Run(Tails));
        yield return ("sqlite.engine.empty-blob", () => Run(EmptyBlob));
        yield return ("sqlite.engine.bind-copy-int64", () => Run(BindCopy));
        yield return ("sqlite.engine.bind-error", () => Run(BindError));
        yield return ("sqlite.engine.bind-throw-finalizes", () => Run(BindThrow));
    }
    static Task Run(Action test) { test(); return Task.CompletedTask; }
    static SqliteConnection Open() => new(new SqliteConnectionString(":memory:", true));
    static unsafe void TransactionError()
    {
        using var db = Open();
        db.ExecuteNonQuery("CREATE TABLE t(v INTEGER UNIQUE); BEGIN IMMEDIATE; INSERT INTO t VALUES(9223372036854775765)");
        var rejected = false;
        try { db.ExecuteNonQuery("INSERT INTO t VALUES(9223372036854775765); INSERT INTO t VALUES(2)"); }
        catch (SqliteException e) { Check.Equal(SQLITE_CONSTRAINT, e.Result & 255, "constraint code"); Check.That(e.Message.Contains("UNIQUE"), "error message retained"); rejected = true; }
        Check.That(rejected, "constraint error escapes"); Check.That(sqlite3_next_stmt(db.Handle, null) == null, "failed execution finalizes statement");
        using (var r = db.ExecuteReader("SELECT count(*) FROM t")) { Check.That(r.Read(), "count row"); Check.Equal(1L, r.GetInt64(0), "tail stops at error"); }
        db.ExecuteNonQuery("ROLLBACK");
        using (var r = db.ExecuteReader("SELECT count(*) FROM t")) { Check.That(r.Read(), "count row"); Check.Equal(0L, r.GetInt64(0), "rollback atomicity"); }
        db.ExecuteNonQuery("BEGIN IMMEDIATE; INSERT INTO t VALUES(3); COMMIT");
        using (var r = db.ExecuteReader("SELECT v FROM t")) { Check.That(r.Read(), "committed row"); Check.Equal(3L, r.GetInt64(0), "connection reusable after error"); }
    }
    static void Tails()
    {
        using var db = Open();
        db.ExecuteNonQuery("; -- leading empty statement\nCREATE TABLE t(v TEXT); INSERT INTO t VALUES('a;b'); /* tail */ INSERT INTO t VALUES('last');");
        using var r = db.ExecuteReader("SELECT count(*),max(v) FROM t");
        Check.That(r.Read(), "aggregate row"); Check.Equal(2L, r.GetInt64(0), "all tails executed"); Check.Equal("last", r.GetString(1)!, "quoted semicolon preserved");
    }
    static void EmptyBlob()
    {
        using var db = Open();
        using var r = db.ExecuteReader("SELECT typeof($b),length($b),$n IS NULL,$t", static (in SqliteStatementBinder b, int _) =>
        { b.SetBlob(b.GetParameterIndex("$b"), []); b.SetBlob(b.GetParameterIndex("$n"), null); b.SetString(b.GetParameterIndex("$t"), ""); }, 0);
        Check.That(r.Read(), "bound row"); Check.Equal("blob", r.GetString(0)!, "empty BLOB keeps storage class");
        Check.Equal(0L, r.GetInt64(1), "empty length"); Check.Equal(1L, r.GetInt64(2), "null distinct"); Check.Equal("", r.GetString(3)!, "empty text distinct");
    }
    static void BindCopy()
    {
        using var db = Open();
        var bytes = new byte[] { 0, 17, 255 };
        using var r = db.ExecuteReader("SELECT $t,$t,$b,$i", static (in SqliteStatementBinder b, byte[] bytes) =>
        { b.SetString(b.GetParameterIndex("$t"), new string('λ', 8192) + "'; DROP TABLE ignored; --"); b.SetBlob(b.GetParameterIndex("$b"), bytes); b.SetInt64(b.GetParameterIndex("$i"), long.MaxValue - 42); }, bytes);
        bytes.AsSpan().Fill(9); GC.Collect(2, GCCollectionMode.Forced, true, true);
        Check.That(r.Read(), "bound row"); Check.Equal(new string('λ', 8192) + "'; DROP TABLE ignored; --", r.GetString(0)!, "copied text");
        Check.Equal(r.GetString(0)!, r.GetString(1)!, "repeated named binding"); Check.That(r.GetBlob(2)!.SequenceEqual(new byte[] { 0, 17, 255 }), "copied blob"); Check.Equal(long.MaxValue - 42, r.GetInt64(3), "64-bit integer");
    }
    static void BindError()
    {
        using var db = Open();
        var rejected = false;
        try { using var r = db.ExecuteReader("SELECT ?1", static (in SqliteStatementBinder b, int _) => b.SetInt64(2, 1), 0); }
        catch (SqliteException e) { Check.Equal(SQLITE_RANGE, e.Result, "binding result code"); rejected = true; }
        Check.That(rejected, "out-of-range bind reports SQLITE_RANGE");
    }
    static unsafe void BindThrow()
    {
        using var db = Open();
        try { using var r = db.ExecuteReader("SELECT ?1", static (in SqliteStatementBinder _, int ignored) => throw new InvalidOperationException("bind sentinel"), 0); }
        catch (InvalidOperationException e) when (e.Message == "bind sentinel") { }
        Check.That(sqlite3_next_stmt(db.Handle, null) == null, "failed bind finalizes prepared statement");
    }
}
