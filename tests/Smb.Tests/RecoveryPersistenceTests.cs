using Smb.Persistence.Sqlite;
using Smb.FileSystem;
using Smb.FileSystem.Sqlite;
using Smb.Protocol.Enums;
using Smb.Server.Recovery;
using Smb.Testing;

internal static class RecoveryPersistenceTests
{
    internal sealed class Root : IDisposable
    {
        public string Path { get; } = System.IO.Path.Combine(System.IO.Path.GetTempPath(), "smb-recovery-" + Guid.NewGuid().ToString("N"));
        public Root() => Directory.CreateDirectory(Path);
        public string Journal => System.IO.Path.Combine(Path, "recovery.db");
        public string Files => System.IO.Path.Combine(Path, "files.db");
        public void Dispose() => Directory.Delete(Path, true);
    }
    public static IEnumerable<(string Name, Func<Task> Run)> Cases()
    {
        yield return ("recovery.backend.retention", BackendRetention);
        yield return ("recovery.store.roundtrip", () => Run(Roundtrip));
        yield return ("recovery.store.exclusive", () => Run(Exclusive));
        yield return ("recovery.store.id-allocation", () => Run(Ids));
    }
    static Task Run(Action action) { action(); return Task.CompletedTask; }
    internal static RecoveryHandleRecord Record() => new()
    {
        PersistentId = ulong.MaxValue - 2, VolatileId = ulong.MaxValue - 3, SessionId = 42,
        OwnerKey = "owner';--λ", ClientGuid = Guid.NewGuid(), CreateGuid = Guid.NewGuid(), Token = Guid.NewGuid(),
        ShareName = "DATA", BackendIdentity = "backend", ObjectId = "object", Path = "name';--λ",
        GrantedAccess = 0x10003, ShareAccess = 7, TimeoutTicks = TimeSpan.FromSeconds(60).Ticks,
        Locks = [new(ulong.MaxValue - 123, 7, true)], LockSequences = Enumerable.Range(0, 64).Select(i => (byte)(i % 16 + 1)).ToArray()
    };
    static async Task BackendRetention()
    {
        using var root = new Root(); var token = Guid.NewGuid(); FileIdentity identity;
        using (var store = new SqliteFileStore(root.Files))
        {
            var opened = await store.CreateAsync("retained", FileAccessIntent.ReadWrite | FileAccessIntent.Delete, CreateDispositionIntent.Create, false, true);
            Check.Equal(NtStatus.Success, opened.Status, "create retained"); using var h = opened.Value.Handle;
            identity = h.Identity!.Value; await store.WriteAsync(h, 0, new byte[] { 1, 2, 3 });
            Check.Equal(NtStatus.Success, store.RetainForRecovery(h, token), "retain original object");
            Check.Equal(NtStatus.Success, await store.SetDeleteOnCloseAsync(h, true), "pending disposition");
        }
        using (var store = new SqliteFileStore(root.Files))
        {
            Check.That(store.GetRecoveryTokens().Contains(token), "token survives process lifetime");
            var wrong = await store.ReopenForRecoveryAsync(token, new FileIdentity("foreign"), FileAccessIntent.Read);
            Check.Equal(NtStatus.ObjectNameNotFound, wrong.Status, "identity substitution rejected");
            var result = await store.ReopenForRecoveryAsync(token, identity, FileAccessIntent.ReadWrite | FileAccessIntent.Delete);
            Check.Equal(NtStatus.Success, result.Status, "reopen pending object by token and identity");
            using (var h = result.Value!)
            { Check.That(h.DeletePending, "pending retained"); var bytes = new byte[3]; Check.Equal(3, (await store.ReadAsync(h, 0, bytes)).Value, "retained EOF"); Check.That(bytes.SequenceEqual(new byte[] { 1, 2, 3 }), "retained bytes"); }
            Check.Equal(NtStatus.Success, store.ReleaseRecovery(token), "release final anchor");
            Check.That(await store.ResolveIdentityAsync("retained") is null, "pending deletion completes after anchor release");
        }
    }
    static void Roundtrip()
    {
        using var root = new Root(); var expected = Record(); Guid server;
        using (var store = new SqliteServerRecoveryStore(root.Journal))
        { server = store.ServerGuid; store.SaveSession(new(42, expected.ClientGuid, expected.OwnerKey, DateTimeOffset.UtcNow)); store.SaveHandle(expected); }
        using (var store = new SqliteServerRecoveryStore(root.Journal))
        {
            Check.Equal(server, store.ServerGuid, "server identity persists"); var actual = store.LoadHandles().Single();
            Check.Equal(expected.PersistentId, actual.PersistentId, "unsigned ID"); Check.Equal(expected.OwnerKey, actual.OwnerKey, "owner bound as data");
            Check.Equal(expected.Locks[0], actual.Locks[0], "unsigned range"); Check.That(expected.LockSequences.SequenceEqual(actual.LockSequences), "replay slots");
            store.RemoveHandle(actual.PersistentId); store.RetireSession(42);
        }
        using (var store = new SqliteServerRecoveryStore(root.Journal)) Check.Equal(0, store.LoadHandles().Count, "terminal removal survives restart");
    }
    static void Exclusive()
    {
        using var root = new Root(); using var owner = new SqliteServerRecoveryStore(root.Journal);
        var rejected = false; try { using var other = new SqliteServerRecoveryStore(root.Journal); } catch (IOException) { rejected = true; }
        Check.That(rejected, "second journal owner rejected");
    }
    static void Ids()
    {
        using var root = new Root(); ulong id;
        using (var store = new SqliteServerRecoveryStore(root.Journal)) { id = store.AllocateId(RecoveryIdKind.Session); Check.That(id != store.AllocateId(RecoveryIdKind.Session), "IDs unique"); }
        using (var store = new SqliteServerRecoveryStore(root.Journal)) Check.That(store.AllocateId(RecoveryIdKind.Session) > id, "IDs never reused after restart");
    }
}
