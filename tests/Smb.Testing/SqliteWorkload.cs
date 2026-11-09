using Smb.FileSystem.Sqlite;
using Smb.Server;

namespace Smb.Testing;

// Actual loopback SMB against a database, shared by the published host and harness.
public static class SqliteWorkload
{
    public static async Task RunAsync(ushort dialect = 0x311, Action<string>? log = null)
    {
        var root = Path.Combine(Path.GetTempPath(), "smb-sqlite-workload-" + Guid.NewGuid().ToString("N"));
        Directory.CreateDirectory(root);
        try
        {
            var database = Path.Combine(root, "files.db"); byte[]? identity = null;
            for (var run = 0; run < 2; run++)
            {
                // Reverse declaration disposal: server (and all SMB opens) before provider.
                await using var store = new SqliteFileStore(database);
                await using var server = HostFixture.Build(store, 0, HostFixture.Domain, HostFixture.User, HostFixture.Password);
                Check.Equal(SmbFeaturePolicy.Restricted, server.State.Options.FeaturePolicy, "SQLite host retains Restricted default");
                await server.StartAsync().WaitAsync(Check.Timeout);
                await using var c = new WireClient();
                await c.ConnectAsync(server.Endpoint, HostFixture.Domain, HostFixture.User, HostFixture.Password, dialect);
                byte[] Create(string path, bool directory, uint disposition)
                { var b = RawSmb.Create(path, directory, c.NextMessageId(), c.Session, c.Tree); RawSmb.Put32(b, 100, disposition); RawSmb.Put32(b, 88, 0x1f01ff); return b; }
                async Task<(ulong P, ulong V)> Open(string path, bool directory, uint disposition)
                { var b = await c.ExchangeAsync(Create(path, directory, disposition)); return (RawSmb.U64(b, 128), RawSmb.U64(b, 136)); }
                byte[] Query((ulong P, ulong V) id, byte cls)
                { var b = RawSmb.Header(16, 40, c.NextMessageId(), c.Session, c.Tree); RawSmb.Put16(b, 64, 41); b[66] = 1; b[67] = cls; RawSmb.Put32(b, 68, 4096); RawSmb.Put64(b, 88, id.P); RawSmb.Put64(b, 96, id.V); return b; }
                byte[] Set((ulong P, ulong V) id, byte cls, byte[] data)
                { var b = RawSmb.Header(17, 32 + data.Length, c.NextMessageId(), c.Session, c.Tree); RawSmb.Put16(b, 64, 33); b[66] = 1; b[67] = cls; RawSmb.Put32(b, 68, (uint)data.Length); RawSmb.Put16(b, 72, 96); RawSmb.Put64(b, 80, id.P); RawSmb.Put64(b, 88, id.V); data.CopyTo(b, 96); return b; }
                var dir = await Open("tree", true, run == 0 ? 2u : 1u);
                var id = await Open("tree\\bytes", false, run == 0 ? 2u : 1u);
                var bytes = "SQLite over signed SMB TCP"u8.ToArray();
                if (run == 0)
                {
                    await c.WriteAsync(id, bytes);
                    var eof = new byte[8]; RawSmb.Put64(eof, 0, 70000); await c.ExchangeAsync(Set(id, 20, eof));
                    var flush = RawSmb.Header(7, 24, c.NextMessageId(), c.Session, c.Tree); RawSmb.Put16(flush, 64, 24); RawSmb.Put64(flush, 72, id.P); RawSmb.Put64(flush, 80, id.V); await c.ExchangeAsync(flush);
                    var basic = new byte[40]; RawSmb.Put64(basic, 0, 132000000000000000); RawSmb.Put32(basic, 32, 2); await c.ExchangeAsync(Set(id, 4, basic));
                }
                Check.That((await c.ReadAsync(id, (uint)bytes.Length)).SequenceEqual(bytes), "reopened SQLite TCP bytes");
                var hole = await c.ExchangeAsync(RawSmb.Read(id, 8, 69992, c.NextMessageId(), c.Session, c.Tree));
                Check.That(RawSmb.Buffer(hole, hole[66], RawSmb.U32(hole, 68)).SequenceEqual(new byte[8]), "sparse tail zeroes");
                var all = await c.ExchangeAsync(Query(id, 18)); var output = RawSmb.Buffer(all, RawSmb.U16(all, 66), RawSmb.U32(all, 68));
                Check.Equal(70000ul, RawSmb.U64(output, 48), "persisted EOF"); Check.Equal(132000000000000000ul, RawSmb.U64(output, 0), "persisted creation time"); Check.That((RawSmb.U32(output, 32) & 2) != 0, "persisted hidden attribute");
                var index = await c.ExchangeAsync(Query(id, 6)); var value = RawSmb.Buffer(index, RawSmb.U16(index, 66), RawSmb.U32(index, 68));
                if (identity is null) identity = value; else Check.That(value.SequenceEqual(identity), "persisted wire object index");
                Check.That((await c.EnumerateAsync(dir)).SequenceEqual(new[] { "bytes" }), "persisted exact tree");
                await c.CloseAsync(id); await c.CloseAsync(dir);
                await Open("tree\\tree-owned", false, 3); await c.DisconnectTreeAsync();
                Check.That(server.State.SessionGlobalList.Values.All(s => s.Opens.IsEmpty), "tree disconnect drains SQLite opens");
                // Remove the temporary tree-owned name for the next exact enumeration.
                var owned = await store.CreateAsync("tree/tree-owned", Smb.FileSystem.FileAccessIntent.ReadWrite | Smb.FileSystem.FileAccessIntent.Delete, Smb.FileSystem.CreateDispositionIntent.Open, false, true);
                Check.That(owned.IsSuccess, "tree-owned provider pin released"); Check.Equal(Smb.Protocol.Enums.NtStatus.Success, await store.SetDeleteOnCloseAsync(owned.Value.Handle, true), "remove temporary file"); await owned.Value.Handle.DisposeAsync();
                await server.StopAsync(TimeSpan.Zero).WaitAsync(Check.Timeout);
                log?.Invoke($"SQLITE TCP dialect={dialect:x} run={run} bytes={bytes.Length} EOF=70000 tree=verified identity=stable profile=Restricted");
            }
        }
        finally { Directory.Delete(root, true); }
    }
}
