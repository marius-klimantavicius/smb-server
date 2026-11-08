using Smb.Auth;
using Smb.FileSystem.Local;
using Smb.Protocol.Enums;
using Smb.Server;
using Smb.Server.State;
using Smb.Testing;

internal static partial class UpstreamMicrosoftTests
{
    static IEnumerable<(string Name, Func<Task> Run)> ContextCases()
    {
        foreach (var kind in new[] { "unknown-name", "short-name", "data-overrun" })
            yield return ("upstream.microsoft.context.create-" + kind, () => CreateContextValidation(kind));
        foreach (var dialect in new[] { SmbDialect.Smb300, SmbDialect.Smb302 })
            foreach (var field in new[] { "name", "attributes", "disposition", "oplock", "new-guid" })
                yield return ($"upstream.microsoft.replay.{(ushort)dialect:x}.{field}", () => ReplayModified(dialect, field));
        foreach (var v1 in new[] { false, true })
            foreach (var extra in new[] { "DHnQ", "DH2Q", "DHnC", "DH2C" })
            {
                if (v1 && extra == "DHnC" || !v1 && extra == "DH2C") continue;
                yield return ($"upstream.microsoft.context.reconnect-{(v1 ? 1 : 2)}-plus-{extra}", () => ReconnectContext(v1, extra));
            }
    }
    // DurableHandle{,V2}: _Reconnect_Include* matrix. Grant and lose a real
    // supported open before presenting mixed contexts; no seeded recovery record.
    static async Task ReconnectContext(bool v1, string extra)
    {
        using var root = new P7cTests.Root(); await using var d = new P2Tests.Direct(root.Store());
        d.Options.FeaturePolicy = SmbFeaturePolicy.Durable; d.Connection.Dialect = SmbDialect.Smb300;
        d.Session.Identity = new SecurityIdentity { DomainName = "UPSTREAM", UserName = "context" };
        var guid = Guid.NewGuid(); var grant = new byte[32]; RawSmb.Put32(grant, 0, 10000); guid.ToByteArray().CopyTo(grant, 16);
        var request = RawSmb.Create("data", false, 0, 1, 42); request[67] = 9;
        request = P7cTests.Context(request, v1 ? "DHnQ" : "DH2Q", v1 ? new byte[16] : grant);
        try
        {
            var response = await d.Send(request); Status(response, 0, "actual durable grant"); var id = (RawSmb.U64(response, 128), RawSmb.U64(response, 136));
            Check.That(HasContext(response, v1 ? "DHnQ" : "DH2Q"), "server granted selected durable version");
            await Write(d, id, [1, 2, 3], 0); await d.Dispatcher.OnConnectionClosedAsync(d.Connection);
            var connection = d.Channel(); connection.Dialect = SmbDialect.Smb300; connection.ClientGuid = d.Connection.ClientGuid.ToArray();
            var session = new SmbSession { SessionId = 2, SessionGlobalId = 2, Connection = connection, State = SessionState.Valid,
                SigningRequired = true, SigningKey = new byte[16], SessionKey = new byte[16], Identity = d.Session.Identity };
            Check.That(session.TryAttachChannel(new SmbChannel { Connection = connection, SigningKey = session.SigningKey }), "attach reconnect channel");
            connection.Sessions.TryAdd(2, session); d.State.Connections.TryAdd(connection.ConnectionId, connection); d.State.SessionGlobalList.TryAdd(2, session);
            session.TreeConnects.TryAdd(42, new SmbTreeConnect { TreeId = 42, Session = session, Share = d.Tree.Share, MaximalAccess = d.Tree.MaximalAccess });
            d.Options.Metrics.OnAuthenticationSucceeded(); d.Options.Metrics.OnTreeConnected();
            var reconnect = new byte[v1 ? 16 : 36]; RawSmb.Put64(reconnect, 0, id.Item1); RawSmb.Put64(reconnect, 8, id.Item2); if (!v1) guid.ToByteArray().CopyTo(reconnect, 16);
            byte[] Claim() => P7cTests.Context(RawSmb.Create("data", false, 0, 2, 42), v1 ? "DHnC" : "DH2C", reconnect);
            var extraData = extra switch { "DHnQ" => new byte[16], "DH2Q" => grant, "DHnC" => reconnect[..16], _ => new byte[36] };
            var combined = P7cTests.Context(Claim(), extra, extraData);
            response = await d.Send(combined, connection);
            var expected = v1 ? extra == "DHnQ" ? 0u : Invalid : 0xc0000034u;
            Status(response, expected, "mixed durable reconnect context status from pinned upstream case");
            if (expected != 0) { response = await d.Send(Claim(), connection); Status(response, 0, "rejected claim leaves valid recovery available"); }
            var restored = (RawSmb.U64(response, 128), RawSmb.U64(response, 136));
            response = await d.Send(RawSmb.Read(restored, 3, 0, 0, 2, 42), connection); Status(response, 0, "recovered FileId reads");
            Check.That(ReadData(response).SequenceEqual(new byte[] { 1, 2, 3 }), "mixed-context rejection cannot erase retained data");
        }
        finally
        {
            foreach (var connection in d.State.Connections.Values.ToArray()) await d.Dispatcher.OnConnectionClosedAsync(connection, Smb2Dispatcher.CloseReason.Shutdown);
            await d.Dispatcher.CloseRetainedHandlesAsync();
        }
    }
    static async Task CreateContextValidation(string kind)
    {
        using var root = new Root(); await using var d = root.Direct();
        var request = P7cTests.Context(RawSmb.Create("context", false, 0, 1, 42), kind == "data-overrun" ? "MxAc" : "InvX", new byte[8]);
        var at = (int)RawSmb.U32(request, 112);
        if (kind == "short-name") RawSmb.Put16(request, at + 6, 3);
        if (kind == "data-overrun") RawSmb.Put32(request, at + 12, 9);
        var response = await d.Send(request); Status(response, kind == "unknown-name" ? 0u : Invalid, "CREATE context name/length validation");
        if (kind == "unknown-name")
        {
            Check.That(!HasContext(response, "InvX"), "unrecognized context is ignored, not echoed as granted");
            await ReadEqualsAfterWrite(d, (RawSmb.U64(response, 128), RawSmb.U64(response, 136)));
        }
        else Check.That(!File.Exists(root.At("context")), "malformed context cannot create file");
    }
    static async Task ReadEqualsAfterWrite(P2Tests.Direct d, (ulong P, ulong V) id)
    {
        await Write(d, id, [42], 0); await ReadEquals(d, id, [42]);
    }
    // SMB2Model ReplayCreate* selectors: retransmission preserves the original
    // CREATE result despite changed name/attrs/disposition/oplock request fields.
    static async Task ReplayModified(SmbDialect dialect, string field)
    {
        using var root = new P7cTests.Root(); File.WriteAllBytes(Path.Combine(root.Path, "data"), [1, 2, 3]);
        await using var d = new P2Tests.Direct(root.Store()); d.Options.FeaturePolicy = SmbFeaturePolicy.Durable; d.Connection.Dialect = dialect;
        var guid = Guid.NewGuid(); var context = new byte[32]; RawSmb.Put32(context, 0, 10000); guid.ToByteArray().CopyTo(context, 16);
        byte[] Request(string path, byte[] data) { var b = RawSmb.Create(path, false, 0, 1, 42); b[67] = 9; return P7cTests.Context(b, "DH2Q", data); }
        try
        {
            var original = await d.Send(Request("data", context)); Status(original, 0, "durable CREATE before replay"); Check.That(HasContext(original, "DH2Q"), "actual durable v2 grant");
            var repeated = Request(field == "name" ? "not-the-original-name" : "data", context);
            if (field == "attributes") RawSmb.Put32(repeated, 92, 1);
            if (field == "disposition") RawSmb.Put32(repeated, 100, 0);
            if (field == "oplock") repeated[67] = 0;
            if (field == "new-guid") Guid.NewGuid().ToByteArray().CopyTo(repeated, (int)RawSmb.U32(repeated, 112) + 40);
            RawSmb.Put32(repeated, 16, 0x20000000); var response = await d.Send(repeated); Status(response, 0, "replayed CREATE");
            var id = (RawSmb.U64(response, 128), RawSmb.U64(response, 136));
            if (field == "new-guid") Check.That(id != (RawSmb.U64(original, 128), RawSmb.U64(original, 136)), "new CreateGuid is an independent open");
            else Check.That(original.AsSpan(66, 78).SequenceEqual(response.AsSpan(66, 78)), "replayed CREATE cached action/metadata/oplock/FileId");
            await ReadEquals(d, id, [1, 2, 3]); Check.That(!File.Exists(Path.Combine(root.Path, "not-the-original-name")), "replay cannot create changed pathname");
        }
        finally { await d.Dispatcher.OnConnectionClosedAsync(d.Connection, Smb2Dispatcher.CloseReason.Shutdown); await d.Dispatcher.CloseRetainedHandlesAsync(); }
    }
    static bool HasContext(byte[] response, string name)
    {
        var at = (int)RawSmb.U32(response, 144); var end = at + (int)RawSmb.U32(response, 148);
        while (at != 0 && at < end)
        {
            Check.That(at + 16 <= end && end <= response.Length, "response context bounded");
            if (System.Text.Encoding.ASCII.GetString(response, at + RawSmb.U16(response, at + 4), RawSmb.U16(response, at + 6)) == name) return true;
            var next = RawSmb.U32(response, at); if (next == 0) break; Check.That(next >= 16 && (next & 7) == 0, "context progresses"); at += (int)next;
        }
        return false;
    }
}
