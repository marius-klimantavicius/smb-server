using Smb.Protocol.Enums;
using Smb.Server;
using Smb.Server.State;
using Smb.Testing;

internal static partial class UpstreamInventoryTests
{
    static IEnumerable<(string Name, Func<Task> Run)> RecoveryCases()
    {
        foreach (var zeroVolatile in new[] { false, true })
            yield return ($"upstream.inventory.durable-v1.missing-persistent-{zeroVolatile}", () => MissingPersistent(zeroVolatile));
        yield return ("upstream.inventory.create.handle-cap-close-retry", HandleCap);
        foreach (var kind in new[] { "missing-persistent", "wrong-lease", "missing-lease", "no-held-lease", "active", "client-guid", "owner", "not-durable" })
            yield return ("upstream.inventory.durable-v1." + kind, () => DurableV1Claim(kind));
        foreach (var size in new ushort[] { 0, 56, 58 })
            yield return ($"upstream.inventory.create.structure-size-{size}", () => CreateStructure(size));
    }
    static async Task CreateStructure(ushort size)
    {
        await using var h = await UpstreamLocalFixture.StartAsync(); await using var c = await h.ConnectAsync();
        var b = RawSmb.Create("malformed", false, c.NextMessageId(), c.Session, c.Tree); RawSmb.Put16(b, 64, size);
        await c.ExchangeAsync(b, Invalid); Check.That(!File.Exists(h.PathFor("malformed")), "invalid CREATE structure cannot create an object");
        var id = await c.CreateAsync("malformed"); await c.CloseAsync(id);
    }
    static byte[] WithLease(byte[] request, ulong key)
    {
        var data = new byte[32]; RawSmb.Put64(data, 0, key); RawSmb.Put64(data, 8, 0x12345678); RawSmb.Put32(data, 16, 7);
        request[67] = 255; return P7cTests.Context(request, "RqLs", data);
    }
    static bool ReturnedContext(byte[] b, string name)
    {
        var at = (int)RawSmb.U32(b, 144); var end = at + (int)RawSmb.U32(b, 148);
        while (at >= 152 && at + 16 <= end && end <= b.Length)
        {
            if (b.AsSpan(at + RawSmb.U16(b, at + 4), RawSmb.U16(b, at + 6)).SequenceEqual(System.Text.Encoding.ASCII.GetBytes(name))) return true;
            var next = RawSmb.U32(b, at); if (next == 0) break; Check.That(next >= 16 && next % 8 == 0, "bounded context progress"); at += checked((int)next);
        }
        return false;
    }
    static async Task DurableV1Claim(string kind)
    {
        using var root = new P7cTests.Root(); await using var d = new P2Tests.Direct(root.Store());
        d.Options.FeaturePolicy = SmbFeaturePolicy.Durable; d.Connection.Dialect = SmbDialect.Smb300;
        d.Connection.ServerCapabilities |= Smb2Capabilities.Leasing;
        d.Session.Identity = new Smb.Auth.SecurityIdentity { DomainName = "AUDIT", UserName = "owner" };
        var request = RawSmb.Create("v1", false, 0, 1, 42); request[67] = 9;
        if (kind != "not-durable") request = P7cTests.Context(request, "DHnQ", new byte[16]);
        if (kind != "no-held-lease") request = WithLease(request, 1);
        try
        {
            var response = await d.Send(request); Check.Equal(0u, RawSmb.U32(response, 8), "actual v1/lease source setup CREATE");
            Check.Equal(kind != "not-durable", ReturnedContext(response, "DHnQ"), "actual selected durable grant state");
            if (kind != "no-held-lease") Check.That(ReturnedContext(response, "RqLs"), "actual file lease grant");
            var id = (P: RawSmb.U64(response, 128), V: RawSmb.U64(response, 136));
            Check.Equal(0u, RawSmb.U32(await d.Send(RawSmb.Write(id, [42], 0, 0, 1, 42)), 8), "retained content before claim");
            if (kind != "active") await d.Dispatcher.OnConnectionClosedAsync(d.Connection);
            var connection = d.Channel(); connection.Dialect = SmbDialect.Smb300; connection.ClientGuid = d.Connection.ClientGuid.ToArray(); connection.ServerCapabilities |= Smb2Capabilities.Leasing;
            if (kind == "client-guid") connection.ClientGuid = Guid.NewGuid().ToByteArray();
            var session = new SmbSession { SessionId = 2, SessionGlobalId = 2, Connection = connection, State = SessionState.Valid, SigningRequired = true,
                SigningKey = new byte[16], SessionKey = new byte[16], Identity = kind == "owner" ? new Smb.Auth.SecurityIdentity { DomainName = "AUDIT", UserName = "other" } : d.Session.Identity };
            Check.That(session.TryAttachChannel(new SmbChannel { Connection = connection, SigningKey = session.SigningKey }), "established new source claim session");
            connection.Sessions.TryAdd(2, session); d.State.Connections.TryAdd(connection.ConnectionId, connection); d.State.SessionGlobalList.TryAdd(2, session);
            session.TreeConnects.TryAdd(42, new SmbTreeConnect { TreeId = 42, Session = session, Share = d.Tree.Share, MaximalAccess = d.Tree.MaximalAccess });
            d.Options.Metrics.OnAuthenticationSucceeded(); d.Options.Metrics.OnTreeConnected();
            byte[] Claim(bool malformed)
            {
                var data = new byte[16]; RawSmb.Put64(data, 0, malformed && kind == "missing-persistent" ? 0 : id.P);
                var b = P7cTests.Context(RawSmb.Create("v1", false, 0, 2, 42), "DHnC", data);
                return malformed && kind == "missing-lease" ? b : WithLease(b, malformed && kind == "wrong-lease" ? 9ul : 1ul);
            }
            response = await d.Send(Claim(true), connection);
            Check.Equal(kind == "owner" ? 0xc0000022u : 0xc0000034u, RawSmb.U32(response, 8), "source v1 durable claim rejection");
            if (kind is "missing-persistent" or "wrong-lease" or "missing-lease")
            {
                response = await d.Send(Claim(false), connection); Check.Equal(0u, RawSmb.U32(response, 8), "rejected malformed claim leaves real retained open recoverable");
                var recovered = (RawSmb.U64(response, 128), RawSmb.U64(response, 136)); response = await d.Send(RawSmb.Read(recovered, 1, 0, 0, 2, 42), connection);
                Check.Equal(0u, RawSmb.U32(response, 8), "recovered v1 reads"); Check.That(OutputRead(response).SequenceEqual(new byte[] { 42 }), "retained byte preserved");
            }
        }
        finally
        {
            foreach (var connection in d.State.Connections.Values.ToArray()) await d.Dispatcher.OnConnectionClosedAsync(connection, Smb2Dispatcher.CloseReason.Shutdown);
            await d.Dispatcher.CloseRetainedHandlesAsync();
        }
    }
    static byte[] OutputRead(byte[] b) => RawSmb.Buffer(b, b[66], RawSmb.U32(b, 68));
    static async Task HandleCap()
    {
        await using var h = await UpstreamLocalFixture.StartAsync(); h.Server.State.Options.MaxOpenHandlesPerSession = 1;
        await using var c = await h.ConnectAsync(); var first = await c.CreateAsync("first");
        await c.ExchangeAsync(RawSmb.Create("second", false, c.NextMessageId(), c.Session, c.Tree), 0xc000009a);
        Check.That(!File.Exists(h.PathFor("second")), "handle cap rejects before object creation");
        await c.WriteAsync(first, [42]); await c.CloseAsync(first); var next = await c.CreateAsync("second"); await c.CloseAsync(next);
    }
    static async Task MissingPersistent(bool zeroVolatile)
    {
        using var root = new P7cTests.Root(); await using var d = new P2Tests.Direct(root.Store());
        d.Options.FeaturePolicy = SmbFeaturePolicy.Durable; d.Connection.Dialect = SmbDialect.Smb300;
        // This fixture starts with an established signed session. The durable open
        // is obtained via CREATE; no retained record or open state is fabricated.
        var request = RawSmb.Create("data", false, 0, 1, 42); request[67] = 9;
        request = P7cTests.Context(request, "DHnQ", new byte[16]);
        try
        {
            var response = await d.Send(request); Check.Equal(0u, RawSmb.U32(response, 8), "grant CREATE");
            var at = (int)RawSmb.U32(response, 144); Check.That(at >= 152 && RawSmb.U32(response, 148) >= 24, "actual durable grant context");
            Check.That(response.AsSpan(at + RawSmb.U16(response, at + 4), 4).SequenceEqual("DHnQ"u8), "actual durable v1 granted");
            var id = (P: RawSmb.U64(response, 128), V: RawSmb.U64(response, 136));
            Check.Equal(0u, RawSmb.U32(await d.Send(RawSmb.Write(id, [42], 0, 0, 1, 42)), 8), "write retained bytes");
            await d.Dispatcher.OnConnectionClosedAsync(d.Connection);
            var connection = d.Channel(); connection.Dialect = SmbDialect.Smb300; connection.ClientGuid = d.Connection.ClientGuid.ToArray();
            var session = new SmbSession { SessionId = 2, SessionGlobalId = 2, Connection = connection, State = SessionState.Valid, SigningRequired = true,
                SigningKey = new byte[16], SessionKey = new byte[16], Identity = d.Session.Identity };
            Check.That(session.TryAttachChannel(new SmbChannel { Connection = connection, SigningKey = session.SigningKey }), "established reconnect fixture channel");
            connection.Sessions.TryAdd(2, session); d.State.Connections.TryAdd(connection.ConnectionId, connection); d.State.SessionGlobalList.TryAdd(2, session);
            session.TreeConnects.TryAdd(42, new SmbTreeConnect { TreeId = 42, Session = session, Share = d.Tree.Share, MaximalAccess = d.Tree.MaximalAccess });
            d.Options.Metrics.OnAuthenticationSucceeded(); d.Options.Metrics.OnTreeConnected();
            byte[] Claim(ulong persistent, ulong transient)
            { var data = new byte[16]; RawSmb.Put64(data, 0, persistent); RawSmb.Put64(data, 8, transient); return P7cTests.Context(RawSmb.Create("data", false, 0, 2, 42), "DHnC", data); }
            response = await d.Send(Claim(0, zeroVolatile ? 0 : id.V), connection);
            Check.Equal(0xc0000034u, RawSmb.U32(response, 8), "missing FileId.Persistent does not locate retained durable open");
            response = await d.Send(Claim(id.P, id.V), connection); Check.Equal(0u, RawSmb.U32(response, 8), "invalid claim does not consume valid recovery");
            var recovered = (RawSmb.U64(response, 128), RawSmb.U64(response, 136)); response = await d.Send(RawSmb.Read(recovered, 1, 0, 0, 2, 42), connection);
            Check.Equal(0u, RawSmb.U32(response, 8), "recovered open reads"); Check.That(RawSmb.Buffer(response, response[66], RawSmb.U32(response, 68)).SequenceEqual(new byte[] { 42 }), "retained data preserved");
        }
        finally
        {
            foreach (var connection in d.State.Connections.Values.ToArray()) await d.Dispatcher.OnConnectionClosedAsync(connection, Smb2Dispatcher.CloseReason.Shutdown);
            await d.Dispatcher.CloseRetainedHandlesAsync();
        }
    }
}
