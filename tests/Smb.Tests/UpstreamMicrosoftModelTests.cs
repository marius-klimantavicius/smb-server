using Smb.Testing;

internal static partial class UpstreamMicrosoftTests
{
    static IEnumerable<(string Name, Func<Task> Run)> ModelCases()
    {
        foreach (var directory in new[] { false, true })
            foreach (var attributes in new[] { false, true })
                yield return ($"upstream.microsoft.close.attributes-{directory}-{attributes}", () => CloseAttributes(directory, attributes));
        foreach (var persistent in new[] { false, true })
            yield return ($"upstream.microsoft.close.invalid-id-{persistent}", () => CloseInvalidId(persistent));
        foreach (var dialect in new ushort[] { 0x202, 0x210, 0x300, 0x302, 0x311 })
            foreach (var client in new[] { false, true })
                foreach (var global in new[] { false, true })
                    yield return ($"upstream.microsoft.model.encryption-{dialect:x}-{client}-{global}", () => EncryptionConfiguration(dialect, client, global));
        foreach (var logoff in new[] { false, true })
            yield return ($"upstream.microsoft.auth.bind-retired-session-{logoff}", () => BindRetired(logoff));
        foreach (var kind in new[] { "unsigned", "different-dialect", "existing-channel", "in-progress" })
            yield return ("upstream.microsoft.auth.bind-" + kind, () => BindingInitial(kind));
        yield return ("upstream.microsoft.auth.bind-different-user", BindingUser);
        foreach (var dialect in new ushort[] { 0x202, 0x210, 0x300, 0x302 })
            foreach (var setup in new[] { false, true })
                foreach (var mode in new ushort[] { 0, 1, 2 })
                    yield return ($"upstream.microsoft.auth.client-mode-{dialect:x}-{setup}-{mode}", () => ClientSigningMode(dialect, setup, mode));
        yield return ("upstream.microsoft.auth.signed-negotiate", SignedNegotiate);
        yield return ("upstream.microsoft.auth.signed-initial-session", SignedInitialSession);
        foreach (var dialect in new ushort[] { 0x300, 0x311 })
            yield return ($"upstream.microsoft.auth.encrypted-share-incapable-{dialect:x}", () => EncryptedShareIncapable(dialect));
        yield return ("upstream.microsoft.tree.unknown-share", UnknownShare);
        foreach (var tree in new uint[] { 0, uint.MaxValue })
            yield return ($"upstream.microsoft.tree.disconnect-unknown-{tree}", () => UnknownDisconnect(tree));
        foreach (var offer in new ushort[][] { [0x202, 0x210], [0x202, 0x210, 0x300], [0x202, 0x210, 0x300, 0x302] })
            yield return ($"upstream.microsoft.negotiate.greatest-common-{offer[^1]:x}", () => GreatestDialect(offer));
    }
    // SMB2Model/CreateCloseTestCase CloseFlagType and FileId selectors. These
    // assertions concern SMB2 CLOSE bytes, not a modeled private open table.
    static async Task CloseAttributes(bool directory, bool attributes)
    {
        using var root = new Root(); if (directory) Directory.CreateDirectory(root.At("data")); else File.WriteAllBytes(root.At("data"), [1, 2, 3]);
        await using var d = root.Direct(); var id = await Open(d, "data", directory); var basic = Output(await Query(d, id, 4, 40));
        var standard = Output(await Query(d, id, 5, 24)); var close = RawSmb.Close(id, 0, 1, 42); RawSmb.Put16(close, 66, attributes ? (ushort)1 : (ushort)0);
        var response = await d.Send(close); Status(response, 0, "CLOSE"); Check.Equal((ushort)60, RawSmb.U16(response, 64), "CLOSE response StructureSize");
        Check.Equal(attributes ? (ushort)1 : (ushort)0, RawSmb.U16(response, 66), "CLOSE attribute-valid flag");
        if (attributes)
        {
            Check.That(basic.AsSpan(0, 32).SequenceEqual(response.AsSpan(72, 32)), "CLOSE returns basic timestamps");
            Check.Equal(RawSmb.U64(standard, 0), RawSmb.U64(response, 104), "CLOSE allocation size"); Check.Equal(RawSmb.U64(standard, 8), RawSmb.U64(response, 112), "CLOSE EOF");
            Check.Equal(RawSmb.U32(basic, 32), RawSmb.U32(response, 120), "CLOSE attributes");
        }
        else Check.That(response.AsSpan(72, 52).IndexOfAnyExcept((byte)0) == -1, "timestamps/sizes/attributes MUST be zero without POSTQUERY_ATTRIB");
        Status(await d.Send(RawSmb.Close(id, 0, 1, 42)), Closed, "repeat CLOSE rejects retired FileId");
    }
    static async Task CloseInvalidId(bool persistent)
    {
        using var root = new Root(); await using var d = root.Direct(); var id = await Open(d, "data");
        var invalid = persistent ? (id.P ^ 0x1234000000000000, id.V) : (id.P, id.V ^ 0x1234000000000000);
        Status(await d.Send(RawSmb.Close(invalid, 0, 1, 42)), Closed, "both FileId halves must identify the open");
        await Write(d, id, [42], 0); await ReadEquals(d, id, [42]);
        Status(await d.Send(RawSmb.Close(id, 0, 1, 42)), 0, "failed CLOSE leaves actual FileId usable");
    }
    // SMB2Model/EncryptionTestCase: supported dialect, client capability and
    // global policy partitions. Security is strengthened only; signing is kept.
    static async Task EncryptionConfiguration(ushort dialect, bool client, bool global)
    {
        await using var host = await UpstreamLocalFixture.StartAsync(); host.Server.State.Options.RequireEncryption = global;
        await using var c = await AuthWire.Connect(host.Server.Endpoint); await c.Negotiate(dialect, encryptionCipher: client ? (ushort)1 : (ushort)0);
        if (global && (!client || dialect < 0x300)) { await c.Login(finalStatus: Denied); return; }
        await c.Login(expectEncryption: global);
        var request = RawSmb.TreeConnect("\\\\localhost\\P0", 0, c.Session);
        if (global) await c.Encrypted(request); else await c.Exchange(request, 0, true);
    }
    // SMB2Model SessionMgmtBindSessionAfter{LogOff,Disconnection}: retired IDs
    // cannot be resurrected by the binding flag, even with the old signing key.
    static async Task BindRetired(bool logoff)
    {
        await using var host = await UpstreamLocalFixture.StartAsync(); host.Server.State.Options.FeaturePolicy = Smb.Server.SmbFeaturePolicy.MultichannelOnly; host.Server.State.Options.EnableMultichannel = true;
        await using var a = await AuthWire.Connect(host.Server.Endpoint); await a.Negotiate(0x300); await a.Login();
        if (logoff) { var request = RawSmb.Header(2, 4, 0, a.Session); RawSmb.Put16(request, 64, 4); await a.Exchange(request, 0, true); }
        else await a.CloseAndWait();
        await using var b = await AuthWire.Connect(host.Server.Endpoint); await b.Negotiate(0x300); await b.RejectRetiredBinding(a);
    }
    static async Task BindingInitial(string kind)
    {
        await using var host = await UpstreamLocalFixture.StartAsync(); host.Server.State.Options.FeaturePolicy = Smb.Server.SmbFeaturePolicy.MultichannelOnly; host.Server.State.Options.EnableMultichannel = true;
        await using var a = await AuthWire.Connect(host.Server.Endpoint); await a.Negotiate(0x300);
        if (kind == "in-progress") await a.BeginAuthentication(); else await a.Login();
        await using var b = await AuthWire.Connect(host.Server.Endpoint); await b.Negotiate(kind == "different-dialect" ? (ushort)0x302 : (ushort)0x300);
        if (kind == "existing-channel") await a.RejectInitialBinding(a, 0xc00000d0, true);
        else await b.RejectInitialBinding(a, kind == "in-progress" ? 0xc00000d0u : Invalid, kind != "unsigned", kind == "in-progress");
    }
    static async Task BindingUser()
    {
        await using var host = await UpstreamLocalFixture.StartAsync(); host.Server.State.Options.FeaturePolicy = Smb.Server.SmbFeaturePolicy.MultichannelOnly; host.Server.State.Options.EnableMultichannel = true;
        host.Server.State.Options.SpnegoNegotiator = new Smb.Auth.Ntlm.NtlmSpnegoNegotiator(new Smb.Auth.InMemoryIdentityBackend()
            .AddUser(HostFixture.Domain, HostFixture.User, HostFixture.Password).AddUser(HostFixture.Domain, "second-fixture-user", HostFixture.Password));
        await using var a = await AuthWire.Connect(host.Server.Endpoint); await a.Negotiate(0x300); await a.Login();
        await using var b = await AuthWire.Connect(host.Server.Endpoint); await b.Negotiate(0x300);
        await b.Login(user: "second-fixture-user", finalStatus: 0xc00000bb, bindTo: a);
        await a.Exchange(a.Echo(), 0, true);
    }
    static async Task UnknownShare()
    {
        await using var host = await UpstreamLocalFixture.StartAsync(); await using var c = await host.ConnectAsync();
        await c.ExchangeAsync(RawSmb.TreeConnect("\\\\localhost\\absent-share", c.NextMessageId(), c.Session), 0xc00000cc);
        var id = await c.CreateAsync("control"); await c.CloseAsync(id);
    }
    // SigningTestCase varies client SecurityMode separately in NEGOTIATE and
    // SESSION_SETUP. The server still requires signing for every partition.
    static async Task ClientSigningMode(ushort dialect, bool setup, ushort mode)
    {
        await using var host = await UpstreamLocalFixture.StartAsync(); await using var c = await AuthWire.Connect(host.Server.Endpoint);
        await c.Negotiate(dialect, clientSecurityMode: setup ? (ushort)3 : mode);
        await c.Login(clientSecurityMode: setup ? (byte)mode : (byte)3); await c.Exchange(c.Echo(), 0, true);
        await c.Exchange(RawSmb.TreeConnect("\\\\localhost\\P0", 0, c.Session), Denied);
    }
    static async Task SignedNegotiate()
    {
        await using var host = await UpstreamLocalFixture.StartAsync(); await using var c = await AuthWire.Connect(host.Server.Endpoint);
        var request = AuthWire.NegotiatePacket(0x202); RawSmb.Put32(request, 16, 8);
        await c.Exchange(request, Invalid);
    }
    static async Task SignedInitialSession()
    {
        await using var host = await UpstreamLocalFixture.StartAsync(); await using var c = await AuthWire.Connect(host.Server.Endpoint); await c.Negotiate(0x202);
        var request = RawSmb.SessionSetup(new Smb.Auth.Ntlm.NtlmClient(HostFixture.Domain, HostFixture.User, HostFixture.Password).BuildNegotiate(), 0);
        RawSmb.Put32(request, 16, 8); await c.Exchange(request, 0xc0000203);
    }
    static async Task EncryptedShareIncapable(ushort dialect)
    {
        await using var host = await UpstreamLocalFixture.StartAsync();
        host.Server.State.Options.Shares.Add(new Smb.FileSystem.Share { Name = "ENC", EncryptData = true, FileStore = host.Server.State.Options.Shares.All.Single(s => s.Name == "P0").FileStore });
        await using var c = await AuthWire.Connect(host.Server.Endpoint); await c.Negotiate(dialect); await c.Login();
        await c.Exchange(RawSmb.TreeConnect("\\\\localhost\\ENC", 0, c.Session), Denied, true);
        await c.Exchange(RawSmb.TreeConnect("\\\\localhost\\P0", 0, c.Session), 0, true);
    }
    static async Task UnknownDisconnect(uint tree)
    {
        await using var host = await UpstreamLocalFixture.StartAsync(); await using var c = await host.ConnectAsync();
        await c.ExchangeAsync(RawSmb.TreeDisconnect(c.NextMessageId(), c.Session, tree), 0xc00000c9);
        var id = await c.CreateAsync("control"); await c.CloseAsync(id);
    }
    static async Task GreatestDialect(ushort[] offer)
    {
        await using var host = await UpstreamLocalFixture.StartAsync(); await using var c = await AuthWire.Connect(host.Server.Endpoint);
        var request = RawSmb.Negotiate(); Array.Resize(ref request, 100 + offer.Length * 2); RawSmb.Put16(request, 66, (ushort)offer.Length);
        for (var i = 0; i < offer.Length; i++) RawSmb.Put16(request, 100 + i * 2, offer[i]);
        var response = await c.Exchange(request, 0); Check.Equal(offer[^1], RawSmb.U16(response, 68), "greatest common offered dialect");
    }
}
