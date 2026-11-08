using System.Net;
using System.Net.Sockets;
using Smb.Auth;
using Smb.Auth.Ntlm;
using Smb.Host;
using Smb.Protocol.Enums;
using Smb.Server;
using Smb.Testing;

internal static partial class UpstreamSambaMoreTests
{
    static IEnumerable<(string Name, Func<Task> Run)> ManyChannelCases()
    {
        yield return ("upstream.samba.more.multichannel.parallel-negotiate-echo-bind-32", ManyChannels);
    }
    sealed class MultiPeer : IAsyncDisposable
    {
        readonly TcpClient tcp = new(); ulong mid; byte[]? key; internal ulong Session; internal uint Tree;
        internal async Task Negotiate(IPEndPoint endpoint)
        {
            using var timeout = new CancellationTokenSource(Check.Timeout); await tcp.ConnectAsync(endpoint.Address, endpoint.Port, timeout.Token);
            var request = RawSmb.Negotiate(); RawSmb.Put16(request, 100, 0x300); RawSmb.Put32(request, 72, 12);
            var response = await Exchange(request, false); Status(response, Ok, "parallel actual TCP NEGOTIATE"); Check.Equal((ushort)0x300, RawSmb.U16(response, 68), "all channels negotiate same dialect"); Check.That((RawSmb.U32(response, 88) & 8) != 0, "actual negotiation advertises multichannel");
        }
        internal async Task Echo()
        { var request = RawSmb.Header(13, 4, 0); RawSmb.Put16(request, 64, 4); Status(await Exchange(request, false), Ok, "negotiated unauthenticated ECHO remains responsive"); }
        internal async Task Login(MultiPeer? primary = null)
        {
            if (primary != null) { key = primary.key; Session = primary.Session; Tree = primary.Tree; }
            var ntlm = new NtlmClient(HostFixture.Domain, HostFixture.User, HostFixture.Password); var request = RawSmb.SessionSetup(ntlm.BuildNegotiate(), 0, Session); if (primary != null) request[66] = 1;
            var challenge = await Exchange(request, false, false); Status(challenge, 0xc0000016, "actual NTLM session/binding challenge"); Session = RawSmb.U64(challenge, 40);
            request = RawSmb.SessionSetup(ntlm.BuildAuthenticate(RawSmb.Buffer(challenge, RawSmb.U16(challenge, 68), RawSmb.U16(challenge, 70))), 0, Session); if (primary != null) request[66] = 1;
            Status(await Exchange(request, false, false), Ok, "actual NTLM authenticated session/binding"); key = Smb.Crypto.Smb3KeyDerivation.Derive(SmbDialect.Smb300, SmbCipherId.None, ntlm.ExportedSessionKey, ntlm.ExportedSessionKey, new byte[64]).SigningKey;
            if (primary == null) { var tree = await Exchange(RawSmb.TreeConnect("\\\\localhost\\P0", 0, Session), false); Status(tree, Ok, "primary signed tree connect"); Tree = RawSmb.U32(tree, 36); }
        }
        internal async Task<byte[]> Exchange(byte[] request, bool route = true, bool verify = true)
        {
            RawSmb.Put64(request, 24, mid++); if (route) { RawSmb.Put64(request, 40, Session); RawSmb.Put32(request, 36, Tree); }
            if (key != null) { RawSmb.Put32(request, 16, RawSmb.U32(request, 16) | 8); request.AsSpan(48, 16).Clear(); Smb.Crypto.AesCmac.Compute(key, request).CopyTo(request, 48); }
            using var timeout = new CancellationTokenSource(Check.Timeout); var frame = new byte[request.Length + 4]; frame[1] = (byte)(request.Length >> 16); frame[2] = (byte)(request.Length >> 8); frame[3] = (byte)request.Length; request.CopyTo(frame, 4);
            var stream = tcp.GetStream(); await stream.WriteAsync(frame, timeout.Token); var prefix = new byte[4]; await stream.ReadExactlyAsync(prefix, timeout.Token); var length = prefix[1] << 16 | prefix[2] << 8 | prefix[3]; Check.That(prefix[0] == 0 && length is >= 64 and <= 1048576, "bounded native SMB response");
            var response = new byte[length]; await stream.ReadExactlyAsync(response, timeout.Token); Check.Equal(RawSmb.U64(request, 24), RawSmb.U64(response, 24), "parallel response matches channel MessageId"); Check.Equal(RawSmb.U16(request, 12), RawSmb.U16(response, 12), "parallel response command");
            if (key != null && verify) { var unsigned = response.ToArray(); unsigned.AsSpan(48, 16).Clear(); Check.That((RawSmb.U32(response, 16) & 8) != 0 && Smb.Crypto.AesCmac.Compute(key, unsigned).SequenceEqual(response.AsSpan(48, 16).ToArray()), "bound channel's own signing key verifies response CMAC"); }
            return response;
        }
        public ValueTask DisposeAsync() { tcp.Dispose(); return ValueTask.CompletedTask; }
    }
    static async Task ManyChannels()
    {
        using var root = new P7cTests.Root(); await using var server = SmbServerBuilder.Create().WithEndpoint(IPAddress.Loopback, 0)
            .UseAuthentication(new NtlmSpnegoNegotiator(new InMemoryIdentityBackend().AddUser(HostFixture.Domain, HostFixture.User, HostFixture.Password)))
            .AddShare(new Smb.FileSystem.Share { Name = "P0", FileStore = root.Store() }).Configure(o => { o.FeaturePolicy = SmbFeaturePolicy.MultichannelWithCaching; o.EnableMultichannel = true; }).Build();
        await server.StartAsync().WaitAsync(Check.Timeout); var peers = Enumerable.Range(0, 32).Select(_ => new MultiPeer()).ToArray();
        try
        {
            await peers[0].Negotiate(server.Endpoint); await peers[0].Login(); var id = Id(await peers[0].Exchange(Create("", directory: true)));
            await Task.WhenAll(peers.Skip(1).Select(p => p.Negotiate(server.Endpoint))).WaitAsync(Check.Timeout);
            for (var round = 0; round < 2; round++) await Task.WhenAll(peers.Skip(1).Select(p => p.Echo())).WaitAsync(Check.Timeout);
            await Task.WhenAll(peers.Skip(1).Select(p => p.Login(peers[0]))).WaitAsync(Check.Timeout);
            await Task.WhenAll(peers.Select(async p => { var result = Output(await p.Exchange(Query(id, 18))); Check.Equal((byte)1, result[61], "all 32 actual bound channels query the same original directory open"); })).WaitAsync(Check.Timeout);
            Status(await peers[0].Exchange(RawSmb.Close(id, 0, 1, 42)), Ok, "original channel closes shared directory after all bound queries");
        }
        finally { foreach (var peer in peers) await peer.DisposeAsync(); await server.StopAsync(TimeSpan.FromSeconds(1)).WaitAsync(Check.Timeout); }
    }
}
