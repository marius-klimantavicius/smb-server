using System.Net;
using System.Net.Sockets;
using Smb.Auth.Ntlm;
using Smb.Crypto;

namespace Smb.Testing;

public sealed class WireClient : IAsyncDisposable
{
    private readonly TcpClient _client = new TcpClient();
    private NetworkStream Stream => _client.GetStream();
    private ulong _mid;
    private byte[]? _key;
    private ushort _dialect;
    private readonly Smb.Crypto.PreauthIntegrityHash _preauth = new PreauthIntegrityHash();
    private byte[]? _sessionKey;
    static byte[] Negotiate(ulong mid,ushort dialect)
    {
        var b=RawSmb.Negotiate(mid);RawSmb.Put16(b,100,dialect);
        if(dialect!=0x311)return b;
        // Aligned SMB311 preauthentication SHA512 and signing AES-CMAC contexts.
        Array.Resize(ref b,144);RawSmb.Put32(b,92,104);RawSmb.Put16(b,96,2);
        RawSmb.Put16(b,104,1);RawSmb.Put16(b,106,6);RawSmb.Put16(b,112,1);RawSmb.Put16(b,114,0);RawSmb.Put16(b,116,1);
        RawSmb.Put16(b,120,8);RawSmb.Put16(b,122,4);RawSmb.Put16(b,128,1);RawSmb.Put16(b,130,1);
        Array.Resize(ref b,132);return b;
    }
    public ulong NextMessageId() => _mid++;
    public ulong Session { get; private set; }
    public uint Tree { get; private set; }
    public Action<string>? Trace { get; set; }
    public async Task ConnectAsync(IPEndPoint endpoint, string domain, string user, string password, ushort dialect = 0x202)
    {
        using var timeout = new CancellationTokenSource(Check.Timeout);
        await _client.ConnectAsync(endpoint.Address, endpoint.Port, timeout.Token);
        _dialect=dialect;var negotiate = Negotiate(_mid++,dialect);
        var b = await ExchangeAsync(negotiate, size: 65);
        Check.Equal(dialect, RawSmb.U16(b, 68), "negotiated offered dialect");
        Check.That((RawSmb.U16(b, 66) & 2) != 0, "server retains required signing");
        var ntlm = new NtlmClient(domain, user, password);
        b = await ExchangeAsync(RawSmb.SessionSetup(ntlm.BuildNegotiate(), _mid++), 0xc0000016, 9);
        Session = RawSmb.U64(b, 40);
        var challenge = RawSmb.Buffer(b, RawSmb.U16(b, 68), RawSmb.U16(b, 70));
        b = await ExchangeAsync(RawSmb.SessionSetup(ntlm.BuildAuthenticate(challenge), _mid++, Session), size: 9);
        Check.Equal(Session, RawSmb.U64(b, 40), "established SessionId");
        Check.Equal((ushort)0, RawSmb.U16(b, 66), "session is neither guest nor anonymous");
        _dialect = dialect;
        _sessionKey=ntlm.ExportedSessionKey;
        _key = dialect >= 0x300 ? Smb.Crypto.Smb3KeyDerivation.Derive((Smb.Protocol.Enums.SmbDialect)dialect, Smb.Protocol.Enums.SmbCipherId.None, ntlm.ExportedSessionKey, ntlm.ExportedSessionKey, dialect==0x311?_preauth.Value:new byte[64]).SigningKey : ntlm.ExportedSessionKey; // Existing excluded auth helper; no SMB wire expectations from it.
        b = await ExchangeAsync(RawSmb.TreeConnect("\\\\localhost\\P0", _mid++, Session), size: 16);
        Tree = RawSmb.U32(b, 36); Check.That(Tree != 0, "allocated TreeId");
    }
    // Independent binding packets; authentication and signing use the existing fixture helpers.
    public async Task BindAsync(IPEndPoint endpoint, WireClient primary)
    {
        using var timeout = new CancellationTokenSource(Check.Timeout);
        await _client.ConnectAsync(endpoint.Address, endpoint.Port, timeout.Token);
        _dialect=primary._dialect;var negotiate = Negotiate(_mid++,_dialect);
        await ExchangeAsync(negotiate,size:65);
        _dialect=primary._dialect; _key=primary._key; Session=primary.Session; Tree=primary.Tree;
        var ntlm = new NtlmClient(HostFixture.Domain,HostFixture.User,HostFixture.Password);
        var request=RawSmb.SessionSetup(ntlm.BuildNegotiate(),_mid++,Session);request[66]=1;
        var b=await ExchangeAsync(request,0xc0000016,9);
        var challenge=RawSmb.Buffer(b,RawSmb.U16(b,68),RawSmb.U16(b,70));
        request=RawSmb.SessionSetup(ntlm.BuildAuthenticate(challenge),_mid++,Session);request[66]=1;
        await ExchangeAsync(request,size:9);
        if(_dialect==0x311)_key=Smb.Crypto.Smb3KeyDerivation.Derive(Smb.Protocol.Enums.SmbDialect.Smb311,Smb.Protocol.Enums.SmbCipherId.None,primary._sessionKey!,primary._sessionKey!,_preauth.Value).SigningKey;
    }
    public async Task<byte[]> ExchangeAsync(byte[] request, uint status = 0, ushort? size = null)
    {
        await SendAsync(request);
        var response = await ReceiveAsync();
        RawSmb.Response(response, RawSmb.U16(request, 12), RawSmb.U64(request, 24), status, size);
        return response;
    }
    public async Task SendAsync(byte[] request)
    {
        if (_key is not null) {
            if (_dialect < 0x300) RawSmb.Sign(request, _key);
            else { RawSmb.Put32(request,16,RawSmb.U32(request,16)|8); Smb.Crypto.Smb2Signer.SignInPlace(Smb.Crypto.Smb2Signer.ResolveAlgorithm((Smb.Protocol.Enums.SmbDialect)_dialect,Smb.Protocol.Enums.SmbSigningAlgorithmId.AesCmac),_key,request,RawSmb.U64(request,24),false,false); }
        }
        if(_dialect==0x311 && RawSmb.U16(request,12) is 0 or 1)_preauth.Append(request);
        using var timeout = new CancellationTokenSource(Check.Timeout);
        var length = request.Length;
        var frame = new byte[4 + length];
        frame[1] = (byte)(length >> 16); frame[2] = (byte)(length >> 8); frame[3] = (byte)length;
        request.CopyTo(frame, 4);
        await Stream.WriteAsync(frame, timeout.Token);
    }
    public async Task<byte[]> ReceiveAsync()
    {
        using var timeout = new CancellationTokenSource(Check.Timeout);
        var prefix = new byte[4]; await Stream.ReadExactlyAsync(prefix, timeout.Token);
        Check.Equal((byte)0, prefix[0], "direct TCP frame type");
        var length = (prefix[1] << 16) | (prefix[2] << 8) | prefix[3];
        Check.That(length is >= 64 and <= 16 * 1024 * 1024, "bounded direct TCP response length");
        var response = new byte[length]; await Stream.ReadExactlyAsync(response, timeout.Token);
        if(_dialect==0x311 && (RawSmb.U16(response,12)==0 || RawSmb.U16(response,12)==1 && RawSmb.U32(response,8)==0xc0000016))_preauth.Append(response);
        return response;
    }

    public async Task<(ulong P, ulong V)> CreateAsync(string path, bool directory = false)
    {
        var b = await ExchangeAsync(RawSmb.Create(path, directory, _mid++, Session, Tree), size: 89);
        Check.That(b.Length >= 152, "fixed CREATE response");
        return (RawSmb.U64(b, 128), RawSmb.U64(b, 136));
    }
    public async Task WriteAsync((ulong P, ulong V) id, byte[] data)
    {
        var b = await ExchangeAsync(RawSmb.Write(id, data, 0, _mid++, Session, Tree), size: 17);
        Check.Equal((uint)data.Length, RawSmb.U32(b, 68), "WRITE Count");
    }
    public async Task<byte[]> ReadAsync((ulong P, ulong V) id, uint length)
    {
        var b = await ExchangeAsync(RawSmb.Read(id, length, 0, _mid++, Session, Tree), size: 17);
        Check.That(RawSmb.U32(b, 68) <= length, "READ respects requested length");
        return RawSmb.Buffer(b, b[66], RawSmb.U32(b, 68));
    }
    public async Task<string[]> EnumerateAsync((ulong P, ulong V) id)
    {
        var b = await ExchangeAsync(RawSmb.Enumerate(id, _mid++, Session, Tree), size: 9);
        return RawSmb.Names(RawSmb.Buffer(b, RawSmb.U16(b, 66), RawSmb.U32(b, 68)));
    }
    public async Task CloseAsync((ulong P, ulong V) id) =>
        await ExchangeAsync(RawSmb.Close(id, _mid++, Session, Tree), size: 60);
    public async Task DisconnectTreeAsync() =>
        await ExchangeAsync(RawSmb.TreeDisconnect(_mid++, Session, Tree), size: 4);
    public ValueTask DisposeAsync() { _client.Dispose(); return ValueTask.CompletedTask; }
}
