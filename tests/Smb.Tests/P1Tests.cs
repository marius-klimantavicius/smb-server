using System.Net;
using System.Net.Sockets;
using System.Text;
using Smb.Auth;
using Smb.Auth.Ntlm;
using Smb.FileSystem;
using Smb.FileSystem.Local;
using Smb.Host;
using Smb.Protocol.Enums;
using Smb.Server;
using Smb.Server.Durable;
using Smb.Server.Leases;
using Smb.Server.Oplocks;
using Smb.Testing;

static class P1Tests
{
    public static IEnumerable<(string Name, Func<Task> Run)> Cases()
    {
        yield return ("p1.delete.nonempty-disposition", NonemptyAsync);
        yield return ("p1.delete.intervening-child", ChildAsync);
        yield return ("p1.delete.empty-and-clear", EmptyClearAsync);
        yield return ("p1.wire.delete-create", () => DeleteWireAsync("create"));
        yield return ("p1.wire.delete-set", () => DeleteWireAsync("set"));
        yield return ("p1.wire.delete-close", () => DeleteWireAsync("close"));
        yield return ("p1.config.multichannel-default", () => { Check.That(!new SmbServerOptions().EnableMultichannel, "multichannel disabled by default"); return Task.CompletedTask; });
        yield return ("p1.config.multichannel-rejected", () => ConfigAsync("multichannel"));
        yield return ("p1.config.direct-ca-rejected", () => ConfigAsync("direct-ca"));
        yield return ("p1.config.supplied-persistent-rejected", () => ConfigAsync("supplied-persistent"));
        yield return ("p1.config.supplied-persistent-timeout-rejected", () => ConfigAsync("supplied-timeout"));
        yield return ("p1.config.configure-persistent-rejected", () => ConfigAsync("configure-persistent"));
        yield return ("p1.wire.custom-managers-not-called", CustomManagersAsync);
        yield return ("p1.wire.custom-network-not-called", CustomNetworkAsync);
        yield return ("p1.wire.runtime-ca-create-rejected", RuntimeCaCreateAsync);
        yield return ("p1.config.ca-rejected", () => ConfigAsync("ca"));
        yield return ("p1.config.builder-ca-rejected", () => ConfigAsync("builder-ca"));
        yield return ("p1.config.builder-persistent-rejected", () => ConfigAsync("persistent"));
        yield return ("p1.config.builder-multichannel-rejected", () => ConfigAsync("builder-multi"));
        yield return ("p1.negotiate.capabilities", NegotiateAsync);
        foreach (var level in new byte[] { 1, 8, 9 })
        { var l = level; yield return ($"p1.wire.oplock-{l}", () => ContextAsync(null, [], l)); }
        yield return ("p1.wire.lease-v1-custom-manager", () => ContextAsync("RqLs", new byte[32], 0xff));
        yield return ("p1.wire.lease-v2-custom-manager", () => ContextAsync("RqLs", new byte[52], 0xff));
        yield return ("p1.wire.durable-v1", () => ContextAsync("DHnQ", new byte[16], 9));
        yield return ("p1.wire.durable-v2", () => ContextAsync("DH2Q", new byte[32], 9));
        yield return ("p1.wire.persistent-request", () => { var data = new byte[32]; RawSmb.Put32(data, 4, 2); return ContextAsync("DH2Q", data, 9); });
        yield return ("p1.wire.durable-invalid-combination", InvalidCombinationAsync);
        yield return ("p1.wire.reconnect-v1", () => ReconnectAsync(false));
        yield return ("p1.wire.reconnect-v2", () => ReconnectAsync(true));
        yield return ("p1.wire.copy-resume-key", () => IoctlAsync(0x00140078));
        yield return ("p1.wire.copychunk", () => IoctlAsync(0x001440f2));
        yield return ("p1.wire.copychunk-write", () => IoctlAsync(0x001480f2));
        yield return ("p1.wire.network-interfaces", () => IoctlAsync(0x001401fc));
        yield return ("p1.wire.binding-disabled", BindingAsync);
        yield return ("p1.wire.runtime-ca-rejected", RuntimeCaAsync);
    }
    sealed class Root : IDisposable
    {
        public string Path { get; } = System.IO.Path.Combine(System.IO.Path.GetTempPath(), "smb-p1-" + Guid.NewGuid());
        public Root() { Directory.CreateDirectory(Path); }
        public void Dispose() { Directory.Delete(Path, true); }
    }
    static async Task<IFileHandle> OpenAsync(LocalFileStore s, string path) {
        var r = await s.CreateAsync(path, FileAccessIntent.ReadWrite | FileAccessIntent.Delete, CreateDispositionIntent.Open, true, false);
        Check.Equal(NtStatus.Success, r.Status, "open directory"); return r.Value.Handle;
    }
    static async Task NonemptyAsync() {
        using var root = new Root(); Directory.CreateDirectory(root.Path + "/d"); File.WriteAllText(root.Path + "/d/child", "keep");
        var s = new LocalFileStore(root.Path, false); using var h = await OpenAsync(s, "d");
        Check.Equal(NtStatus.DirectoryNotEmpty, await s.SetDeleteOnCloseAsync(h, true), "nonempty disposition status");
        h.Dispose(); Check.Equal("keep", NativeHost.ReadAllText(root.Path + "/d/child"), "descendant preserved");
    }
    static async Task ChildAsync() {
        using var root = new Root(); Directory.CreateDirectory(root.Path + "/d");
        var s = new LocalFileStore(root.Path, false); var h = await OpenAsync(s, "d");
        Check.Equal(NtStatus.Success, await s.SetDeleteOnCloseAsync(h, true), "mark empty directory");
        // Strict order: marking completed, child committed, then final disposal. No timing assumption.
        File.WriteAllText(root.Path + "/d/child", "keep"); await h.DisposeAsync();
        Check.That(File.Exists(root.Path + "/d/child"), "child inserted after marking survives final disposal");
        h.Dispose(); Check.That(File.Exists(root.Path + "/d/child"), "idempotent disposal preserves child");
    }
    static async Task EmptyClearAsync() {
        using var root = new Root(); Directory.CreateDirectory(root.Path + "/d");
        var s = new LocalFileStore(root.Path, false); var h = await OpenAsync(s, "d");
        Check.Equal(NtStatus.Success, await s.SetDeleteOnCloseAsync(h, true), "mark");
        Check.Equal(NtStatus.Success, await s.SetDeleteOnCloseAsync(h, false), "clear");
        await h.DisposeAsync(); Check.That(Directory.Exists(root.Path + "/d"), "clearing preserves directory");
        h = await OpenAsync(s, "d"); Check.Equal(NtStatus.Success, await s.SetDeleteOnCloseAsync(h, true), "remark");
        await h.DisposeAsync(); Check.That(!Directory.Exists(root.Path + "/d"), "empty directory removed");
        Directory.CreateDirectory(root.Path + "/d"); h.Dispose(); Check.That(Directory.Exists(root.Path + "/d"), "second disposal cannot delete replacement");
    }
    static SmbServerBuilder Builder(IFileStore s) => SmbServerBuilder.Create().WithEndpoint(IPAddress.Loopback, 0)
        .UseAuthentication(new NtlmSpnegoNegotiator(new InMemoryIdentityBackend().AddUser(HostFixture.Domain, HostFixture.User, HostFixture.Password)))
        .AddShare(new Share { Name = "P0", FileStore = s });
    static async Task<WireClient> ConnectAsync(Smb.Host.SmbServer s, ushort dialect = 0x210) {
        var c = new WireClient(); await c.ConnectAsync(s.Endpoint, HostFixture.Domain, HostFixture.User, HostFixture.Password, dialect); return c;
    }
    static byte[] Disposition((ulong P, ulong V) id, WireClient c, bool delete) {
        var b = RawSmb.Header(17, 33, c.NextMessageId(), c.Session, c.Tree); RawSmb.Put16(b, 64, 33); b[66]=1; RawSmb.Put32(b,16,8); b[67]=13;
        RawSmb.Put32(b,68,1); RawSmb.Put16(b,72,96); RawSmb.Put64(b,80,id.P); RawSmb.Put64(b,88,id.V); b[96]=(byte)(delete?1:0); return b;
    }
    static async Task DeleteWireAsync(string mode) {
        using var root = new Root(); Directory.CreateDirectory(root.Path + "/d");
        if (mode != "close") File.WriteAllText(root.Path + "/d/child", "keep");
        await using var s = Builder(new LocalFileStore(root.Path, false)).Build(); await s.StartAsync(); await using var c = await ConnectAsync(s);
        var b = RawSmb.Create("d",true,c.NextMessageId(),c.Session,c.Tree); RawSmb.Put32(b,88,0x10003);
        if (mode == "create") { RawSmb.Put32(b,104,0x1001); await c.ExchangeAsync(b,0xc0000101,9); }
        else {
            var r = await c.ExchangeAsync(b,size:89); var id=(RawSmb.U64(r,128),RawSmb.U64(r,136));
            await c.ExchangeAsync(Disposition(id,c,true), mode=="set" ? 0xc0000101u : 0, mode=="set" ? (ushort)9 : (ushort)2);
            if (mode=="close") {
                File.WriteAllText(root.Path + "/d/child","keep");
                await c.ExchangeAsync(RawSmb.Close(id,c.NextMessageId(),c.Session,c.Tree),0xc0000101,9);
                await c.ExchangeAsync(RawSmb.Close(id,c.NextMessageId(),c.Session,c.Tree),0xc0000128,9);
                Check.That(s.State.SessionGlobalList.Values.All(x=>x.Opens.IsEmpty), "failed delete still closes open");
            } else await c.CloseAsync(id);
        }
        Check.Equal("keep",NativeHost.ReadAllText(root.Path + "/d/child"),"wire deletion preserves child");
    }
    static async Task ConfigAsync(string mode) {
        using var root = new Root(); var b=Builder(new FakeFileStore());
        var rejected=false;
        try {
            switch(mode) {
                case "direct-ca": b.Configure(o=>o.Shares.Add(new Share{Name="CA",FileStore=new FakeFileStore(),ContinuousAvailability=true}));break;
                case "supplied-persistent": b.UseDurableHandleStore(new FileDurableHandleStore(root.Path));break;
                case "supplied-timeout": b.UseDurableHandleStore(new FileDurableHandleStore(root.Path),TimeSpan.FromMinutes(1));break;
                case "configure-persistent": b.Configure(o=>o.DurableHandleStore=new FileDurableHandleStore(root.Path));break;
                case "multichannel": b.Configure(o=>o.EnableMultichannel=true); break;
                case "ca": b.AddShare(new Share{Name="CA",FileStore=new FakeFileStore(),ContinuousAvailability=true});break;
                case "builder-ca": b.AddDiskShare("CA",root.Path,continuousAvailability:true);break;
                case "persistent": b.UsePersistentDurableHandles(root.Path);break;
                case "builder-multi": b.EnableMultichannel();break;
            }
            await using var s=b.Build();
        } catch(InvalidOperationException) {rejected=true;}
        Check.That(rejected,$"unsupported {mode} configuration must be rejected explicitly");
    }
    static async Task NegotiateAsync() {
        await using var s=Builder(new FakeFileStore()).Build(); await s.StartAsync();
        using var tcp=new TcpClient(); await tcp.ConnectAsync(s.Endpoint.Address,s.Endpoint.Port);
        var b=RawSmb.Negotiate(); RawSmb.Put16(b,100,0x300); RawSmb.Put32(b,72,0x7e);
        var frame=new byte[b.Length+4]; frame[3]=(byte)b.Length; b.CopyTo(frame,4); await tcp.GetStream().WriteAsync(frame);
        var p=new byte[4]; await tcp.GetStream().ReadExactlyAsync(p).AsTask().WaitAsync(Check.Timeout);
        var r=new byte[(p[1]<<16)|(p[2]<<8)|p[3]]; await tcp.GetStream().ReadExactlyAsync(r).AsTask().WaitAsync(Check.Timeout);
        RawSmb.Response(r,0,0,0,65); Check.Equal((ushort)0x300,RawSmb.U16(r,68),"default still offers SMB3");
        Check.Equal(0u,RawSmb.U32(r,88)&0x3a,"no leases/multichannel/persistent/directory leasing claims");
        Check.That((RawSmb.U16(r,66)&2)!=0,"signing remains required");
    }
    static byte[] Context(string? name, byte[] data, byte oplock, WireClient c) {
        var b=RawSmb.Create("ctx",false,c.NextMessageId(),c.Session,c.Tree); b[67]=oplock;
        if(name==null)return b;
        var offset=(b.Length+7)&~7; Array.Resize(ref b,offset+24+data.Length);
        RawSmb.Put32(b,112,(uint)offset); RawSmb.Put32(b,116,(uint)(24+data.Length));
        RawSmb.Put16(b,offset+4,16); RawSmb.Put16(b,offset+6,4); RawSmb.Put16(b,offset+10,24); RawSmb.Put32(b,offset+12,(uint)data.Length);
        Encoding.ASCII.GetBytes(name).CopyTo(b,offset+16); data.CopyTo(b,offset+24); return b;
    }
    static async Task ContextAsync(string? name,byte[] data,byte oplock) {
        // Explicitly supplied real managers cannot bypass policy; lease data requests all rights.
        if(name=="RqLs") {new byte[]{1,2,3,4}.CopyTo(data,0);RawSmb.Put32(data,16,7);}
        await using var s=Builder(new FakeFileStore()).UseLeaseManager(new InMemoryLeaseManager()).UseOplockManager(new InMemoryOplockManager())
            .UseDurableHandleStore(new InMemoryDurableHandleStore()).Build(); await s.StartAsync(); await using var c=await ConnectAsync(s, name is "DH2Q" || (name=="RqLs" && data.Length==52) ? (ushort)0x300 : (ushort)0x210);
        var r=await c.ExchangeAsync(Context(name,data,oplock,c),size:89);
        Check.Equal(0u,RawSmb.U32(r,148),"no lease/durable response context"); Check.Equal((byte)0,r[66],"no caching grant");
        Check.That(s.State.SessionGlobalList[c.Session].Opens.Values.All(o=>!o.IsDurable&&!o.IsPersistentHandle&&o.LeaseState==0&&o.OplockLevel==0),"no recovery/caching state");
        await c.CloseAsync((RawSmb.U64(r,128),RawSmb.U64(r,136)));
    }
    static async Task InvalidCombinationAsync() {
        await using var s=Builder(new FakeFileStore()).Build();await s.StartAsync();await using var c=await ConnectAsync(s,0x300);
        var b=Context("DH2Q",new byte[32],0,c); var first=(int)RawSmb.U32(b,112);var second=(b.Length+7)&~7;
        RawSmb.Put32(b,first,(uint)(second-first));Array.Resize(ref b,second+40);
        RawSmb.Put16(b,second+4,16);RawSmb.Put16(b,second+6,4);RawSmb.Put16(b,second+10,24);RawSmb.Put32(b,second+12,16);
        Encoding.ASCII.GetBytes("DHnQ").CopyTo(b,second+16);RawSmb.Put32(b,116,(uint)(b.Length-first));
        await c.ExchangeAsync(b,0xc000000d,9); Check.Equal(0,s.State.SessionGlobalList[c.Session].Opens.Count,"invalid contexts fail before acquisition");
    }
    static async Task ReconnectAsync(bool v2) {
        var store=new InMemoryDurableHandleStore();
        await using var s=Builder(new FakeFileStore()).UseDurableHandleStore(store).Build(); await s.StartAsync(); await using var c=await ConnectAsync(s,v2?(ushort)0x300:(ushort)0x210);
        var id=await c.CreateAsync("ctx"); var session=s.State.SessionGlobalList[c.Session]; var open=session.Opens[id];
        session.Opens.TryRemove(id,out _);
        store.Add(new DurableHandle {PersistentId=id.P,VolatileId=id.V,Open=open,OwnerKey=session.Identity!.UserSid ?? session.Identity.DomainName+"\\"+session.Identity.UserName,
            Deadline=DateTimeOffset.UtcNow.AddMinutes(1),CreateGuid=Guid.Empty});
        var data=new byte[v2?36:16];RawSmb.Put64(data,0,id.P);RawSmb.Put64(data,8,id.V);
        await c.ExchangeAsync(Context(v2?"DH2C":"DHnC",data,0,c),0xc0000034,9);
        Check.That(store.TryClaim(id.P,id.V,out _),"disabled reconnect must not consume supplied store record");
        await open.LocalOpen!.DisposeAsync();
    }
    static byte[] Ioctl(uint code, (ulong P,ulong V) id,WireClient c,byte[]? input=null) {
        input??=[]; var b=RawSmb.Header(11,56+Math.Max(1,input.Length),c.NextMessageId(),c.Session,c.Tree);RawSmb.Put16(b,64,57);
        RawSmb.Put32(b,68,code);RawSmb.Put64(b,72,id.P);RawSmb.Put64(b,80,id.V);RawSmb.Put32(b,88,120);RawSmb.Put32(b,92,(uint)input.Length);
        RawSmb.Put32(b,108,4096);RawSmb.Put32(b,112,1);input.CopyTo(b,120);return b;
    }
    static async Task IoctlAsync(uint code) {
        await using var s=Builder(new FakeFileStore()).Build(); await s.StartAsync(); await using var c=await ConnectAsync(s,0x300);
        var id=await c.CreateAsync("ctx");var input=new byte[56];
        if(code is 0x1440f2 or 0x1480f2) {
            var key=Enumerable.Range(1,24).Select(x=>(byte)x).ToArray();
            s.State.SessionGlobalList[c.Session].Opens[id].ResumeKey=key;key.CopyTo(input,0);
            RawSmb.Put32(input,24,1); RawSmb.Put32(input,48,1);
        }
        // Seed the source key directly so a disabled resume-key endpoint cannot mask a COPYCHUNK bypass.
        await c.ExchangeAsync(Ioctl(code,code==0x1401fc ? (ulong.MaxValue,ulong.MaxValue) : id,c,code==0x1401fc ? [] : input),0xc00000bb,9); await c.CloseAsync(id);
    }
    static async Task BindingAsync() {
        await using var s=Builder(new FakeFileStore()).Build();await s.StartAsync();await using var c=await ConnectAsync(s,0x300);
        var conn=s.State.SessionGlobalList[c.Session].Connection;
        var other=new Smb.Server.State.SmbConnection {Dialect=conn.Dialect,NegotiateDone=true,ClientGuid=conn.ClientGuid,SigningAlgorithmId=conn.SigningAlgorithmId};
        var b=RawSmb.SessionSetup(new NtlmClient(HostFixture.Domain,HostFixture.User,HostFixture.Password).BuildNegotiate(),0,c.Session);b[66]=1; RawSmb.Put32(b,16,8);
        Smb.Crypto.Smb2Signer.SignInPlace(Smb.Crypto.Smb2Signer.ResolveAlgorithm(conn.Dialect,conn.SigningAlgorithmId),s.State.SessionGlobalList[c.Session].SigningKey,b,0,false,false);
        var r=(await new Smb2Dispatcher(s.State).ProcessMessageAsync(other,b))!;
        Check.Equal(0xc00000d0u,RawSmb.U32(r,8),"disabled binding rejected before auth/binding state");
        Check.That(other.PendingBindings.IsEmpty&&other.Sessions.IsEmpty,"no binding state");
    }
    sealed class CountingOplocks : IOplockManager {
        public int Requests;
        public OplockGrant RequestOplock(Smb.Server.State.SmbOpen o,OplockLevel l) {Requests++;return new InMemoryOplockManager().RequestOplock(o,l);}
        public OplockLevel Acknowledge(Smb.Server.State.SmbOpen o,OplockLevel l)=>OplockLevel.None;
        public void ReleaseOwner(Smb.Server.State.SmbOpen o) { }
    }
    sealed class CountingLeases : ILeaseManager {
        public int Requests;
        public LeaseGrant RequestLease(Smb.Server.State.SmbOpen o,Smb.Protocol.Messages.LeaseRequest r) {Requests++;return new InMemoryLeaseManager().RequestLease(o,r);}
        public LeaseState Acknowledge(Smb.Protocol.Messages.LeaseKey k,LeaseState s)=>LeaseState.None;
        public void ReleaseOwner(Smb.Server.State.SmbOpen o) { }
        public IReadOnlyList<LeaseBreak> BreakDirectoryLease(string k)=>Array.Empty<LeaseBreak>();
    }
    sealed class CountingNetwork : Smb.Server.Multichannel.INetworkInterfaceProvider {
        public int Calls;
        public IReadOnlyList<Smb.Protocol.Messages.NetworkInterfaceInfo> GetInterfaces() { Calls++;return []; }
    }
    sealed class MutableShare(IFileStore store) : IShare {
        public string Name=>"P0";public ShareType Type=>ShareType.Disk; public IFileStore FileStore=>store;
        public bool EncryptData=>false;public bool ContinuousAvailability{get;set;} public string Remark=>"";
    }
    static async Task CustomManagersAsync() {
        var oplocks=new CountingOplocks();var leases=new CountingLeases();
        await using var s=Builder(new FakeFileStore()).Configure(o=>{o.LeaseManager=leases;o.OplockManager=oplocks;}).Build();await s.StartAsync();await using var c=await ConnectAsync(s);
        var r=await c.ExchangeAsync(Context(null,[],9,c),size:89);await c.CloseAsync((RawSmb.U64(r,128),RawSmb.U64(r,136)));
        var data=new byte[32];RawSmb.Put32(data,16,7);
        r=await c.ExchangeAsync(Context("RqLs",data,255,c),size:89);await c.CloseAsync((RawSmb.U64(r,128),RawSmb.U64(r,136)));
        Check.Equal(0,oplocks.Requests,"custom oplock manager cannot run grant path");Check.Equal(0,leases.Requests,"custom lease manager cannot run grant path");
    }
    static async Task CustomNetworkAsync() {
        var provider=new CountingNetwork();await using var s=Builder(new FakeFileStore()).UseNetworkInterfaceProvider(provider).Build();await s.StartAsync();await using var c=await ConnectAsync(s,0x300);
        s.State.Options.EnableMultichannel=true; // Runtime mutation cannot bypass the fixed policy.
        try {await c.ExchangeAsync(Ioctl(0x1401fc,(ulong.MaxValue,ulong.MaxValue),c),0xc00000bb,9);Check.Equal(0,provider.Calls,"disabled network provider not consulted");}
        finally {s.State.Options.EnableMultichannel=false;}
    }
    static async Task RuntimeCaCreateAsync() {
        var share=new MutableShare(new FakeFileStore());
        await using var s=Builder(new FakeFileStore()).Configure(o=>o.Shares.Add(share)).Build();await s.StartAsync();await using var c=await ConnectAsync(s,0x300);
        share.ContinuousAvailability=true;
        await c.ExchangeAsync(RawSmb.Create("ctx",false,c.NextMessageId(),c.Session,c.Tree),0xc00000bb,9);
    }
    static async Task RuntimeCaAsync() {
        await using var s=Builder(new FakeFileStore()).Build();await s.StartAsync();await using var c=await ConnectAsync(s,0x300);
        s.State.Shares.Add(new Share{Name="CA",FileStore=new FakeFileStore(),ContinuousAvailability=true});
        await c.ExchangeAsync(RawSmb.TreeConnect("\\\\localhost\\CA",c.NextMessageId(),c.Session),0xc00000bb,9);
    }
}
