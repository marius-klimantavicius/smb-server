using Smb.Testing;
using Smb.FileSystem;
using Smb.FileSystem.Local;
using Smb.Protocol.Messages;
using Smb.Server;
using Smb.Server.State;
using Smb.Server.Durable;
using Smb.Server.Locking;
using Smb.Server.Sharing;
using Smb.Protocol.Enums;

internal static class P7cTests
{
    public static IEnumerable<(string, Func<Task>)> Cases()
    {
        foreach(var test in P7cNetwork.Cases())yield return test;
        yield return ("p7c.records.zero-v2", Zero);
        yield return ("p7c.cache.shared-live-sender",SharedLiveLease);
        yield return ("p7c.replay.lease-response-version",LeaseReplayVersion);
        yield return ("p7c.replay.lease-breaking",LeaseBreaking);
        yield return ("p7c.reconnect.v1-name-status",V1Name);
        foreach(var duration in new[]{TimeSpan.Zero,TimeSpan.FromMilliseconds(-1),TimeSpan.MaxValue})yield return ("p7c.policy.timeout."+duration.Ticks,()=>TimeoutPolicy(duration,false));
        foreach(var duration in new[]{TimeSpan.Zero,TimeSpan.FromMilliseconds(-1),TimeSpan.MaxValue})yield return ("p7c.policy.maximum-timeout."+duration.Ticks,()=>TimeoutPolicy(duration,true));
        yield return ("p7c.stress.recovery",Stress);
        yield return ("p7c.registry.late-publish",RegistryLate);
        yield return ("p7c.reconnect.expiry-preparation",ExpiryPreparation);
        yield return ("p7c.replay-close.physical", ReplayClose);
        foreach(var mode in new[]{ "batch", "lease", "same-client-lease" })yield return ("p7c.cache.disconnected-"+mode,()=>CacheLoss(mode));
        foreach(var dialect in new ushort[]{0x300,0x302})foreach(var mode in new[]{ "v1", "v2", "lease1", "lease2", "expire", "shutdown", "replay-after-reconnect" })yield return ($"p7c.tcp.{dialect:x}.{mode}",()=>Tcp(dialect,mode));
        foreach(var mode in new[] { "active", "zero", "duplicate", "inflight", "failure", "owner", "session", "client", "lease", "close", "read", "write", "flush", "lock", "query", "set", "ioctl", "directory", "notify", "oplock-ack", "lease-ack" })
            yield return ("p7c.replay."+mode,()=>Replay(mode));
        foreach(var mode in new[] { "v1", "v2", "zero", "timeout", "persistent", "exclusive", "none", "directory", "legacy", "202", "210", "311" })
            yield return ("p7c.grant."+mode,()=>Grant(mode));
        foreach(var mode in new[] { "ok", "v1", "fault", "collision", "parallel", "wrong-guid", "owner", "active", "expired", "share", "lease-absent", "lease-key", "lease-name", "lease-version", "persistent", "cache-revoked" })
            yield return ("p7c.reconnect."+mode,()=>Reconnect(mode));
        foreach (var reason in new[] { "loss", "send", "expire", "physical", "revoke-physical", "close", "tree", "logoff", "shutdown" })
            yield return ("p7c.retention."+reason,()=>Retention(reason));
    }
    [System.Diagnostics.CodeAnalysis.DynamicDependency(System.Diagnostics.CodeAnalysis.DynamicallyAccessedMemberTypes.PublicProperties,typeof(SmbFeaturePolicy))]
    internal static SmbFeaturePolicy Profile(string name="Durable") => (SmbFeaturePolicy?)typeof(SmbFeaturePolicy).GetProperty(name)?.GetValue(null) ?? SmbFeaturePolicy.Caching;
    sealed class DurableFixture(IFileStore? store=null) : IAsyncDisposable
    {
        public readonly P2Tests.Direct Direct= new P2Tests.Direct(store);
        public async ValueTask DisposeAsync()
        {
            foreach(var connection in Direct.State.Connections.Values)
                await Direct.Dispatcher.OnConnectionClosedAsync(connection,Smb2Dispatcher.CloseReason.Shutdown);
            await Direct.Dispatcher.CloseRetainedHandlesAsync();
            Check.Equal(0,Direct.State.CreateReplays.Count,"fixture drains replay registry");
            Check.Equal(0,Direct.Options.CacheCoordinator.GrantCount,"fixture drains caching records");
        }
    }
    internal sealed class Root : IDisposable
    {
        public string Path { get; }=System.IO.Path.Combine(System.IO.Path.GetTempPath(),"smb-p7c-"+Guid.NewGuid());
        public Root()=>Directory.CreateDirectory(Path);
        public LocalFileStore Store() => new LocalFileStore(Path, false, null, exclusiveServerAccess: true);
        public void Dispose()=>Directory.Delete(Path,true);
    }
    internal static byte[] Context(byte[] request,string name,byte[] data)
    {
        var start=(request.Length+7)&~7;var total=(24+data.Length+7)&~7;
        var previous=(int)RawSmb.U32(request,112);
        if(previous!=0) { while(RawSmb.U32(request,previous)!=0)previous+=(int)RawSmb.U32(request,previous);RawSmb.Put32(request,previous,(uint)(start-previous)); }
        Array.Resize(ref request,start+total);RawSmb.Put16(request,start+4,16);RawSmb.Put16(request,start+6,4);RawSmb.Put16(request,start+10,24);RawSmb.Put32(request,start+12,(uint)data.Length);
        System.Text.Encoding.ASCII.GetBytes(name).CopyTo(request,start+16);data.CopyTo(request,start+24);
        if(previous==0)RawSmb.Put32(request,112,(uint)start);RawSmb.Put32(request,116,(uint)(request.Length-RawSmb.U32(request,112)));return request;
    }
    internal static byte[] Request(string path,Guid guid,bool v1=false,byte level=9,uint timeout=2000)
    {
        var b=RawSmb.Create(path,false,0,1,42);b[67]=level;return Context(b,v1?"DHnQ":"DH2Q",v1?new byte[16]:DurableHandleMessages.BuildV2RequestData(timeout,guid,false));
    }
    internal static byte[] Lease(byte[] request,ulong key=1,bool v2=false)
    { request[67]=255;var data=new byte[v2?52:32];RawSmb.Put64(data,0,key);RawSmb.Put64(data,8,2);RawSmb.Put32(data,16,7);return Context(request,"RqLs",data); }
    static void Status(byte[] response,NtStatus status,string why)=>Check.Equal((uint)status,RawSmb.U32(response,8),why);
    internal static (ulong P,ulong V) Id(byte[] response)=>(RawSmb.U64(response,128),RawSmb.U64(response,136));
    static byte[]? ResponseContext(byte[] response,string name)
    {
        var at=(int)RawSmb.U32(response,144);while(at!=0&&at<response.Length) { if(System.Text.Encoding.ASCII.GetString(response,at+RawSmb.U16(response,at+4),RawSmb.U16(response,at+6))==name)return response.AsSpan(at+RawSmb.U16(response,at+10),(int)RawSmb.U32(response,at+12)).ToArray();var next=(int)RawSmb.U32(response,at);if(next==0)break;at+=next; }return null;
    }
    static async Task Grant(string mode)
    {
        using var root=new Root();await using var fixture=new DurableFixture(mode=="legacy"?null:root.Store());var d=fixture.Direct;d.Options.FeaturePolicy=Profile();d.Connection.Dialect=mode switch { "202"=>SmbDialect.Smb202,"210"=>SmbDialect.Smb210,"311"=>SmbDialect.Smb311,_=>SmbDialect.Smb300 };
        var v1=mode=="v1";var guid=mode=="zero"?Guid.Empty:Guid.NewGuid();var req=Request("a",guid,v1,mode=="exclusive"?(byte)8:mode=="none"?(byte)0:(byte)9,mode=="timeout"?900000u:2000);
        if(mode=="directory")RawSmb.Put32(req,104,1);
        if(mode=="persistent")RawSmb.Put32(req,(int)RawSmb.U32(req,112)+28,2);
        var response=await d.Send(req);Status(response,NtStatus.Success,"valid request");
        var ctx=ResponseContext(response,v1?"DHnQ":"DH2Q");
        if(mode is "exclusive" or "none" or "directory" or "legacy" or "202" or "210" or "311") { Check.That(ctx==null,"ineligible durable context withheld");return; }
        Check.That(ctx!=null,"eligible file receives durable response");var open=d.Session.Opens[Id(response)];Check.That(open.IsDurable&&!open.IsPersistentHandle,"basic durability without persistence");
        if(!v1) { Check.Equal(mode=="timeout"?300000u:2000u,RawSmb.U32(ctx!,0),"specified bounded timeout");Check.Equal(0u,RawSmb.U32(ctx!,4),"no persistent flag on ordinary share"); }
        await d.Send(RawSmb.Close(Id(response),0,1,42));
    }
    static async Task Replay(string mode)
    {
        using var root=new Root();await using var fixture=new DurableFixture(root.Store());var d=fixture.Direct;d.Options.FeaturePolicy=Profile();d.Connection.Dialect=SmbDialect.Smb300;d.Connection.ServerCapabilities|=Smb2Capabilities.Leasing;
        var guid=mode=="zero"?Guid.Empty:Guid.NewGuid();File.WriteAllText(root.Path+"/a","original");
        byte[] Req() { var r=Request("a",guid);RawSmb.Put32(r,100,5);return mode is "lease" or "lease-ack"?Lease(r):r; }
        var original=Req();byte[] first;
        if(mode is "inflight" or "failure") {
            // Hold response preparation after the first destructive acquisition. The duplicate must wait.
            var gate=new AsyncBarrier();var held=root.Store();
            var wrapper=new PausedStore(held,gate,mode=="failure");
            var replacement=new SmbTreeConnect { TreeId=42,Session=d.Session,Share=new Share { Name="P0",FileStore=wrapper },MaximalAccess=0x1f01ff };d.Session.TreeConnects[42]=replacement;
            var winner=d.Send(original);await gate.Entered.WaitAsync(Check.Timeout);
            var retry=Req();RawSmb.Put32(retry,16,0x20000000);var loser=d.Send(retry);
            try { Check.Equal(1,wrapper.Creates,"duplicate cannot acquire backend while winner prepares response"); }
            finally { gate.Release(); }
            first=await winner.WaitAsync(Check.Timeout);var second=await loser.WaitAsync(Check.Timeout);
            if(mode=="failure") { Check.That(RawSmb.U32(first,8)!=0,"first provisional winner failed");Status(second,NtStatus.Success,"failed arbitration owner permits valid retry");Check.Equal(2,wrapper.Creates,"one retry after provisional failure"); }
            else { Status(first,NtStatus.Success,"winner success");Status(second,NtStatus.Success,"inflight replay success");Check.Equal(Id(first),Id(second),"inflight replay result");Check.Equal(1,wrapper.Creates,"one backend acquisition"); }
            return;
        }
        first=await d.Send(original);Status(first,NtStatus.Success,"initial CREATE");var id=Id(first);var open=d.Session.Opens[id];
        // Mutate using the retained handle directly: replaying the truncating disposition must not erase it.
        await ((IFileStore)d.Tree.Share.FileStore!).WriteAsync(open.LocalOpen!,0,new byte[]{99});
        if(mode=="owner")d.Session.Identity=new Smb.Auth.SecurityIdentity { UserName="other",DomainName="other" };
        if(mode=="client")d.Connection.ClientGuid=Guid.NewGuid().ToByteArray();
        if(mode=="close")await d.Send(RawSmb.Close(id,0,1,42));
        if(mode is "read" or "write" or "flush" or "lock" or "query" or "set" or "ioctl" or "directory" or "notify" or "oplock-ack" or "lease-ack") {
            var command=mode switch {
                "read"=>RawSmb.Read(id,1,0,0,1,42),"write"=>RawSmb.Write(id,new byte[]{88},0,0,1,42),
                "flush"=>RawSmb.Header(7,24,0,1,42),"lock"=>RawSmb.Header(10,48,0,1,42),
                "query"=>RawSmb.Header(16,40,0,1,42),"set"=>RawSmb.Header(17,32,0,1,42),"directory"=>RawSmb.Header(14,32,0,1,42),"notify"=>RawSmb.Header(15,32,0,1,42),"oplock-ack"=>RawSmb.Header(18,24,0,1,42),"lease-ack"=>P6Tests.LeaseAck(new LeaseKey(1,2)),_=>RawSmb.Header(11,56,0,1,42) };
            if(mode is "directory" or "notify" or "oplock-ack") { RawSmb.Put16(command,64,mode=="directory"?(ushort)33:mode=="notify"?(ushort)32:(ushort)24);RawSmb.Put64(command,72,id.P);RawSmb.Put64(command,80,id.V);if(mode=="directory") {command[66]=1;RawSmb.Put32(command,92,1024);}if(mode=="notify")RawSmb.Put32(command,68,1024); }
            if(mode=="flush") { RawSmb.Put16(command,64,24);RawSmb.Put64(command,72,id.P);RawSmb.Put64(command,80,id.V); }
            if(mode=="lock") { RawSmb.Put16(command,64,48);RawSmb.Put16(command,66,1);RawSmb.Put64(command,72,id.P);RawSmb.Put64(command,80,id.V);RawSmb.Put64(command,96,1);RawSmb.Put32(command,104,0x12); }
            if(mode=="query") { RawSmb.Put16(command,64,41);command[66]=1;command[67]=4;RawSmb.Put32(command,68,40);RawSmb.Put64(command,88,id.P);RawSmb.Put64(command,96,id.V); }
            if(mode=="set") { Array.Resize(ref command,104);RawSmb.Put16(command,64,33);command[66]=1;command[67]=14;RawSmb.Put32(command,68,8);RawSmb.Put16(command,72,96);RawSmb.Put64(command,80,id.P);RawSmb.Put64(command,88,id.V); }
            if(mode=="ioctl") { RawSmb.Put16(command,64,57);RawSmb.Put32(command,68,0x140078);RawSmb.Put64(command,72,id.P);RawSmb.Put64(command,80,id.V);RawSmb.Put32(command,108,2); }
            var r=await d.Send(command);Console.WriteLine($"invalidation {mode} command status={RawSmb.U32(r,8):x8}");
        }
        var replay=Req();if(mode!="duplicate")RawSmb.Put32(replay,16,0x20000000);
        if(mode=="lease") { replay=Request("a",guid);RawSmb.Put32(replay,16,0x20000000);replay=Lease(replay,9); }
        byte[] result;
        SmbSession? other=null;
        try {
            if(mode=="session") { other=NewSession(d);RawSmb.Put64(replay,40,2);RawSmb.Put32(replay,36,43);result=await d.Send(replay,other.Connection); }
            else result=await d.Send(replay);
            if(mode=="duplicate") { Status(result,(NtStatus)0xc000022a,"non-replay duplicate GUID");return; }
            if(mode is "owner" or "lease") { Status(result,NtStatus.AccessDenied,"replay owner and lease checks");return; }
            if(mode=="session") { Status(result,(NtStatus)0xc000022a,"nonpersistent replay cannot transplant to new session");return; }
            Status(result,NtStatus.Success,"eligible replay or new execution");
            if(mode is "close" or "read" or "write" or "flush" or "lock" or "query" or "set" or "ioctl" or "directory" or "notify" or "oplock-ack" or "lease-ack" or "client")Check.That(Id(result)!=id,"invalidation or client scope executes a new CREATE");
            else { Check.Equal(id,Id(result),"eligible replay returns original IDs");Check.Equal((byte)99,NativeHost.ReadAllBytes(root.Path+"/a")[0],"replay never truncates twice");Check.Equal(1,d.Session.Opens.Count,"one acquired open"); }
        } finally { if(other!=null)await d.Dispatcher.OnConnectionClosedAsync(other.Connection,Smb2Dispatcher.CloseReason.Shutdown); }
    }
    static Task TimeoutPolicy(TimeSpan duration,bool maximum)
    {
        var options=new SmbServerOptions { FeaturePolicy=Profile(),DurableHandleTimeout=duration };
        if(maximum) { options.DurableHandleTimeout=TimeSpan.FromSeconds(60);options.MaxDurableHandleTimeout=duration; }
        var rejected=false;try { options.FeaturePolicy.Validate(options); }catch(InvalidOperationException){rejected=true;}
        Check.That(rejected,"durable profile rejects unusable retention deadline");return Task.CompletedTask;
    }
    static async Task LeaseBreaking()
    {
        using var root=new Root();await using var fixture=new DurableFixture(root.Store());var d=fixture.Direct;d.Options.FeaturePolicy=Profile();d.Connection.Dialect=SmbDialect.Smb300;d.Connection.ServerCapabilities|=Smb2Capabilities.Leasing;d.Session.TryAttachChannel(new SmbChannel{Connection=d.Connection,SigningKey=d.Session.SigningKey});new RecordingTransport().Attach(d.Connection);
        var guid=Guid.NewGuid();var first=await d.Send(Lease(Request("a",guid),1,true));var open=d.Session.Opens[Id(first)];var other=NewSession(d);other.Connection.ClientGuid=Guid.NewGuid().ToByteArray();
        var foreign=new SmbOpen { VolatileFileId=99,Session=other,TreeConnect=other.TreeConnects[43],LocalOpen=open.LocalOpen };var wait=d.Options.CacheCoordinator.AcquireAsync(new[]{new FileIoRange(foreign,0,1,true)}).AsTask();
        try { Check.That(d.Options.CacheCoordinator.IsBreaking(open),"independent conflict establishes pending lease break");var replay=Lease(Request("a",guid),1,true);RawSmb.Put32(replay,16,0x20000000);var result=await d.Send(replay);Status(result,NtStatus.Success,"replay during break");Check.That((RawSmb.U32(ResponseContext(result,"RqLs")!,20)&2)!=0,"replay reports common coordinator break-in-progress"); }
        finally { d.Options.CacheCoordinator.Acknowledge(d.Connection,open.LeaseKey,LeaseState.None,out _);using var scope=await wait.WaitAsync(Check.Timeout);await d.Dispatcher.OnConnectionClosedAsync(other.Connection,Smb2Dispatcher.CloseReason.Shutdown); }
    }
    static async Task LeaseReplayVersion()
    {
        using var root=new Root();await using var fixture=new DurableFixture(root.Store());var d=fixture.Direct;d.Options.FeaturePolicy=Profile();d.Connection.Dialect=SmbDialect.Smb300;d.Connection.ServerCapabilities|=Smb2Capabilities.Leasing;
        var guid=Guid.NewGuid();var first=await d.Send(Lease(Request("a",guid),1,true));Status(first,NtStatus.Success,"v2 lease CREATE");var ctx=ResponseContext(first,"RqLs")!;Check.Equal(52,ctx.Length,"v2 lease wire response fixture");
        var replay=Lease(Request("a",guid),1,false);RawSmb.Put32(replay,16,0x20000000);var result=await d.Send(replay);Status(result,NtStatus.Success,"matching lease key replay");Check.Equal(52,ResponseContext(result,"RqLs")!.Length,"replay reconstructs retained lease version");
    }
    static async Task V1Name()
    {
        using var root=new Root();await using var fixture=new DurableFixture(root.Store());var d=fixture.Direct;d.Options.FeaturePolicy=Profile();d.Connection.Dialect=SmbDialect.Smb300;d.Connection.ServerCapabilities|=Smb2Capabilities.Leasing;
        var first=await d.Send(Lease(Request("a",Guid.NewGuid(),true)));var id=Id(first);await d.Dispatcher.OnConnectionClosedAsync(d.Connection);var session=NewSession(d);
        try { var req=Lease(Context(RawSmb.Create("wrong",false,1,2,43),"DHnC",DurableHandleMessages.BuildReconnectData(id.P,id.V)));Status(await d.Send(req,session.Connection),NtStatus.InvalidParameter,"v1 reconnect name validation precedes eligibility error"); }
        finally { await d.Dispatcher.OnConnectionClosedAsync(session.Connection,Smb2Dispatcher.CloseReason.Shutdown);await d.Dispatcher.CloseRetainedHandlesAsync(); }
    }
    static async Task Stress()
    {
        for(var i=0;i<16;i++) {
            using var root=new Root();await using var host=HostFixture.Build(root.Store(),0,HostFixture.Domain,HostFixture.User,HostFixture.Password);var options=host.State.Options;options.FeaturePolicy=Profile();var metrics=new ClosedMetrics();options.Metrics=metrics;await host.StartAsync();var a=new WireClient();await a.ConnectAsync(host.Endpoint,HostFixture.Domain,HostFixture.User,HostFixture.Password,0x300);
            var guid=i%2==0?Guid.Empty:Guid.NewGuid();var first=await a.ExchangeAsync(Wire(Request("a",guid),a));var original=Id(first);var open=host.State.SessionGlobalList[a.Session].Opens[original];await a.DisposeAsync();await metrics.Closed.Task.WaitAsync(Check.Timeout);
            await using var b=new WireClient();await b.ConnectAsync(host.Endpoint,HostFixture.Domain,HostFixture.User,HostFixture.Password,0x300);var request=Context(RawSmb.Create("a",false,0,0,0),"DH2C",DurableHandleMessages.BuildV2ReconnectData(original.P,original.V,guid,false));var response=await b.ExchangeAsync(Wire(request,b));await b.WriteAsync(Id(response),new byte[]{(byte)i});await b.CloseAsync(Id(response));await host.StopAsync(TimeSpan.Zero);
            Check.Equal("Closed",open.Lifetime.State.ToString(),"stress terminal open");Check.Equal(0,host.State.CreateReplays.Count,"stress replay registry");Check.Equal(0,options.DurableHandleStore.TakeAll().Count,"stress retained records");Check.Equal(0,options.CacheCoordinator.GrantCount,"stress grants");Check.Equal(0,options.CacheCoordinator.BreakingCount,"stress breaks");Check.Equal(0,options.CacheCoordinator.PhysicalScopeCount,"stress physical scopes");Check.Equal(0,options.CacheCoordinator.NamespaceScopeCount,"stress namespace scopes");Check.Equal(0,((InMemoryLockManager)options.LockManager).ActiveLockCount,"stress locks");Check.Equal(0,((InMemoryShareModeManager)options.ShareModeManager).ReservationCount,"stress shares");Check.Equal(0L,metrics.OpenHandles,"stress counts");Check.Equal(0,Smb2Dispatcher.ActiveNamespaceCount,"stress namespace keys");
        }
    }
    static async Task SharedLiveLease()
    {
        using var root=new Root();await using var fixture=new DurableFixture(root.Store());var d=fixture.Direct;d.Options.FeaturePolicy=Profile();d.Connection.Dialect=SmbDialect.Smb300;d.Connection.ServerCapabilities|=Smb2Capabilities.Leasing;
        var first=await d.Send(Lease(Request("a",Guid.NewGuid())));var retained=d.Session.Opens[Id(first)];await d.Dispatcher.OnConnectionClosedAsync(d.Connection);
        var live=NewSession(d);var transport=new RecordingTransport();transport.Attach(live.Connection);
        var joined=await d.Send(Lease(RawSmb.Create("a",false,1,2,43)),live.Connection);Status(joined,NtStatus.Success,"live open joins retained same-client lease");var active=live.Opens[Id(joined)];Check.Equal(LeaseState.ReadWriteHandle,active.LeaseState,"shared lease held");
        var foreign=new SmbOpen { VolatileFileId=99,Session=live,TreeConnect=live.TreeConnects[43],LocalOpen=active.LocalOpen };
        var conflict=d.Options.CacheCoordinator.AcquireAsync(new[]{new FileIoRange(foreign,0,1,true)}).AsTask();
        try { Check.That(!conflict.IsCompleted,"retiring disconnected lease owner cannot revoke live client's unacknowledged rights");Check.That(transport.Sends.Any(send=>RawSmb.U16(send.Message,64)==44),"break delivered to live lease owner");Check.Equal(LeaseState.ReadWriteHandle,active.LeaseState,"live caching promise held until ACK"); }
        finally { d.Options.CacheCoordinator.Acknowledge(live.Connection,active.LeaseKey,LeaseState.None,out _);using var scope=await conflict.WaitAsync(Check.Timeout);await d.Dispatcher.OnConnectionClosedAsync(live.Connection,Smb2Dispatcher.CloseReason.Shutdown); }
        Check.Equal("Closed",retained.Lifetime.State.ToString(),"unreachable old open closed");
    }
    static async Task RegistryLate()
    {
        var registry=new CreateReplayRegistry();var client=Guid.NewGuid();var create=Guid.NewGuid();var open=new SmbOpen { VolatileFileId=1,DurableClientGuid=client,DurableCreateGuid=create,IsReplayEligible=true };open.Lifetime.Activate();
        using(var reservation=await registry.EnterAsync(client,create,default)) {
            open.Lifetime.BeginClose(out _);registry.Retire(open);open.IsReplayEligible=false;open.Lifetime.CompleteClose();reservation.Open=open;
        }
        Check.Equal(0,registry.Count,"late publication cannot resurrect terminal CREATE replay record");
    }
    static async Task ExpiryPreparation()
    {
        using var root=new Root();await using var fixture=new DurableFixture(root.Store());var d=fixture.Direct;d.Options.FeaturePolicy=Profile();d.Connection.Dialect=SmbDialect.Smb300;var clock=new ManualClock();d.Options.TimeProvider=clock;
        var guid=Guid.NewGuid();var first=await d.Send(Request("a",guid));var open=d.Session.Opens[Id(first)];await d.Dispatcher.OnConnectionClosedAsync(d.Connection);
        var session=NewSession(d);var barrier=new AsyncBarrier();var handle=new FaultHandle(open.LocalOpen!){Barrier=barrier};open.LocalOpen=handle;
        var request=Context(RawSmb.Create("a",false,1,2,43),"DH2C",DurableHandleMessages.BuildV2ReconnectData(open.PersistentFileId,open.VolatileFileId,guid,false));
        var reconnect=d.Send(request,session.Connection);await barrier.Entered.WaitAsync(Check.Timeout);clock.Advance(TimeSpan.FromSeconds(3));var started=new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously);
        var expiry=Task.Run(()=> { started.SetResult();d.Dispatcher.ScavengeDurableHandles(); });await started.Task.WaitAsync(Check.Timeout);
        try { await Task.WhenAny(expiry,Task.Delay(150));Check.That(!expiry.IsCompleted&&!handle.Disposed,"expiry cannot dispose during reconnect metadata preparation"); }
        finally { barrier.Release();await reconnect.WaitAsync(Check.Timeout);await expiry.WaitAsync(Check.Timeout);await d.Dispatcher.OnConnectionClosedAsync(session.Connection,Smb2Dispatcher.CloseReason.Shutdown); }
        Check.Equal("Closed",open.Lifetime.State.ToString(),"expiry wins unpublished reconnect");Check.That(session.Opens.IsEmpty,"expired reconnect cannot publish");
    }
    static async Task ReplayClose()
    {
        using var root=new Root();await using var fixture=new DurableFixture(root.Store());var d=fixture.Direct;d.Options.FeaturePolicy=Profile();d.Connection.Dialect=SmbDialect.Smb300;
        var guid=Guid.NewGuid();var first=await d.Send(Request("a",guid));Status(first,NtStatus.Success,"initial durable CREATE");var id=Id(first);var open=d.Session.Opens[id];var inner=open.LocalOpen!;
        var gate=new AsyncBarrier();open.LocalOpen=new FaultHandle(inner){Barrier=gate};var replay=Request("a",guid);RawSmb.Put32(replay,16,0x20000000);
        var retry=d.Send(replay);await gate.Entered.WaitAsync(Check.Timeout);var close=d.Send(RawSmb.Close(id,0,1,42));
        try { Check.That(!close.IsCompleted,"CLOSE drains replay response preparation before disposal"); }
        finally { gate.Release();await retry.WaitAsync(Check.Timeout);await close.WaitAsync(Check.Timeout); }
    }
    static async Task CacheLoss(string mode)
    {
        using var root=new Root();await using var fixture=new DurableFixture(root.Store());var d=fixture.Direct;d.Options.FeaturePolicy=Profile();d.Connection.Dialect=SmbDialect.Smb300;d.Connection.ServerCapabilities|=Smb2Capabilities.Leasing;
        var clock=new ManualClock();d.Options.TimeProvider=clock;
        var req=Request("a",Guid.NewGuid());if(mode!="batch")req=Lease(req);
        var result=await d.Send(req);Status(result,NtStatus.Success,"eligible grant");var open=d.Session.Opens[Id(result)];
        await d.Dispatcher.OnConnectionClosedAsync(d.Connection);
        var other=NewSession(d);if(mode!="same-client-lease")other.Connection.ClientGuid=Guid.NewGuid().ToByteArray();
        try {
            var conflict=RawSmb.Create("a",false,1,2,43);RawSmb.Put32(conflict,100,5);if(mode=="same-client-lease")conflict=Lease(conflict);
            var response=await d.Send(conflict,other.Connection);if(RawSmb.U32(response,8)==0x103){var pending=other.Connection.PendingRequests.Values.Single();await pending.Finished.WaitAsync(Check.Timeout);Check.Equal(NtStatus.Success,pending.FinalStatus,"disconnected conflict final");}else Status(response,NtStatus.Success,"disconnected cache owner cannot block destructive CREATE");
            if(mode=="same-client-lease") { Check.Equal("Disconnected",open.Lifetime.State.ToString(),"same-client lease shares existing grant");Check.Equal(LeaseState.ReadWriteHandle,open.LeaseState,"joining same lease preserves granted rights");clock.Advance(TimeSpan.FromSeconds(3));d.Dispatcher.ScavengeDurableHandles();return; }
            Check.Equal("Closed",open.Lifetime.State.ToString(),"failed disconnected break closes durable open");Check.Equal(0,d.Options.DurableHandleStore.TakeAll().Count,"break removes retained record");
        } finally { await d.Dispatcher.OnConnectionClosedAsync(other.Connection,Smb2Dispatcher.CloseReason.Shutdown); }
    }
    internal sealed class ClosedMetrics : Smb.Server.Diagnostics.SmbServerMetrics
    {
        public readonly TaskCompletionSource Closed= new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously);
        public override void OnSessionClosed(){base.OnSessionClosed();Closed.TrySetResult();}
    }
    internal static byte[] Wire(byte[] request,WireClient c) { RawSmb.Put64(request,24,c.NextMessageId());RawSmb.Put64(request,40,c.Session);RawSmb.Put32(request,36,c.Tree);return request; }
    static async Task Tcp(ushort dialect,string mode)
    {
        using var root=new Root();await using var host=HostFixture.Build(root.Store(),0,HostFixture.Domain,HostFixture.User,HostFixture.Password);
        var options=host.State.Options;options.FeaturePolicy=Profile();var metrics=new ClosedMetrics();options.Metrics=metrics;var clock=new ManualClock();options.TimeProvider=clock;
        await host.StartAsync();var a=new WireClient();await a.ConnectAsync(host.Endpoint,HostFixture.Domain,HostFixture.User,HostFixture.Password,dialect);
        var guid=Guid.NewGuid();var req=Request("a",guid,mode=="v1");if(mode.StartsWith("lease"))req=Lease(req,1,mode=="lease2");
        var first=await a.ExchangeAsync(Wire(req,a),size:89);var id=Id(first);var session=host.State.SessionGlobalList[a.Session];var open=session.Opens[id];Check.That(open.IsDurable,"actual TCP durable grant");var handle=open.LocalOpen;var tree=open.TreeConnect!;
        if(mode!="replay-after-reconnect")await a.WriteAsync(id,new byte[]{7});var dispatcher=new Smb2Dispatcher(host.State);
        await a.DisposeAsync();await metrics.Closed.Task.WaitAsync(Check.Timeout);Check.That(open.Session==null&&session.Opens.IsEmpty,"real final transport loss detaches");Check.Equal(0,tree.OpenCount,"old tree count zero");
        if(mode=="shutdown") { await host.StopAsync(TimeSpan.Zero);Check.Equal("Closed",open.Lifetime.State.ToString(),"host shutdown drains retained records");Check.Equal(0L,metrics.OpenHandles,"shutdown metric");return; }
        if(mode=="expire") { clock.Advance(TimeSpan.FromSeconds(2));dispatcher.ScavengeDurableHandles();Check.Equal("Closed",open.Lifetime.State.ToString(),"actual TCP durable expiry");return; }
        await using var b=new WireClient();await b.ConnectAsync(host.Endpoint,HostFixture.Domain,HostFixture.User,HostFixture.Password,dialect);
        var reconnect=Context(RawSmb.Create("a",false,0,b.Session,b.Tree),mode=="v1"?"DHnC":"DH2C",mode=="v1"?DurableHandleMessages.BuildReconnectData(id.P,id.V):DurableHandleMessages.BuildV2ReconnectData(id.P,id.V,guid,false));if(mode.StartsWith("lease"))reconnect=Lease(reconnect,1,mode=="lease2");
        var response=await b.ExchangeAsync(Wire(reconnect,b),size:89);var restored=Id(response);Check.That(restored.V!=id.V,"wire volatile ID renewed");Check.That(ReferenceEquals(open,host.State.SessionGlobalList[b.Session].Opens[restored])&&ReferenceEquals(handle,open.LocalOpen),"TCP reconnect retains actual open");if(mode=="replay-after-reconnect") { var replay=Request("wrong-path",guid);RawSmb.Put32(replay,16,0x20000000);var repeated=await b.ExchangeAsync(Wire(replay,b));Check.Equal(restored,Id(repeated),"replay after reconnect uses attached session and actual retained open");await b.WriteAsync(restored,new byte[]{7}); }
        Check.Equal((byte)7,(await b.ReadAsync(restored,1))[0],"same retained bytes");await b.CloseAsync(restored);Check.Equal(0L,metrics.OpenHandles,"TCP cleanup metric");
    }
    internal sealed class PausedStore(IFileStore inner,AsyncBarrier gate,bool fail) : IFileStore,ICacheCoherentFileStore
    {
        public int Creates;public bool HasExclusiveServerAccess=>true;
        public ValueTask<FileIdentity?> ResolveIdentityAsync(string p,string stream="",CancellationToken ct=default)=>((IFileIdentityStore)inner).ResolveIdentityAsync(p,stream,ct);
        public async ValueTask<FileStoreResult<FileCreateResult>> CreateAsync(string p,FileAccessIntent a,CreateDispositionIntent d,bool dir,bool non,CancellationToken ct=default) { Interlocked.Increment(ref Creates);var r=await inner.CreateAsync(p,a,d,dir,non,ct);if(Creates==1&&r.IsSuccess)return FileStoreResult<FileCreateResult>.Ok(new FileCreateResult(new FaultHandle(r.Value.Handle){Barrier=gate,Fail=fail},r.Value.Action));return r; }
        public ValueTask<FileStoreResult<int>> ReadAsync(IFileHandle h,long o,Memory<byte> b,CancellationToken ct=default)=>inner.ReadAsync(h,o,b,ct);
        public ValueTask<FileStoreResult<int>> WriteAsync(IFileHandle h,long o,ReadOnlyMemory<byte> b,CancellationToken ct=default)=>inner.WriteAsync(h,o,b,ct);
        public ValueTask<FileStoreResult<IReadOnlyList<FileEntryInfo>>> QueryDirectoryAsync(IFileHandle h,string p,CancellationToken ct=default)=>inner.QueryDirectoryAsync(h,p,ct);
        public ValueTask<NtStatus> SetEndOfFileAsync(IFileHandle h,long n,CancellationToken ct=default)=>inner.SetEndOfFileAsync(h,n,ct);
        public ValueTask<NtStatus> RenameAsync(IFileHandle h,string p,bool r,CancellationToken ct=default)=>inner.RenameAsync(h,p,r,ct);
        public ValueTask<NtStatus> SetDeleteOnCloseAsync(IFileHandle h,bool b,CancellationToken ct=default)=>inner.SetDeleteOnCloseAsync(h,b,ct);
        public ValueTask<NtStatus> FlushAsync(IFileHandle h,CancellationToken ct=default)=>inner.FlushAsync(h,ct);
    }
    sealed class FaultHandle(IFileHandle inner) : IFileHandle
    {
        public bool Fail;public bool Disposed;public AsyncBarrier? Barrier;
        public FileIdentity? Identity=>inner.Identity;public string Path=>inner.Path;public string? PhysicalPath=>inner.PhysicalPath;public bool IsDirectory=>inner.IsDirectory;public bool DeletePending=>inner.DeletePending;
        public FileEntryInfo GetInfo()=>inner.GetInfo();
        public async ValueTask<FileEntryInfo> GetInfoAsync(CancellationToken ct=default) { if(Barrier is { } gate)await gate.WaitAsync(ct);if(Fail)throw new IOException("reconnect preparation fault");return await inner.GetInfoAsync(ct); }
        public void Dispose(){Disposed=true;inner.Dispose();}public ValueTask DisposeAsync(){Disposed=true;return inner.DisposeAsync();}public ValueTask<NtStatus> CloseAsync()=>inner.CloseAsync();
    }
    static SmbSession NewSession(P2Tests.Direct d)
    {
        var c=d.Channel();c.Dialect=SmbDialect.Smb300;c.ServerCapabilities=d.Connection.ServerCapabilities;c.ClientGuid=d.Connection.ClientGuid.ToArray();
        var session=new SmbSession { SessionId=2,SessionGlobalId=2,Connection=c,State=SessionState.Valid,SigningRequired=true,SigningKey=new byte[16],SessionKey=new byte[16],Identity=d.Session.Identity };
        d.State.Connections.TryAdd(c.ConnectionId,c);d.State.SessionGlobalList.TryAdd(2,session);session.TryAttachChannel(new SmbChannel { Connection=c,SigningKey=session.SigningKey });d.Options.Metrics.OnAuthenticationSucceeded();
        session.TreeConnects.TryAdd(43,new SmbTreeConnect { Session=session,TreeId=43,Share=d.Tree.Share,MaximalAccess=d.Tree.MaximalAccess });d.Options.Metrics.OnTreeConnected();return session;
    }
    static async Task Reconnect(string mode)
    {
        using var root=new Root();await using var fixture=new DurableFixture(root.Store());var d=fixture.Direct;d.Options.FeaturePolicy=Profile();d.Connection.Dialect=SmbDialect.Smb300;d.Connection.ServerCapabilities|=Smb2Capabilities.Leasing;
        var clock=new ManualClock();d.Options.TimeProvider=clock;var id=await d.Open();var open=d.Session.Opens[id];var handle=open.LocalOpen;
        // Seed a pre-existing promise so reconnect RED is independent of profile/grant bootstrap.
        open.IsDurable=true;open.DurableTimeout=TimeSpan.FromSeconds(2);open.OplockLevel=OplockLevel.Batch;open.DurableCreateGuid=Guid.NewGuid();open.DurableIsV2=mode!="v1";
        typeof(SmbOpen).GetField("DurableShare",System.Reflection.BindingFlags.Instance|System.Reflection.BindingFlags.NonPublic)!.SetValue(open,d.Tree.Share);
        var leased=mode.StartsWith("lease-");if(leased) { open.LeaseKey=new LeaseKey(1,2);var grant=d.Options.CacheCoordinator.RequestLease(open,new LeaseRequest { Key=open.LeaseKey,RequestedState=LeaseState.ReadWriteHandle });Check.Equal(LeaseState.ReadWriteHandle,grant.GrantedState,"seed held lease");open.OplockLevel=OplockLevel.Lease; }
        // Capture scope explicitly while session is still attached, then detach through existing state.
        var record=new DurableHandle { PersistentId=id.P,VolatileId=id.V,Open=open,OwnerKey="<none>",ClientGuid=new Guid(d.Connection.ClientGuid),CreateGuid=open.DurableCreateGuid,Deadline=clock.GetUtcNow()+TimeSpan.FromSeconds(2) };
        if(mode!="active") { d.Session.Opens.TryRemove(id,out _);Interlocked.Decrement(ref d.Tree.OpenCount);typeof(SmbOpen).GetField("Counted",System.Reflection.BindingFlags.Instance|System.Reflection.BindingFlags.NonPublic)!.SetValue(open,false);open.Session=null;open.TreeConnect=null;var life=open.Lifetime;life.GetType().GetMethod("BeginDisconnect")?.Invoke(life,new object?[]{null});life.GetType().GetMethod("CompleteDisconnect")?.Invoke(life,null); }
        d.Options.DurableHandleStore.Add(record);
        var session=NewSession(d);var tree=session.TreeConnects[43];if(mode=="share") { session.TreeConnects[43]=tree=new SmbTreeConnect { TreeId=43,Session=session,Share=new Share { Name="foreign",FileStore=root.Store() },MaximalAccess=0x1f01ff }; }
        var req=Context(RawSmb.Create("a",false,0,2,43),mode=="v1"?"DHnC":"DH2C",mode=="v1"?DurableHandleMessages.BuildReconnectData(id.P,id.V):DurableHandleMessages.BuildV2ReconnectData(id.P,id.V,mode=="wrong-guid"?Guid.NewGuid():open.DurableCreateGuid,mode=="persistent"));
        if(leased&&mode!="lease-absent")req=Lease(req,mode=="lease-key"?9UL:1,mode=="lease-version");if(mode=="lease-name") { req=Context(RawSmb.Create("wrong",false,0,2,43),"DH2C",DurableHandleMessages.BuildV2ReconnectData(id.P,id.V,open.DurableCreateGuid,false));req=Lease(req); }
        if(mode=="owner") session.Identity=new Smb.Auth.SecurityIdentity { UserName="foreign",DomainName="foreign" };
        if(mode=="expired")clock.Advance(TimeSpan.FromSeconds(3));
        if(mode=="cache-revoked")open.OplockLevel=OplockLevel.None;
        var wrapper=new FaultHandle(handle!);open.LocalOpen=handle=wrapper;
        if(mode=="fault")wrapper.Fail=true;
        if(mode is "collision" or "parallel")wrapper.Barrier=new AsyncBarrier();
        async Task<byte[]> Send(byte[] b,ulong mid=1) { RawSmb.Put64(b,24,mid);RawSmb.Put32(b,16,8);Smb.Crypto.Smb2Signer.SignInPlace(Smb.Crypto.Smb2Signer.ResolveAlgorithm(SmbDialect.Smb300,session.Connection.SigningAlgorithmId),session.SigningKey,b,mid,false,false);return await d.Dispatcher.ProcessMessageAsync(session.Connection,b); }
        try {
            byte[] response;
            if(mode is "collision" or "parallel") {
                var first=Send(req);await wrapper.Barrier!.Entered.WaitAsync(Check.Timeout);
                Task<byte[]>? second=null;SmbOpen? foreign=null;
                try { if(mode=="collision") { foreign=new SmbOpen { PersistentFileId=id.P,VolatileFileId=2 };session.Opens.TryAdd((id.P,2),foreign); }
                    else second=Send(req.ToArray(),2);
                } finally { wrapper.Barrier.Release(); }
                response=await first.WaitAsync(Check.Timeout);
                if(mode=="collision") { Status(response,NtStatus.InsufficientResources,"publication collision rolls back");Check.That(ReferenceEquals(foreign,session.Opens[(id.P,2)]),"foreign entry preserved");session.Opens.TryRemove((id.P,2),out _);response=await Send(req,3); }
                else { var other=await second!.WaitAsync(Check.Timeout);Check.Equal(1,new[]{response,other}.Count(r=>RawSmb.U32(r,8)==0),"one concurrent reconnect winner");if(RawSmb.U32(response,8)!=0)response=other; }
            } else response=await Send(req);
            if(mode=="fault") { Check.That(RawSmb.U32(response,8)!=0,"response fault observed");Check.That(((InMemoryDurableHandleStore)d.Options.DurableHandleStore).TryGetReplay(new Guid(d.Connection.ClientGuid),open.DurableCreateGuid,out _),"failed preparation preserves retained record");Check.That(open.Session==null&&session.Opens.IsEmpty,"fault cannot publish owner");wrapper.Fail=false;response=await Send(req,2); }
            if(mode is "wrong-guid" or "active" or "expired" or "share" or "lease-absent" or "lease-key" or "lease-name" or "lease-version" or "cache-revoked") { Status(response,NtStatus.ObjectNameNotFound,"invalid reconnect rejected");if(mode!="expired")Check.That(((InMemoryDurableHandleStore)d.Options.DurableHandleStore).TryGetReplay(new Guid(d.Connection.ClientGuid),open.DurableCreateGuid,out _),"invalid request preserves claim");return; }
            if(mode=="owner") { Status(response,NtStatus.AccessDenied,"owner check preserved");return; }
            if(mode=="persistent") { Status(response,NtStatus.InvalidParameter,"persistent reconnect flag mismatch");return; }
            Status(response,NtStatus.Success,"reconnect attaches actual open");var restored=Id(response);Check.That(restored.V!=id.V,"new protocol volatile ID");Check.That(ReferenceEquals(open,session.Opens[restored])&&ReferenceEquals(handle,open.LocalOpen),"same open and handle restored");Check.Equal(1,tree.OpenCount,"new tree counted once");Check.Equal("Active",open.Lifetime.State.ToString(),"reconnected state");
        } finally { await d.Dispatcher.OnConnectionClosedAsync(session.Connection,Smb2Dispatcher.CloseReason.Shutdown);await d.Dispatcher.CloseRetainedHandlesAsync(); }
    }
    [System.Diagnostics.CodeAnalysis.DynamicDependency(System.Diagnostics.CodeAnalysis.DynamicallyAccessedMemberTypes.PublicProperties,typeof(DurableHandle))]
    static Task Zero()
    {
        var store=new InMemoryDurableHandleStore();var client=Guid.NewGuid();
        var record=new DurableHandle { PersistentId=1,VolatileId=2,Open=new SmbOpen { VolatileFileId=2 },OwnerKey="owner",ClientGuid=client,Deadline=DateTimeOffset.MaxValue,CreateGuid=Guid.Empty };
        typeof(DurableHandle).GetProperty("IsV2")?.SetValue(record,true);
        store.Add(record);
        Check.That(store.TryGetReplay(client,Guid.Empty,out var found)&&ReferenceEquals(record,found),"explicit v2 zero GUID owns replay index");
        Check.That(store.TryClaim(1,2,out _),"claim zero GUID owner");Check.That(!store.TryGetReplay(client,Guid.Empty,out _),"claim retires zero GUID index");
        return Task.CompletedTask;
    }
    static async Task Retention(string mode)
    {
        await using var fixture=new DurableFixture();var d=fixture.Direct;var clock=new ManualClock();d.Options.TimeProvider=clock;
        var id=await d.Open();var open=d.Session.Opens[id];var handle=open.LocalOpen;
        // Dormant eligible flow: an already established durable promise, with a held Batch grant.
        open.IsDurable=true;open.DurableTimeout=TimeSpan.FromSeconds(2);open.OplockLevel=OplockLevel.Batch;
        await d.Options.LockManager.ApplyAsync(open,[new LockElement(0,1,true,false)],true,default);
        await open.LockSequences.ApplyAsync(0x11,()=>Task.FromResult(LockOutcome.Granted),default);
        var before=open.ChannelSequences.Snapshot;
        var barrier=new AsyncBarrier();Task<byte[]>? read=null;
        if(mode is "physical" or "revoke-physical") { d.Store.Control.Enqueue("Read",new OperationStep(Barrier:barrier,IgnoreCancellation:true));read=d.Send(RawSmb.Read(id,1,0,0,1,42));await barrier.Entered.WaitAsync(Check.Timeout); }
        Task cleanup;
        if(mode=="close") cleanup=d.Send(RawSmb.Close(id,0,1,42));
        else if(mode=="tree") cleanup=d.Send(RawSmb.TreeDisconnect(0,1,42));
        else if(mode=="logoff") { var b=RawSmb.Header(2,4,0,1,0);RawSmb.Put16(b,64,4);cleanup=d.Send(b); }
        else cleanup=d.Dispatcher.OnConnectionClosedAsync(d.Connection,mode=="shutdown"?Smb2Dispatcher.CloseReason.Shutdown:mode=="send"?Smb2Dispatcher.CloseReason.SendFailure:Smb2Dispatcher.CloseReason.ConnectionLoss).AsTask();
        if(mode is "physical" or "revoke-physical") { try { Check.That(!cleanup.IsCompleted,"physical operation holds disconnect retirement");Check.Equal(1,d.Store.ActiveHandles,"retained handle live during physical work"); } finally { if(mode=="revoke-physical")open.OplockLevel=OplockLevel.None;barrier.Release();await read!.WaitAsync(Check.Timeout); } }
        await cleanup.WaitAsync(Check.Timeout);
        if(mode is "close" or "tree" or "logoff" or "shutdown" or "revoke-physical") { Check.Equal(0,d.Store.ActiveHandles,"explicit teardown never retains");Check.Equal(0,d.Options.DurableHandleStore.TakeAll().Count,"no explicit retained record");return; }
        Check.Equal(1,d.Store.ActiveHandles,"final loss retains backend handle");Check.That(ReferenceEquals(handle,open.LocalOpen),"same handle retained");
        Check.That(open.Session==null&&open.TreeConnect==null&&d.Session.Opens.IsEmpty,"detached ownership");Check.Equal(0,d.Tree.OpenCount,"old tree count released");
        Check.Equal("Disconnected",open.Lifetime.State.ToString(),"disconnected state");Check.That(open.Lifetime.TryAcquire()==null,"disconnected admission denied");
        Check.Equal(1,((InMemoryLockManager)d.Options.LockManager).ActiveLockCount,"byte locks retained");Check.Equal(before,open.ChannelSequences.Snapshot,"sequence state preserved");
        var applies=0;await open.LockSequences.ApplyAsync(0x11,()=>{applies++;return Task.FromResult(LockOutcome.Granted);},default);Check.Equal(0,applies,"same lock slots retained");
        if(mode=="expire") { clock.Advance(TimeSpan.FromSeconds(2));d.Dispatcher.ScavengeDurableHandles();Check.Equal(0,d.Store.ActiveHandles,"deadline disposes retained resource");Check.Equal(0L,d.Options.Metrics.OpenHandles,"deadline balances metric");Check.Equal(0,((InMemoryShareModeManager)d.Options.ShareModeManager).ReservationCount,"deadline releases shares");Check.Equal(0,((InMemoryLockManager)d.Options.LockManager).ActiveLockCount,"deadline releases locks");Check.Equal("Closed",open.Lifetime.State.ToString(),"expiry centralized close"); }
        else { clock.Advance(TimeSpan.FromSeconds(3));d.Dispatcher.ScavengeDurableHandles(); }
        Check.Equal(0,d.Options.DurableHandleStore.TakeAll().Count,"no stale record");Check.Equal(1,d.Store.Handles.Single().DisposeCalls,"one disposer");
    }
}
