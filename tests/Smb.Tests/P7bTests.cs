using Smb.Testing;
using Smb.Server;
using Smb.Server.State;
using Smb.Protocol.Enums;
using Smb.Protocol.Messages;
using Smb.Server.Durable;

internal static class P7bTests
{
    public static IEnumerable<(string, Func<Task>)> Cases()
    {
        foreach (var failure in new[] { "removed", "failed", "terminate" })
            yield return ("p7b.sender." + failure, () => Sender(failure));
        yield return ("p7b.loss.live-open", Loss);
        yield return ("p7b.loss.all-session-detach",AllDetach);
        yield return ("p7b.loss.promotes-channel", Promote);
        yield return ("p7b.binding.final-loss-race", BindingRace);
        yield return ("p7b.tcp.final-loss-physical", HostLoss);
        yield return ("p7b.tcp.loss-survivor", Survivor);
        foreach(var profile in new[] { "MultichannelWithCaching", "MultichannelWithCachingAndCopy" })
            yield return ("p7b.tcp.break-survivor."+profile,()=>BreakSurvivor(profile));
        foreach(var dialect in new ushort[] { 0x300,0x302 })
            yield return ("p7b.tcp.lost-lock."+dialect.ToString("x"),()=>LostLock(dialect));
        yield return ("p7b.stress.bound-channels",Stress);
        yield return ("p7b.tcp.nic-ioctl",Nic);
        yield return ("p7b.create-record.inflight-arbitration",ArbitrateCreate);
        foreach(var profile in new[] { "MultichannelWithCopy", "MultichannelWithCachingAndCopy" })
            yield return ("p7b.profile.coordinated-copy."+profile,()=>CopyProfile(profile));
        yield return ("p7b.policy.gate311",Gate311);
        foreach(var mode in new[] { "id", "guid", "parallel", "client", "claim", "expiry", "clear", "explicit", "foreign" })
            yield return ("p7b.create-record."+mode,()=>Records(mode));
        yield return ("p7b.lock.physical-close", LockClose);
        foreach (var mode in new[] { "lock", "unlock", "changed", "failed", "inflight", "cancel", "close" })
            yield return ("p7b.lock."+mode,()=>LockReplay(mode));
        foreach (var sequence in new uint[] { 0, 65*16+1 })
            yield return ("p7b.lock.skip."+sequence,()=>LockSkip(sequence));
        foreach (var profile in new[] { "MultichannelOnly", "MultichannelWithCopy", "MultichannelWithCaching", "MultichannelWithCachingAndCopy" })
            yield return ("p7b.policy."+profile, () => Policy(profile));
        foreach (var dialect in new ushort[] { 0x300,0x302 })
            yield return ("p7b.tcp.bind."+dialect.ToString("x"), () => Bind(dialect));
    }
    [System.Diagnostics.CodeAnalysis.DynamicDependency(System.Diagnostics.CodeAnalysis.DynamicallyAccessedMemberTypes.PublicProperties,typeof(SmbFeaturePolicy))]
    static SmbFeaturePolicy Profile(string name) => (SmbFeaturePolicy?)typeof(SmbFeaturePolicy).GetProperty(name)?.GetValue(null) ?? SmbFeaturePolicy.Restricted;
    static Task Policy(string name)
    {
        using var auth=new System.Threading.CancellationTokenSource();
        var options=new SmbServerOptions { FeaturePolicy=Profile(name), EnableMultichannel=true, SpnegoNegotiator=new Smb.Auth.Ntlm.NtlmSpnegoNegotiator(new Smb.Auth.InMemoryIdentityBackend().AddUser("a","b","c")) };
        options.FeaturePolicy.Validate(options);
        var c=new SmbConnection();var b=RawSmb.Negotiate();RawSmb.Put16(b,100,0x300);
        var response=new Smb2Dispatcher(new SmbServerState(options)).ProcessMessage(c,b);
        Check.That((RawSmb.U32(response,88)&8)!=0,"opt-in advertises multichannel");
        Check.That(!options.FeaturePolicy.DurableHandles && !options.FeaturePolicy.PersistentHandles && !options.FeaturePolicy.ContinuousAvailability,"no recovery claims");
        Check.Equal(name.Contains("Copy"),options.FeaturePolicy.CopyChunk,"copy combination");
        Check.Equal(name.Contains("Caching"),options.FeaturePolicy.Leasing,"cache combination");
        return Task.CompletedTask;
    }
    internal static Task Probe311()=>Bind(0x311);
    static async Task Gate311()
    {
        await using var h=new HostFixture();h.Server.State.Options.FeaturePolicy=Profile("MultichannelOnly");h.Server.State.Options.EnableMultichannel=true;
        await h.StartAsync();await using var a=new WireClient();await a.ConnectAsync(h.Server.Endpoint,HostFixture.Domain,HostFixture.User,HostFixture.Password,0x311);
        Check.That((h.Server.State.SessionGlobalList[a.Session].Connection.ServerCapabilities&Smb2Capabilities.MultiChannel)!=0,"validated SMB311 opt-in advertises multichannel");
        await using var b=new WireClient();await b.BindAsync(h.Server.Endpoint,a);
        Check.Equal(2,h.Server.State.SessionGlobalList[a.Session].Channels.Count,"SMB311 gate requires actual authenticated binding");
    }
    static async Task Bind(ushort dialect)
    {
        await using var h=new HostFixture();h.Server.State.Options.FeaturePolicy=Profile("MultichannelOnly");h.Server.State.Options.EnableMultichannel=true;
        await h.StartAsync();await using var a=new WireClient();await a.ConnectAsync(h.Server.Endpoint,HostFixture.Domain,HostFixture.User,HostFixture.Password,dialect);
        await using var b=new WireClient();await b.BindAsync(h.Server.Endpoint,a);
        var session=h.Server.State.SessionGlobalList[a.Session];
        Check.Equal(2,session.Channels.Count,"actual authenticated binding shares channel set");
        var id=await a.CreateAsync("bound");Console.WriteLine($"binding probe {dialect:x}: primary CREATE succeeded");
        var id2=await b.CreateAsync("second");Check.That(id.V!=id2.V,"cross-channel IDs unique");
        var ca=session.Channels.Values.Single(c=>c.Connection==session.Connection).Connection;
        var cb=session.Channels.Values.Single(c=>c.Connection!=session.Connection).Connection;
        var credit=ca.Credits.AvailableCount;await b.WriteAsync(id,[9]);Check.Equal(credit,ca.Credits.AvailableCount,"per-connection credits independent");
        await b.CloseAsync(id);Check.Equal(1,h.Store.ActiveHandles,"cross-channel CLOSE");
        await b.DisconnectTreeAsync();Check.Equal(0,h.Store.ActiveHandles,"cross-channel TREE closes all");
        Check.Equal(2,h.Store.Control.Count("Create"),"exact backend acquisitions");
    }
    static async Task BindingRace()
    {
        await using var h=new HostFixture();h.Server.State.Options.FeaturePolicy=Profile("MultichannelOnly");h.Server.State.Options.EnableMultichannel=true;
        await h.StartAsync();await using var a=new WireClient();await a.ConnectAsync(h.Server.Endpoint,HostFixture.Domain,HostFixture.User,HostFixture.Password,0x300);
        var id=await a.CreateAsync("race");var session=h.Server.State.SessionGlobalList[a.Session];
        var gate=new AsyncBarrier();h.Store.Control.Enqueue("Read",new OperationStep(Barrier:gate,IgnoreCancellation:true));
        var read=a.ReadAsync(id,1);await gate.Entered.WaitAsync(Check.Timeout);
        var close=new Smb2Dispatcher(h.Server.State).OnConnectionClosedAsync(session.Connection).AsTask();
        try {
            Check.That(!close.IsCompleted,"physical read holds final retirement");
            await using var b=new WireClient();
            var rejected=false;
            try { await b.BindAsync(h.Server.Endpoint,a); }
            catch (InvalidOperationException e) when (e.Message.Contains("NTSTATUS cmd=1")) { rejected=true; }
            Check.That(rejected,"binding cannot publish into final-loss closing session");
            Check.That(session.Channels.IsEmpty,"no orphan binding after final loss");
        } finally { gate.Release();try { await read.WaitAsync(Check.Timeout); } catch (InvalidOperationException) { } await close.WaitAsync(Check.Timeout); }
        Check.Equal(0,h.Store.ActiveHandles,"final-loss physical cleanup");
    }
    static byte[] Lock((ulong P,ulong V) id,uint sequence,uint flags=0x12)
    { var b=RawSmb.Header(10,48,0,1,42);RawSmb.Put16(b,64,48);RawSmb.Put16(b,66,1);RawSmb.Put32(b,68,sequence);RawSmb.Put64(b,72,id.P);RawSmb.Put64(b,80,id.V);RawSmb.Put64(b,96,1);RawSmb.Put32(b,104,flags);return b; }
    static void Status(byte[] b,uint status,string message) => Check.Equal(status,RawSmb.U32(b,8),message);
    static async Task LockSkip(uint sequence)
    {
        await using var d=new P2Tests.Direct();var c=Seed(d);d.Connection.ServerCapabilities=c.ServerCapabilities=Smb2Capabilities.MultiChannel;
        var id=await d.Open();try {
            // Shared locks may stack; exclusive locks conflict even for the same open (MS-FSA 2.1.4.10).
            Status(await d.Send(Lock(id,sequence,0x11)),0,"first unsequenced lock");Status(await d.Send(Lock(id,sequence,0x11),c),0,"second unsequenced lock");
            Check.Equal(2,((Smb.Server.Locking.InMemoryLockManager)d.Options.LockManager).ActiveLockCount,"reserved/out-of-array slot continues normal processing");
        } finally { await d.Dispatcher.OnConnectionClosedAsync(c); }
    }
    static async Task LockClose()
    {
        await using var d=new P2Tests.Direct();var c=Seed(d);var id=await d.Open();var locks=new BarrierLocks(d.Options.LockManager);d.Options.LockManager=locks;
        Status(await d.Send(Lock(id,0x11)),0x103,"physical lock parked");await locks.Gate.Entered.WaitAsync(Check.Timeout);
        var close=d.Send(RawSmb.Close(id,0,1,42),c);
        try { Check.That(!close.IsCompleted,"CLOSE must await physical lock producer after response ownership ends");Check.Equal(1,d.Store.ActiveHandles,"backend remains live"); }
        finally { locks.Gate.Release();await close.WaitAsync(Check.Timeout);await d.Dispatcher.OnConnectionClosedAsync(c); }
    }
    static async Task LockReplay(string mode)
    {
        await using var d=new P2Tests.Direct();var c=Seed(d);d.Connection.ServerCapabilities=c.ServerCapabilities=Smb2Capabilities.MultiChannel;
        var id=await d.Open();var locks=(Smb.Server.Locking.InMemoryLockManager)d.Options.LockManager;
        try {
            if(mode is "inflight" or "cancel" or "close") {
                var controlled=new BarrierLocks(locks);d.Options.LockManager=controlled;
                var first=await d.Send(Lock(id,0x11));Status(first,0x103,"controlled first lock pending");
                await controlled.Gate.Entered.WaitAsync(Check.Timeout);
                var second=await d.Send(Lock(id,0x11),c);Status(second,0x103,"duplicate waits for physical winner");
                var pending=c.PendingRequests.Values.Single();
                if(mode=="cancel") pending.Cancel();
                Task<byte[]>? close=null;if(mode=="close")close=d.Send(RawSmb.Close(id,0,1,42),c);
                try { Check.Equal(1,controlled.Calls,"one physical lock application while winner parked"); }
                finally { controlled.Gate.Release(); }
                if(close!=null) await close.WaitAsync(Check.Timeout);
                else { await pending.Finished.WaitAsync(Check.Timeout);Check.Equal(mode=="cancel"?NtStatus.Cancelled:NtStatus.Success,pending.FinalStatus,"duplicate completion result"); }
                return;
            }
            if(mode=="failed") {
                var other=await d.Open();Status(await d.Send(Lock(other,0)),0,"foreign lock holds range");
                Status(await d.Send(Lock(id,0x11)),0xc0000055,"conflict is not saved as success");await d.Send(Lock(other,0,4));
            }
            // A changed slot must reapply a legal shared acquisition, rather than stack exclusive locks.
            var flags=mode=="changed"?0x11u:0x12u;
            Status(await d.Send(Lock(id,0x11,flags)),0,"first successful lock");
            if(mode=="unlock") {
                Status(await d.Send(Lock(id,0x12,4)),0,"unlock once");Status(await d.Send(Lock(id,0x12,4),c),0,"lost unlock response reexecutes as success");Check.Equal(0,locks.ActiveLockCount,"unlock applied once");
            } else {
                var replay=Lock(id,mode=="changed"?0x12u:0x11u,flags);RawSmb.Put32(replay,16,0x20000000);
                Status(await d.Send(replay,c),0,"replayed/changed LOCK succeeds");
                Check.Equal(mode=="changed"?2:1,locks.ActiveLockCount,"sequence slot decides applications, replay flag alone does not");
                await d.Send(Lock(id,0x13,4));Check.Equal(mode=="changed"?1:0,locks.ActiveLockCount,"one unlock removes one established lock");
            }
        } finally { await d.Dispatcher.OnConnectionClosedAsync(c); }
        await d.Dispatcher.OnConnectionClosedAsync(d.Connection);
        Check.Equal(0,locks.ActiveLockCount,"final loss releases locks");
    }
    sealed class BarrierLocks(Smb.Server.Locking.ILockManager inner) : Smb.Server.Locking.ILockManager
    {
        public readonly AsyncBarrier Gate= new AsyncBarrier();public int Calls;
        public async Task<Smb.Server.Locking.LockOutcome> ApplyAsync(SmbOpen owner,IReadOnlyList<Smb.Server.Locking.LockElement> elements,bool fail,CancellationToken token)
        { Interlocked.Increment(ref Calls);await Gate.WaitAsync(CancellationToken.None);return await inner.ApplyAsync(owner,elements,fail,token); }
        public bool IsRangeAccessible(SmbOpen owner,ulong offset,ulong length,bool write)=>inner.IsRangeAccessible(owner,offset,length,write);
        public void ReleaseOwner(SmbOpen owner)=>inner.ReleaseOwner(owner);
    }
    static async Task Until(Func<bool> condition)
    { using var timeout=new CancellationTokenSource(Check.Timeout);while(!condition()) { timeout.Token.ThrowIfCancellationRequested();await Task.Yield(); } }
    static async Task HostLoss()
    {
        await using var h=new HostFixture();h.Server.State.Options.FeaturePolicy=Profile("MultichannelOnly");h.Server.State.Options.EnableMultichannel=true;
        await h.StartAsync();await using var a=new WireClient();await a.ConnectAsync(h.Server.Endpoint,HostFixture.Domain,HostFixture.User,HostFixture.Password,0x300);
        var id=await a.CreateAsync("loss");var session=h.Server.State.SessionGlobalList[a.Session];var ca=session.Connection;
        var gate=new AsyncBarrier();h.Store.Control.Enqueue("Read",new OperationStep(Barrier:gate,IgnoreCancellation:true));
        await a.SendAsync(RawSmb.Read(id,1,0,a.NextMessageId(),a.Session,a.Tree));await gate.Entered.WaitAsync(Check.Timeout);
        ca.RequestClose!();await Until(()=>ca.SendRawAsync==null);
        try {
            await using var b=new WireClient();var rejected=false;
            try { await b.BindAsync(h.Server.Endpoint,a); } catch(InvalidOperationException e) when(e.Message.Contains("NTSTATUS cmd=1")){rejected=true;}
            Check.That(rejected,"transport loss retires final channel before waiting for physical IO");
            Check.Equal(1,h.Store.ActiveHandles,"physical work keeps backend live until release");
        } finally { gate.Release(); }
    }
    static byte[] Wire(byte[] packet,WireClient client)
    { RawSmb.Put64(packet,24,client.NextMessageId());RawSmb.Put64(packet,40,client.Session);RawSmb.Put32(packet,36,client.Tree);return packet; }
    static async Task Survivor()
    {
        await using var h=new HostFixture();h.Server.State.Options.FeaturePolicy=Profile("MultichannelOnly");h.Server.State.Options.EnableMultichannel=true;
        await h.StartAsync();await using var a=new WireClient();await a.ConnectAsync(h.Server.Endpoint,HostFixture.Domain,HostFixture.User,HostFixture.Password,0x300);
        await using var b=new WireClient();await b.BindAsync(h.Server.Endpoint,a);var session=h.Server.State.SessionGlobalList[a.Session];var ca=session.Connection;
        var id=await a.CreateAsync("old");var other=await b.CreateAsync("independent");
        var dir=await a.CreateAsync("",true);await a.SendAsync(Wire(P4Tests.Notify(dir),a));Status(await a.ReceiveAsync(),0x103,"notify pending on lost channel");
        var gate=new AsyncBarrier();h.Store.Control.Enqueue("Read",new OperationStep(Barrier:gate,IgnoreCancellation:true));
        await a.SendAsync(RawSmb.Read(id,1,0,a.NextMessageId(),a.Session,a.Tree));await gate.Entered.WaitAsync(Check.Timeout);
        await a.DisposeAsync();await Until(()=>session.Channels.Count==1);
        try {
            await b.WriteAsync(other,[8]);Check.Equal(3,h.Store.ActiveHandles,"survivor retains all opens during lost physical read");
            Check.That(ca.PendingRequests.IsEmpty && ca.AsyncRequests.IsEmpty,"lost channel abandons pending maps");
            Check.Equal(1,h.Watcher.ActiveCount,"watcher remains per shared open");
        } finally { gate.Release(); }
        await b.CloseAsync(id);await b.CloseAsync(other);await b.CloseAsync(dir);Check.Equal(0,h.Watcher.ActiveCount,"explicit CLOSE returns shared watcher");
    }
    static async Task LostLock(ushort dialect)
    {
        await using var h=new HostFixture();h.Server.State.Options.FeaturePolicy=Profile("MultichannelOnly");h.Server.State.Options.EnableMultichannel=true;
        await h.StartAsync();await using var a=new WireClient();await a.ConnectAsync(h.Server.Endpoint,HostFixture.Domain,HostFixture.User,HostFixture.Password,dialect);
        await using var b=new WireClient();await b.BindAsync(h.Server.Endpoint,a);var session=h.Server.State.SessionGlobalList[a.Session];var ca=session.Connection;
        var id=await a.CreateAsync("lock");var inner=h.Server.State.Options.LockManager;var locks=new BarrierLocks(inner);h.Server.State.Options.LockManager=locks;
        var lost=new AsyncBarrier();var sent=new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously);
        ca.SendRawAsync=async (_,_)=> { await lost.WaitAsync();sent.TrySetResult();throw new IOException("controlled lost LOCK final"); };
        await a.SendAsync(Wire(Lock(id,0x11),a));Status(await a.ReceiveAsync(),0x103,"LOCK interim delivered");
        await locks.Gate.Entered.WaitAsync(Check.Timeout);locks.Gate.Release();await lost.Entered.WaitAsync(Check.Timeout);
        lost.Release();await sent.Task.WaitAsync(Check.Timeout);await Until(()=>session.Channels.Count==1);
        var replay=Wire(Lock(id,0x11),b);RawSmb.Put32(replay,16,0x20000000);await b.ExchangeAsync(replay,size:4);
        Check.Equal(1,locks.Calls,"lost final replay never calls lock manager twice");Check.Equal(1,((Smb.Server.Locking.InMemoryLockManager)inner).ActiveLockCount,"one established range lock");
        await b.ExchangeAsync(Wire(Lock(id,0x12,4),b),size:4);Check.Equal(0,((Smb.Server.Locking.InMemoryLockManager)inner).ActiveLockCount,"one unlock removes lock");
        await b.ExchangeAsync(Wire(Lock(id,0x12,4),b),size:4);await b.CloseAsync(id);
        Check.Equal(0,h.Store.ActiveHandles,"lost-response cleanup");Check.That(ca.PendingRequests.IsEmpty,"lost final abandons map");
    }
    static async Task BreakSurvivor(string profile)
    {
        using var root=new P6Tests.Root();var store=P6Tests.Local(root.Path);
        await using var h=HostFixture.Build(store,0,HostFixture.Domain,HostFixture.User,HostFixture.Password);
        h.State.Options.FeaturePolicy=Profile(profile);h.State.Options.EnableMultichannel=true;
        await h.StartAsync();try {
            await using var a=new WireClient();await a.ConnectAsync(h.Endpoint,HostFixture.Domain,HostFixture.User,HostFixture.Password,0x300);
            await using var b=new WireClient();await b.BindAsync(h.Endpoint,a);var session=h.State.SessionGlobalList[a.Session];
            var request=RawSmb.Create("cached",false,a.NextMessageId(),a.Session,a.Tree);request[67]=9;
            var opened=await a.ExchangeAsync(request,size:89);Check.Equal((byte)9,opened[66],"batch granted on common coordinator");var id=(RawSmb.U64(opened,128),RawSmb.U64(opened,136));
            await a.DisposeAsync();await Until(()=>session.Channels.Count==1);
            Check.Equal(1,h.State.Options.CacheCoordinator.GrantCount,"one-channel loss keeps grant");
            await using var other=new WireClient();await other.ConnectAsync(h.Endpoint,HostFixture.Domain,HostFixture.User,HostFixture.Password,0x300);
            await other.SendAsync(RawSmb.Create("cached",false,other.NextMessageId(),other.Session,other.Tree));var notification=await b.ReceiveAsync();Check.Equal((ushort)18,RawSmb.U16(notification,12),"break on surviving bound channel");
            Check.Equal(1,h.State.Options.CacheCoordinator.BreakingCount,"conflicting CREATE waits for break ACK");
            await b.ExchangeAsync(Wire(P6Tests.Ack(id,OplockLevel.None),b),size:24);
            var result=await other.ReceiveAsync();if(RawSmb.U32(result,8)==0x103)result=await other.ReceiveAsync();Status(result,0,"CREATE final after ACK");var second=(RawSmb.U64(result,128),RawSmb.U64(result,136));await other.CloseAsync(second);await b.CloseAsync(id);
            Check.Equal(0,h.State.Options.CacheCoordinator.GrantCount,"cache records returned");Check.Equal(0,h.State.Options.CacheCoordinator.PhysicalScopeCount,"physical scopes returned");
        } finally { await h.StopAsync(TimeSpan.FromSeconds(1)).WaitAsync(Check.Timeout); }
    }
    static async Task Stress()
    {
        await using var h=new HostFixture();h.Server.State.Options.FeaturePolicy=Profile("MultichannelWithCopy");h.Server.State.Options.EnableMultichannel=true;
        await h.StartAsync();await using var a=new WireClient();await a.ConnectAsync(h.Server.Endpoint,HostFixture.Domain,HostFixture.User,HostFixture.Password,0x302);
        await using var b=new WireClient();await b.BindAsync(h.Server.Endpoint,a);var ids=new HashSet<ulong>();
        for(var i=0;i<24;i++) {
            var pair=await Task.WhenAll(a.CreateAsync("a"+i),b.CreateAsync("b"+i));
            foreach(var id in pair)Check.That(id.V!=0 && id.V!=ulong.MaxValue && ids.Add(id.V),"unique reserved-safe IDs across channels");
            await Task.WhenAll(a.WriteAsync(pair[1],[1]),b.WriteAsync(pair[0],[2]));
            await Task.WhenAll(a.CloseAsync(pair[1]),b.CloseAsync(pair[0]));
        }
        Check.Equal(48,h.Store.Control.Count("Create"),"bounded exact create count");Check.Equal(48,h.Store.Control.Count("Write"),"bounded exact mutations");Check.Equal(0,h.Store.ActiveHandles,"stress returns backend handles");
        var session=h.Server.State.SessionGlobalList[a.Session];Check.That(session.Opens.IsEmpty,"stress returns open table");Check.Equal(0,session.ProvisionalOpenCount,"stress returns reservations");
    }
    // Exercises the existing retained-record API on current source; no durable wire grant is enabled.
    static async Task Records(string mode)
    {
        await using var d=new P2Tests.Direct();var store=new Smb.Server.Durable.InMemoryDurableHandleStore();var clock=new ManualClock();
        var guid=Guid.NewGuid();var id=await d.Open();var open=d.Session.Opens[id];open.IsDurable=true;open.DurableCreateGuid=guid;
        Smb.Server.Durable.DurableHandle Record(ulong v,SmbOpen o) => new DurableHandle { PersistentId=0,VolatileId=v,Open=o,OwnerKey="unchanged-fixture-owner",CreateGuid=guid,Deadline=clock.GetUtcNow().AddMinutes(1) };
        var first=Record(id.V,mode=="foreign"?new SmbOpen{VolatileFileId=id.V,Session=d.Session}:open);store.Add(first);
        if(mode is "explicit" or "foreign") {
            d.Options.DurableHandleStore=store;Status(await d.Send(RawSmb.Close(id,0,1,42)),0,"explicit close succeeds");
            Check.Equal(mode=="foreign",store.TryClaim(id.P,id.V,out _),"explicit close retires only its own retained/replay record");return;
        }
        if(mode is "id" or "guid" or "parallel") {
            var next=await d.Open("second");var loser=Record(mode=="id"?id.V:next.V,d.Session.Opens[next]);
            var rejected=false;try { if(mode=="parallel")await Task.Run(()=>store.Add(loser));else store.Add(loser); }catch(InvalidOperationException){rejected=true;}
            Check.That(rejected,"duplicate retained "+mode+" must not overwrite/duplicate replay winner");
            Check.That(store.TryClaim(id.P,id.V,out var winner)&&ReferenceEquals(first,winner),"original replay/open owner preserved");
            Check.Equal(0,store.TakeAll().Count,"losing record was never published");
        } else if(mode=="client") {
            var c=d.Channel();c.ClientGuid=Guid.NewGuid().ToByteArray();var session=new SmbSession{SessionId=2,SessionGlobalId=2,Connection=c};
            var foreign=new SmbOpen{VolatileFileId=99,Session=session};store.Add(Record(99,foreign));Check.Equal(2,store.TakeAll().Count,"CreateGuid scoped to client GUID");
        } else if(mode=="claim") {
            var results=await Task.WhenAll(Enumerable.Range(0,16).Select(i=>Task.Run(()=>store.TryClaim(id.P,id.V,out _))));Check.Equal(1,results.Count(x=>x),"one retained claim owner");store.Add(first);Check.Equal(1,store.TakeAll().Count,"claim retires replay key for new registration");
        } else if(mode=="expiry") {
            Check.Equal(0,store.TakeExpired(clock.GetUtcNow()).Count,"no early expiry");clock.Advance(TimeSpan.FromMinutes(1));Check.Equal(1,store.TakeExpired(clock.GetUtcNow()).Count,"deadline expires once");store.Add(first);Check.Equal(1,store.TakeAll().Count,"expiration releases replay key");
        } else { Check.Equal(1,store.TakeAll().Count,"drain once");Check.Equal(0,store.TakeAll().Count,"drain idempotent");store.Add(first);Check.Equal(1,store.TakeAll().Count,"drain retires replay key"); }
    }
    sealed class NicProvider : Smb.Server.Multichannel.INetworkInterfaceProvider
    {
        public IReadOnlyList<Smb.Protocol.Messages.NetworkInterfaceInfo> GetInterfaces()=>[new NetworkInterfaceInfo(7,0,1000000000,System.Net.IPAddress.Loopback)];
    }
    static async Task Nic()
    {
        await using var h=new HostFixture();h.Server.State.Options.FeaturePolicy=Profile("MultichannelOnly");h.Server.State.Options.EnableMultichannel=true;h.Server.State.Options.NetworkInterfaceProvider=new NicProvider();
        await h.StartAsync();await using var c=new WireClient();await c.ConnectAsync(h.Server.Endpoint,HostFixture.Domain,HostFixture.User,HostFixture.Password,0x300);
        var packet=Wire(P5Tests.Ioctl((ulong.MaxValue,ulong.MaxValue),0x1401fc,[],4096),c);var response=await c.ExchangeAsync(packet,size:49);
        Check.Equal(152u,RawSmb.U32(response,100),"one fixed NIC entry");Check.Equal(7u,RawSmb.U32(response,116),"provider interface index");
        packet=Wire(P5Tests.Ioctl((ulong.MaxValue,ulong.MaxValue),0x1401fc,[],1),c);await c.ExchangeAsync(packet,0xc0000023,9);
    }
    static async Task CopyProfile(string profile)
    {
        await using var d=new P2Tests.Direct();var c=Seed(d);d.Options.FeaturePolicy=Profile(profile);d.Options.EnableMultichannel=true;
        d.Store.Seed("source",[1,2,3]);var source=await d.Open("source");var target=await d.Open("target");
        try {
            var reply=await d.Send(P5Tests.Ioctl(source,0x140078,[],32));Status(reply,0,"resume key on combined profile");var key=reply.AsSpan(112,24).ToArray();
            var data=new byte[56];key.CopyTo(data,0);RawSmb.Put32(data,24,1);RawSmb.Put32(data,48,3);
            var gate=new AsyncBarrier();d.Store.Control.Enqueue("Read",new OperationStep(Barrier:gate,IgnoreCancellation:true));
            var copy=d.Send(P5Tests.Ioctl(target,0x1440f2,data,12),c);await gate.Entered.WaitAsync(Check.Timeout);
            try {Check.That(d.Options.CacheCoordinator.PhysicalScopeCount>0,"combined profile COPY holds common physical scope");}
            finally {gate.Release();}
            var result=await copy.WaitAsync(Check.Timeout);if(RawSmb.U32(result,8)==0x103){var pending=c.PendingRequests.Values.SingleOrDefault();if(pending!=null)await pending.Finished.WaitAsync(Check.Timeout);}else Status(result,0,"combined profile COPY success");
            Check.That(d.Store.Contents("target").SequenceEqual(new byte[]{1,2,3}),"copy result exact");Check.Equal(0,d.Options.CacheCoordinator.PhysicalScopeCount,"copy releases common scopes");
        }finally{await d.Dispatcher.OnConnectionClosedAsync(c);}
    }
    static async Task ArbitrateCreate()
    {
        // Component-only CREATE arbitration. No server feature flag enables these records on the wire.
        await using var d=new P2Tests.Direct();var store=new Smb.Server.Durable.InMemoryDurableHandleStore();var guid=Guid.NewGuid();
        var gate=new AsyncBarrier();d.Store.Control.Enqueue("Create",new OperationStep(Barrier:gate,IgnoreCancellation:true));
        var provisional=new SmbOpen{VolatileFileId=1,Session=d.Session};
        var first=new Smb.Server.Durable.DurableHandle{PersistentId=0,VolatileId=1,Open=provisional,OwnerKey="fixture",CreateGuid=guid,Deadline=DateTimeOffset.MaxValue};store.Add(first);
        var acquisition=d.Store.CreateAsync("replay",Smb.FileSystem.FileAccessIntent.ReadWrite,Smb.FileSystem.CreateDispositionIntent.OverwriteIf,false,true).AsTask();await gate.Entered.WaitAsync(Check.Timeout);
        try {
            var rejected=false;try{store.Add(new DurableHandle {PersistentId=0,VolatileId=2,Open=new SmbOpen {VolatileFileId=2,Session=d.Session},OwnerKey="fixture",CreateGuid=guid,Deadline=DateTimeOffset.MaxValue});}catch(InvalidOperationException){rejected=true;}
            Check.That(rejected,"inflight client/CreateGuid has one registration winner");
            Check.That(store.TryGetReplay(new Guid(d.Connection.ClientGuid),guid,out var found)&&ReferenceEquals(first,found),"lookup retains actual inflight open owner");
            Check.Equal(1,d.Store.Control.Count("Create"),"arbitrated backend acquisition exactly once");
        }finally{gate.Release();var acquired=await acquisition.WaitAsync(Check.Timeout);await acquired.Value.Handle.DisposeAsync();}
        Check.That(store.TryClaim(0,1,out _),"failed/retired owner can release registration");Check.That(!store.TryGetReplay(new Guid(d.Connection.ClientGuid),guid,out _),"retirement removes replay index");Check.Equal(0,d.Store.ActiveHandles,"component backend returned");
    }
    static async Task AllDetach()
    {
        await using var d=new P2Tests.Direct();d.Connection.Dialect=SmbDialect.Smb300;
        d.Session.Channels.TryAdd(d.Connection.ConnectionId,new SmbChannel {Connection=d.Connection,SigningKey=d.Session.SigningKey});
        var second=new SmbSession{SessionId=2,SessionGlobalId=2,Connection=d.Connection,State=SessionState.Valid};
        second.Channels.TryAdd(d.Connection.ConnectionId,new SmbChannel {Connection=d.Connection,SigningKey=d.Session.SigningKey});d.Connection.Sessions.TryAdd(2,second);d.State.SessionGlobalList.TryAdd(2,second);d.Options.Metrics.OnAuthenticationSucceeded();
        var firstPhysical=d.Session.Lifetime.TryAcquire()!;var secondPhysical=second.Lifetime.TryAcquire()!;
        var loss=d.Dispatcher.OnConnectionClosedAsync(d.Connection).AsTask();
        try {Check.That(d.Session.Channels.IsEmpty && second.Channels.IsEmpty,"detach all affected session channel sets before any physical drain");}
        finally{firstPhysical.Dispose();secondPhysical.Dispose();await loss.WaitAsync(Check.Timeout);}
        Check.That(d.Connection.Sessions.IsEmpty && d.State.SessionGlobalList.IsEmpty,"all session maps returned");
    }
    static async Task Promote()
    {
        await using var d=new P2Tests.Direct();var c=Seed(d);
        await d.Dispatcher.OnConnectionClosedAsync(d.Connection);
        try { Check.That(ReferenceEquals(c,d.Session.Connection),"loss promotes surviving session connection"); }
        finally { await d.Dispatcher.OnConnectionClosedAsync(c); }
    }
    static SmbConnection Seed(P2Tests.Direct d)
    {
        var c = d.Channel(); c.Dialect = d.Connection.Dialect = SmbDialect.Smb300;
        c.Sessions.TryAdd(1, d.Session); d.State.Connections.TryAdd(c.ConnectionId, c);
        d.Session.Channels.TryAdd(d.Connection.ConnectionId, new SmbChannel { Connection=d.Connection, SigningKey=d.Session.SigningKey });
        d.Session.Channels.TryAdd(c.ConnectionId, new SmbChannel { Connection=c, SigningKey=d.Session.SigningKey });
        new RecordingTransport().Attach(d.Connection);new RecordingTransport().Attach(c);
        return c;
    }
    static async Task Sender(string failure)
    {
        await using var d = new P2Tests.Direct(); var c = Seed(d);
        d.Connection.SendRawAsync = (_,_) => Task.CompletedTask; c.SendRawAsync = (_,_) => Task.CompletedTask;
        if (failure == "removed") d.Session.Channels.TryRemove(d.Connection.ConnectionId, out _);
        if (failure == "failed") d.Connection.ResponseSendFailed = true;
        if (failure == "terminate") d.Connection.MustTerminate = true;
        try { Check.That(ReferenceEquals(c,d.Session.SelectSendChannel(d.Connection)), "sender must choose live bound channel over dead preferred"); }
        finally { await d.Dispatcher.OnConnectionClosedAsync(c); }
    }
    static async Task Loss()
    {
        await using var d = new P2Tests.Direct(); var c = Seed(d); var id = await d.Open();
        var open = d.Session.Opens[id];
        await d.Dispatcher.OnConnectionClosedAsync(d.Connection).AsTask().WaitAsync(Check.Timeout);
        try {
            Check.Equal(1,d.Store.ActiveHandles,"one channel loss preserves backend");
            Check.That(ReferenceEquals(open,d.Session.Opens[id]),"same open retained");
            var b=await d.Send(RawSmb.Write(id,[7],0,0,1,42),c);
            Check.Equal(0u,RawSmb.U32(b,8),"surviving signed channel writes");
        } finally { await d.Dispatcher.OnConnectionClosedAsync(c); }
        Check.Equal(0,d.Store.ActiveHandles,"final loss closes nondurable open");
        Check.Equal(1,d.Store.Handles.Single().DisposeCalls,"exact disposal");
    }
}
