using Smb.Testing;
using Smb.Server;
using Smb.Server.Locking;
using Smb.Server.Sharing;
using Smb.Protocol.Enums;
using Smb.Protocol.Messages;

internal static class P7cNetwork
{
    public static IEnumerable<(string,Func<Task>)> Cases()
    {
        foreach(var profile in new[]{"DurableWithCopy","DurableWithMultichannel","DurableWithMultichannelAndCopy"})yield return ("p7c.profile."+profile,()=>Combination(profile));
        foreach(var dialect in new ushort[]{0x300,0x302}) {
            yield return ($"p7c.tcp.{dialect:x}.lost-create",()=>LostCreate(dialect,false));
            yield return ($"p7c.tcp.{dialect:x}.lost-create-final",()=>LostCreate(dialect,true));
            yield return ($"p7c.tcp.{dialect:x}.retained-lock",()=>RetainedLock(dialect));
        }
    }
    static async Task Combination(string profile)
    {
        using var root=new P7cTests.Root();await using var host=HostFixture.Build(root.Store(),0,HostFixture.Domain,HostFixture.User,HostFixture.Password);
        var options=host.State.Options;options.FeaturePolicy=P7cTests.Profile(profile);options.EnableMultichannel=profile.Contains("Multichannel");
        Check.That(options.FeaturePolicy.DurableHandles&&options.FeaturePolicy.Leasing,"explicit combination grants durability and coordinated caching");
        Check.Equal(profile.Contains("Copy"),options.FeaturePolicy.CopyChunk,"copy composition");Check.Equal(profile.Contains("Multichannel"),options.FeaturePolicy.Multichannel,"channel composition");options.FeaturePolicy.Validate(options);
        await host.StartAsync();await using var c=new WireClient();await c.ConnectAsync(host.Endpoint,HostFixture.Domain,HostFixture.User,HostFixture.Password,0x302);
        var response=await c.ExchangeAsync(P7cTests.Wire(P7cTests.Request("a",Guid.NewGuid()),c));var id=P7cTests.Id(response);Check.That(host.State.SessionGlobalList[c.Session].Opens[id].IsDurable,"composed TCP durable grant");await c.CloseAsync(id);
    }
    sealed class ClosedMetrics : Smb.Server.Diagnostics.SmbServerMetrics
    {
        internal readonly TaskCompletionSource ConnectionClosed= new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously);
        public override void OnConnectionClosed(){base.OnConnectionClosed();ConnectionClosed.TrySetResult();}
    }
    sealed class LostStream : MemoryStream
    { public override ValueTask WriteAsync(ReadOnlyMemory<byte> data,CancellationToken ct=default)=>ValueTask.FromException(new IOException("controlled lost CREATE send")); }
    static async Task LostCreate(ushort dialect,bool final)
    {
        using var root=new P7cTests.Root();var store=root.Store();await using var host=HostFixture.Build(store,0,HostFixture.Domain,HostFixture.User,HostFixture.Password);
        var options=host.State.Options;options.FeaturePolicy=P7cTests.Profile("DurableWithMultichannel");options.EnableMultichannel=true;options.ConcurrentMetadataOps=true;var metrics=new ClosedMetrics();options.Metrics=metrics;
        await host.StartAsync();await using var a=new WireClient();await a.ConnectAsync(host.Endpoint,HostFixture.Domain,HostFixture.User,HostFixture.Password,dialect);
        await using var b=new WireClient();if(!final)await b.BindAsync(host.Endpoint,a);
        var session=host.State.SessionGlobalList[a.Session];var ca=session.Connection;var guid=Guid.NewGuid();var request=P7cTests.Wire(P7cTests.Request("a",guid),a);RawSmb.Put32(request,100,5);RawSmb.Put32(request,16,8);Smb.Crypto.Smb2Signer.SignInPlace(Smb.Crypto.Smb2Signer.ResolveAlgorithm(ca.Dialect,ca.SigningAlgorithmId),session.SigningKey,request,RawSmb.U64(request,24),false,false);
        var dispatcher=new Smb2Dispatcher(host.State);Check.That(dispatcher.TryBeginConcurrentFrame(ca,request,false,out var frame),"actual session admits CREATE with physical owner");
        var handler=new Smb.Host.SmbConnectionHandler(host.State,null);await handler.ConcurrentOperations!.WaitAsync();await handler.RunConcurrentFrameAsync(new LostStream(),ca,frame,default);await metrics.ConnectionClosed.Task.WaitAsync(Check.Timeout);
        Check.That(ca.ResponseSendFailed,"transport send actually failed");Check.Equal(1L,metrics.OpenHandles,"eligible uncertain CREATE retains one open");
        if(final) { Check.That(session.Opens.IsEmpty,"final loss detached CREATE");var records=options.DurableHandleStore.TakeAll();Check.Equal(1,records.Count,"one eligible retained CREATE");options.DurableHandleStore.Add(records.Single());Check.Equal("Disconnected",records.Single().Open.Lifetime.State.ToString(),"lost CREATE final retained");await host.StopAsync(TimeSpan.Zero);Check.Equal(0L,metrics.OpenHandles,"lost CREATE shutdown drains");return; }
        var open=session.Opens.Values.Single();var original=open.Key;var identity=open.LocalOpen!.Identity;
        await store.WriteAsync(open.LocalOpen,0,new byte[]{99});var replay=P7cTests.Request("wrong-path",guid);RawSmb.Put32(replay,16,0x20000000);RawSmb.Put32(replay,100,5);
        var result=await b.ExchangeAsync(P7cTests.Wire(replay,b),size:89);Check.Equal(original,P7cTests.Id(result),"lost CREATE reconstructs original result");Check.Equal(1,session.Opens.Count,"no duplicate acquisition");Check.That(!File.Exists(root.Path+"/wrong-path"),"eligible replay never opens wrong path");Check.That(identity==open.LocalOpen.Identity,"retained identity");Check.Equal((byte)99,NativeHost.ReadAllBytes(root.Path+"/a")[0],"truncate side effect not repeated");
        await b.CloseAsync(original);Check.Equal(0,host.State.CreateReplays.Count,"terminal close retires replay index");Check.Equal(0,((InMemoryShareModeManager)options.ShareModeManager).ReservationCount,"lost response shares released");
    }
    static byte[] Lock((ulong P,ulong V) id,uint sequence,uint flags=0x12)
    {var b=RawSmb.Header(10,48,0,0,0);RawSmb.Put16(b,64,48);RawSmb.Put16(b,66,1);RawSmb.Put32(b,68,sequence);RawSmb.Put64(b,72,id.P);RawSmb.Put64(b,80,id.V);RawSmb.Put64(b,96,1);RawSmb.Put32(b,104,flags);return b;}
    static async Task RetainedLock(ushort dialect)
    {
        using var root=new P7cTests.Root();await using var host=HostFixture.Build(root.Store(),0,HostFixture.Domain,HostFixture.User,HostFixture.Password);var options=host.State.Options;options.FeaturePolicy=P7cTests.Profile();var metrics=new P7cTests.ClosedMetrics();options.Metrics=metrics;
        await host.StartAsync();var a=new WireClient();await a.ConnectAsync(host.Endpoint,HostFixture.Domain,HostFixture.User,HostFixture.Password,dialect);var guid=Guid.NewGuid();var first=await a.ExchangeAsync(P7cTests.Wire(P7cTests.Request("a",guid),a));var id=P7cTests.Id(first);var open=host.State.SessionGlobalList[a.Session].Opens[id];
        await a.ExchangeAsync(P7cTests.Wire(Lock(id,0x11),a));Check.Equal(1,((InMemoryLockManager)options.LockManager).ActiveLockCount,"wire established lock");var sequence=open.ChannelSequences;var slots=open.LockSequences;
        await a.DisposeAsync();await metrics.Closed.Task.WaitAsync(Check.Timeout);Check.Equal(1,((InMemoryLockManager)options.LockManager).ActiveLockCount,"transport loss retains lock");
        await using var b=new WireClient();await b.ConnectAsync(host.Endpoint,HostFixture.Domain,HostFixture.User,HostFixture.Password,dialect);var reconnect=P7cTests.Context(RawSmb.Create("a",false,0,0,0),"DH2C",DurableHandleMessages.BuildV2ReconnectData(id.P,id.V,guid,false));var response=await b.ExchangeAsync(P7cTests.Wire(reconnect,b));var restored=P7cTests.Id(response);
        await b.ExchangeAsync(P7cTests.Wire(RawSmb.Read(id,1,0,0,0,0),b),(uint)NtStatus.FileClosed);
        Check.That(ReferenceEquals(sequence,open.ChannelSequences)&&ReferenceEquals(slots,open.LockSequences),"actual open retains both sequence owners");await b.ExchangeAsync(P7cTests.Wire(Lock(restored,0x11),b));Check.Equal(1,((InMemoryLockManager)options.LockManager).ActiveLockCount,"duplicate slot not reapplied after reconnect");
        await b.ExchangeAsync(P7cTests.Wire(Lock(restored,0x12,4),b));await b.ExchangeAsync(P7cTests.Wire(Lock(restored,0x12,4),b));Check.Equal(0,((InMemoryLockManager)options.LockManager).ActiveLockCount,"lost unlock replay applied once");await b.CloseAsync(restored);
    }
}
