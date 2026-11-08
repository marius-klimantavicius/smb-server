using Smb.Testing;
using Smb.Protocol.Enums;
using Smb.Server;
using Smb.Server.State;
using Smb.Server.Locking;

static class P7aTests
{
    const uint Unavailable = 0xc0000467;
    public static IEnumerable<(string, Func<Task>)> Cases()
    {
        foreach (var dialect in new ushort[]{0x202,0x210,0x300,0x302,0x311})
        foreach (var profile in new[]{SmbFeaturePolicy.Restricted,SmbFeaturePolicy.CopyOnly,SmbFeaturePolicy.Caching,SmbFeaturePolicy.CachingWithCopy})
        { var di=dialect; var pr=profile; yield return ($"p7a.basic.{di:x}.{Array.IndexOf(new[]{SmbFeaturePolicy.Restricted,SmbFeaturePolicy.CopyOnly,SmbFeaturePolicy.Caching,SmbFeaturePolicy.CachingWithCopy},pr)}",()=>Basic(di,pr)); }
        foreach (var kind in new[]{"write","set","ioctl"})
        foreach (var replay in new[]{false,true})
        {var k=kind;var r=replay;yield return ($"p7a.stale.{k}.{r}",()=>Stale(k,r));}
        foreach (var pair in new (ushort Start,ushort Next,bool New)[]{(0,0x7fff,true),(0,0x8000,false),(0xffff,0,true),(1,0xffff,false)})
        {var p=pair;yield return ($"p7a.serial.{p.Start:x}.{p.Next:x}",()=>Serial(p.Start,p.Next,p.New));}
        foreach(var kind in new[]{"read","write","set","ioctl","query","flush","lock","notify","directory","close"})
        {var k=kind;yield return ($"p7a.advance.{k}",()=>Advance(k));}
        foreach(var replay in new[]{false,true}) {var r=replay;yield return ($"p7a.stale.read.{r}",()=>StaleRead(r));}
        foreach(var kind in new[]{"equal","new","old","cancel","error","close","teardown","out-of-order","wrap-generation"})
        {var k=kind;yield return ($"p7a.physical.{k}",()=>Physical(k));}
        foreach(var kind in new[]{"lock","notify"}) {var k=kind;yield return ($"p7a.pending.{k}",()=>Pending(k));}
        yield return ("p7a.compound.inherited",Compound);
        yield return ("p7a.compound.resumed",Resumed);
        yield return ("p7a.skip.server-ioctl",ServerIoctl);
        yield return ("p7a.ack.classic-fileid",ClassicAck);
        foreach(var kind in new[]{"unsigned","altered","invalid-session"})foreach(var prepared in new[]{false,true}){var k=kind;var pr=prepared;yield return ($"p7a.preservation.{k}.{pr}",()=>Preserve(k,pr));}

        yield return ("p7a.coverage.lease-ack-no-fileid",LeaseAck);

        foreach(var kind in new[]{"execute","abandon","cancel-gate","stale"}) {var k=kind;yield return ($"p7a.prepared.{k}",()=>Prepared(k));}
        foreach(var kind in new[]{"current","prior","total"}) {var k=kind;yield return ($"p7a.exhaustion.{k}",()=>Exhaustion(k));}
        yield return ("p7a.stress.accounting",Stress);
        yield return ("p7a.prepared.pre-core-rejection",PreparedRejected);
        yield return ("p7a.pending.abandon-physical-lock",()=>AbandonedLock(false));
        yield return ("p7a.pending.abandon-before-core-handoff",()=>AbandonedLock(true));

        yield return ("p7a.coverage.replay-new-idle",ReplayIdle);
        foreach(var kind in new[]{"read","stale-read","replay-read","new-replay-read","same-sequence"}){var k=kind;yield return ($"p7a.coverage.physical-{k}",()=>Reader(k));}

        yield return ("p7a.coverage.pipe-create-sequence",PipeCreate);

        foreach(var di in new ushort[]{0x300,0x302}) {var dialect=di;yield return ($"p7a.tcp.{di:x}",()=>Tcp(dialect));}
    }
    static void Status(byte[] b,uint expected,string why)=>Check.Equal(expected,RawSmb.U32(b,8),why);
    internal static byte[] Seq(byte[] b,ushort seq,bool replay=false){RawSmb.Put16(b,8,seq);if(replay)RawSmb.Put32(b,16,RawSmb.U32(b,16)|0x20000000);return b;}
    static P2Tests.Direct Direct(ushort dialect=0x300){var d=new P2Tests.Direct();d.Connection.Dialect=(SmbDialect)dialect;if(dialect>=0x300)d.Session.Channels.TryAdd(d.Connection.ConnectionId,new SmbChannel {Connection=d.Connection,SigningKey=d.Session.SigningKey});return d;}
    static async Task<(ulong P,ulong V)> Open(P2Tests.Direct d,ushort seq=0,bool directory=false)
    {var b=await d.Send(Seq(directory?RawSmb.Create("",true,0,1,42):d.Create(),seq));Status(b,0,"CREATE fixture");return (RawSmb.U64(b,128),RawSmb.U64(b,136));}
    static byte[] Write((ulong P,ulong V) id)=>RawSmb.Write(id,[7],0,0,1,42);
    static byte[] Read((ulong P,ulong V) id)=>RawSmb.Read(id,1,0,0,1,42);
    static byte[] Lock((ulong P,ulong V) id)
    {var b=RawSmb.Header(10,48,0,1,42);RawSmb.Put16(b,64,48);RawSmb.Put16(b,66,1);RawSmb.Put64(b,72,id.P);RawSmb.Put64(b,80,id.V);RawSmb.Put64(b,96,1);RawSmb.Put32(b,104,2);return b;}
    static byte[] Query((ulong P,ulong V) id)
    {var b=RawSmb.Header(16,40,0,1,42);RawSmb.Put16(b,64,41);b[66]=1;b[67]=5;RawSmb.Put32(b,68,24);RawSmb.Put64(b,88,id.P);RawSmb.Put64(b,96,id.V);return b;}
    static byte[] Flush((ulong P,ulong V) id){var b=RawSmb.Header(7,24,0,1,42);RawSmb.Put16(b,64,24);RawSmb.Put64(b,72,id.P);RawSmb.Put64(b,80,id.V);return b;}
    static byte[] Mutate((ulong P,ulong V) id,string kind)=>kind switch{
        "set"=>P6Tests.Set(id,20,new byte[8]),"ioctl"=>P5Tests.Ioctl(id,0x140078,[],32),_=>Write(id)};
    static async Task Basic(ushort dialect,SmbFeaturePolicy policy)
    {await using var d=Direct(dialect);d.Options.FeaturePolicy=policy;var id=await Open(d,11);var before=d.Store.Control.Count("Write");var b=await d.Send(Seq(Write(id),10));Status(b,dialect<0x300?0:Unavailable,"mandatory CREATE initial sequence independent of profile");Check.Equal(before+(dialect<0x300?1:0),d.Store.Control.Count("Write"),"stale mutation backend entry");}
    static async Task Stale(string kind,bool replay)
    {await using var d=Direct();var id=await Open(d,10);var count=d.Store.Control.Count(kind=="set"?"SetEndOfFile":"Write");Status(await d.Send(Seq(Mutate(id,kind),9,replay)),Unavailable,"old mutation rejected before command-specific execution");Check.Equal(count,d.Store.Control.Count(kind=="set"?"SetEndOfFile":"Write"),"no backend mutation");}
    static async Task Serial(ushort start,ushort next,bool newer)
    {await using var d=Direct();var id=await Open(d,start);Status(await d.Send(Seq(Write(id),next)),newer?0:Unavailable,"unsigned sixteen-bit serial boundary");if(newer)Status(await d.Send(Seq(Write(id),start)),Unavailable,"new sequence became current");}
    static async Task Advance(string kind)
    {
        await using var d=Direct();d.Options.DirectoryWatcher=new FakeWatcher();var transport=new RecordingTransport();transport.Attach(d.Connection);
        var id=await Open(d,0,kind is "notify" or "directory");
        var request=kind switch {"read"=>Read(id),"set"=>Mutate(id,"set"),"ioctl"=>P5Tests.Ioctl(id,0xdeadbeef,[],0),"query"=>Query(id),"flush"=>Flush(id),"lock"=>Lock(id),"notify"=>P4Tests.Notify(id),"directory"=>RawSmb.Enumerate(id,0,1,42),"close"=>RawSmb.Close(id,0,1,42),_=>Write(id)};
        if(kind=="close") {var barrier=new AsyncBarrier();RawSmb.Put16(request,66,1);d.Store.Control.Enqueue("GetInfo",new OperationStep(Barrier:barrier));var close=d.Send(Seq(request,1));await barrier.Entered.WaitAsync(Check.Timeout);try{Status(await d.Send(Seq(Write(id),0)),Unavailable,"CLOSE sequence established before physical close drain");}finally{barrier.Release();await close;}return;}
        await d.Send(Seq(request,1));Status(await d.Send(Seq(Write(id),0)),Unavailable,"FileId command advances sequence even when command fails later");
    }
    static async Task StaleRead(bool replay)
    {await using var d=Direct();var id=await Open(d,10);d.Store.Seed("unused",[]);Status(await d.Send(Seq(Read(id),9,replay)),0xc0000011,"old READ uses normal EOF behavior");Status(await d.Send(Seq(Write(id),9)),Unavailable,"old READ cannot rewind current");Status(await d.Send(Seq(Write(id),10,true)),0,"old READ did not strand prior accounting");}
    static async Task Physical(string kind)
    {
        await using var d=Direct();var id=await Open(d);var state=d.Session.Opens[id].ChannelSequences;var other=await d.Open("other");var c=d.Channel();c.Dialect=SmbDialect.Smb300;c.Sessions.TryAdd(1,d.Session);
        var gate=new AsyncBarrier();d.Store.Control.Enqueue("Write",new OperationStep(Barrier:gate,IgnoreCancellation:true,Error:kind=="error"?new IOException("controlled physical fault"):null));
        var first=d.Send(Seq(Write(id),0));await gate.Entered.WaitAsync(Check.Timeout);var physicalFinished=d.Connection.OrdinaryRequests.Values.Single().PhysicalFinished;
        Task<byte[]>? teardown=null;Task<byte[]>? second=null;AsyncBarrier? gate2=null;
        try
        {
            Status(await d.Send(Seq(Write(other),0),c),0,"unrelated open continues");
            if(kind=="cancel") {var mid=d.Connection.OrdinaryRequests.Keys.Single();var cancel=RawSmb.Header(12,4,mid,1,42);RawSmb.Put16(cancel,64,4);Sign(d,cancel);await d.Dispatcher.ProcessMessageAsync(d.Connection,cancel);Status(await first.WaitAsync(Check.Timeout),0xc0000120,"cancelled response before physical completion");}
            if(kind=="out-of-order" || kind=="wrap-generation")
            {gate2=new AsyncBarrier();d.Store.Control.Enqueue("Write",new OperationStep(Barrier:gate2,IgnoreCancellation:true));second=d.Send(Seq(Write(id),0));await gate2.Entered.WaitAsync(Check.Timeout);}
            Status(await d.Send(Seq(Read(id),1),c),0xc0000011,"advance while old backend remains pending");
            if(kind=="wrap-generation") {Status(await d.Send(Seq(Read(id),0x7fff),c),0xc0000011,"half-range step");Status(await d.Send(Seq(Read(id),0xfffe),c),0xc0000011,"next step");Status(await d.Send(Seq(Read(id),0),c),0xc0000011,"numeric sequence reused while original generation pending");}
            var replaySeq=(ushort)(kind=="new"?2:kind=="old"?0:kind=="wrap-generation"?0:1);
            Status(await d.Send(Seq(Write(id),replaySeq,true),c),Unavailable,"replay cannot overtake older physical work");
            if(kind=="new")Status(await d.Send(Seq(Write(id),1),c),Unavailable,"rejected new replay still advances sequence per SHOULD choice");
            if(kind=="close")teardown=d.Send(Seq(RawSmb.Close(id,0,1,42),1),c);
            if(kind=="teardown")teardown=d.Send(RawSmb.TreeDisconnect(0,1,42),c);
            if(teardown!=null)Check.That(!teardown.IsCompleted,"teardown drains physical backend");
            if(second!=null){gate2!.Release();await second.WaitAsync(Check.Timeout);Status(await d.Send(Seq(Write(id),replaySeq,true),c),Unavailable,"one out-of-order retirement leaves original prior alive");}
        }
        finally{gate.Release();gate2?.Release();await first.WaitAsync(Check.Timeout);await physicalFinished.WaitAsync(Check.Timeout);if(second!=null)await second.WaitAsync(Check.Timeout);if(teardown!=null)await teardown.WaitAsync(Check.Timeout);}
        Check.Equal(0L,state.Snapshot.Current,"physical current returns to baseline");Check.Equal(0L,state.Snapshot.Prior,"physical prior returns to baseline");
        if(teardown==null){var current=(ushort)(kind=="new"?2:kind=="wrap-generation"?0:1);Status(await d.Send(Seq(Write(id),current,true),c),0,"replay after physical retirement");Status(await d.Send(Seq(Write(id),current,true),c),0,"no leaked or double-decremented counter");}
    }
    static void Sign(P2Tests.Direct d,byte[] b){RawSmb.Sign(b,d.Session.SigningKey);Smb.Crypto.Smb2Signer.SignInPlace(Smb.Crypto.Smb2Signer.ResolveAlgorithm(d.Connection.Dialect,d.Connection.SigningAlgorithmId),d.Session.SigningKey,b,0,false,false);}
    static async Task Pending(string kind)
    {
        await using var d=Direct();var watcher=new FakeWatcher();d.Options.DirectoryWatcher=watcher;var transport=new RecordingTransport();transport.Attach(d.Connection);
        var id=await Open(d,0,kind=="notify");var owner=await d.Open("blocker");
        if(kind=="lock"){var open=d.Session.Opens[owner];open.ShareModeKey=d.Session.Opens[id].IdentityKey;await d.Options.LockManager.ApplyAsync(open,[new LockElement(0,1,true,false)],true,default);}
        var interim=await d.Send(Seq(kind=="notify"?P4Tests.Notify(id):Lock(id),0));Status(interim,0x103,"pending fixture");var pending=d.Connection.PendingRequests.Values.Single();
        Status(await d.Send(Seq(P5Tests.Ioctl(id,0xdeadbeef,[],0),1)),0xc0000010,"advance via ordinary unsupported IOCTL");
        Status(await d.Send(Seq(Write(id),1,true)),Unavailable,"pending original is prior until completion");
        if(kind=="lock")d.Options.LockManager.ReleaseOwner(d.Session.Opens[owner]);else watcher.Subscriptions.Single().Emit(new Smb.Server.Notification.FileNotifyEvent(Smb.Server.Notification.FileNotifyAction.Added,"x"));
        await pending.Finished.WaitAsync(Check.Timeout);Status(await d.Send(Seq(P5Tests.Ioctl(id,0xdeadbeef,[],0),2,true)),0xc0000010,"pending retirement releases accounting");
    }
    static byte[] Join(P2Tests.Direct d,params byte[][] requests)
    {var size=requests.Select((b,i)=>i+1<requests.Length?(b.Length+7)&~7:b.Length).Sum();var result=new byte[size];var offset=0;for(var i=0;i<requests.Length;i++){var b=new byte[i+1<requests.Length?(requests[i].Length+7)&~7:requests[i].Length];requests[i].CopyTo(b,0);RawSmb.Put64(b,24,(ulong)(20+i));if(i+1<requests.Length)RawSmb.Put32(b,20,(uint)((b.Length+7)&~7));if(i>0){RawSmb.Put32(b,16,RawSmb.U32(b,16)|4);RawSmb.Put64(b,40,ulong.MaxValue);RawSmb.Put32(b,36,uint.MaxValue);}Sign(d,b);b.CopyTo(result,offset);offset+=(b.Length+7)&~7;}return result;}
    static async Task Compound()
    {await using var d=Direct();var create=Seq(d.Create(),7);var write=Seq(Write((ulong.MaxValue,ulong.MaxValue)),6);var b=await d.Dispatcher.ProcessMessageAsync(d.Connection,Join(d,create,write));var offset=(int)RawSmb.U32(b,20);Check.Equal(Unavailable,RawSmb.U32(b,offset+8),"inherited FileId resolved before channel sequence");Check.Equal(0,d.Store.Control.Count("Write"),"compound stale WRITE has no side effect");}
    static async Task Resumed()
    {await using var d=Direct();var w=new FakeWatcher();d.Options.DirectoryWatcher=w;var t=new RecordingTransport();t.Attach(d.Connection);var id=await Open(d,0,true);
     var bytes=Join(d,Seq(P4Tests.Notify(id),0),Seq(Write((ulong.MaxValue,ulong.MaxValue)),0));var interim=await d.Dispatcher.ProcessMessageAsync(d.Connection,bytes);await t.SendAsync(interim,false);
     Status(await d.Send(Seq(P5Tests.Ioctl(id,0xdeadbeef,[],0),1)),0xc0000010,"advance before deferred command resolves");w.Subscriptions.Single().Emit(new Smb.Server.Notification.FileNotifyEvent(Smb.Server.Notification.FileNotifyAction.Added,"x"));
     var child=d.Connection.PendingRequests.GetValueOrDefault(21UL);if(child!=null)await child.Finished.WaitAsync(Check.Timeout);var final=t.Sends.Select(x=>x.Message).Last(b=>RawSmb.U64(b,24)==21);Status(final,Unavailable,"resumed request sequence checked once against resolved open");Check.Equal(0,d.Store.Control.Count("Write"),"resumed stale write cannot enter backend");}
    static async Task ServerIoctl()
    {await using var d=Direct();var id=await Open(d,10);Status(await d.Send(Seq(P5Tests.Ioctl((ulong.MaxValue,ulong.MaxValue),0x1401fc,[],0),11)),0xc00000bb,"server IOCTL sentinel remains server scoped");Status(await d.Send(Seq(Write(id),10,true)),0,"server IOCTL does not change unrelated open");}





    static async Task Preserve(string kind,bool prepared)
    {
        await using var d=Direct();var id=await Open(d);var b=Seq(Write(id),1);RawSmb.Put64(b,24,20);Sign(d,b);
        if(kind=="unsigned")RawSmb.Put32(b,16,0);else if(kind=="altered")b[48]^=1;else d.Session.State=SessionState.Expired;
        byte[] response;
        try
        {
            if(prepared){Check.That(d.Dispatcher.TryBeginConcurrentFrame(d.Connection,b,false,out var frame),"preservation prepared fixture");response=await d.Dispatcher.ExecutePreparedFrameAsync(d.Connection,frame);}
            else response=await d.Dispatcher.ProcessMessageAsync(d.Connection,b);
            Status(response,kind=="invalid-session"?0xc0000203u:0xc0000022u,"existing prerequisite rejection unchanged");
        }
        finally{d.Session.State=SessionState.Valid;}
        Status(await d.Send(Seq(Write(id),0)),0,"a request rejected by existing prerequisites must not change sequence state");
        Check.Equal(1,d.Store.Control.Count("Write"),"only the valid request reaches backend");
    }
    static async Task ClassicAck()
    {await using var d=Direct();var id=await Open(d);Status(await d.Send(Seq(P6Tests.Ack(id,OplockLevel.None),1)),0xc0000184,"unsolicited classic ACK ordinary status");Status(await d.Send(Seq(Write(id),0)),Unavailable,"classic ACK includes FileId and must advance sequence");Check.Equal(0L,d.Session.Opens[id].ChannelSequences.Snapshot.Current,"classic ACK count balanced");}
    static async Task LeaseAck()
    {await using var d=Direct();var id=await Open(d);await d.Send(Seq(P6Tests.LeaseAck(new Smb.Protocol.Messages.LeaseKey(1,2)),1));Status(await d.Send(Seq(Write(id),0,true)),0,"lease ACK has no FileId and must skip channel sequence");}
    static async Task Reader(string kind)
    {
        await using var d=Direct();var id=await Open(d);var state=d.Session.Opens[id].ChannelSequences;var gate=new AsyncBarrier();d.Store.Control.Enqueue("Read",new OperationStep(Barrier:gate,IgnoreCancellation:true));
        var reading=d.Send(Seq(Read(id),0));await gate.Entered.WaitAsync(Check.Timeout);var physical=d.Connection.OrdinaryRequests.Values.Single().PhysicalFinished;
        try
        {
            Check.Equal((0,1L,0L),((int)state.Snapshot.Sequence,state.Snapshot.Current,state.Snapshot.Prior),"current reader counted once");
            if(kind=="same-sequence")Status(await d.Send(Seq(Write(id),0,true)),0,"equal replay is allowed with current work and no prior work");
            else
            {
                Status(await d.Send(Seq(Read(id),1)),0xc0000011,"advance over physical reader");
                if(kind is "stale-read" or "replay-read")Status(await d.Send(Seq(Read(id),0,kind=="replay-read")),0xc0000011,"old nonmutating command retains normal semantics");
                if(kind=="new-replay-read")Status(await d.Send(Seq(Read(id),2,true)),0xc0000011,"new nonmutating replay proceeds with prior work");
                var snapshot=state.Snapshot;Check.Equal(0L,snapshot.Current,"unadmitted nonmutating command does not borrow a counter");Check.Equal(1L,snapshot.Prior,"prior physical reader survives nonmutating request completion");
                Status(await d.Send(Seq(Write(id),snapshot.Sequence,true)),Unavailable,"reader physical lifetime blocks mutating replay");
            }
        }
        finally {gate.Release();await reading.WaitAsync(Check.Timeout);await physical.WaitAsync(Check.Timeout);}
        Check.Equal(0L,state.Snapshot.Current,"physical read current baseline");Check.Equal(0L,state.Snapshot.Prior,"physical read prior baseline");Status(await d.Send(Seq(Write(id),state.Snapshot.Sequence,true)),0,"reader retirement opens replay admission");
    }
    static async Task PreparedRejected()
    {
        await using var d=Direct();d.Options.FeaturePolicy=SmbFeaturePolicy.Caching;var id=await Open(d);d.Options.MaxOutstandingRequests=0;
        var request=Seq(Write(id),0);RawSmb.Put64(request,24,20);Sign(d,request);Check.That(d.Dispatcher.TryBeginConcurrentFrame(d.Connection,request,false,out var frame),"prepared rejection fixture");
        Status(await d.Dispatcher.ExecutePreparedFrameAsync(d.Connection,frame),0xc000009a,"pending-cap pre-core error");d.Options.MaxOutstandingRequests=100;
        Status(await d.Send(Seq(Read(id),1)),0xc0000011,"advance after rejected prepared frame");Status(await d.Send(Seq(Write(id),1,true)),0,"pre-core rejection must release prepared ticket");
    }
    sealed class SlowLocks : ILockManager
    {
        public readonly AsyncBarrier Gate= new AsyncBarrier();
        public Action? OnEnter;
        public readonly TaskCompletionSource Finished= new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously);
        public async Task<LockOutcome> ApplyAsync(SmbOpen owner,IReadOnlyList<LockElement> elements,bool immediate,CancellationToken token)
        {OnEnter?.Invoke();await Gate.WaitAsync();Finished.TrySetResult();return LockOutcome.Granted;}
        public bool IsRangeAccessible(SmbOpen owner,ulong offset,ulong length,bool write)=>true;
        public void ReleaseOwner(SmbOpen owner){}
    }
    static async Task AbandonedLock(bool early)
    {
        await using var d=Direct();var locks=new SlowLocks();d.Options.LockManager=locks;var id=await Open(d);var state=d.Session.Opens[id].ChannelSequences;
        if(early)locks.OnEnter=()=>d.Connection.PendingRequests.Values.Single().Abandon();
        Status(await d.Send(Seq(Lock(id),0)),0x103,"physical lock pending fixture");await locks.Gate.Entered.WaitAsync(Check.Timeout);var pending=d.Connection.PendingRequests.Values.SingleOrDefault();
        try{Status(await d.Send(Seq(Read(id),1)),0xc0000011,"advance over slow lock");pending?.Abandon();Status(await d.Send(Seq(Write(id),1,true)),Unavailable,"abandoned response cannot retire physical lock producer");}
        finally{locks.Gate.Release();await locks.Finished.Task.WaitAsync(Check.Timeout);}
        using var timeout=new CancellationTokenSource(Check.Timeout);while(state.Snapshot.Prior!=0)await Task.Delay(1,timeout.Token);
        Status(await d.Send(Seq(Write(id),1,true)),0,"physical lock retirement releases ticket despite abandoned response");
    }
    static async Task PipeCreate()
    {await using var d=Direct();d.Session.TreeConnects.TryRemove(42,out _);d.Tree=new SmbTreeConnect{TreeId=42,Session=d.Session,Share=Smb.FileSystem.Share.CreateIpc(),MaximalAccess=0x1f01ff};d.Session.TreeConnects.TryAdd(42,d.Tree);var b=await d.Send(Seq(RawSmb.Create("srvsvc",false,0,1,42),10));Status(b,0,"pipe CREATE fixture");var id=(RawSmb.U64(b,128),RawSmb.U64(b,136));Status(await d.Send(Seq(Write(id),9)),Unavailable,"pipe CREATE initializes same per-open sequence");}
    static async Task ReplayIdle()
    {await using var d=Direct();var id=await Open(d,1);Status(await d.Send(Seq(Write(id),2,true)),0,"new replay with no old work is admitted");Status(await d.Send(Seq(Write(id),1)),Unavailable,"new idle replay establishes sequence");var state=d.Session.Opens[id].ChannelSequences.Snapshot;Check.Equal((2,(long)0,(long)0),((int)state.Sequence,state.Current,state.Prior),"idle counters balanced");}
    static async Task Prepared(string kind)
    {
        await using var d=Direct();d.Options.ConcurrentMetadataOps=true;var id=await Open(d);var b=Seq(Write(id),(ushort)(kind=="stale"?0:1));RawSmb.Put64(b,24,20);Sign(d,b);
        if(kind=="stale")Status(await d.Send(Seq(Read(id),1)),0xc0000011,"advance before preparing stale write");
        Check.That(d.Dispatcher.TryBeginConcurrentFrame(d.Connection,b,false,out var frame),"prepared fixture admitted once");
        AsyncBarrier? blockerGate=null;Task<byte[]>? blockerTask=null;
        if(kind=="cancel-gate")
        {
            blockerGate=new AsyncBarrier();d.Store.Control.Enqueue("Flush",new OperationStep(Barrier:blockerGate));var read=Seq(Flush(id),1);RawSmb.Put64(read,24,19);Sign(d,read);
            Check.That(d.Dispatcher.TryBeginConcurrentFrame(d.Connection,read,false,out var blocker),"gate blocker fixture");blocker=d.Dispatcher.ReserveScope(blocker);blockerTask=d.Dispatcher.ExecutePreparedFrameAsync(d.Connection,blocker).AsTask();await blockerGate.Entered.WaitAsync(Check.Timeout);
        }
        var held=d.Dispatcher.ReserveScope(frame);
        if(kind=="stale") {Status(await d.Dispatcher.ExecutePreparedFrameAsync(d.Connection,held),Unavailable,"prepared stale fails before backend");return;}
        Status(await d.Send(Seq(Read(id),2)),0xc0000011,"new channel advances over queued prepared request");
        try{Status(await d.Send(Seq(Write(id),2,true)),Unavailable,"queued prepared work counts as prior before execution");}
        catch {await d.Dispatcher.AbandonPreparedFrameAsync(d.Connection,held);blockerGate?.Release();if(blockerTask!=null)await blockerTask;throw;}
        if(kind=="execute")Status(await d.Dispatcher.ExecutePreparedFrameAsync(d.Connection,held),0,"prepared admitted sequence is not processed twice after newer request");
        else if(kind=="abandon")await d.Dispatcher.AbandonPreparedFrameAsync(d.Connection,held);
        else {try{await d.Dispatcher.ExecutePreparedFrameAsync(d.Connection,held,new CancellationToken(true));throw new InvalidOperationException("missing gate cancellation");}catch(OperationCanceledException){}}
        blockerGate?.Release();if(blockerTask!=null)await blockerTask.WaitAsync(Check.Timeout);
        Status(await d.Send(Seq(Write(id),2,true)),0,"prepared retirement releases one ticket");Check.Equal((long)0,d.Session.Opens[id].ChannelSequences.Snapshot.Prior,"prepared prior drained");
    }
    [System.Diagnostics.CodeAnalysis.DynamicDependency(System.Diagnostics.CodeAnalysis.DynamicallyAccessedMemberTypes.NonPublicFields,typeof(ChannelSequenceState))]
    static async Task Exhaustion(string kind)
    {
        await using var d=Direct();var id=await Open(d);var state=d.Session.Opens[id].ChannelSequences;
        // Seed numerical exhaustion, without allocating billions of work items. No production test hook.
        var prior=typeof(ChannelSequenceState).GetField("_prior",System.Reflection.BindingFlags.Instance|System.Reflection.BindingFlags.NonPublic)!;
        var count=typeof(ChannelSequenceState).GetField("_outstanding",System.Reflection.BindingFlags.Instance|System.Reflection.BindingFlags.NonPublic)!;
        long old=kind=="current"?int.MaxValue:kind=="total"?int.MaxValue-1:0;
        prior.SetValue(state,kind=="prior"?(long)int.MaxValue:kind=="total"?1L:0L);count.SetValue(state,old);
        var snapshot=state.Snapshot;
        try{Status(await d.Send(Seq(Write(id),(ushort)(kind=="prior"?1:0))),0xc000009a,"bounded total accounting rejects admission honestly");Check.Equal(snapshot,state.Snapshot,"exhaustion does not partly mutate sequence or counts");}
        finally{prior.SetValue(state,0L);count.SetValue(state,0L);}
    }
    static Task Stress()
    {
        var state=new ChannelSequenceState();var tickets=new List<IDisposable>();
        for(var round=0;round<256;round++)
        {
            var seq=(ushort)(round*32767);Check.Equal(NtStatus.Success,state.TryAdmit(seq,false,SmbCommand.Write,out var ticket),"stress serial admission");tickets.Add(ticket!);
            if(round%4==3){Parallel.ForEach(tickets,t=>{t.Dispose();t.Dispose();});tickets.Clear();Check.Equal((long)0,state.Snapshot.Prior,"generation tickets drain prior");Check.Equal((long)0,state.Snapshot.Current,"generation tickets drain current");}
        }
        var tasks=Enumerable.Range(0,32).Select(_=>Task.Run(()=>{for(var i=0;i<128;i++){Check.Equal(NtStatus.Success,state.TryAdmit(state.Snapshot.Sequence,false,SmbCommand.Read,out var t),"parallel equal admission");t!.Dispose();t.Dispose();}})).ToArray();
        Task.WaitAll(tasks);Check.Equal((long)0,state.Snapshot.Prior,"parallel prior balanced");Check.Equal((long)0,state.Snapshot.Current,"parallel current balanced");return Task.CompletedTask;
    }
    static async Task Tcp(ushort dialect)
    {await using var h=new HostFixture();await h.StartAsync();await using var c=new WireClient();await c.ConnectAsync(h.Server.Endpoint,HostFixture.Domain,HostFixture.User,HostFixture.Password,dialect);
     var b=await c.ExchangeAsync(Seq(RawSmb.Create("a",false,c.NextMessageId(),c.Session,c.Tree),0xffff));var id=(RawSmb.U64(b,128),RawSmb.U64(b,136));
     await c.ExchangeAsync(Seq(RawSmb.Write(id,[1],0,c.NextMessageId(),c.Session,c.Tree),0xffff));await c.ExchangeAsync(Seq(RawSmb.Write(id,[2],0,c.NextMessageId(),c.Session,c.Tree),0));
     await c.ExchangeAsync(Seq(RawSmb.Write(id,[3],0,c.NextMessageId(),c.Session,c.Tree),0xffff,true),Unavailable);Check.Equal(2,h.Store.Control.Count("Write"),"signed stale replay never enters backend");
     await c.ExchangeAsync(Seq(RawSmb.Write(id,[4],0,c.NextMessageId(),c.Session,c.Tree),0,true));await c.CloseAsync(id);Check.Equal(0,h.Store.ActiveHandles,"TCP cleanup");}
}
