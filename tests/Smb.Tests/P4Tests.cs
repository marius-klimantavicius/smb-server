using Smb.Testing;
using Smb.Protocol.Enums;
using Smb.Server.Locking;
using Smb.Server.Notification;
using Smb.Server.State;
using System.Diagnostics.CodeAnalysis;
using System.Reflection;
using Smb.Server.Rpc;
using Smb.Server.Witness;

internal static class P4Tests
{
    public static IEnumerable<(string, Func<Task>)> Cases()
    {
        yield return ("p4.lock.callback-gate-inversion", ()=>LockInversion("release"));
        yield return ("p4.lock.callback-unlock-gate", ()=>LockInversion("unlock"));
        yield return ("p4.lock.callback-release-waiter-gate", ()=>LockInversion("cancel-owner"));
        yield return ("p4.notify.synchronous-before-watch-returns", EarlyNotify);
        yield return ("p4.notify.local-watcher-error", LocalWatcherError);
        yield return ("p4.notify.record-padding", NotifyPadding);
        yield return ("p4.notify.interim-transmission-barrier", SendBarrier);
        yield return ("p4.notify.events-between-calls", BetweenCalls);
        yield return ("p4.notify.empty-filter", EmptyFilter);
        yield return ("p4.notify.error-rescan", ErrorNotify);
        yield return ("p4.notify.rescan-response-layout", ()=>ErrorLayout(true));
        yield return ("p4.notify.error-response-layout", ()=>ErrorLayout(false));
        yield return ("p4.notify.initial-policy", InitialPolicy);
        yield return ("p4.notify.bounded-queue", BoundedNotify);
        yield return ("p4.pending.lock-before-interim", PendingLock);
        yield return ("p4.pending.failed-final-abandoned", FailedFinal);
        yield return ("p4.control.host-cancel-read", ()=>HostControl(false));
        yield return ("p4.control.host-cancel-write", ()=>HostControl(false,false,true));
        yield return ("p4.control.host-tree-teardown", ()=>HostControl(true));
        yield return ("p4.control.host-serial-cancel", ()=>HostControl(false,true));
        yield return ("p4.control.ignoring-backend-drains", IgnoringBackend);
        yield return ("p4.notify.cancel-message-before-interim", ()=>CancelNotify(false));
        yield return ("p4.notify.cancel-async-before-interim", ()=>CancelNotify(true));
        yield return ("p4.notify.fifo-rename", FifoRename);
        yield return ("p4.notify.close-inside-watch", CloseInsideWatch);
        yield return ("p4.lock.release-unlock-cancel-stress", LockRaces);
        yield return ("p4.pending.witness-before-interim", Witness);
        yield return ("p4.control.duplicate-keeps-physical-owner", DuplicateOrdinary);
        yield return ("p4.notify.credit-charge", NotifyCharge);
        yield return ("p4.notify.max-transact", NotifyMax);
        yield return ("p4.compound.earlier-results-and-flags", CompoundEarlier);
        yield return ("p4.compound.pending-invalid-header", CompoundBadHeader);
        yield return ("p4.compound.pending-resource-cap", CompoundCap);
        yield return ("p4.compound.retained-request-owned", RetainedRequest);
        yield return ("p4.pending.cancel-callback-fault", CancelFault);
        yield return ("p4.stress.pending-resources", PendingStress);
        yield return ("p4.pending.resource-once", PendingResources);
        yield return ("p4.control.shutdown-queued-physical", ShutdownQueued);
        foreach (var kind in new[]{"lock-success","lock-cancel","notify-success","notify-cancel","notify-unrelated"}) yield return ("p4.compound."+kind,()=>Compound(kind));
    }
    public static byte[] Notify((ulong P,ulong V) id, uint filter=1, uint size=4096)
    {
        var b=RawSmb.Header(15,32,0,1,42);RawSmb.Put16(b,64,32);RawSmb.Put32(b,68,size);RawSmb.Put64(b,72,id.P);RawSmb.Put64(b,80,id.V);RawSmb.Put32(b,88,filter);return b;
    }
    static async Task<(ulong P,ulong V)> Directory(P2Tests.Direct d)
    {var b=await d.Send(RawSmb.Create("",true,0,1,42));Check.Equal(0u,RawSmb.U32(b,8),"directory open");return (RawSmb.U64(b,128),RawSmb.U64(b,136));}
    static async Task EarlyNotify()
    {
        await using var d=new P2Tests.Direct { CommitResponses = false };var w=new FakeWatcher();d.Options.DirectoryWatcher=w;var t=new RecordingTransport();t.Attach(d.Connection);
        w.OnWatch=s=>s.Emit(new FileNotifyEvent(FileNotifyAction.Added,"early"));var id=await Directory(d);var interim=await d.Send(Notify(id));
        Check.Equal(0,t.Control.Count("Send"),"no final before interim transmission");
        await t.SendAsync(interim,false);await t.WaitForSendAsync();await t.WaitForSendAsync();
        Check.Equal(0x103u,RawSmb.U32(t.Sends[0].Message,8),"interim first");Check.Equal(0u,RawSmb.U32(t.Sends[1].Message,8),"one final");
        Check.That(d.Connection.PendingRequests.IsEmpty,"early callback leaves no stale pending entry");
    }
    static async Task SendBarrier()
    {
        await using var d=new P2Tests.Direct { CommitResponses = false };var w=new FakeWatcher();d.Options.DirectoryWatcher=w;var t=new RecordingTransport();t.Attach(d.Connection);
        var id=await Directory(d);var interim=await d.Send(Notify(id));var barrier=new AsyncBarrier();t.Control.Enqueue("Send",new OperationStep(Barrier:barrier));
        var sending=t.SendAsync(interim,false);await barrier.Entered;
        try {w.Subscriptions[0].Emit(new FileNotifyEvent(FileNotifyAction.Added,"during-send"));Check.Equal(1,t.Control.Count("Send"),"final cannot enter sender while interim uncommitted");}
        finally {barrier.Release();await sending;}
        await t.WaitForSendAsync();await t.WaitForSendAsync();Check.Equal(2,t.Sends.Length,"one interim one final");
    }
    static async Task BetweenCalls()
    {
        await using var d=new P2Tests.Direct { CommitResponses = false };var w=new FakeWatcher();d.Options.DirectoryWatcher=w;var t=new RecordingTransport();t.Attach(d.Connection);var id=await Directory(d);
        var b=await d.Send(Notify(id));await t.SendAsync(b,false);w.Subscriptions[0].Emit(new FileNotifyEvent(FileNotifyAction.Added,"first"));
        await t.WaitForSendAsync();await t.WaitForSendAsync();Check.Equal(1,w.ActiveCount,"watcher persists after first response");
        w.Subscriptions[0].Emit(new FileNotifyEvent(FileNotifyAction.Added,"between"));b=await d.Send(Notify(id));
        Check.That(System.Text.Encoding.Unicode.GetString(b).Contains("between"),"queued event returned on next call");Check.Equal(1,w.Subscriptions.Length,"no rearm gap");
    }
    static async Task EmptyFilter()
    {
        await using var d=new P2Tests.Direct { CommitResponses = false };var w=new FakeWatcher();d.Options.DirectoryWatcher=w;var t=new RecordingTransport();t.Attach(d.Connection);var id=await Directory(d);
        var b=await d.Send(Notify(id,0x80000000));w.Subscriptions.FirstOrDefault()?.Emit(new FileNotifyEvent(FileNotifyAction.Added,"ignored"));
        Check.Equal(0,t.Control.Count("Send"),"all-invalid filter remains pending despite events");Check.Equal(1,d.Connection.PendingRequests.Count,"pending until cancellation or close");
    }
    static async Task ErrorNotify()
    {
        await using var d=new P2Tests.Direct { CommitResponses = false };var w=new FakeWatcher();d.Options.DirectoryWatcher=w;var t=new RecordingTransport();t.Attach(d.Connection);var id=await Directory(d);
        var b=await d.Send(Notify(id));await t.SendAsync(b,false);w.Subscriptions[0].Fail(NtStatus.NotifyEnumDir);
        Check.Equal(2,t.Control.Count("Send"),"watcher loss completes outstanding request with rescan");Check.Equal(0x10cu,RawSmb.U32(t.Sends.Last().Message,8),"STATUS_NOTIFY_ENUM_DIR");
    }
    static async Task InitialPolicy()
    {
        await using var d=new P2Tests.Direct { CommitResponses = false };var w=new FakeWatcher();d.Options.DirectoryWatcher=w;var t=new RecordingTransport();t.Attach(d.Connection);var id=await Directory(d);
        var b=Notify(id,1);RawSmb.Put16(b,66,1);b=await d.Send(b);await t.SendAsync(b,false);w.Subscriptions[0].Emit(new FileNotifyEvent(FileNotifyAction.Added,"sub\\first"));
        await t.WaitForSendAsync();await t.WaitForSendAsync();await d.Send(Notify(id,0x10));Check.Equal(1,w.Subscriptions.Length,"subsequent filter/subtree ignored");Check.That(w.Subscriptions[0].Subtree,"initial subtree retained");
    }
    static async Task BoundedNotify()
    {
        await using var d=new P2Tests.Direct { CommitResponses = false };var w=new FakeWatcher();d.Options.DirectoryWatcher=w;var t=new RecordingTransport();t.Attach(d.Connection);var id=await Directory(d);
        var b=await d.Send(Notify(id));await t.SendAsync(b,false);w.Subscriptions[0].Emit(new FileNotifyEvent(FileNotifyAction.Added,"first"));await t.WaitForSendAsync();await t.WaitForSendAsync();
        for(var i=0;i<10000;i++)w.Subscriptions[0].Emit(new FileNotifyEvent(FileNotifyAction.Added,"queued-"+i));
        b=await d.Send(Notify(id));Check.Equal(0x10cu,RawSmb.U32(b,8),"bounded buffer exhaustion forces rescan");
    }
    static byte[] LockRequest((ulong P,ulong V) id)
    {var b=RawSmb.Header(10,48,0,1,42);RawSmb.Put16(b,64,48);RawSmb.Put16(b,66,1);RawSmb.Put64(b,72,id.P);RawSmb.Put64(b,80,id.V);RawSmb.Put64(b,96,1);RawSmb.Put32(b,104,2);return b;}
    static async Task PendingLock()
    {
        await using var d=new P2Tests.Direct{CommitResponses=false};var b=await d.Open();var locks=new ControlledLocks();d.Options.LockManager=locks;
        var t=new RecordingTransport();t.Attach(d.Connection);var interim=await d.Send(LockRequest(b));
        locks.Result.SetResult(LockOutcome.Granted); // Inline task continuation forces completion before the next assertion.
        Check.Equal(0,t.Control.Count("Send"),"lock final waits for actual interim transmission");await t.SendAsync(interim,false);await t.WaitForSendAsync();await t.WaitForSendAsync();
        Check.Equal((ushort)0,RawSmb.U16(t.Sends.Last().Message,14),"final grants zero");
    }
    sealed class ControlledLocks : ILockManager
    {
        public readonly TaskCompletionSource<LockOutcome> Result= new TaskCompletionSource<LockOutcome>();
        public Task<LockOutcome> ApplyAsync(SmbOpen owner,IReadOnlyList<LockElement> elements,bool fail,CancellationToken ct) {ct.Register(()=>Result.TrySetResult(LockOutcome.Cancelled));return Result.Task;}
        public bool IsRangeAccessible(SmbOpen owner,ulong offset,ulong length,bool write)=>true;
        public void ReleaseOwner(SmbOpen owner) { }
    }
    static async Task FailedFinal()
    {
        await using var d=new P2Tests.Direct{CommitResponses=false};var w=new FakeWatcher();d.Options.DirectoryWatcher=w;var t=new RecordingTransport();t.Attach(d.Connection);var id=await Directory(d);
        var interim=await d.Send(Notify(id));var p=d.Connection.PendingRequests.Values.Single();await t.SendAsync(interim,false);t.Control.Enqueue("Send",new OperationStep(Error:new IOException("lost final")));
        w.Subscriptions[0].Emit(new FileNotifyEvent(FileNotifyAction.Added,"failure"));await p.Finished.WaitAsync(Check.Timeout);Check.Equal(PendingRequestState.Abandoned,p.State,"failed final explicitly abandons transport");Check.That(d.Connection.PendingRequests.IsEmpty && d.Connection.AsyncRequests.IsEmpty,"both maps removed");
    }
    static async Task HostControl(bool teardown, bool serial=false, bool write=false)
    {
        await using var h=new HostFixture();if(serial)h.Server.State.Options.MaxConcurrentFileOpsPerConnection=1;await h.StartAsync();await using var c=await h.ConnectAsync();var id=await c.CreateAsync("blocked");await c.WriteAsync(id,[1]);
        var gate=new AsyncBarrier();h.Store.Control.Enqueue(write?"Write":"Read",new OperationStep(Barrier:gate));var mid=c.NextMessageId();await c.SendAsync(write?RawSmb.Write(id,[2],0,mid,c.Session,c.Tree):RawSmb.Read(id,1,0,mid,c.Session,c.Tree));await gate.Entered;
        try
        {
            if(teardown)await c.SendAsync(RawSmb.TreeDisconnect(c.NextMessageId(),c.Session,c.Tree));
            else {var b=RawSmb.Header(12,4,mid,c.Session,c.Tree);RawSmb.Put16(b,64,4);await c.SendAsync(b);}
            var response=await c.ReceiveAsync().WaitAsync(TimeSpan.FromSeconds(2));Check.Equal(mid,RawSmb.U64(response,24),"blocked response identity");Check.Equal(0xc0000120u,RawSmb.U32(response,8),"control reaches blocked backend without drain");
            if(teardown)Check.Equal(0u,RawSmb.U32(await c.ReceiveAsync(),8),"teardown finishes after cancellation drains physical work");
        }
        finally {gate.Release();}
    }
    static async Task Witness()
    {
        await using var d=new P2Tests.Direct{CommitResponses=false};var id=await d.Open();var store=d.State.WitnessRegistrations;var reg=store.Add(d.Connection.ConnectionId,65537,null,null,null,null);
        d.Session.Opens[id].Pipe=new RpcPipe(new Smb.Server.Witness.WitnessEndpoint(store,d.Connection.ConnectionId,()=>Array.Empty<Smb.Server.Witness.WitnessInterfaceInfo>()));
        var pdu=new byte[44];pdu[0]=5;pdu[3]=3;pdu[4]=16;RawSmb.Put16(pdu,8,44);RawSmb.Put32(pdu,12,7);RawSmb.Put32(pdu,16,20);RawSmb.Put16(pdu,22,3);reg.ContextHandle().CopyTo(pdu,24);
        var b=RawSmb.Header(11,56+pdu.Length,0,1,42);RawSmb.Put16(b,64,57);RawSmb.Put32(b,68,0x0011c017);RawSmb.Put64(b,72,id.P);RawSmb.Put64(b,80,id.V);RawSmb.Put32(b,88,120);RawSmb.Put32(b,92,(uint)pdu.Length);RawSmb.Put32(b,108,4096);RawSmb.Put32(b,112,1);pdu.CopyTo(b,120);
        var t=new RecordingTransport();t.Attach(d.Connection);var interim=await d.Send(b);Check.Equal(0x103u,RawSmb.U32(interim,8),"Witness transceive pending");
        reg.Notifications.Push(new WitnessNotification {Type=Smb.Server.Witness.WitnessNotifyType.ResourceChange,MessageCount=1,MessageBuffer=[1]});Check.Equal(0,t.Control.Count("Send"),"Witness final waits for interim commit");
        await t.SendAsync(interim,false);await t.WaitForSendAsync();await t.WaitForSendAsync();Check.That(d.Connection.PendingRequests.IsEmpty,"Witness maps released");
    }
    static async Task Compound(string kind)
    {
        await using var f=new P3Tests.Direct();f.D.CommitResponses=false;var w=new FakeWatcher();f.D.Options.DirectoryWatcher=w;var t=new RecordingTransport();t.Attach(f.C);
        var notify=kind.StartsWith("notify");var open=await f.Send(notify?RawSmb.Create("",true,0,1,42):f.D.Create());var id=(RawSmb.U64(open,128),RawSmb.U64(open,136));
        var locks=new ControlledLocks();if(!notify)f.D.Options.LockManager=locks;
        var second=notify?RawSmb.Close((ulong.MaxValue,ulong.MaxValue),0,1,42):RawSmb.Write((ulong.MaxValue,ulong.MaxValue),[42],0,0,1,42);
        var packet=f.Join([notify?Notify(id):LockRequest(id),second]);var unrelated=kind.EndsWith("unrelated");if(unrelated){var off=(int)RawSmb.U32(packet,20);RawSmb.Put32(packet,off+16,8);RawSmb.Put64(packet,off+40,1);RawSmb.Put32(packet,off+36,42);RawSmb.Put64(packet,off+72,id.Item1);RawSmb.Put64(packet,off+80,id.Item2);RawSmb.Sign(packet.AsSpan(off).ToArray(),new byte[16]);var part=packet.AsSpan(off).ToArray();RawSmb.Sign(part,new byte[16]);part.CopyTo(packet,off);}
        var response=await f.D.Dispatcher.ProcessMessageAsync(f.C,packet);Check.Equal(0x103u,RawSmb.U32(response,8),"compound predecessor uses async interim");
        if(unrelated){Check.Equal(0,f.D.Store.ActiveHandles,"unrelated close progresses independently");await t.SendAsync(response,false);return;}
        Check.Equal(0,f.D.Store.Control.Count("Write"),"dependent mutation waits");Check.Equal(1,f.D.Store.ActiveHandles,"dependent close waits");
        var allPending=f.C.PendingRequests.Values.ToArray();
        var pending=allPending.OrderBy(p=>p.MessageId).First();
        if(kind.EndsWith("cancel"))pending.Cancel();else if(notify)w.Subscriptions[0].Emit(new FileNotifyEvent(FileNotifyAction.Added,"changed"));else locks.Result.SetResult(LockOutcome.Granted);
        Check.Equal(0,t.Control.Count("Send"),"compound finals wait for sender");await t.SendAsync(response,false);await t.WaitForSendAsync();await t.WaitForSendAsync();await t.WaitForSendAsync();
        await Task.WhenAll(allPending.Select(p=>p.Finished)).WaitAsync(Check.Timeout);
        Check.Equal(3,t.Sends.Length,"one interim frame then two finals");var final=t.Sends[2].Message;Check.Equal(kind.EndsWith("cancel")?0xc0000120u:0u,RawSmb.U32(final,8),"dependent result follows predecessor");Check.Equal((ushort)0,RawSmb.U16(final,14),"resumed final grants zero");Check.That((RawSmb.U32(final,16)&6)==6,"related async final flags");
        Check.Equal(kind=="lock-success"?1:0,f.D.Store.Control.Count("Write"),"dependent writes only on success");
        Check.That(f.C.PendingRequests.IsEmpty && f.C.AsyncRequests.IsEmpty,"compound pending maps quiescent");
    }
    static async Task DuplicateOrdinary()
    {
        await using var f=new P3Tests.Direct();var id=await f.Open();var gate=new AsyncBarrier();f.D.Store.Control.Enqueue("Read",new OperationStep(Barrier:gate));var b=RawSmb.Read(id,1,0,0,1,42);var first=f.Send(b);await gate.Entered;
        try {var duplicate=await f.D.Dispatcher.ProcessMessageAsync(f.C,b);Check.Equal(0xc000000du,RawSmb.U32(duplicate,8),"duplicate sequence rejected");Check.Equal(1,f.C.OrdinaryRequests.Count,"duplicate cannot retire active physical operation");}
        finally {gate.Release();await first;}
    }
    static async Task NotifyCharge()
    {
        await using var f=new P3Tests.Direct();var w=new FakeWatcher();f.D.Options.DirectoryWatcher=w;var open=await f.Send(RawSmb.Create("",true,0,1,42));var id=(RawSmb.U64(open,128),RawSmb.U64(open,136));f.C.Dialect=SmbDialect.Smb210;f.C.SupportsMultiCredit=true;
        var b=Notify(id,1,65537);RawSmb.Put16(b,6,1);Check.Equal(0xc000000du,RawSmb.U32(await f.Send(b),8),"notify output requires adequate credit charge");Check.Equal(0,w.ActiveCount,"undercharged notify never subscribes");
    }
    static async Task NotifyMax()
    {
        await using var f=new P3Tests.Direct();var w=new FakeWatcher();f.D.Options.DirectoryWatcher=w;var open=await f.Send(RawSmb.Create("",true,0,1,42));var id=(RawSmb.U64(open,128),RawSmb.U64(open,136));f.C.MaxTransactSize=100;
        Check.Equal(0xc000000du,RawSmb.U32(await f.Send(Notify(id,1,101)),8),"notify output bounded by negotiated transaction size");
    }
    static async Task IgnoringBackend()
    {
        await using var f=new P3Tests.Direct();var id=await f.Open();var gate=new AsyncBarrier();f.D.Store.Control.Enqueue("Read",new OperationStep(Barrier:gate,IgnoreCancellation:true));var read=RawSmb.Read(id,1,0,0,1,42);var task=f.Send(read);await gate.Entered;
        var cancel=RawSmb.Header(12,4,RawSmb.U64(read,24),1,42);RawSmb.Put16(cancel,64,4);RawSmb.Sign(cancel,new byte[16]);await f.D.Dispatcher.ProcessMessageAsync(f.C,cancel);
        var response=await task.WaitAsync(Check.Timeout);Check.Equal(0xc0000120u,RawSmb.U32(response,8),"response cancelled despite ignored physical token");
        var close=f.Send(RawSmb.Close(id,0,1,42));try {Check.That(!close.IsCompleted,"close retains physical operation ownership");Check.Equal(1,f.C.OrdinaryRequests.Count,"physical operation remains tracked");Check.Equal(1,f.D.Store.ActiveHandles,"backend handle stays alive");}finally{gate.Release();await close;}
        Check.That(f.C.OrdinaryRequests.IsEmpty,"physical retirement cleans map");
    }
    static async Task CancelNotify(bool asyncId)
    {
        await using var d=new P2Tests.Direct{CommitResponses=false};var w=new FakeWatcher();d.Options.DirectoryWatcher=w;var t=new RecordingTransport();t.Attach(d.Connection);var id=await Directory(d);var interim=await d.Send(Notify(id));var p=d.Connection.PendingRequests.Values.Single();
        var cancel=RawSmb.Header(12,4,p.MessageId,1,42);RawSmb.Put16(cancel,64,4);if(asyncId){RawSmb.Put32(cancel,16,2);RawSmb.Put64(cancel,32,p.AsyncId);}RawSmb.Sign(cancel,new byte[16]);var credits=d.Connection.Credits.AvailableCount;
        await d.Dispatcher.ProcessMessageAsync(d.Connection,cancel);Check.Equal(credits,d.Connection.Credits.AvailableCount,"cancel consumes/grants zero");Check.Equal(0,t.Control.Count("Send"),"cancel final queued before interim");await t.SendAsync(interim,false);await p.Finished;
        Check.Equal(0xc0000120u,RawSmb.U32(t.Sends.Last().Message,8),"cancel result");Check.That(d.Connection.PendingRequests.IsEmpty && d.Connection.AsyncRequests.IsEmpty,"both identities retired");await d.Send(RawSmb.Close(id,0,1,42));Check.Equal(0,w.ActiveCount,"watcher released on close");
    }
    static async Task FifoRename()
    {
        await using var d=new P2Tests.Direct{CommitResponses=false};var w=new FakeWatcher();d.Options.DirectoryWatcher=w;var t=new RecordingTransport();t.Attach(d.Connection);var id=await Directory(d);var a=await d.Send(Notify(id));var b=await d.Send(Notify(id,0x10));await t.SendAsync(a,false);await t.SendAsync(b,false);
        w.Subscriptions[0].Emit(new FileNotifyEvent(FileNotifyAction.RenamedOldName,"old"),new FileNotifyEvent(FileNotifyAction.RenamedNewName,"new"));Check.Equal(RawSmb.U64(a,24),RawSmb.U64(t.Sends.Last().Message,24),"first queued request owns rename pair");
        var names=System.Text.Encoding.Unicode.GetString(t.Sends.Last().Message);Check.That(names.Contains("old")&&names.Contains("new"),"rename pair preserved");w.Subscriptions[0].Emit(new FileNotifyEvent(FileNotifyAction.Added,"next"));Check.Equal(RawSmb.U64(b,24),RawSmb.U64(t.Sends.Last().Message,24),"second queued request is next");Check.That(d.Connection.PendingRequests.IsEmpty,"FIFO drains maps");
    }
    static async Task CloseInsideWatch()
    {
        await using var d=new P2Tests.Direct{CommitResponses=false};var w=new FakeWatcher();d.Options.DirectoryWatcher=w;var t=new RecordingTransport();t.Attach(d.Connection);var id=await Directory(d);Task<byte[]>? close=null;w.OnWatch=_=>close=d.Send(RawSmb.Close(id,0,1,42));
        var interim=await d.Send(Notify(id));await close!.WaitAsync(Check.Timeout);Check.Equal(0,w.ActiveCount,"subscription returned after close is disposed");Check.Equal(0,t.Control.Count("Send"),"close completion still waits for interim");await t.SendAsync(interim,false);await t.WaitForSendAsync();await t.WaitForSendAsync();Check.Equal(0x10bu,RawSmb.U32(t.Sends.Last().Message,8),"cleanup status");Check.That(d.Connection.PendingRequests.IsEmpty,"no stale entries after close inside watcher");
    }
    static async Task LockRaces()
    {
        for(var i=0;i<128;i++)
        {
            var m=new InMemoryLockManager();var a=new SmbOpen{VolatileFileId=1,ShareModeKey="object"};var b=new SmbOpen{VolatileFileId=2,ShareModeKey="object"};using var c=new CancellationTokenSource();await m.ApplyAsync(a,[new LockElement(0,10,true,false)],true,default);
            if(i%3==0)c.Cancel();var waiter=m.ApplyAsync(b,[new LockElement(0,10,true,false)],false,c.Token);
            if(i%3==1){await Task.WhenAll(Task.Run(c.Cancel),Task.Run(()=>m.ReleaseOwner(a)));}else if(i%3==2){await m.ApplyAsync(a,[new LockElement(0,10,false,true)],true,default);c.Cancel();}else m.ReleaseOwner(a);
            var winner=await waiter.WaitAsync(Check.Timeout);Check.That(winner is LockOutcome.Granted or LockOutcome.Cancelled,"one valid race outcome");m.ReleaseOwner(a);m.ReleaseOwner(b);Check.Equal(0,m.ActiveLockCount,"stress active locks");Check.Equal(0,m.PendingLockCount,"stress waiters");
        }
    }
    static async Task CompoundEarlier()
    {
        await using var f=new P3Tests.Direct();f.D.CommitResponses=false;var w=new FakeWatcher();f.D.Options.DirectoryWatcher=w;var t=new RecordingTransport();t.Attach(f.C);
        var request=f.Join([RawSmb.Create("",true,0,1,42),Notify((ulong.MaxValue,ulong.MaxValue)),RawSmb.Close((ulong.MaxValue,ulong.MaxValue),0,1,42)]);var original=request.ToArray();var before=f.C.Credits.AvailableCount;
        var response=await f.D.Dispatcher.ProcessMessageAsync(f.C,request);Check.That(request.SequenceEqual(original),"wire request retained byte-for-byte");Check.Equal(0u,RawSmb.U32(response,8),"earlier CREATE result preserved");
        int off=(int)RawSmb.U32(response,20),last=off+(int)RawSmb.U32(response,off+20);Check.Equal(0x103u,RawSmb.U32(response,off+8),"related notify pending");Check.Equal(0x103u,RawSmb.U32(response,last+8),"dependent close also async");Check.That((RawSmb.U32(response,last+16)&4)!=0,"deferred related interim flag retained");
        var grants=RawSmb.U16(response,14)+RawSmb.U16(response,off+14)+RawSmb.U16(response,last+14);Check.Equal(before-3+grants,f.C.Credits.AvailableCount,"each request consumed once and each actual grant reserved once");var reserved=f.C.Credits.AvailableCount;
        await t.SendAsync(response,false);w.Subscriptions[0].Emit(new FileNotifyEvent(FileNotifyAction.Added,"wake"));await t.WaitForSendAsync();await t.WaitForSendAsync();await t.WaitForSendAsync();Check.Equal(0,f.D.Store.ActiveHandles,"resumed close uses generated FileId");Check.Equal(reserved,f.C.Credits.AvailableCount,"resumed finals neither consume nor grant");
        foreach(var item in t.Sends.Skip(1)){var b=item.Message.ToArray();var signature=b.AsSpan(48,16).ToArray();b.AsSpan(48,16).Clear();Check.That(System.Security.Cryptography.HMACSHA256.HashData(new byte[16],b).AsSpan(0,16).SequenceEqual(signature),"independent signed async final");}
    }
    static async Task CompoundBadHeader()
    {
        await using var f=new P3Tests.Direct();f.D.Options.DirectoryWatcher=new FakeWatcher();var b=await f.Send(RawSmb.Create("",true,0,1,42));var id=(RawSmb.U64(b,128),RawSmb.U64(b,136));var request=f.Join([Notify(id),RawSmb.Close((ulong.MaxValue,ulong.MaxValue),0,1,42)]);var off=(int)RawSmb.U32(request,20);RawSmb.Put16(request,off+4,1);
        var response=await f.D.Dispatcher.ProcessMessageAsync(f.C,request);var next=(int)RawSmb.U32(response,20);Check.Equal(0xc000000du,RawSmb.U32(response,next+8),"malformed retained successor gives bounded parser error");
    }
    static async Task CompoundCap()
    {
        await using var f=new P3Tests.Direct();f.D.CommitResponses=false;var id=await f.Open();f.D.Options.LockManager=new ControlledLocks();f.D.Options.MaxOutstandingRequests=1;
        var response=await f.Compound(LockRequest(id),RawSmb.Write((ulong.MaxValue,ulong.MaxValue),[1],0,0,1,42));
        Check.Equal(1,f.C.PendingRequests.Count,"compound respects pending resource limit");var off=(int)RawSmb.U32(response,20);Check.Equal(0xc000009au,RawSmb.U32(response,off+8),"resource-constrained dependent rejected without work");Check.Equal(0,f.D.Store.Control.Count("Write"),"resource rejection cannot mutate");
    }
    sealed class Counted : IDisposable {public int Calls;public void Dispose()=>Calls++;}
    static async Task PendingResources()
    {
        var c=new SmbConnection();var p=new PendingAsyncRequest{MessageId=4,AsyncId=7};Check.That(c.RegisterPending(p),"publish both pending identities");var resource=new Counted();p.Attach(resource);var finals=0;
        p.Cancel();p.Attach(p.Token.Register(()=>p.Complete(NtStatus.Cancelled,[],()=>{finals++;return Task.CompletedTask;})));
        Check.Equal(0,finals,"already-cancelled registration queued before transmission");p.CommitInterim();await p.Finished;Check.Equal(1,finals,"one final");Check.Equal(1,resource.Calls,"one resource disposal");Check.That(!p.Complete(NtStatus.Success,[],()=>Task.CompletedTask),"duplicate completion rejected");p.CommitInterim();p.Abandon();Check.Equal(1,resource.Calls,"repeat cleanup harmless");Check.That(c.PendingRequests.IsEmpty && c.AsyncRequests.IsEmpty,"both maps clean");
        var abandoned=new PendingAsyncRequest{MessageId=5,AsyncId=8};c.RegisterPending(abandoned);var r=new Counted();abandoned.Attach(r);abandoned.Abandon();Check.Equal(1,r.Calls,"abandon before interim disposes resources");Check.That(abandoned.Token.IsCancellationRequested,"abandon cancels backend");
    }
    static async Task PendingStress()
    {
        for(var i=0;i<32;i++)
        {
            await using var d=new P2Tests.Direct{CommitResponses=false};var w=new FakeWatcher();d.Options.DirectoryWatcher=w;var t=new RecordingTransport();t.Attach(d.Connection);var id=await Directory(d);var interim=await d.Send(Notify(id));var p=d.Connection.PendingRequests.Values.Single();
            if(i%2==0){p.Cancel();await t.SendAsync(interim,false);}else{await t.SendAsync(interim,false);w.Subscriptions[0].Emit(new FileNotifyEvent(FileNotifyAction.Added,"event"));}
            await p.Finished.WaitAsync(Check.Timeout);await d.Send(RawSmb.TreeDisconnect(0,1,42));Check.Equal(0,w.ActiveCount,"stress watchers");Check.Equal(0,d.Store.ActiveHandles,"stress backend handles");Check.That(d.Connection.PendingRequests.IsEmpty && d.Connection.AsyncRequests.IsEmpty && d.Connection.OrdinaryRequests.IsEmpty,"stress pending resources");Check.Equal(0,((InMemoryLockManager)d.Options.LockManager).PendingLockCount,"stress lock waiters");
        }
    }
    static async Task ShutdownQueued()
    {
        await using var h=new HostFixture();h.Server.State.Options.MaxConcurrentFileOpsPerConnection=1;await h.StartAsync();await using var c=await h.ConnectAsync();var id=await c.CreateAsync("shutdown-queue");await c.WriteAsync(id,[1]);var connection=h.Server.State.Connections.Values.Single();
        var gate=new AsyncBarrier();h.Store.Control.Enqueue("Read",new OperationStep(Barrier:gate,IgnoreCancellation:true));var mid=c.NextMessageId();await c.SendAsync(RawSmb.Read(id,1,0,mid,c.Session,c.Tree));await gate.Entered;
        await c.SendAsync(RawSmb.Write(id,[2],0,c.NextMessageId(),c.Session,c.Tree));var cancel=RawSmb.Header(12,4,mid,c.Session,c.Tree);RawSmb.Put16(cancel,64,4);await c.SendAsync(cancel);await c.ReceiveAsync();Check.Equal(2,connection.OrdinaryRequests.Count,"active and queued operation admitted before shutdown");
        var queued=connection.OrdinaryRequests.Single(pair=>pair.Key!=mid).Value;var shutdown=h.Server.StopAsync(TimeSpan.Zero);await queued.PhysicalFinished.WaitAsync(Check.Timeout);gate.Release();await shutdown.WaitAsync(Check.Timeout);Check.That(connection.OrdinaryRequests.IsEmpty,"shutdown retires queued cancellation owners");Check.Equal(0,h.Store.ActiveHandles,"shutdown physical handles drained");
    }
    static async Task ErrorLayout(bool rescan)
    {
        await using var d=new P2Tests.Direct{CommitResponses=false};var w=new FakeWatcher();d.Options.DirectoryWatcher=w;var t=new RecordingTransport();t.Attach(d.Connection);var id=await Directory(d);var b=await d.Send(Notify(id));await t.SendAsync(b,false);w.Subscriptions[0].Fail(rescan?NtStatus.NotifyEnumDir:(NtStatus)0xc0000001);var response=t.Sends.Last().Message;
        if(rescan)Check.Equal(0u,RawSmb.U32(response,68),"rescan has zero OutputBufferLength");else Check.Equal((ushort)0,RawSmb.U16(response,66),"backend error has no invented ErrorContextCount");Check.Equal((ushort)9,RawSmb.U16(response,64),"response structure");Check.Equal(rescan?0x10cu:0xc0000001u,RawSmb.U32(response,8),"backend status propagated");
    }

    [DynamicDependency(DynamicallyAccessedMemberTypes.NonPublicMethods, typeof(FileSystemWatcher))]
    static Task LocalWatcherError()
    {
        var root=System.IO.Path.Combine(System.IO.Path.GetTempPath(),"smb-p4-"+Guid.NewGuid().ToString("N"));System.IO.Directory.CreateDirectory(root);
        try
        {
            NtStatus? error=null;var watcher=new FileSystemDirectoryWatcher();using var subscription=watcher.Watch(root,false,ChangeNotifyFilter.FileName,_=>{},status=>error=status);
            Check.That(subscription is FileSystemWatcher,"local watcher activated");typeof(FileSystemWatcher).GetMethod("OnError",BindingFlags.Instance|BindingFlags.NonPublic)!.Invoke(subscription,[new ErrorEventArgs(new InternalBufferOverflowException("controlled overflow"))]);Check.Equal(NtStatus.NotifyEnumDir,error!.Value,"FileSystemWatcher.Error signals rescan");
            using var empty=watcher.Watch(root,false,ChangeNotifyFilter.None,_=>throw new InvalidOperationException("empty filter fired"));Check.That(empty is not FileSystemWatcher,"no default mapped filter for empty filter");
        }
        finally {System.IO.Directory.Delete(root);}
        return Task.CompletedTask;
    }
    static async Task RetainedRequest()
    {
        await using var f=new P3Tests.Direct();f.D.CommitResponses=false;var id=await f.Open();var locks=new ControlledLocks();f.D.Options.LockManager=locks;var t=new RecordingTransport();t.Attach(f.C);
        var request=f.Join([LockRequest(id),RawSmb.Write((ulong.MaxValue,ulong.MaxValue),[42],0,0,1,42)]);var interim=await f.D.Dispatcher.ProcessMessageAsync(f.C,request);
        request.AsSpan((int)RawSmb.U32(request,20)).Fill(0); // Caller reuses input after ProcessMessageAsync has returned.
        locks.Result.SetResult(LockOutcome.Granted);await t.SendAsync(interim,false);await t.WaitForSendAsync();await t.WaitForSendAsync();await t.WaitForSendAsync();Check.Equal(0u,RawSmb.U32(t.Sends.Last().Message,8),"resumed parser/signature sees retained original bytes");Check.Equal((byte)42,f.D.Store.Contents("a")[0],"resumed original mutation");
    }
    static async Task CancelFault()
    {
        await using var d=new P2Tests.Direct();var p=new PendingAsyncRequest{MessageId=123,AsyncId=456};d.Connection.RegisterPending(p);p.Attach(p.Token.Register(()=>throw new IOException("controlled consumer callback fault")));
        var b=RawSmb.Header(12,4,123,1,42);RawSmb.Put16(b,64,4);RawSmb.Sign(b,new byte[16]);var response=await d.Dispatcher.ProcessMessageAsync(d.Connection,b);Check.Equal(0,response.Length,"CANCEL has no response even when consumer callback faults");p.Abandon();Check.That(d.Connection.PendingRequests.IsEmpty,"fallible cancellation still permits cleanup");
    }
    static async Task NotifyPadding()
    {
        await using var d=new P2Tests.Direct{CommitResponses=false};var w=new FakeWatcher();d.Options.DirectoryWatcher=w;var t=new RecordingTransport();t.Attach(d.Connection);var id=await Directory(d);var b=await d.Send(Notify(id));await t.SendAsync(b,false);w.Subscriptions[0].Emit(new FileNotifyEvent(FileNotifyAction.Added,"x"));var final=t.Sends.Last().Message;
        Check.Equal(16u,RawSmb.U32(final,68),"FSCC notification record includes final 4-byte filename padding");Check.Equal(0u,RawSmb.U32(final,72),"last record NextEntryOffset zero");Check.Equal(2u,RawSmb.U32(final,80),"filename length excludes padding");Check.Equal((byte)0,final[86],"filename padding zero");
    }
    sealed class GateComparer(IEqualityComparer<string> original, Action inside) : IEqualityComparer<string>
    {
        public bool Armed;
        public bool Equals(string? a,string? b)=>original.Equals(a!,b!);
        public int GetHashCode(string s){if(Armed){Armed=false;inside();}return original.GetHashCode(s);}
    }
    // Reflect only for deterministic scheduling of the existing private callback/gate inversion.
    [DynamicDependency(DynamicallyAccessedMemberTypes.All, typeof(InMemoryLockManager))]
    [DynamicDependency(DynamicallyAccessedMemberTypes.NonPublicFields, typeof(Dictionary<,>))]
    [UnconditionalSuppressMessage("Trimming","IL2075",Justification="Test retains dictionary fields via DynamicDependency; only _comparer is accessed.")]
    static async Task LockInversion(string kind)
    {
        var m=new InMemoryLockManager();var a=new SmbOpen{VolatileFileId=1,ShareModeKey="same"};var b=new SmbOpen{VolatileFileId=2,ShareModeKey="same"};
        using var cts=new CancellationTokenSource();await m.ApplyAsync(a,[new LockElement(0,1,true,false)],true,default);var pending=m.ApplyAsync(b,[new LockElement(0,1,true,false)],false,cts.Token);
        var dict=typeof(InMemoryLockManager).GetField("_files",BindingFlags.Instance|BindingFlags.NonPublic)!.GetValue(m)!;
        using var entered=new ManualResetEventSlim();using var cancelStarted=new ManualResetEventSlim();
        var cancel=new Thread(()=>{entered.Wait();cancelStarted.Set();cts.Cancel();}){IsBackground=true};cancel.Start();
        var comparer=new GateComparer((IEqualityComparer<string>)dict.GetType().GetField("_comparer",BindingFlags.Instance|BindingFlags.NonPublic)!.GetValue(dict)!,()=>{entered.Set();Check.That(cancelStarted.Wait(Check.Timeout),"cancellation thread started");Check.That(SpinWait.SpinUntil(()=> (cancel.ThreadState & System.Threading.ThreadState.WaitSleepJoin)!=0,Check.Timeout),"actual cancellation callback blocked on manager gate");});
        dict.GetType().GetField("_comparer",BindingFlags.Instance|BindingFlags.NonPublic)!.SetValue(dict,comparer);
        comparer.Armed=true;
        var released=new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously);
        new Thread(()=>{try{if(kind=="unlock")m.ApplyAsync(a,[new LockElement(0,1,false,true)],true,default).GetAwaiter().GetResult();else m.ReleaseOwner(kind=="cancel-owner"?b:a);released.SetResult();}catch(Exception ex){released.SetException(ex);}}){IsBackground=true}.Start();
        await released.Task.WaitAsync(TimeSpan.FromSeconds(2));Check.That(cancel.Join(Check.Timeout),"callback completed");
        var result=await pending.WaitAsync(Check.Timeout);Check.That(result is LockOutcome.Cancelled or LockOutcome.Granted,"one winner");m.ReleaseOwner(a);m.ReleaseOwner(b);Check.Equal(0,m.PendingLockCount,"waiters drained");Check.Equal(0,m.ActiveLockCount,"locks released");
    }
}
