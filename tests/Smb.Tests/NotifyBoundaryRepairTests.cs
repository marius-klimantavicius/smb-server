using Smb.Testing;

// Literal SMB2 packets over separately authenticated TCP connections and real LocalFileStore.
internal static class NotifyBoundaryRepairTests
{
    public static IEnumerable<(string, Func<Task>)> Cases()
    {
        foreach (var initial in new[] { false, true })
            yield return ($"repair.notify.delete-tcp.{initial}", () => Delete(initial));
        yield return ("repair.notify.delete-cleared-sticky", DeleteCleared);
        foreach (var same in new[] { false, true })
            foreach (var recursive in new[] { false, true })
                yield return ($"repair.notify.security-tcp.{same}.{recursive}", () => Security(same, recursive));
        yield return ("repair.notify.security-fifo-cancel-filter-isolation", SecurityIsolation);
        yield return ("repair.boundary.archive-eof-and-stream", Archive);
        yield return ("repair.notify.security-before-watch-returns-tcp", SecurityBeforeWatchReturns);
        yield return ("repair.notify.security-after-rename-tcp", SecurityAfterRename);
        yield return ("repair.boundary.inherited-deny-controls-tcp", InheritedDenyControls);
        yield return ("repair.notify.delete-registration-race-tcp", DeleteRegistrationRace);
        yield return ("repair.notify.security-zero-fields-tcp", SecurityZeroFields);
    }
    static async Task<(ulong P,ulong V)> Open(WireClient c,string path,bool directory=false)
    {var b=RawSmb.Create(path,directory,c.NextMessageId(),c.Session,c.Tree);RawSmb.Put32(b,88,0x1f01ff);RawSmb.Put32(b,100,3);var r=await c.ExchangeAsync(b);return (RawSmb.U64(r,128),RawSmb.U64(r,136));}
    static byte[] Route(WireClient c, byte[] b) { RawSmb.Put64(b,24,c.NextMessageId()); RawSmb.Put64(b,40,c.Session); RawSmb.Put32(b,36,c.Tree); return b; }
    static byte[] Notify(WireClient c, (ulong P,ulong V) id, uint filter=0x100, bool recursive=false)
    { var b=Route(c,P4Tests.Notify(id,filter)); RawSmb.Put16(b,66,recursive?(ushort)1:(ushort)0); return b; }
    static byte[] Set(WireClient c,(ulong P,ulong V) id,byte cls,byte[] data,byte type=1,uint flags=0)
    { var b=RawSmb.Header(17,32+data.Length,c.NextMessageId(),c.Session,c.Tree); RawSmb.Put16(b,64,33);b[66]=type;b[67]=cls;RawSmb.Put32(b,68,(uint)data.Length);RawSmb.Put16(b,72,96);RawSmb.Put32(b,76,flags);RawSmb.Put64(b,80,id.P);RawSmb.Put64(b,88,id.V);data.CopyTo(b,96);return b; }
    static byte[] Query(WireClient c,(ulong P,ulong V) id,byte type=1,uint flags=0)
    { var b=RawSmb.Header(16,40,c.NextMessageId(),c.Session,c.Tree);RawSmb.Put16(b,64,41);b[66]=type;b[67]=type==1?(byte)4:(byte)0;RawSmb.Put32(b,68,4096);RawSmb.Put32(b,80,flags);RawSmb.Put64(b,88,id.P);RawSmb.Put64(b,96,id.V);return b; }
    static byte[] Data(byte[] b)=>RawSmb.Buffer(b,RawSmb.U16(b,66),RawSmb.U32(b,68));
    static async Task<byte[]> Arm(WireClient c,(ulong P,ulong V) id,uint filter=0x100,bool recursive=false)
        =>await c.ExchangeAsync(Notify(c,id,filter,recursive),0x103);
    static async Task Final(WireClient c,byte[] interim,uint status,string? name=null)
    { var b=await c.ReceiveAsync();RawSmb.Response(b,15,RawSmb.U64(interim,24),status);Check.Equal(RawSmb.U64(interim,32),RawSmb.U64(b,32),"terminal AsyncId");if(name!=null){var data=Data(b);Check.Equal(0u,RawSmb.U32(data,0),"one event");Check.Equal(3u,RawSmb.U32(data,4),"MODIFIED");Check.Equal(name,System.Text.Encoding.Unicode.GetString(data,12,(int)RawSmb.U32(data,8)),"relative security name");} }
    static async Task Cancel(WireClient c,byte[] pending,uint status=0xc0000120)
    {var b=RawSmb.Header(12,4,0,c.Session);RawSmb.Put16(b,64,4);RawSmb.Put32(b,16,2);RawSmb.Put64(b,32,RawSmb.U64(pending,32));await c.SendAsync(b);await Final(c,pending,status);}
    static async Task Delete(bool initial)
    {
        await using var h=await UpstreamLocalFixture.StartAsync();await using var w=await h.ConnectAsync();await using var m=await h.ConnectAsync();
        var dir=await Open(w,"watched",true);var pending=await Arm(w,dir,3);
        var create=RawSmb.Create("watched",true,m.NextMessageId(),m.Session,m.Tree);RawSmb.Put32(create,100,1);RawSmb.Put32(create,88,0x10000);if(initial)RawSmb.Put32(create,104,0x1001);
        var reply=await m.ExchangeAsync(create);var owner=(RawSmb.U64(reply,128),RawSmb.U64(reply,136));
        if(!initial)await m.ExchangeAsync(Set(m,owner,13,[1]));await m.CloseAsync(owner);
        await Final(w,pending,0xc0000056);Check.That(Directory.Exists(h.PathFor("watched")),"watched open retains native directory lifetime");
        create=RawSmb.Create("watched",true,m.NextMessageId(),m.Session,m.Tree);RawSmb.Put32(create,100,1);await m.ExchangeAsync(create,0xc0000056);
        await w.CloseAsync(dir);Check.That(!Directory.Exists(h.PathFor("watched")),"last close deletes directory");
        await w.ExchangeAsync(Route(w,P4Tests.Notify(dir)),0xc0000128);
    }
    static async Task DeleteCleared()
    {
        await using var h=await UpstreamLocalFixture.StartAsync();await using var w=await h.ConnectAsync();await using var m=await h.ConnectAsync();
        var dir=await Open(w,"sticky",true);var owner=await Open(m,"sticky",true);var pending=await Arm(w,dir,3);var second=await Arm(w,dir,3);
        await m.ExchangeAsync(Set(m,owner,13,[1]));await Final(w,pending,0xc0000056);await Final(w,second,0xc0000056);
        await m.ExchangeAsync(Set(m,owner,13,[0]));
        // MS-FSA 2.1.5.15.3 marks the disposition-setting Open only. Other
        // opens lose pending notifications but may subscribe again after clear.
        await m.ExchangeAsync(Notify(m,owner,3),0xc0000056);
        var rearmed=await Arm(w,dir,3);await Cancel(w,rearmed);
        await m.CloseAsync(owner);await w.CloseAsync(dir);Check.That(Directory.Exists(h.PathFor("sticky")),"cleared disposition preserves directory");
    }
    static async Task Security(bool same,bool recursive)
    {
        await using var h=await UpstreamLocalFixture.StartAsync();await using var w=await h.ConnectAsync();await using var m=await h.ConnectAsync();
        var dir=await Open(w,"watched",true);var sub=await Open(m,"watched\\sub",true);await m.CloseAsync(sub);
        var file=await Open(m,recursive?"watched\\sub\\file":"watched\\file");var sd=Data(await m.ExchangeAsync(Query(m,file,3,4)));
        if(!same) {var at=(int)RawSmb.U32(sd,16)+12;RawSmb.Put32(sd,at,0x120089);}
        var pending=await Arm(w,dir,0x100,recursive);await m.ExchangeAsync(Set(m,file,0,sd,3,4));await Final(w,pending,0,recursive?"sub\\file":"file");
        // The same successful SET is observable once. A following subscription stays
        // pending until explicitly canceled, rather than consuming a duplicate.
        var next=await Arm(w,dir,0x100,recursive);await Cancel(w,next);await m.CloseAsync(file);await w.CloseAsync(dir);
    }
    static async Task SecurityIsolation()
    {
        await using var h=await UpstreamLocalFixture.StartAsync();await using var w=await h.ConnectAsync();await using var m=await h.ConnectAsync();await using var other=await h.ConnectAsync();
        var root=await Open(w,"dir",true);var attrs=await Open(other,"dir",true);var foreign=await Open(other,"foreign",true);var nested=await Open(m,"dir\\sub",true);await m.CloseAsync(nested);
        var file=await Open(m,"dir\\sub\\file");var sd=Data(await m.ExchangeAsync(Query(m,file,3,4)));
        var noSub=await Arm(w,root);var noFilter=await Arm(other,attrs,1);var unrelated=await Arm(other,foreign);
        await m.ExchangeAsync(Set(m,file,0,sd,3,4));await Cancel(w,noSub);await Cancel(other,noFilter);await Cancel(other,unrelated);
        await w.CloseAsync(root);root=await Open(w,"dir",true);
        var canceled=await Arm(w,root,0x100,true);var first=await Arm(w,root,0x100,true);var second=await Arm(w,root,0x100,true);await Cancel(w,canceled);
        await m.ExchangeAsync(Set(m,file,0,sd,3,4));await Final(w,first,0,"sub\\file");await m.ExchangeAsync(Set(m,file,0,sd,3,4));await Final(w,second,0,"sub\\file");
        var cleanup=await Arm(w,root,0x100,true);await w.SendAsync(RawSmb.Close(root,w.NextMessageId(),w.Session,w.Tree));
        var a=await w.ReceiveAsync();var b=await w.ReceiveAsync();Check.That(new[]{a,b}.Count(x=>RawSmb.U16(x,12)==15&&RawSmb.U32(x,8)==0x10b)==1,"close yields exactly one notify cleanup");Check.That(new[]{a,b}.Count(x=>RawSmb.U16(x,12)==6&&RawSmb.U32(x,8)==0)==1,"close succeeds");
        await m.ExchangeAsync(Set(m,file,0,sd,3,4));await m.CloseAsync(file);await other.CloseAsync(attrs);await other.CloseAsync(foreign);
    }
    sealed class WatchBarrier : Smb.Server.Notification.IDirectoryWatcher, IDisposable
    {
        readonly Smb.Server.Notification.FileSystemDirectoryWatcher native = new();
        readonly ManualResetEventSlim release = new();
        public TaskCompletionSource Entered { get; } = new(TaskCreationOptions.RunContinuationsAsynchronously);
        public IDisposable? Watch(string path,bool subtree,Smb.Server.Notification.ChangeNotifyFilter filter,Action<IReadOnlyList<Smb.Server.Notification.FileNotifyEvent>> callback)
        {var subscription=native.Watch(path,subtree,filter,callback);Entered.TrySetResult();if(!release.Wait(Check.Timeout)){subscription?.Dispose();throw new TimeoutException("watch registration barrier");}return subscription;}
        public void Release()=>release.Set();
        public void Dispose(){Release();release.Dispose();}
    }
    static async Task SecurityBeforeWatchReturns()
    {
        await using var h=await UpstreamLocalFixture.StartAsync();await using var w=await h.ConnectAsync();await using var m=await h.ConnectAsync();
        var dir=await Open(w,"dir",true);var file=await Open(m,"dir\\file");var sd=Data(await m.ExchangeAsync(Query(m,file,3,4)));
        using var barrier=new WatchBarrier();h.Server.State.Options.DirectoryWatcher=barrier;
        var request=Notify(w,dir);await w.SendAsync(request);await barrier.Entered.Task.WaitAsync(Check.Timeout);
        try {await m.ExchangeAsync(Set(m,file,0,sd,3,4));} finally {barrier.Release();}
        var interim=await w.ReceiveAsync();RawSmb.Response(interim,15,RawSmb.U64(request,24),0x103);await Final(w,interim,0,"file");
        var next=await Arm(w,dir);await Cancel(w,next);await m.CloseAsync(file);await w.CloseAsync(dir);
    }
    static async Task SecurityAfterRename()
    {
        await using var h=await UpstreamLocalFixture.StartAsync();await using var w=await h.ConnectAsync();await using var m=await h.ConnectAsync();
        // MS-FSA 2.1.5.15.12 / 2.1.4.2 reject a directory rename while
        // descendants remain acquired. A watch handle needs LIST_DIRECTORY,
        // not DELETE (which conflicts with the child's implicit parent open).
        async Task<(ulong P,ulong V)> WatchOpen(string path)
        {var b=RawSmb.Create(path,true,w.NextMessageId(),w.Session,w.Tree);RawSmb.Put32(b,88,0x120089);var r=await w.ExchangeAsync(b);return(RawSmb.U64(r,128),RawSmb.U64(r,136));}
        async Task<byte[]> Info(WireClient c,(ulong P,ulong V) id,byte cls)
        {var q=Query(c,id);q[67]=cls;return Data(await c.ExchangeAsync(q));}
        async Task Name(WireClient c,(ulong P,ulong V) id,string expected)
        {var data=await Info(c,id,9);Check.Equal(expected,System.Text.Encoding.Unicode.GetString(data,4,(int)RawSmb.U32(data,0)),"acquired current name");}
        async Task Bytes((ulong P,ulong V) id,byte[] expected)
        {var actual=await m.ReadAsync(id,(uint)expected.Length);Check.That(expected.SequenceEqual(actual),"acquired bytes survive rename boundary");}
        var root=await Open(m,"dir",true);var dir=await WatchOpen("dir");var file=await Open(m,"dir\\old");var sd=Data(await m.ExchangeAsync(Query(m,file,3,4)));
        var payload="notification rename preserves acquired child"u8.ToArray();await m.WriteAsync(file,payload);
        var identity=await Info(m,file,6);var dirIdentity=await Info(w,dir,6);
        var first=await Arm(w,dir);await m.ExchangeAsync(Set(m,file,0,sd,3,4));await Final(w,first,0,"old");
        byte[] Rename(string path){var name=System.Text.Encoding.Unicode.GetBytes(path);var data=new byte[20+name.Length];RawSmb.Put32(data,16,(uint)name.Length);name.CopyTo(data,20);return data;}
        var rejected=await Arm(w,dir);await m.ExchangeAsync(Set(m,root,10,Rename("moved")),0xc0000022);
        await Bytes(file,payload);var actualSd=Data(await m.ExchangeAsync(Query(m,file,3,4)));Check.That(sd.SequenceEqual(actualSd),"rejected rename preserves complete descriptor");
        await Name(m,file,"\\dir\\old");await Name(w,dir,"dir");
        var actualIdentity=await Info(m,file,6);Check.That(identity.SequenceEqual(actualIdentity),"rejected rename preserves identity");
        Check.That(File.Exists(h.PathFor("dir/old"))&&!Directory.Exists(h.PathFor("moved")),"rejected rename preserves native names");await Cancel(w,rejected);
        await m.CloseAsync(file);await m.ExchangeAsync(Set(m,root,10,Rename("moved")));await m.CloseAsync(root);
        var actualDirIdentity=await Info(w,dir,6);Check.That(dirIdentity.SequenceEqual(actualDirIdentity),"same watched handle retains directory identity");await Name(w,dir,"moved");
        file=await Open(m,"moved\\old");await Bytes(file,payload);actualIdentity=await Info(m,file,6);Check.That(identity.SequenceEqual(actualIdentity),"reopened child retains acquired object identity");
        actualSd=Data(await m.ExchangeAsync(Query(m,file,3,4)));Check.That(sd.SequenceEqual(actualSd),"descriptor survives valid parent rename");
        await m.ExchangeAsync(Set(m,file,10,Rename("moved\\new")));await Name(m,file,"\\moved\\new");await Bytes(file,payload);
        var filtered=await WatchOpen("moved");var nameOnly=await Arm(w,filtered,1);
        var second=await Arm(w,dir);await m.ExchangeAsync(Set(m,file,0,sd,3,4));await Final(w,second,0,"new");await Cancel(w,nameOnly);
        var next=await Arm(w,dir);await Cancel(w,next);
        var cleanup=await Arm(w,dir);var close=RawSmb.Close(dir,w.NextMessageId(),w.Session,w.Tree);await w.SendAsync(close);
        // Both frames are mandatory and fully checked; transport ordering can vary.
        var a=await w.ReceiveAsync();var b=await w.ReceiveAsync();
        var final=RawSmb.U16(a,12)==15?a:b;var closed=RawSmb.U16(a,12)==6?a:b;
        RawSmb.Response(final,15,RawSmb.U64(cleanup,24),0x10b);Check.Equal(RawSmb.U64(cleanup,32),RawSmb.U64(final,32),"rename watch cleanup AsyncId");
        RawSmb.Response(closed,6,RawSmb.U64(close,24),0);
        await w.CloseAsync(filtered);await m.CloseAsync(file);
        Check.That(payload.SequenceEqual(File.ReadAllBytes(h.PathFor("moved/new"))),"final renamed bytes intact");
    }
    static async Task SecurityZeroFields()
    {
        await using var h=await UpstreamLocalFixture.StartAsync();await using var w=await h.ConnectAsync();await using var m=await h.ConnectAsync();
        var dir=await Open(w,"dir",true);var file=await Open(m,"dir\\file");var sd=Data(await m.ExchangeAsync(Query(m,file,3,4)));
        var pending=await Arm(w,dir);await m.ExchangeAsync(Set(m,file,0,sd,3,0));await Cancel(w,pending);
        pending=await Arm(w,dir);await m.ExchangeAsync(Set(m,file,0,sd,3,4));await Final(w,pending,0,"file");
        await m.CloseAsync(file);await w.CloseAsync(dir);
    }
    sealed class DispositionBarrier(Smb.FileSystem.IFileHandle inner) : Smb.FileSystem.IFileHandle
    {
        readonly ManualResetEventSlim release=new();
        int armed=1;
        public TaskCompletionSource Entered { get; }=new(TaskCreationOptions.RunContinuationsAsynchronously);
        public Smb.FileSystem.FileIdentity? Identity=>inner.Identity;
        public bool DeletePending { get {var value=inner.DeletePending;if(Interlocked.Exchange(ref armed,0)==1){Entered.TrySetResult();if(!release.Wait(Check.Timeout))throw new TimeoutException("disposition snapshot barrier");}return value;} }
        public string Path=>inner.Path;
        public bool IsDirectory=>inner.IsDirectory;
        public string? PhysicalPath=>inner.PhysicalPath;
        public Smb.FileSystem.FileEntryInfo GetInfo()=>inner.GetInfo();
        public ValueTask<Smb.FileSystem.FileEntryInfo> GetInfoAsync(CancellationToken ct=default)=>inner.GetInfoAsync(ct);
        public ValueTask<Smb.Protocol.Enums.NtStatus> CloseAsync()=>inner.CloseAsync();
        public void Release()=>release.Set();
        public void Dispose(){Release();inner.Dispose();release.Dispose();}
        public ValueTask DisposeAsync(){Dispose();return ValueTask.CompletedTask;}
    }
    static async Task DeleteRegistrationRace()
    {
        await using var h=await UpstreamLocalFixture.StartAsync();await using var w=await h.ConnectAsync();await using var m=await h.ConnectAsync();
        var dir=await Open(w,"race",true);var owner=await Open(m,"race",true);
        var open=h.Server.State.SessionGlobalList.Values.Single(x=>x.SessionId==w.Session).Opens[dir];var original=open.LocalOpen!;
        // Instrument only the snapshot boundary; storage, native watcher, authentication,
        // disposition, notification registration and both transports remain real.
        var barrier=new DispositionBarrier(original);open.LocalOpen=barrier;
        var request=Notify(w,dir,3);await w.SendAsync(request);await barrier.Entered.Task.WaitAsync(Check.Timeout);
        var deleting=m.ExchangeAsync(Set(m,owner,13,[1]));
        try {Check.That(SpinWait.SpinUntil(()=>original.DeletePending,Check.Timeout),"other session commits disposition while initial snapshot is held");}finally{barrier.Release();}
        await deleting;var response=await w.ReceiveAsync();
        if(RawSmb.U32(response,8)==0x103)await Final(w,response,0xc0000056);else RawSmb.Response(response,15,RawSmb.U64(request,24),0xc0000056);
        await m.CloseAsync(owner);await w.CloseAsync(dir);Check.That(!Directory.Exists(h.PathFor("race")),"race retains final-close deletion semantics");
    }
    static async Task InheritedDenyControls()
    {
        // MS-DTYP 2.4.4.1: INHERITED_ACE records origin; it does not remove
        // the deny mask. Exercise every control partition through access checks.
        await using var h=await UpstreamLocalFixture.StartAsync();await using var c=await h.ConnectAsync();
        for(var p=0;p<16;p++)
        {
            var path="parent"+p;var parent=await Open(c,path,true);var sd=new byte[68];sd[0]=1;
            RawSmb.Put16(sd,2,(ushort)(0x8004|((p&1)!=0?0x400:0)|((p&2)!=0?0x100:0)|((p&4)!=0?0x1000:0)));RawSmb.Put32(sd,16,20);
            sd[20]=2;RawSmb.Put16(sd,22,48);RawSmb.Put16(sd,24,2);
            for(var i=0;i<2;i++){var at=28+i*20;sd[at]=i==0?(byte)1:(byte)0;sd[at+1]=(byte)(3|((p&8)!=0?16:0));RawSmb.Put16(sd,at+2,20);RawSmb.Put32(sd,at+4,i==0?1u:0x1f01ffu);sd[at+8]=1;sd[at+9]=1;sd[at+15]=1;}
            await c.ExchangeAsync(Set(c,parent,0,sd,3,4));
            var create=RawSmb.Create(path+"\\child",false,c.NextMessageId(),c.Session,c.Tree);RawSmb.Put32(create,88,0x20002);var reply=await c.ExchangeAsync(create);var child=(RawSmb.U64(reply,128),RawSmb.U64(reply,136));
            var actual=Data(await c.ExchangeAsync(Query(c,child,3,4)));var acl=(int)RawSmb.U32(actual,16);Check.Equal((ushort)2,RawSmb.U16(actual,acl+4),"both inherited ACEs retained");
            Check.Equal((byte)1,actual[acl+8],"deny ACE stays first");Check.Equal((byte)16,actual[acl+9],"inherited deny origin retained");Check.Equal(1u,RawSmb.U32(actual,acl+12),"inherited READ deny mask retained");
            create=RawSmb.Create(path+"\\child",false,c.NextMessageId(),c.Session,c.Tree);RawSmb.Put32(create,88,1);await c.ExchangeAsync(create,0xc0000022);
            await c.WriteAsync(child,[42]);await c.ExchangeAsync(RawSmb.Read(child,1,0,c.NextMessageId(),c.Session,c.Tree),0xc0000022);
            await c.CloseAsync(child);await c.CloseAsync(parent);
        }
    }
    static async Task Archive()
    {
        await using var h=await UpstreamLocalFixture.StartAsync();await using var c=await h.ConnectAsync();var file=await Open(c,"archive");var clear=new byte[40];RawSmb.Put32(clear,32,0x80);
        foreach(var stream in new[]{false,true})
        {var id=stream?await Open(c,"archive:ads"):file;await c.ExchangeAsync(Set(c,file,4,clear));var length=new byte[8];RawSmb.Put64(length,0,12);await c.ExchangeAsync(Set(c,id,20,length));Check.That((RawSmb.U32(Data(await c.ExchangeAsync(Query(c,file))),32)&0x20)!=0,"EOF including ADS reasserts base ARCHIVE");if(stream)await c.CloseAsync(id);}
        await c.CloseAsync(file);
    }
}
