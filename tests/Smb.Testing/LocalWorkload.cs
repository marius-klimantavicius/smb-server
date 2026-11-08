using System.Text;
using Smb.FileSystem.Local;
using Smb.Server.Diagnostics;
using Smb.Server.Locking;
using Smb.Server.Sharing;
using Smb.Server.Notification;
using Smb.Protocol.Enums;

namespace Smb.Testing;

// Supplemental final-source integration coverage; no claim of original repair RED.
public static class LocalWorkload
{
    sealed class Watcher : IDirectoryWatcher
    {
        readonly FileSystemDirectoryWatcher inner = new FileSystemDirectoryWatcher();
        public int Active;
        public IDisposable? Watch(string p,bool s,ChangeNotifyFilter f,Action<IReadOnlyList<FileNotifyEvent>> c)
            => Watch(p,s,f,c,_=>{});
        public IDisposable? Watch(string p,bool s,ChangeNotifyFilter f,Action<IReadOnlyList<FileNotifyEvent>> c,Action<NtStatus> e)
        {var item=inner.Watch(p,s,f,c,e);if(item is null)return null;Interlocked.Increment(ref Active);return new Subscription(this,item);}
        sealed class Subscription(Watcher owner,IDisposable inner) : IDisposable
        {int done; public void Dispose(){if(Interlocked.Exchange(ref done,1)==0){inner.Dispose();Interlocked.Decrement(ref owner.Active);}}}
    }
    static byte[] Request(WireClient c,ushort cmd,int bytes)
        => RawSmb.Header(cmd,bytes,c.NextMessageId(),c.Session,c.Tree);
    static void Id(byte[] b,int offset,(ulong P,ulong V) id)
    {RawSmb.Put64(b,offset,id.P);RawSmb.Put64(b,offset+8,id.V);}
    static byte[] Set(WireClient c,(ulong P,ulong V) id,byte cls,byte[] data)
    {var b=Request(c,17,32+data.Length);RawSmb.Put16(b,64,33);b[66]=1;b[67]=cls;RawSmb.Put32(b,68,(uint)data.Length);RawSmb.Put16(b,72,96);Id(b,80,id);data.CopyTo(b,96);return b;}
    static byte[] Lock(WireClient c,(ulong P,ulong V) id,uint flags)
    {var b=Request(c,10,48);RawSmb.Put16(b,64,48);RawSmb.Put16(b,66,1);Id(b,72,id);RawSmb.Put64(b,96,1);RawSmb.Put32(b,104,flags);return b;}
    static async Task<(ulong P,ulong V)> CreateDelete(WireClient c,string name)
    {var request=RawSmb.Create(name,false,c.NextMessageId(),c.Session,c.Tree);RawSmb.Put32(request,88,0x10003);var result=await c.ExchangeAsync(request);return (RawSmb.U64(result,128),RawSmb.U64(result,136));}
    public static async Task RunAsync(ushort dialect=0x302,int rounds=12,Action<string>? log=null)
    {
        var root=Path.Combine(Path.GetTempPath(),"smb-p8-local-"+Guid.NewGuid().ToString("N"));Directory.CreateDirectory(root);
        try
        {
            var watcher=new Watcher();var metrics=new SmbServerMetrics();
            await using var host=HostFixture.Build(new LocalFileStore(root,false),0,HostFixture.Domain,HostFixture.User,HostFixture.Password);
            var o=host.State.Options;o.DirectoryWatcher=watcher;o.Metrics=metrics;
            await host.StartAsync();
            int? warmFd=null;long warmMemory=0;
            for(var i=0;i<rounds;i++)
            {
                await using(var c=new WireClient())
                {
                    await c.ConnectAsync(host.Endpoint,HostFixture.Domain,HostFixture.User,HostFixture.Password,dialect);
                    var a=await CreateDelete(c,"a");var b=await c.CreateAsync("a");
                    await c.WriteAsync(a,"first"u8.ToArray());await c.ExchangeAsync(RawSmb.Write(b,"+append"u8.ToArray(),5,c.NextMessageId(),c.Session,c.Tree));
                    Check.That((await c.ReadAsync(a,12)).SequenceEqual("first+append"u8.ToArray()),"actual local append and second open read");
                    await c.ExchangeAsync(Lock(c,a,0x12));
                    await c.ExchangeAsync(RawSmb.Write(b,[0],0,c.NextMessageId(),c.Session,c.Tree),(uint)NtStatus.FileLockConflict);
                    await c.ExchangeAsync(Lock(c,a,4));
                    await c.WriteAsync(a,"FIRST"u8.ToArray());
                    var flush=Request(c,7,24);RawSmb.Put16(flush,64,24);Id(flush,72,a);await c.ExchangeAsync(flush);
                    var rename=new byte[24];RawSmb.Put32(rename,16,2);Encoding.Unicode.GetBytes("b").CopyTo(rename,20);
                    await c.ExchangeAsync(Set(c,a,10,rename));
                    Check.That((await c.ReadAsync(b,12)).SequenceEqual("FIRST+append"u8.ToArray()),"rename preserves other local open");
                    var dir=await c.CreateAsync("",true);Check.That((await c.EnumerateAsync(dir)).Contains("b"),"real directory enumeration");
                    var notify=Request(c,15,32);RawSmb.Put16(notify,64,32);RawSmb.Put32(notify,68,4096);Id(notify,72,dir);RawSmb.Put32(notify,88,1);
                    var interim=await c.ExchangeAsync(notify,(uint)NtStatus.Pending);Check.Equal(1,watcher.Active,"actual OS watcher alive");
                    await using(var other=new WireClient())
                    {await other.ConnectAsync(host.Endpoint,HostFixture.Domain,HostFixture.User,HostFixture.Password,dialect);var trigger=await other.CreateAsync("notify-"+i);await other.CloseAsync(trigger);}
                    var final=await c.ReceiveAsync();Check.Equal(0u,RawSmb.U32(final,8),"actual local watcher completes");Check.Equal(RawSmb.U64(interim,32),RawSmb.U64(final,32),"notify AsyncId");
                    await c.CloseAsync(dir);await c.CloseAsync(a);await c.CloseAsync(b);
                    var remove=await CreateDelete(c,"b");await c.ExchangeAsync(Set(c,remove,13,[1]));await c.CloseAsync(remove);Check.That(!File.Exists(root+"/b"),"wire disposition and close deletes local file");
                    await c.CreateAsync("tree-owned");await c.DisconnectTreeAsync();
                    Check.Equal(0L,metrics.OpenHandles,"tree teardown drains actual backend");Check.Equal(0,watcher.Active,"watchers quiescent");
                }
                var until=DateTime.UtcNow+Check.Timeout;
                while(metrics.ActiveConnections!=0&&DateTime.UtcNow<until)await Task.Delay(10);
                Check.Equal(0L,metrics.ActiveConnections,"transport drains");
                Check.Equal(0L,metrics.ActiveSessions,"sessions drain");Check.Equal(0L,metrics.ActiveTreeConnects,"trees drain");
                Check.Equal(0,host.State.Connections.Values.Sum(x=>x.PendingRequests.Count),"pending requests quiescent");
                Check.Equal(0,((InMemoryLockManager)o.LockManager).ActiveLockCount,"locks quiescent");Check.Equal(0,((InMemoryLockManager)o.LockManager).PendingLockCount,"waiters quiescent");
                Check.Equal(0,((InMemoryShareModeManager)o.ShareModeManager).ReservationCount,"shares quiescent");
                Check.Equal(0,o.CacheCoordinator.GrantCount,"grants quiescent");Check.Equal(0,host.State.CreateReplays.Count,"replays quiescent");Check.Equal(0,o.DurableHandleStore.TakeAll().Count,"no retained records");
                GC.Collect();GC.WaitForPendingFinalizers();GC.Collect();
                var fd=NativeHost.HandleCount();var memory=GC.GetTotalMemory(true);
                if(i==2){warmFd=fd;warmMemory=memory;}
                if(i>2){Check.That(fd<=warmFd+8,"quiescent native handle growth bound");Check.That(memory<=warmMemory+16*1024*1024,"quiescent managed memory growth bound");}
                using var process=System.Diagnostics.Process.GetCurrentProcess();
                log?.Invoke($"RESOURCE dialect={dialect:x} round={i} nativeHandles={fd} counter={(OperatingSystem.IsWindows()?"Process.HandleCount":"/proc/self/fd")} managed={memory} rss={process.WorkingSet64} handles={metrics.OpenHandles} pending=0 watchers={watcher.Active} locks=0 waiters=0 shares=0 recovery=0");
            }
            await host.StopAsync(TimeSpan.FromSeconds(1));
        }
        finally{Directory.Delete(root,true);}
    }
}
