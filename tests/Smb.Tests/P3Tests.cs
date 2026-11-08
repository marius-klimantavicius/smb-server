using Smb.Testing;
using Smb.Protocol.Enums;
using Smb.Protocol.Messages;
using Smb.Protocol.Wire;
using Smb.Server;
using Smb.Server.State;
using System.Security.Cryptography;

internal static class P3Tests
{
    const uint Invalid = 0xc000000d, InvalidHandle = 0xc0000008;
    static readonly (ulong P, ulong V) Inherit = (ulong.MaxValue, ulong.MaxValue);
    public static IEnumerable<(string, Func<Task>)> Cases()
    {
        yield return ("p3.compound.create-write-read-close", Chain);
        yield return ("p3.compound.tree-create-close", TreeChain);
        yield return ("p3.compound.failed-create-propagates", FailedCreate);
        yield return ("p3.compound.missing-file", MissingFile);
        yield return ("p3.compound.first-related", FirstRelated);
        yield return ("p3.compound.async-notify-declined", NotifyDeclined);
        yield return ("p3.compound.await-backend", AwaitBackend);
        yield return ("p3.compound.resolved-lifetime-reference", Lifetime);
        yield return ("p3.coverage.credit-model", LedgerModel);
        yield return ("p3.coverage.async-grant-once", AsyncGrant);
        yield return ("p3.coverage.unrelated-independence", Unrelated);
        yield return ("p3.coverage.cancel-credit-exception", CancelCredits);
        yield return ("p3.coverage.parser-boundary-matrix", ParserMatrix);
        foreach(var size in new[]{0,65535,65536,65537,131072,131073}) yield return ("p3.coverage.multi-credit-"+size,()=>Boundary(size));
        yield return ("p3.credit.out-of-order", OutOfOrder);
        yield return ("p3.bounds.context-data-wrap",()=>{var b=new byte[24];RawSmb.Put16(b,4,16);RawSmb.Put16(b,6,4);RawSmb.Put16(b,10,24);RawSmb.Put32(b,12,uint.MaxValue);Reject(()=>CreateContextList.Parse(b,0,b.Length),"unsigned context DataLength cannot disappear after signed conversion");return Task.CompletedTask;});
        yield return ("p3.bounds.zero-context-offset",()=>{var b=RawSmb.Create("a",false,0,1,42);RawSmb.Put32(b,112,120);Reject(()=>CreateRequest.Parse(b,64),"no contexts requires zero CreateContextsOffset");return Task.CompletedTask;});
        foreach(var field in new[]{"name-align","context-name-align","context-data-align","empty-create-buffer","cancel-fixed"})yield return ("p3.offsets."+field,()=>ExactOffsets(field));
        yield return ("p3.edge.smb1-negotiate-actual-grant", Smb1Credits);
        yield return ("p3.edge.server-ioctl-no-file",async()=>{await using var d=new Direct();var b=RawSmb.Header(11,56,0,1,42);RawSmb.Put16(b,64,57);RawSmb.Put32(b,68,0x001401fc);RawSmb.Put64(b,72,ulong.MaxValue);RawSmb.Put64(b,80,ulong.MaxValue);RawSmb.Put32(b,112,1);var r=Responses(await d.Compound(RawSmb.TreeConnect("\\\\host\\P0",0,1),b));Check.Equal(0xc00000bbu,RawSmb.U32(r[1],8),"server-level IOCTL sentinel is not inherited FileId");});
        yield return ("p3.final.response-padding", async()=>{await using var d=new Direct();var r=await d.Compound(d.D.Create(),RawSmb.Close(Inherit,0,1,42));Check.Equal(0,r.Length%8,"final compound response padded to 8 bytes");});
        yield return ("p3.final.ioctl-output-bounds",()=>{var b=RawSmb.Header(11,56,0);RawSmb.Put16(b,64,57);RawSmb.Put32(b,100,64);RawSmb.Put32(b,104,1);Reject(()=>IoctlMessage.ParseRequest(b,64),"IOCTL output cannot reach fixed header");return Task.CompletedTask;});
        yield return ("p3.extra.related-create-failure", async () => { await using var d=new Direct();d.D.Store.Control.Enqueue("Create",new OperationStep(Status:NtStatus.DiskFull));var r=Responses(await d.Compound(d.D.Create(),d.D.Create("b")));Check.Equal(0xc000007fu,RawSmb.U32(r[1],8),"related second CREATE cannot mutate after prerequisite failed");Check.Equal(1,d.D.Store.Control.Count("Create"),"no later backend acquisition"); });
        yield return ("p3.extra.zero-requested-grant", async () => {await using var d=new Direct();var b=d.Echo(0);RawSmb.Put16(b,14,0);Check.Equal((ushort)0,RawSmb.U16(await d.Send(b),14),"no unsolicited credits while client has credits");});
        foreach(var command in new ushort[]{2,4}) yield return ("p3.extra.fixed-"+command,async()=>{await using var d=new Direct();var b=RawSmb.Header(command,4,0,1,42);RawSmb.Put16(b,64,99);Check.Equal(Invalid,RawSmb.U32(await d.Send(b),8),"fixed structure before teardown");Check.That(d.D.Session.TreeConnects.ContainsKey(42),"malformed teardown no mutation");});
        yield return ("p3.credit.requested-grant", async () => { await using var d=new Direct();var b=d.Echo(0);RawSmb.Put16(b,14,2);var r=await d.Send(b);Check.That(RawSmb.U16(r,14)<=2,"grants within requested count"); });
        yield return ("p3.credit.window-overflow", () => {Check.That(CreditManager.IsWithinWindow(ulong.MaxValue-2,ulong.MaxValue-3,4),"bounded range arithmetic");return Task.CompletedTask;});
        yield return ("p3.parse.full-read-fields", () => FullFields(false));
        yield return ("p3.parse.full-write-fields", () => FullFields(true));
        yield return ("p3.credit.grants-only", ActualGrants);
        yield return ("p3.credit.related-duplicate", RelatedDuplicate);
        yield return ("p3.credit.concurrent-duplicate", ConcurrentDuplicate);
        yield return ("p3.credit.charge-overflow", ChargeOverflow);
        foreach (var kind in new[] { "read", "write", "query", "directory", "ioctl", "set" })
            yield return ("p3.credit.undercharge-" + kind, () => Undercharge(kind));
        yield return ("p3.credit.no-large-mtu", NoLargeMtu);
        foreach (var kind in new[] { "read-short", "write-short", "create-odd", "create-offset", "context-cross", "context-align", "write-offset", "query-cross", "directory-cross", "set-offset", "ioctl-wrap", "echo-short", "flush-size" })
            yield return ("p3.parse." + kind, () => Parser(kind));
        yield return ("p3.parse.next-align", NextAlign);
    }
    internal sealed class Direct : IAsyncDisposable
    {
        public readonly P2Tests.Direct D = new P2Tests.Direct();
        public SmbConnection C => D.Connection;
        ulong next = 1;
        public Direct()
        {
            // Actual NEGOTIATE grants, never a fabricated window. Existing auth/signing retained.

        }
        public byte[] Echo(ulong mid) { var b = RawSmb.Header(13, 4, mid, 1); RawSmb.Put16(b, 64, 4); return b; }
        public async Task<byte[]> Send(byte[] b, ulong? mid = null)
        {
            RawSmb.Put64(b, 24, mid ?? next++); RawSmb.Sign(b, D.Session.SigningKey);
            var response = await D.Dispatcher.ProcessMessageAsync(C, b); if (D.CommitResponses) C.ResponseSent(response); return response;
        }
        public Task<byte[]> Compound(params byte[][] packets) => D.Dispatcher.ProcessMessageAsync(C, Join(packets)).AsTask();
        public byte[] Join(byte[][] packets)
        {
            var result = new List<byte>();
            for (var i=0; i<packets.Length; i++)
            {
                var b = packets[i]; Array.Resize(ref b, i+1 < packets.Length ? (b.Length+7)&~7 : b.Length);
                RawSmb.Put64(b, 24, next++); RawSmb.Put32(b, 20, i+1 < packets.Length ? (uint)b.Length : 0);
                if (i>0) { RawSmb.Put32(b, 16, RawSmb.U32(b,16)|4); RawSmb.Put64(b,40,ulong.MaxValue); RawSmb.Put32(b,36,uint.MaxValue); }
                RawSmb.Sign(b, D.Session.SigningKey); result.AddRange(b);
            }
            return result.ToArray();
        }
        public async Task<(ulong P, ulong V)> Open() { var b = await Send(D.Create()); Check.Equal(0u,RawSmb.U32(b,8),"open status"); return (RawSmb.U64(b,128),RawSmb.U64(b,136)); }
        public ValueTask DisposeAsync() => D.DisposeAsync();
    }
    static List<byte[]> Responses(byte[] b)
    {
        var a = new List<byte[]>(); var p=0;
        while (true) { var n=RawSmb.U32(b,p+20); var len=n==0?b.Length-p:checked((int)n); Check.That(n==0 || (n%8==0 && n>=64),"aligned response NextCommand"); var s=b.AsSpan(p,len).ToArray(); a.Add(s); if(n==0)break; p+=len; }
        foreach(var s in a) { var sig=s.AsSpan(48,16).ToArray(); s.AsSpan(48,16).Clear(); Check.That(HMACSHA256.HashData(new byte[16],s).AsSpan(0,16).SequenceEqual(sig),"independent response signature"); sig.CopyTo(s,48); }
        return a;
    }
    static async Task Chain()
    {
        await using var d=new Direct(); var r=Responses(await d.Compound(d.D.Create(),RawSmb.Write(Inherit,[7,8,9],0,0,1,42),RawSmb.Read(Inherit,3,0,0,1,42),RawSmb.Close(Inherit,0,1,42)));
        Check.Equal(4,r.Count,"four responses"); foreach(var s in r)Check.Equal(0u,RawSmb.U32(s,8),"related chain success");
        Check.That(r.Skip(1).All(s=>(RawSmb.U32(s,16)&4)!=0),"related response flags retained"); Check.Equal((byte)80,r[2][66],"READ data offset relative to its command"); Check.That(r[2].AsSpan(80,3).SequenceEqual(new byte[]{7,8,9}),"read own write"); Check.Equal(0,d.D.Store.ActiveHandles,"chain close");
    }
    static async Task TreeChain() { await using var d=new Direct(); var r=Responses(await d.Compound(RawSmb.TreeConnect("\\\\host\\P0",0,1),d.D.Create(),RawSmb.Close(Inherit,0,1,42))); foreach(var b in r)Check.Equal(0u,RawSmb.U32(b,8),"generated TreeId inherited"); Check.Equal(RawSmb.U32(r[0],36),RawSmb.U32(r[1],36),"tree response result"); }
    static async Task FailedCreate() { await using var d=new Direct(); d.D.Store.Control.Enqueue("Create",new OperationStep(Status:NtStatus.DiskFull)); var r=Responses(await d.Compound(d.D.Create(),RawSmb.Write(Inherit,[1],0,0,1,42),RawSmb.Close(Inherit,0,1,42))); Check.Equal(0xc000007fu,RawSmb.U32(r[1],8),"dependent gets CREATE error"); Check.Equal(0xc000007fu,RawSmb.U32(r[2],8),"failure persists"); Check.Equal(0,d.D.Store.Control.Count("Write"),"no dependent write"); }
    static async Task MissingFile() { await using var d=new Direct(); var r=Responses(await d.Compound(RawSmb.TreeConnect("\\\\host\\P0",0,1),RawSmb.Close(Inherit,0,1,42))); Check.Equal(InvalidHandle,RawSmb.U32(r[1],8),"missing prior FileId"); }
    static async Task FirstRelated() { await using var d=new Direct(); var b=d.D.Create(); RawSmb.Put32(b,16,4); Check.Equal(Invalid,RawSmb.U32(await d.Send(b),8),"first related refused"); Check.Equal(0,d.D.Store.Control.Count("Create"),"invalid chain no mutation"); }
    static byte[] Notify((ulong P,ulong V) id) { var b=RawSmb.Header(15,32,0,1,42); RawSmb.Put16(b,64,32); RawSmb.Put32(b,68,100); RawSmb.Put64(b,72,id.P);RawSmb.Put64(b,80,id.V);RawSmb.Put32(b,88,1);return b; }
    static async Task NotifyDeclined() { await using var d=new Direct(); d.D.Options.MaxOutstandingRequests=0; var create=RawSmb.Create("",true,0,1,42); var r=Responses(await d.Compound(create,Notify(Inherit),RawSmb.Close(Inherit,0,1,42))); Check.Equal(0xc000009au,RawSmb.U32(r[1],8),"P3 compound async resources unavailable");Check.Equal(0xc000009au,RawSmb.U32(r[2],8),"dependent not run before async completion"); Check.That(d.C.PendingRequests.IsEmpty,"no pending work launched"); }
    static async Task AwaitBackend() { await using var d=new Direct(); var gate=new AsyncBarrier(); d.D.Store.Control.Enqueue("Create",new OperationStep(Barrier:gate)); var t=d.Compound(d.D.Create(),RawSmb.Write(Inherit,[1],0,0,1,42)); await gate.Entered; try {Check.Equal(0,d.D.Store.Control.Count("Write"),"dependent waits");}finally{gate.Release();} var r=Responses(await t.WaitAsync(Check.Timeout));Check.Equal(0u,RawSmb.U32(r[1],8),"dependent executes after backend completes"); }
    static async Task Lifetime() { await using var d=new Direct(); var gate=new AsyncBarrier(); d.D.Store.Control.Enqueue("Write",new OperationStep(Barrier:gate,IgnoreCancellation:true)); var t=d.Compound(d.D.Create(),RawSmb.Write(Inherit,[1],0,0,1,42)); await Task.WhenAny(gate.Entered,t).WaitAsync(Check.Timeout); Check.That(!t.IsCompleted,"resolved related WRITE admitted to backend"); var id=d.D.Session.Opens.Keys.Single(); var close=d.Send(RawSmb.Close(id,0,1,42),10); try {Check.That(!close.IsCompleted,"close drains resolved related operation");}finally{gate.Release();await t;await close;} }
    static async Task OutOfOrder() { await using var d=new Direct(); Check.Equal(0u,RawSmb.U32(await d.Send(d.Echo(0),4),8),"higher granted ID valid");Check.Equal(0u,RawSmb.U32(await d.Send(d.Echo(0),1),8),"lower unused granted ID remains valid"); }
    static async Task ActualGrants() { await using var d=new Direct(); Check.Equal(Invalid,RawSmb.U32(await d.Send(d.Echo(0),300),8),"ungranted number rejected"); }
    static async Task RelatedDuplicate() { await using var d=new Direct(); var b=d.Join([d.Echo(0),d.Echo(0)]); var p=(int)RawSmb.U32(b,20);RawSmb.Put64(b,p+24,RawSmb.U64(b,24));var tail=b.AsSpan(p).ToArray();RawSmb.Sign(tail,new byte[16]);tail.CopyTo(b,p);var r=Responses(await d.D.Dispatcher.ProcessMessageAsync(d.C,b));Check.Equal(Invalid,RawSmb.U32(r[1],8),"related duplicate consumed once"); }
    static async Task ConcurrentDuplicate() { await using var d=new Direct(); var id=await d.Open(); var req=RawSmb.Write(id,[1],0,2,1,42);RawSmb.Sign(req,new byte[16]);var ready=new ManualResetEventSlim(); var runs=Enumerable.Range(0,16).Select(_=>Task.Run(async()=>{ready.Wait();return await d.D.Dispatcher.ProcessMessageAsync(d.C,req);})).ToArray();ready.Set();var r=await Task.WhenAll(runs);Check.Equal(1,r.Count(b=>RawSmb.U32(b,8)==0),"exactly one duplicate admitted");Check.Equal(1,d.D.Store.Control.Count("Write"),"one backend mutation"); }
    static Task ChargeOverflow(){Check.Equal((ushort)32768,CreditManager.ComputeCreditCharge(SmbDialect.Smb210,int.MaxValue,0),"charge calculation cannot signed-overflow");return Task.CompletedTask;}
    static async Task Undercharge(string kind)
    {
        await using var d=new Direct();var id=await d.Open();d.C.Dialect=SmbDialect.Smb210;d.C.SupportsMultiCredit=true;d.C.MaxReadSize=d.C.MaxWriteSize=d.C.MaxTransactSize=1048576;
        var b=kind switch {"read"=>RawSmb.Read(id,65537,0,0,1,42),"write"=>RawSmb.Write(id,new byte[65537],0,0,1,42),"directory"=>RawSmb.Enumerate(id,0,1,42),"query"=>RawSmb.Header(16,40,0,1,42),"ioctl"=>RawSmb.Header(11,56,0,1,42),_=>RawSmb.Header(17,32+65537,0,1,42)};
        if(kind=="directory")RawSmb.Put32(b,92,65537);
        if(kind=="query"){RawSmb.Put16(b,64,41);b[66]=1;b[67]=5;RawSmb.Put32(b,68,65537);RawSmb.Put64(b,88,id.P);RawSmb.Put64(b,96,id.V);}
        if(kind=="ioctl"){RawSmb.Put16(b,64,57);RawSmb.Put32(b,68,IoctlMessage.FsctlPipeTransceive);RawSmb.Put32(b,108,65537);}
        if(kind=="set"){RawSmb.Put16(b,64,33);b[66]=1;b[67]=20;RawSmb.Put32(b,68,65537);RawSmb.Put16(b,72,96);RawSmb.Put64(b,80,id.P);RawSmb.Put64(b,88,id.V);}
        RawSmb.Put16(b,6,1);Check.Equal(Invalid,RawSmb.U32(await d.Send(b),8),"undercharged "+kind);if(kind=="write")Check.Equal(0,d.D.Store.Control.Count("Write"),"charge checked before mutation");if(kind=="set")Check.Equal(0,d.D.Store.Control.Count("SetEndOfFile"),"charge checked before set EOF");
    }
    static async Task NoLargeMtu(){await using var d=new Direct();var id=await d.Open();var b=RawSmb.Write(id,new byte[65537],0,0,1,42);Check.Equal(Invalid,RawSmb.U32(await d.Send(b),8),"non-multicredit payload ceiling");Check.Equal(0,d.D.Store.Control.Count("Write"),"no oversized mutation");}
    static void Reject(Action parse,string why){try{parse();}catch(SmbWireFormatException){return;}throw new Exception("Expected structural rejection: "+why);}
    static async Task Parser(string kind)
    {
        var id=(0UL,1UL);byte[] b;
        switch(kind)
        {
            case "read-short": b=RawSmb.Read(id,1,0,0,1,42)[..100];Reject(()=>ReadMessage.ParseRequest(b,64),kind);break;
            case "write-short": b=RawSmb.Write(id,[],0,0,1,42)[..96];Reject(()=>WriteMessage.ParseRequest(b,64),kind);break;
            case "create-odd": b=RawSmb.Create("ab",false,0,1,42);RawSmb.Put16(b,110,3);Reject(()=>CreateRequest.Parse(b,64),kind);break;
            case "create-offset": b=RawSmb.Create("ab",false,0,1,42);RawSmb.Put16(b,108,64);Reject(()=>CreateRequest.Parse(b,64),kind);break;
            case "context-cross": case "context-align": b=new byte[48];RawSmb.Put32(b,0,kind=="context-align"?17u:24u);RawSmb.Put16(b,4,16);RawSmb.Put16(b,6,kind=="context-align"?(ushort)0:(ushort)16); Reject(()=>CreateContextList.Parse(b,0,b.Length),kind);break;
            case "write-offset": b=RawSmb.Write(id,[1],0,0,1,42);RawSmb.Put16(b,66,64);Reject(()=>WriteMessage.ParseRequest(b,64),kind);break;
            case "query-cross": b=RawSmb.Header(16,40,0);RawSmb.Put16(b,64,41);RawSmb.Put16(b,72,104);RawSmb.Put32(b,76,100);Reject(()=>QueryInfoMessage.ParseRequest(b,64),kind);break;
            case "directory-cross":b=RawSmb.Enumerate(id,0,1,42);RawSmb.Put16(b,90,100);Reject(()=>QueryDirectoryMessage.ParseRequest(b,64),kind);break;
            case "set-offset":b=RawSmb.Header(17,33,0);RawSmb.Put16(b,64,33);RawSmb.Put32(b,68,1);RawSmb.Put16(b,72,64);Reject(()=>SetInfoMessage.ParseRequest(b,64),kind);break;
            case "ioctl-wrap":b=RawSmb.Header(11,56,0);RawSmb.Put16(b,64,57);RawSmb.Put32(b,88,uint.MaxValue);RawSmb.Put32(b,92,2);Reject(()=>IoctlMessage.ParseRequest(b,64),kind);break;
            case "echo-short":Reject(()=>EchoMessage.ValidateRequest(new byte[]{4,0}),kind);break;
            default:await using(var d=new Direct()){var f=RawSmb.Header(7,24,0,1,42);RawSmb.Put16(f,64,99);Check.Equal(Invalid,RawSmb.U32(await d.Send(f),8),"FLUSH fixed StructureSize");}break;
        }
    }
    static Task ExactOffsets(string field)
    {
        if(field=="cancel-fixed"){var b=RawSmb.Header(12,2,0);RawSmb.Put16(b,64,4);Reject(()=>CancelMessage.ParseRequest(b,64),"CANCEL reserved fixed field must be present");}
        else if(field=="name-align"){var b=RawSmb.Create("ab",false,0,1,42);RawSmb.Put16(b,108,122);RawSmb.Put16(b,110,2);Reject(()=>CreateRequest.Parse(b,64),"CREATE NameOffset requires 8-byte alignment");}
        else if(field=="empty-create-buffer"){var b=RawSmb.Create("",false,0,1,42)[..120];Reject(()=>CreateRequest.Parse(b,64),"CREATE requires at least one Buffer byte");}
        else {var b=new byte[40];RawSmb.Put16(b,4,field=="context-name-align"?(ushort)18:(ushort)16);RawSmb.Put16(b,6,4);RawSmb.Put16(b,10,field=="context-data-align"?(ushort)26:(ushort)24);RawSmb.Put32(b,12,1);Reject(()=>CreateContextList.Parse(b,0,b.Length),"context name/data must be 8-byte aligned");}
        return Task.CompletedTask;
    }
    static async Task Smb1Credits()
    {
        await using var d=new Direct();var c=new SmbConnection();var dialect=System.Text.Encoding.ASCII.GetBytes("SMB 2.002\0");var b=new byte[36+dialect.Length];b[0]=255;b[1]=83;b[2]=77;b[3]=66;b[4]=114;RawSmb.Put16(b,33,(ushort)(dialect.Length+1));b[35]=2;dialect.CopyTo(b,36);
        var response=await d.D.Dispatcher.ProcessMessageAsync(c,b);Check.Equal((ushort)1,RawSmb.U16(response,14),"SMB1 final response grant");c.Sessions.TryAdd(1,d.D.Session);var echo=d.Echo(1);RawSmb.Sign(echo,new byte[16]);Check.Equal(0u,RawSmb.U32(await d.D.Dispatcher.ProcessMessageAsync(c,echo),8),"SMB1 negotiated credit ID 1 available");
    }
    static Task LedgerModel()
    {
        var ledger=new CreditSequenceLedger();var oracle=new HashSet<ulong>{0};ulong granted=0;var random=new Random(4739);
        for(var i=0;i<4000;i++)
        {
            var id=(ulong)random.Next((int)Math.Min(granted+5,100000));var charge=(ushort)random.Next(1,5);
            var expected=Enumerable.Range(0,charge).All(x=>oracle.Contains(id+(ulong)x));
            Check.Equal(expected,ledger.TryConsume(id,charge),"sequence ledger vs independent available set");
            if(expected)for(ulong j=0;j<charge;j++)oracle.Remove(id+j);
            if(i%3==0){var asked=(ushort)random.Next(0,20);var n=ledger.Grant(asked);Check.That(n<=asked || (oracle.Count==0 && n==1),"bounded requested grant");for(var j=0;j<n;j++)oracle.Add(++granted);}
            Check.Equal(oracle.Count,ledger.AvailableCount,"actual grants and consumption conserved");
        }
        Check.That(!ledger.TryConsume(ulong.MaxValue,1) && !ledger.TryConsume(ulong.MaxValue-1,4),"overflow ranges rejected without wrapping");
        var bounded=new CreditSequenceLedger();Check.Equal((ushort)65535,bounded.Grant(65535),"maximum grant fits bounded ledger");Check.Equal((ushort)0,bounded.Grant(1),"old hole bounds sequence range");return Task.CompletedTask;
    }
    static async Task AsyncGrant()
    {
        await using var d=new Direct();var watcher=new FakeWatcher();d.D.Options.DirectoryWatcher=watcher;var transport=new RecordingTransport();d.C.SendRawAsync=transport.SendAsync;
        var b=await d.Send(RawSmb.Create("",true,0,1,42));var id=(RawSmb.U64(b,128),RawSmb.U64(b,136));var before=d.C.Credits.AvailableCount;
        var req=Notify(id);RawSmb.Put16(req,14,3);var interim=await d.Send(req);Check.Equal(0x103u,RawSmb.U32(interim,8),"notify pending");Check.Equal((ushort)3,RawSmb.U16(interim,14),"credits only in interim");Check.Equal(before+2,d.C.Credits.AvailableCount,"interim actual grant");
        watcher.Subscriptions.Single().Emit(new Smb.Server.Notification.FileNotifyEvent(Smb.Server.Notification.FileNotifyAction.Added,"file"));await transport.WaitForSendAsync();var final=transport.Sends.Single().Message;Check.Equal((ushort)0,RawSmb.U16(final,14),"async final zero grant");Check.Equal(before+2,d.C.Credits.AvailableCount,"no double grant on final");
    }
    static async Task Unrelated()
    {
        await using var d=new Direct();d.D.Store.Control.Enqueue("Create",new OperationStep(Status:NtStatus.DiskFull));var a=d.D.Create();Array.Resize(ref a,(a.Length+7)&~7);RawSmb.Put64(a,24,1);RawSmb.Put32(a,20,(uint)a.Length);RawSmb.Sign(a,new byte[16]);var b=d.D.Create("independent");RawSmb.Put64(b,24,2);RawSmb.Sign(b,new byte[16]);var r=Responses(await d.D.Dispatcher.ProcessMessageAsync(d.C,a.Concat(b).ToArray()));Check.Equal(0xc000007fu,RawSmb.U32(r[0],8),"unrelated first fails");Check.Equal(0u,RawSmb.U32(r[1],8),"unrelated second creates independently");Check.That((RawSmb.U32(r[1],16)&4)==0,"unrelated response flag clear");
    }
    static async Task CancelCredits(){await using var d=new Direct();var before=d.C.Credits.AvailableCount;var b=RawSmb.Header(12,4,ulong.MaxValue,1);RawSmb.Put16(b,64,4);RawSmb.Sign(b,new byte[16]);var r=await d.D.Dispatcher.ProcessMessageAsync(d.C,b);Check.Equal(0,r.Length,"CANCEL has no response");Check.Equal(before,d.C.Credits.AvailableCount,"CANCEL consumes no sequence");}
    static Task ParserMatrix()
    {
        foreach(var write in new[]{false,true})
        {
            var b=write?RawSmb.Write(Inherit,[1],0,0,1,42):RawSmb.Read(Inherit,1,0,0,1,42);
            for(var n=64;n<112;n++){var truncated=b[..n];Reject(()=>{if(write)WriteMessage.ParseRequest(truncated,64);else ReadMessage.ParseRequest(truncated,64);},"every truncated fixed field");}
            var invalid=(byte[])b.Clone();RawSmb.Put16(invalid,64,48);Reject(()=>{if(write)WriteMessage.ParseRequest(invalid,64);else ReadMessage.ParseRequest(invalid,64);},"wrong StructureSize");
            if(write)Check.Equal(1,WriteMessage.ParseRequest(b,64).Data.Length,"valid WRITE boundary");else Check.Equal(1u,ReadMessage.ParseRequest(b,64).Length,"valid READ boundary");
        }
        var create=RawSmb.Create("ab",false,0,1,42);Check.Equal("ab",CreateRequest.Parse(create,64).Name,"valid UTF16 name");
        var ctx=new byte[24];RawSmb.Put16(ctx,4,16);RawSmb.Put16(ctx,6,4);new byte[]{1,2,3,4}.CopyTo(ctx,16);Check.Equal(1,CreateContextList.Parse(ctx,0,24).Count,"bounded context accepts its own name");return Task.CompletedTask;
    }
    static async Task Boundary(int size)
    {
        await using var d=new Direct();var id=await d.Open();d.C.Dialect=SmbDialect.Smb210;d.C.SupportsMultiCredit=true;d.C.MaxReadSize=d.C.MaxWriteSize=1048576;
        var charge=(ushort)Math.Max(1,(size+65535)/65536);var b=RawSmb.Write(id,new byte[size],0,0,1,42);RawSmb.Put16(b,6,charge);Check.Equal(0u,RawSmb.U32(await d.Send(b,4),8),"valid size-based charge");
        var duplicate=await d.Send(d.Echo(0),(ulong)(4+charge-1));Check.Equal(Invalid,RawSmb.U32(duplicate,8),"entire multi-credit range consumed");
        if(size<=65536){var zero=RawSmb.Write(id,new byte[size],0,0,1,42);Check.Equal(0u,RawSmb.U32(await d.Send(zero,10),8),"zero charge allowed for single-credit payload");}
        d.C.Dialect=SmbDialect.Smb202;d.C.SupportsMultiCredit=false;var legacy=RawSmb.Write(id,[1],0,0,1,42);RawSmb.Put16(legacy,6,65535);Check.Equal(0u,RawSmb.U32(await d.Send(legacy,20),8),"SMB202 ignores reserved charge");Check.Equal(0u,RawSmb.U32(await d.Send(d.Echo(0),21),8),"SMB202 consumes one ID");
    }
    static Task FullFields(bool write)
    {
        var b=write?RawSmb.Write(Inherit,[],0,0,1,42):RawSmb.Read(Inherit,0,0,0,1,42);RawSmb.Put32(b,write?96:100,0x12345678);RawSmb.Put32(b,write?100:104,123);RawSmb.Put16(b,108,111);RawSmb.Put16(b,110,0);if(write)RawSmb.Put32(b,108,3);else b[67]=3;
        var channel=write?WriteMessage.ParseRequest(b,64).Channel:ReadMessage.ParseRequest(b,64).Channel;
        var flags=write?WriteMessage.ParseRequest(b,64).Flags:ReadMessage.ParseRequest(b,64).Flags;
        Check.Equal(0x12345678u,channel,"full channel value");Check.Equal(3u,flags,"complete flags exposed");return Task.CompletedTask;
    }
    static async Task NextAlign(){await using var d=new Direct();var b=d.Echo(0);Array.Resize(ref b,69);RawSmb.Put32(b,20,69);RawSmb.Put64(b,24,1);RawSmb.Sign(b,new byte[16]);var tail=d.Echo(2);RawSmb.Sign(tail,new byte[16]);b=b.Concat(tail).ToArray();Check.Equal(Invalid,RawSmb.U32(await d.D.Dispatcher.ProcessMessageAsync(d.C,b),8),"unaligned NextCommand refused");}
}
