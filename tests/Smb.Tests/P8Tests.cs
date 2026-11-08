using Smb.Testing;
internal static class P8Tests
{
 public static IEnumerable<(string,Func<Task>)> Cases()
 {
  foreach(var d in new ushort[]{0x202,0x210,0x300,0x302,0x311})yield return ($"p8.local.{d:x}",()=>LocalWorkload.RunAsync(d,4,Console.WriteLine));
 }
}

internal static class P8Profiles
{
    static readonly (string Name,Smb.Server.SmbFeaturePolicy Policy)[] Profiles = [
        ("Restricted",Smb.Server.SmbFeaturePolicy.Restricted),("CopyOnly",Smb.Server.SmbFeaturePolicy.CopyOnly),
        ("Caching",Smb.Server.SmbFeaturePolicy.Caching),("CachingWithCopy",Smb.Server.SmbFeaturePolicy.CachingWithCopy),
        ("MultichannelOnly",Smb.Server.SmbFeaturePolicy.MultichannelOnly),("MultichannelWithCopy",Smb.Server.SmbFeaturePolicy.MultichannelWithCopy),
        ("MultichannelWithCaching",Smb.Server.SmbFeaturePolicy.MultichannelWithCaching),("MultichannelWithCachingAndCopy",Smb.Server.SmbFeaturePolicy.MultichannelWithCachingAndCopy),
        ("Durable",Smb.Server.SmbFeaturePolicy.Durable),("DurableWithCopy",Smb.Server.SmbFeaturePolicy.DurableWithCopy),
        ("DurableWithMultichannel",Smb.Server.SmbFeaturePolicy.DurableWithMultichannel),("DurableWithMultichannelAndCopy",Smb.Server.SmbFeaturePolicy.DurableWithMultichannelAndCopy)];
    public static IEnumerable<(string,Func<Task>)> Cases()
    {
        foreach(var (name,policy) in Profiles)foreach(var dialect in new ushort[]{0x202,0x210,0x300,0x302,0x311})foreach(var exclusive in new[]{false,true})
            yield return ($"p8.audit.{name}.{dialect:x}.{(exclusive?"exclusive":"shared")}",()=>Audit(name,policy,dialect,exclusive));
    }
    static async Task Audit(string name,Smb.Server.SmbFeaturePolicy policy,ushort dialect,bool exclusive)
    {
        var path=Path.Combine(Path.GetTempPath(),"smb-p8-matrix-"+Guid.NewGuid().ToString("N"));Directory.CreateDirectory(path);
        try
        {
            await using var d=new P2Tests.Direct(new Smb.FileSystem.Local.LocalFileStore(path,false,null,exclusive));
            d.Options.FeaturePolicy=policy;d.Options.EnableMultichannel=policy.Multichannel;d.Options.MinDialect=d.Options.MaxDialect=(Smb.Protocol.Enums.SmbDialect)dialect;policy.Validate(d.Options);
            // Client offers LargeMTU/Leasing/Multichannel, no encryption change or security assertion.
            var response=Smb.Server.NegotiateProcessor.BuildResponse(d.Connection,new Smb.Protocol.Messages.NegotiateRequest { Dialects=[(Smb.Protocol.Enums.SmbDialect)dialect],Capabilities=(Smb.Protocol.Enums.Smb2Capabilities)14,SecurityMode=(Smb.Protocol.Enums.SmbSecurityMode)3 },d.Options,[]);
            var expected=(dialect>=0x210?4u:0u)|(policy.Leasing&&exclusive&&dialect>=0x210?2u:0u)|(policy.Multichannel&&dialect is 0x300 or 0x302 or 0x311?8u:0u);
            Check.Equal(expected,(uint)response.Capabilities,"negotiated non-security bits");Check.That(((uint)response.SecurityMode&2)!=0,"signing still required");
            var create=P7cTests.Request("a",Guid.NewGuid());var wire=await d.Send(create);Check.Equal(0u,RawSmb.U32(wire,8),"batch plus DH2Q CREATE succeeds");
            var id=P7cTests.Id(wire);var open=d.Session.Opens[id];var cache=policy.Oplocks&&exclusive;
            Check.Equal(cache?(byte)9:(byte)0,wire[66],"file Batch grant gate");Check.Equal(policy.DurableHandles&&cache&&dialect is 0x300 or 0x302 or 0x311,open.IsDurable,"durable gate");Check.That(!open.IsPersistentHandle,"no persistent handles");
            // Actual FSCTL resume-key gate, rather than only reading policy.
            var ioctl=RawSmb.Header(11,57,0,1,42);RawSmb.Put16(ioctl,64,57);RawSmb.Put32(ioctl,68,0x140078);RawSmb.Put64(ioctl,72,id.P);RawSmb.Put64(ioctl,80,id.V);RawSmb.Put32(ioctl,108,32);RawSmb.Put32(ioctl,112,1);
            Check.Equal(policy.CopyChunk?0u:0xc00000bbu,RawSmb.U32(await d.Send(ioctl),8),"copy resume-key gate");
            await d.Send(RawSmb.Close(id,0,1,42));
            var lease=P7cTests.Lease(RawSmb.Create("lease",false,0,1,42));var result=await d.Send(lease);Check.Equal(0u,RawSmb.U32(result,8),"lease request");var leaseId=P7cTests.Id(result);
            Check.Equal(cache&&dialect>=0x210?(byte)255:(byte)0,result[66],"lease dialect/backend/profile gate");await d.Send(RawSmb.Close(leaseId,0,1,42));
            var directory=P7cTests.Lease(RawSmb.Create("",true,0,1,42));result=await d.Send(directory);Check.Equal(0u,RawSmb.U32(result,8),"directory lease request ignored");Check.Equal((byte)0,result[66],"directory caching withheld");await d.Send(RawSmb.Close(P7cTests.Id(result),0,1,42));
            Console.WriteLine($"AUDIT profile={name} dialect={dialect:x} exclusive={exclusive} bits={expected:x} batch={cache} lease={cache&&dialect>=0x210} durable={open.IsDurable} copy={policy.CopyChunk}");
        }
        finally{Directory.Delete(path,true);}
    }
}
