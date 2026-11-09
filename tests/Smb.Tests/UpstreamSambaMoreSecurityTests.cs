using Smb.Auth;
using Smb.Testing;

internal static partial class UpstreamSambaMoreTests
{
    static IEnumerable<(string Name, Func<Task> Run)> SecurityCases()
    {
        foreach (var row in new (uint Mask, bool Query, bool Dacl, bool Owner)[]
        {
            (0,false,false,false),(1,false,false,false),(2,false,false,false),(4,false,false,false),
            (8,false,false,false),(16,false,false,false),(32,false,false,false),(64,false,false,false),
            (128,false,false,false),(256,false,false,false),(0x10000,false,false,false),
            (0x20000,true,false,false),(0x40000,false,true,false),(0x80000,false,false,true),(0x100000,false,false,false),
            (0x80000000,true,false,false),(0x40000000,true,false,false),(0x20000000,true,false,false),
            (0x10000000,true,true,true),(0x02000000,true,true,true)
        })
            yield return ($"upstream.samba.more.security.access.{row.Mask:x8}", () => SecurityAccessMask(row));
        foreach (var row in new (uint Generic, uint Specific)[] { (0x80000000,0x120089),(0x40000000,0x120116),(0x20000000,0x1200a0),(0x10000000,0x1f01ff) })
            yield return ($"upstream.samba.more.security.generic-ace.{row.Generic:x8}", () => GenericAce(row));
        foreach (var flags in Enumerable.Range(0, 16).Select(value => (byte)value))
            yield return ($"upstream.samba.more.security.inheritance.{flags:x2}", () => WireInheritance(flags));
        foreach (var allowFirst in new[] { false, true })
            yield return ($"upstream.samba.more.security.ace-order.{allowFirst}", () => AceOrder(allowFirst));
        foreach (var shape in new[] { "rename", "hardlink", "stream-from-base", "base-from-stream" })
            yield return ($"upstream.samba.more.security.namespace.{shape}", () => SecurityNamespace(shape));
        foreach (var shape in new[] { "empty", "null", "owner-read-only", "owner-deny-control", "owner-deny-dac" })
            yield return ($"upstream.samba.more.security.owner.{shape}", () => OwnerRights(shape));
        foreach (var row in new (uint Generic, uint Specific)[] { (0x80000000,0x120089),(0x40000000,0x120116),(0x20000000,0x1200a0),(0x10000000,0x1f01ff) })
            yield return ($"upstream.samba.more.security.generic-access.{row.Generic:x8}", () => GenericAceAccess(row));
        yield return ("upstream.samba.more.security.empty-query-fields", EmptySecurityQuery);
        yield return ("upstream.samba.more.security.creator-owner-placeholder", CreatorOwner);
        yield return ("upstream.samba.more.security.partial-field-update-and-remove-ace", DescriptorFieldIsolation);
        yield return ("upstream.samba.more.security.maximum-allowed-explicit-access", MaximumExplicitAccess);
        yield return ("upstream.samba.more.security.access-based-enum-unadvertised", AccessBasedUnadvertised);
        yield return ("upstream.samba.more.security.inheritance-control-table", InheritanceControls);
        yield return ("upstream.samba.more.security.parent-update-is-not-retroactive", StaticInheritance);
        foreach (var directory in new[] { false, true }) yield return ($"upstream.samba.more.security.readonly-maximum.{directory}", () => ReadonlyMaximum(directory));
    }
    static byte[] Sid(uint authority, params uint[] subauthorities)
    {
        var bytes = new byte[8 + 4 * subauthorities.Length]; bytes[0] = 1; bytes[1] = (byte)subauthorities.Length;
        for (var i = 0; i < 6; i++) bytes[7 - i] = (byte)((ulong)authority >> (i * 8));
        for (var i = 0; i < subauthorities.Length; i++) RawSmb.Put32(bytes, 8 + i * 4, subauthorities[i]); return bytes;
    }
    static byte[] WithOwnerGroup(byte[] sd, byte[] owner, byte[] group)
    {
        var original = sd.Length; Array.Resize(ref sd, original + owner.Length + group.Length);
        RawSmb.Put32(sd, 4, (uint)original); RawSmb.Put32(sd, 8, (uint)(original + owner.Length)); owner.CopyTo(sd, original); group.CopyTo(sd, original + owner.Length); return sd;
    }
    static byte[] SecuritySet((ulong P, ulong V) id, byte[] descriptor, uint fields = 4)
    { var b = Set(id, 0, descriptor); b[66] = 3; RawSmb.Put32(b, 76, fields); return b; }
    static byte[] SecurityQuery((ulong P, ulong V) id, uint fields = 4)
    { var b = Query(id, 0, type: 3); RawSmb.Put32(b, 80, fields); return b; }
    static async Task SecurityAccessMask((uint Mask, bool Query, bool Dacl, bool Owner) row)
    {
        using var root = new P7cTests.Root(); await using var d = new P2Tests.Direct(root.Store());
        d.Session.Identity = new SecurityIdentity { DomainName = "UPSTREAM", UserName = "acl-user", UserSid = "S-1-5-21-1-2-3-1000", GroupSids = ["S-1-5-32-545"] };
        var admin = await Open(d, disposition: 3, access: 0x1f01ff); var sd = Dacl(0, false); RawSmb.Put32(sd, 32, 0x1f01ff);
        sd = WithOwnerGroup(sd, Sid(5,21,1,2,3,1000), Sid(5,32,545));
        Status(await d.Send(SecuritySet(admin, sd, 7)), Ok, "install Everyone full access with the caller as owner");
        var id = await Open(d, access: row.Mask);
        foreach (var field in new uint[] { 1, 2, 4 })
            Status(await d.Send(SecurityQuery(id, field)), row.Query ? Ok : Denied, "security query field requires granted READ_CONTROL");
        Status(await d.Send(SecuritySet(id, sd, 4)), row.Dacl ? Ok : Denied, "DACL SET requires granted WRITE_DAC");
        Status(await d.Send(SecuritySet(id, sd, 1)), row.Owner ? Ok : Denied, "owner SET requires granted WRITE_OWNER");
        Status(await d.Send(SecuritySet(id, sd, 2)), row.Owner ? Ok : Denied, "group SET requires granted WRITE_OWNER");
        var stored = Output(await d.Send(SecurityQuery(admin, 7)));
        var owner = (int)RawSmb.U32(stored, 4); Check.That(stored.AsSpan(owner, 28).SequenceEqual(Sid(5,21,1,2,3,1000)), "denied SETs leave owner intact");
        await Close(d, id);
    }
    static async Task GenericAce((uint Generic, uint Specific) row)
    {
        using var root = new P7cTests.Root(); await using var d = new P2Tests.Direct(root.Store()); var admin = await Open(d, disposition: 3, access: 0x1f01ff);
        var descriptor = Dacl(0, false); RawSmb.Put32(descriptor, 32, row.Generic);
        Status(await d.Send(SecuritySet(admin, descriptor)), Ok, "set generic Everyone ACE");
        var q = Output(await d.Send(SecurityQuery(admin))); var acl = (int)RawSmb.U32(q, 16);
        Check.Equal(row.Specific, RawSmb.U32(q, acl + 12), "generic ACE converted to file-specific access mask");
        var peer = await Open(d, access: 0x02000000); // actual MAXIMUM_ALLOWED grant
        if ((row.Specific & 0x80) != 0) Check.Equal(row.Specific, RawSmb.U32(Output(await d.Send(Query(peer, 18))), 76), "MAXIMUM_ALLOWED reflects the specific ACL mask");
        await Close(d, peer);
    }
    static async Task WireInheritance(byte flags)
    {
        using var root = new P7cTests.Root(); await using var d = new P2Tests.Direct(root.Store()); var parent = await Open(d, "parent", 2, access: 0x1f01ff, directory: true);
        var descriptor = DaclWithFallback(flags, true, 3); Status(await d.Send(SecuritySet(parent, descriptor)), Ok, "install inheritable deny plus inheritable allow fallback");
        // Create with WRITE_DATA + metadata/security access, excluding denied bit
        // READ_DATA/LIST_DIRECTORY. Verify denial using fresh independent opens.
        var childFile = await Open(d, "parent\\file", 2, access: 0x1f01fe); await Write(d, childFile, [7]); await Close(d, childFile);
        var childDir = await Open(d, "parent\\dir", 2, access: 0x1f01fe, directory: true); await Close(d, childDir);
        var grandchild = await Open(d, "parent\\dir\\file", 2, access: 0x1f01fe); await Write(d, grandchild, [8]); await Close(d, grandchild);
        foreach (var row in new[]
        {
            (Path:"parent\\file", Directory:false, Denied:(flags & 1) != 0),
            (Path:"parent\\dir", Directory:true, Denied:(flags & 2) != 0),
            (Path:"parent\\dir\\file", Directory:false, Denied:(flags & 1) != 0 && (flags & 4) == 0)
        })
        {
            var b = await d.Send(Create(row.Path, access: 1, directory: row.Directory)); Status(b, row.Denied ? Denied : Ok, "OI/CI/NO_PROPAGATE inheritance controls fresh child/grandchild data access");
            if (!row.Denied) await Close(d, Id(b));
        }
    }
    static async Task AceOrder(bool allowFirst)
    {
        using var root = new P7cTests.Root(); await using var d = new P2Tests.Direct(root.Store()); var admin = await Open(d, disposition: 3, access: 0x1f01ff);
        var sd = DaclWithFallback(0, true);
        if (allowFirst) { var deny = sd.AsSpan(28, 20).ToArray(); sd.AsSpan(48, 20).CopyTo(sd.AsSpan(28)); deny.CopyTo(sd, 48); }
        Status(await d.Send(SecuritySet(admin, sd)), Ok, "explicit ordered basic DACL accepted by the local NT descriptor store");
        var bytes = Output(await d.Send(SecurityQuery(admin))); var acl = (int)RawSmb.U32(bytes, 16);
        Check.Equal(allowFirst ? (byte)0 : (byte)1, bytes[acl + 8], "explicit ACE order retained on query");
        Status(await d.Send(Create(access: 1)), allowFirst ? Ok : Denied, "access check applies ordered allow/deny ACEs");
    }
    static async Task SecurityNamespace(string shape)
    {
        using var root = new P7cTests.Root(); await using var d = new P2Tests.Direct(root.Store()); var admin = await Open(d, disposition: 3, access: 0x1f01ff); await Write(d, admin, Payload);
        var target = admin;
        if (shape.Contains("stream")) { target = await Open(d, "file:stream", 3, access: 0x1f01ff); await Write(d, target, [7]); }
        if (shape == "hardlink")
        {
            NativeHost.HardLink(Path.Combine(root.Path, "file"), Path.Combine(root.Path, "alias")); var alias = await Open(d, "alias", access: 0x81);
            Check.Equal(RawSmb.U64(Output(await d.Send(Query(admin, 6))), 0), RawSmb.U64(Output(await d.Send(Query(alias, 6))), 0), "hardlink prerequisite identifies the same object"); await Close(d, alias);
        }
        Status(await d.Send(SecuritySet(shape == "base-from-stream" ? target : admin, DaclWithFallback(0, true))), Ok, "deny future READ while preserving old granted handles");
        Status(await d.Send(Create(access: 1)), Denied, "base fresh READ denied by applied DACL");
        if (shape == "rename")
        {
            Status(await d.Send(Rename(admin, "renamed")), Ok, "existing DELETE grant permits rename after ACL update");
            Status(await d.Send(Create("renamed", access: 1)), Denied, "ACL follows object through rename");
            var replacement = await Open(d, disposition: 2); await Write(d, replacement, [9]); await Data(d, replacement, [9]); await Data(d, admin, Payload);
        }
        if (shape == "hardlink") Status(await d.Send(Create("alias", access: 1)), Denied, "hardlink cannot bypass the object's deny ACL");
        if (shape.Contains("stream"))
        {
            Status(await d.Send(Create("file:stream", access: 1)), Denied, "base and stream share the same access policy"); await Data(d, target, [7]);
        }
        await Data(d, admin, Payload);
    }
    static async Task OwnerRights(string shape)
    {
        using var root = new P7cTests.Root(); await using var d = new P2Tests.Direct(root.Store());
        d.Session.Identity = new SecurityIdentity { DomainName = "UPSTREAM", UserName = "owner", UserSid = "S-1-5-21-1-2-3-1000", GroupSids = ["S-1-5-32-545"] };
        var admin = await Open(d, disposition: 3, access: 0x1f01ff); var full = Dacl(0, false); RawSmb.Put32(full, 32, 0x1f01ff);
        Status(await d.Send(SecuritySet(admin, WithOwnerGroup(full, Sid(5,21,1,2,3,1000), Sid(5,32,545)), 7)), Ok, "set caller as owner with explicit full access");
        byte[] sd;
        if (shape is "empty" or "null")
        {
            sd = new byte[shape == "empty" ? 28 : 20]; sd[0] = 1; RawSmb.Put16(sd, 2, 0x8004);
            if (shape == "empty") { RawSmb.Put32(sd, 16, 20); sd[20] = 2; RawSmb.Put16(sd, 22, 8); }
        }
        else
        {
            sd = shape == "owner-read-only" ? Dacl(0, false) : DaclWithFallback(0, true);
            Sid(3,4).CopyTo(sd, 36); RawSmb.Put32(sd, 32, shape == "owner-deny-dac" ? 0x40000u : shape == "owner-deny-control" ? 0x20000u : 1u);
        }
        Status(await d.Send(SecuritySet(admin, sd)), Ok, "apply null/empty/OWNER RIGHTS DACL");
        Status(await d.Send(Create(access: 1)), shape == "empty" ? Denied : Ok, "NULL permits data; empty DACL denies; explicit OWNER RIGHTS permits data as specified");
        Status(await d.Send(Create(access: 0x20000)), shape is "owner-read-only" or "owner-deny-control" ? Denied : Ok, "OWNER RIGHTS controls the implicit READ_CONTROL grant");
        Status(await d.Send(Create(access: 0x40000)), shape is "owner-read-only" or "owner-deny-dac" ? Denied : Ok, "OWNER RIGHTS controls the implicit WRITE_DAC grant");
    }
    static async Task GenericAceAccess((uint Generic, uint Specific) row)
    {
        using var root = new P7cTests.Root(); await using var d = new P2Tests.Direct(root.Store()); var admin = await Open(d, disposition: 3, access: 0x1f01ff); await Write(d, admin, Payload);
        var sd = Dacl(0, false); RawSmb.Put32(sd, 32, row.Generic); Status(await d.Send(SecuritySet(admin, sd)), Ok, "generic-mask DACL accepted");
        var read = await d.Send(Create(access: 1)); Status(read, (row.Specific & 1) != 0 ? Ok : Denied, "generic ACE maps READ_DATA admission");
        if ((row.Specific & 1) != 0) await Data(d, Id(read), Payload);
        var write = await d.Send(Create(access: 2)); Status(write, (row.Specific & 2) != 0 ? Ok : Denied, "generic ACE maps WRITE_DATA admission");
        if ((row.Specific & 2) != 0) { await Write(d, Id(write), Payload); await Close(d, Id(write)); }
        if (row.Generic == 0x20000000)
        {
            var execute = await Open(d, access: 0x20); await Data(d, execute, Payload); // READ permits granted EXECUTE too.
        }
        var maximum = await Open(d, access: 0x02000000);
        if ((row.Specific & 0x80) != 0) Check.Equal(row.Specific, RawSmb.U32(Output(await d.Send(Query(maximum, 18))), 76), "generic ACE MAXIMUM_ALLOWED contains specific rights");
    }
    static async Task EmptySecurityQuery()
    {
        using var root = new P7cTests.Root(); await using var d = new P2Tests.Direct(root.Store()); await Close(d, await Open(d, disposition: 3)); var id = await Open(d, access: 0x80);
        foreach (var bits in new uint[] { 1, 2, 3, 4, 5, 6, 7 }) Status(await d.Send(SecurityQuery(id, bits)), Denied, "every nonempty OWNER/GROUP/DACL subset requires READ_CONTROL");
        var empty = Output(await d.Send(SecurityQuery(id, 0))); Check.Equal(20, empty.Length, "zero requested security fields returns a bare self-relative descriptor");
        foreach (var at in new[] { 4, 8, 12, 16 }) Check.Equal(0u, RawSmb.U32(empty, at), "unrequested owner/group/SACL/DACL offsets zero");
    }
    static byte[] SingleAce(byte[] sid, uint mask, byte type = 0, byte flags = 0)
    {
        var sd = new byte[36 + sid.Length]; sd[0] = 1; RawSmb.Put16(sd, 2, 0x8004); RawSmb.Put32(sd, 16, 20);
        sd[20] = 2; RawSmb.Put16(sd, 22, (ushort)(16 + sid.Length)); RawSmb.Put16(sd, 24, 1);
        sd[28] = type; sd[29] = flags; RawSmb.Put16(sd, 30, (ushort)(8 + sid.Length)); RawSmb.Put32(sd, 32, mask); sid.CopyTo(sd, 36); return sd;
    }
    static async Task CreatorOwner()
    {
        using var root = new P7cTests.Root(); await using var d = new P2Tests.Direct(root.Store());
        d.Session.Identity = new SecurityIdentity { DomainName = "UPSTREAM", UserName = "creator", UserSid = "S-1-5-21-1-2-3-1000", GroupSids = ["S-1-5-32-545"] };
        var admin = await Open(d, disposition: 3, access: 0x1f01ff); var owner = Sid(5,21,1,2,3,1000);
        Status(await d.Send(SecuritySet(admin, WithOwnerGroup(SingleAce(Sid(1,0), 0x1f01ff), owner, Sid(5,32,545)), 7)), Ok, "establish named owner");
        Status(await d.Send(SecuritySet(admin, SingleAce(Sid(3,0), 0x1f0089))), Ok, "CREATOR_OWNER placeholder stored without inheritance");
        foreach (var mask in new uint[] { 1, 2, 0x80000000, 0x40000000 }) Status(await d.Send(Create(access: mask)), Denied, "unsubstituted CREATOR_OWNER is not the current object's owner SID");
        foreach (var generic in new[] { false, true })
        {
            Status(await d.Send(SecuritySet(admin, SingleAce(owner, generic ? 0x801f0000u : 0x1f0089u))), Ok, "real owner ACE grants read and standard rights");
            Status(await d.Send(Create(access: 1)), Ok, "real owner READ_DATA permitted"); Status(await d.Send(Create(access: 2)), Denied, "real owner WRITE_DATA not granted");
            Status(await d.Send(Create(access: 0x80000000)), Ok, "generic READ matches real owner allowance"); Status(await d.Send(Create(access: 0x40000000)), Denied, "generic WRITE cannot exceed real owner allowance");
        }
    }
    static async Task DescriptorFieldIsolation()
    {
        using var root = new P7cTests.Root(); await using var d = new P2Tests.Direct(root.Store());
        d.Session.Identity = new SecurityIdentity { DomainName = "UPSTREAM", UserName = "owner", UserSid = "S-1-5-21-1-2-3-1000", GroupSids = ["S-1-5-32-545"] };
        var admin = await Open(d, disposition: 3, access: 0x1f01ff); var owner = Sid(5,21,1,2,3,1000); var group = Sid(5,32,545);
        Status(await d.Send(SecuritySet(admin, WithOwnerGroup(SingleAce(Sid(1,0), 0x1f01ff), owner, group), 7)), Ok, "initial owner/group/DACL");
        var changed = WithOwnerGroup(DaclWithFallback(0, true), Sid(5,7), Sid(5,32,546)); Status(await d.Send(SecuritySet(admin, changed)), Ok, "DACL-only update ignores accompanying unrequested identities");
        var q = Output(await d.Send(SecurityQuery(admin, 7))); Check.That(q.AsSpan((int)RawSmb.U32(q, 4), owner.Length).SequenceEqual(owner), "DACL update preserves owner");
        Check.That(q.AsSpan((int)RawSmb.U32(q, 8), group.Length).SequenceEqual(group), "DACL update preserves group");
        Check.Equal((ushort)2, RawSmb.U16(q, (int)RawSmb.U32(q, 16) + 4), "second ACE added"); Status(await d.Send(Create(access: 1)), Denied, "new deny takes effect");
        Status(await d.Send(SecuritySet(admin, SingleAce(Sid(1,0), 0x1f01ff))), Ok, "replace DACL removing the deny ACE");
        q = Output(await d.Send(SecurityQuery(admin, 7))); Check.Equal((ushort)1, RawSmb.U16(q, (int)RawSmb.U32(q, 16) + 4), "removed ACE absent from query");
        Status(await d.Send(Create(access: 1)), Ok, "fresh READ becomes available after deny removal");
    }
    static async Task MaximumExplicitAccess()
    {
        using var root = new P7cTests.Root(); await using var d = new P2Tests.Direct(root.Store()); var admin = await Open(d, disposition: 3, access: 0x1f01ff); await Write(d, admin, Payload);
        Status(await d.Send(SecuritySet(admin, SingleAce(Sid(1,0), 1))), Ok, "DACL allows READ_DATA only");
        foreach (var mask in new uint[] { 0x02000000, 0x02000001 })
        {
            var permitted = await Open(d, access: mask); await Data(d, permitted, Payload); await Close(d, permitted);
        }
        Status(await d.Send(Create(access: 0x02000002)), Denied, "MAXIMUM_ALLOWED does not waive an explicit denied WRITE_DATA bit"); await Data(d, admin, Payload);
    }
    static async Task AccessBasedUnadvertised()
    {
        using var root = new P7cTests.Root(); await using var d = new P2Tests.Direct(root.Store());
        var tree = await d.Send(RawSmb.TreeConnect("\\\\localhost\\P0", 0, 1)); Status(tree, Ok, "query local share's actual flags");
        Check.Equal(0u, RawSmb.U32(tree, 68) & 0x800u, "access-based directory enumeration is not advertised");
        var directory = await Open(d, "dir", 2, directory: true); var file = await Open(d, "dir\\file", 2, access: 0x1f01ff);
        Status(await d.Send(SecuritySet(file, DaclWithFallback(0, true))), Ok, "deny data access without requesting ABE policy");
        Status(await d.Send(Create("dir\\file", access: 1)), Denied, "file still enforces its DACL");
        var names = Output(await d.Send(Enum(directory, "file"))); Check.Equal("file", System.Text.Encoding.Unicode.GetString(names, 12, (int)RawSmb.U32(names, 8)), "ordinary listing is not an unadvertised hide-unreadable policy");
    }
    static async Task InheritanceControls()
    {
        // Samba acls.c test_inheritance_flags supplies the control partitions.
        // Its conditional origin marker is a backend convention, not this basic
        // profile: MS-DTYP 2.4.4.1 records inherited origin independently of
        // descriptor auto-controls (also covered by grantwire's 16 partitions).
        // All 256 explicit-child replacements must still execute and normalize.
        for (var p = 0; p < 16; p++)
        {
            using var root = new P7cTests.Root(); await using var d = new P2Tests.Direct(root.Store()); var parent = await Open(d, "parent", 3, access: 0x1f01ff, directory: true);
            ushort Control(int n) => (ushort)(0x8004 | ((n & 1) != 0 ? 0x400 : 0) | ((n & 2) != 0 ? 0x100 : 0) | ((n & 4) != 0 ? 0x1000 : 0));
            ushort Normalized(int n) => (ushort)(0x8004 | ((n & 3) == 3 ? 0x400 : 0) | ((n & 4) != 0 ? 0x1000 : 0));
            var sd = SingleAce(Sid(1,0), 0x1f01ff, flags: (byte)(3 | ((p & 8) != 0 ? 16 : 0))); RawSmb.Put16(sd, 2, Control(p));
            Status(await d.Send(SecuritySet(parent, sd)), Ok, "set parent source auto-inheritance/protection control partition"); var read = Output(await d.Send(SecurityQuery(parent)));
            Check.Equal(Normalized(p), (ushort)(RawSmb.U16(read, 2) & 0x9504), "source normalizes parent AUTO_INHERIT_REQ/AUTO_INHERITED/PROTECTED flags");
            var child = await Open(d, "parent\\child", 2, access: 0x1f01ff); read = Output(await d.Send(SecurityQuery(child)));
            Check.Equal((ushort)(0x8004 | ((p & 3) == 3 ? 0x400 : 0)), (ushort)(RawSmb.U16(read, 2) & 0x9504), "child descriptor control derives from parent auto-inherit combination");
            Check.Equal((byte)16, read[(int)RawSmb.U32(read, 16) + 9], "basic profile records inherited origin; noncontainer child clears OI/CI");
            for (var c = 0; c < 16; c++)
            {
                sd = SingleAce(Sid(1,0), 0x1f01ff, flags: (byte)((c & 8) != 0 ? 16 : 0)); RawSmb.Put16(sd, 2, Control(c)); Status(await d.Send(SecuritySet(child, sd)), Ok, "explicit child control SET independent of parent"); read = Output(await d.Send(SecurityQuery(child)));
                Check.Equal(Normalized(c), (ushort)(RawSmb.U16(read, 2) & 0x9504), "explicit child controls normalize independently"); Check.Equal((c & 8) != 0 ? (byte)16 : (byte)0, read[(int)RawSmb.U32(read, 16) + 9], "explicit child ACE inherited marker retained");
                var acl = (int)RawSmb.U32(read, 16);
                Check.That(read.AsSpan(acl, 28).SequenceEqual(sd.AsSpan(20)), "complete explicit child ACL retains revision, count, type, mask and SID");
            }
            await Close(d, child); await Close(d, parent);
        }
    }
    static async Task StaticInheritance()
    {
        using var root = new P7cTests.Root(); await using var d = new P2Tests.Direct(root.Store()); var parent = await Open(d, "parent", 3, access: 0x1f01ff, directory: true);
        Status(await d.Send(SecuritySet(parent, DaclWithFallback(1, true, 3))), Ok, "parent inheritable READ deny"); var child = await Open(d, "parent\\child", 2, access: 2); await Write(d, child, Payload); await Close(d, child);
        Status(await d.Send(Create("parent\\child", access: 1)), Denied, "original child inherits deny");
        Status(await d.Send(SecuritySet(parent, SingleAce(Sid(1,0), 0x1f01ff, flags: 3))), Ok, "change parent to inheritable allow without requesting dynamic subtree rewrite");
        Status(await d.Send(Create("parent\\child", access: 1)), Denied, "existing child is not retroactively reauthorized by ordinary parent descriptor replacement");
        var writer = await Open(d, "parent\\child", access: 2); await Write(d, writer, Payload); await Close(d, writer);
    }
    static async Task ReadonlyMaximum(bool directory)
    {
        using var root = new P7cTests.Root(); await using var d = new P2Tests.Direct(root.Store()); var admin = await Open(d, disposition: 3, access: 0x1f01ff, directory: directory); var data = new byte[40]; RawSmb.Put32(data, 32, 1);
        Status(await d.Send(Set(admin, 4, data)), Ok, "set readonly before MAXIMUM_ALLOWED open");
        try
        {
            var id = await Open(d, access: 0x02000000, directory: directory); var mask = RawSmb.U32(Output(await d.Send(Query(id, 18))), 76);
            if (directory) Check.That((mask & 2) != 0, "readonly directory DOS bit does not deny ADD_FILE"); else Check.Equal(0u, mask & 6u, "readonly file MAXIMUM_ALLOWED cannot grant WRITE_DATA or APPEND_DATA");
            await Close(d, id); var denied = await d.Send(Create(access: 2, directory: directory)); Status(denied, directory ? Ok : Denied, "readonly file/directory access distinction");
        }
        finally { RawSmb.Put32(data, 32, 0x80); await d.Send(Set(admin, 4, data)); }
    }
}
