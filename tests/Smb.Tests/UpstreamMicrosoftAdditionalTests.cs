using Smb.Testing;

internal static partial class UpstreamMicrosoftTests
{
    static IEnumerable<(string Name, Func<Task> Run)> AdditionalCases()
    {
        foreach (var delete in new[] { false, true })
            yield return ($"upstream.microsoft.create.readonly-{(delete ? "delete-on-close" : "write-open")}", () => ReadonlyCreate(delete));
        yield return ("upstream.microsoft.create.wildcard-name", WildcardName);
        yield return ("upstream.microsoft.create.data-suffix-after-separators", DataSuffixAfterSeparators);
        yield return ("upstream.microsoft.create.maximum-allowed-readonly", MaximumAllowedReadonly);
        foreach (var shape in new[] { "valid", "missing", "zero-access", "case" })
            yield return ("upstream.microsoft.pipe.open-" + shape, () => PipeOpen(shape));
    }

    // FSA FileAccess_OpenExistingFile: distinguish denial of data access from
    // the CANNOT_DELETE status specifically required by DELETE_ON_CLOSE.
    static async Task ReadonlyCreate(bool delete)
    {
        using var root = new Root(); await using var d = root.Direct();
        try
        {
            var create = RawSmb.Create("readonly", false, 0, 1, 42); RawSmb.Put32(create, 92, 1); RawSmb.Put32(create, 100, 2);
            var created = await d.Send(create); Status(created, 0, "creating a READONLY file is permitted");
            await Write(d, (RawSmb.U64(created, 128), RawSmb.U64(created, 136)), [42], 0);
            Status(await d.Send(RawSmb.Close((RawSmb.U64(created, 128), RawSmb.U64(created, 136)), 0, 1, 42)), 0, "close initial grant");
            create = RawSmb.Create("readonly", false, 0, 1, 42); RawSmb.Put32(create, 100, 1); RawSmb.Put32(create, 88, delete ? 0x10000u : 0x40000000u);
            if (delete) RawSmb.Put32(create, 104, 0x1040);
            Status(await d.Send(create), delete ? 0xc0000121u : Denied, "readonly reopen status from FSA FileAccess");
            var read = await Open(d, "readonly", access: 0x81); await ReadEquals(d, read, [42]);
        }
        finally { if (File.Exists(root.At("readonly"))) File.SetAttributes(root.At("readonly"), FileAttributes.Normal); }
    }

    // SMB2Model/CreateClose OtherInvalidFileName selects a leading '*'.
    static async Task WildcardName()
    {
        using var root = new Root(); await using var d = root.Direct();
        Status(await d.Send(RawSmb.Create("*CreateClose", false, 0, 1, 42)), 0xc0000033, "wildcard is not a legal CREATE filename");
        var id = await Open(d, "control"); await Write(d, id, [7], 0); await ReadEquals(d, id, [7]);
    }
    // FSAModel S34 adds separators followed by the unnamed DATA stream suffix;
    // this is distinct from an ordinary file name ending in one separator.
    static async Task DataSuffixAfterSeparators()
    {
        using var root = new Root(); await using var d = root.Direct();
        Status(await d.Send(RawSmb.Create("fsa\\\\\\\\\\\\::$DATA", false, 0, 1, 42)), 0xc0000033, "NON_DIRECTORY_FILE separators before stream suffix are invalid");
    }
    static async Task MaximumAllowedReadonly()
    {
        using var root = new Root(); await using var d = root.Direct();
        try
        {
            var create = RawSmb.Create("maximum-readonly", false, 0, 1, 42); RawSmb.Put32(create, 88, 0x02000000); RawSmb.Put32(create, 92, 1); RawSmb.Put32(create, 100, 2);
            var response = await d.Send(create); Status(response, 0, "FSAModel S0 READONLY create with MAXIMUM_ALLOWED succeeds");
            Check.That((RawSmb.U32(response, 120) & 1) != 0, "CREATE reports requested readonly attribute");
            Status(await d.Send(RawSmb.Close((RawSmb.U64(response, 128), RawSmb.U64(response, 136)), 0, 1, 42)), 0, "MAXIMUM_ALLOWED grant can be closed");
        }
        finally { if (File.Exists(root.At("maximum-readonly"))) File.SetAttributes(root.At("maximum-readonly"), FileAttributes.Normal); }
    }

    // FSA FileAccess_OpenNamedPipe: these four contracts apply to the exported
    // srvsvc endpoint. Host-created directional/finite-listener pipes need a
    // separate pipe-export capability and are not simulated with private mocks.
    static async Task PipeOpen(string shape)
    {
        await using var host = await UpstreamLocalFixture.StartAsync(); await using var c = await host.ConnectAsync();
        var tree = await c.ExchangeAsync(RawSmb.TreeConnect("\\\\localhost\\IPC$", c.NextMessageId(), c.Session));
        Check.Equal((byte)2, tree[66], "IPC tree has PIPE share type"); var tid = RawSmb.U32(tree, 36);
        var request = RawSmb.Create(shape == "missing" ? "absent-upstream-pipe" : shape == "case" ? "SrVsVc" : "srvsvc", false, c.NextMessageId(), c.Session, tid);
        RawSmb.Put32(request, 100, 2); if (shape == "zero-access") RawSmb.Put32(request, 88, 0);
        var response = await c.ExchangeAsync(request, shape == "missing" ? 0xc0000034u : shape == "zero-access" ? Denied : 0);
        if (shape is "valid" or "case")
            await c.ExchangeAsync(RawSmb.Close((RawSmb.U64(response, 128), RawSmb.U64(response, 136)), c.NextMessageId(), c.Session, tid));
        await c.ExchangeAsync(RawSmb.TreeDisconnect(c.NextMessageId(), c.Session, tid));
    }
}
