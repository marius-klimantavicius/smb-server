using System;
using System.Collections.Generic;

namespace Smb.Auth.Oids;

public sealed class SpnegoParseResult
{
    public IReadOnlyList<string> MechTypes { get; init; } = Array.Empty<string>();

    public byte[]? MechToken { get; init; }

    public string? SupportedMech { get; init; }

    public int? NegState { get; init; }

    public byte[]? MechListMic { get; init; }

    public byte[]? MechListBytes { get; init; }

    public bool IsResponseToken { get; init; }
}
