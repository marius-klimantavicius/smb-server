using System;
using Smb.Protocol.Wire;

namespace Smb.Protocol.Messages;

public sealed class SessionSetupResponse
{
    public const ushort StructureSize = 9;

    public SessionResponseFlags SessionFlags { get; init; }

    public byte[] SecurityBuffer { get; init; } = Array.Empty<byte>();

    public byte[] ToBody(int headerSize = 64)
    {
        var growableWriter = new GrowableWriter(16 + SecurityBuffer.Length);
        growableWriter.WriteUInt16(StructureSize);
        growableWriter.WriteUInt16((ushort)SessionFlags);
        var position = growableWriter.Position;
        growableWriter.WriteUInt16(0);
        growableWriter.WriteUInt16((ushort)SecurityBuffer.Length);
        var position2 = growableWriter.Position;
        if (SecurityBuffer.Length != 0)
        {
            growableWriter.WriteBytes(SecurityBuffer);
            growableWriter.PatchUInt16(position, (ushort)(headerSize + position2));
        }

        return growableWriter.ToArray();
    }
}
