using System;
using Smb.Protocol.Enums;
using Smb.Protocol.Wire;

namespace Smb.Protocol.Messages;

public sealed class SessionSetupRequest
{
    public const ushort ExpectedStructureSize = 25;

    public SessionSetupFlags Flags { get; init; }

    public SmbSecurityMode SecurityMode { get; init; }

    public Smb2Capabilities Capabilities { get; init; }

    public ulong PreviousSessionId { get; init; }

    public byte[] SecurityBuffer { get; init; } = Array.Empty<byte>();

    public static SessionSetupRequest Parse(ReadOnlySpan<byte> message, int bodyOffset)
    {
        var spanReader = new SpanReader(message.Slice(bodyOffset));
        var num = spanReader.ReadUInt16();
        if (num != ExpectedStructureSize)
        {
            throw new SmbWireFormatException($"SESSION_SETUP Request StructureSize {num} ≠ {ExpectedStructureSize}.");
        }

        var flags = (SessionSetupFlags)spanReader.ReadByte();
        var securityMode = (SmbSecurityMode)spanReader.ReadByte();
        var capabilities = (Smb2Capabilities)spanReader.ReadUInt32();
        spanReader.Skip(4);
        var num2 = spanReader.ReadUInt16();
        var num3 = spanReader.ReadUInt16();
        var previousSessionId = spanReader.ReadUInt64();
        var securityBuffer = Array.Empty<byte>();
        if (num3 > 0)
        {
            if (num2 + num3 > message.Length)
            {
                throw new SmbWireFormatException("SESSION_SETUP security buffer extends past the message.");
            }

            securityBuffer = message.Slice(num2, num3).ToArray();
        }

        return new SessionSetupRequest
        {
            Flags = flags,
            SecurityMode = securityMode,
            Capabilities = capabilities,
            PreviousSessionId = previousSessionId,
            SecurityBuffer = securityBuffer,
        };
    }
}
