using System;
using System.Buffers.Binary;
using Smb.Protocol.Wire;

namespace Smb.Protocol.Messages;

public static class DurableHandleMessages
{
    public readonly record struct V2Request(uint TimeoutMs, uint Flags, Guid CreateGuid)
    {
        public bool IsPersistent => (Flags & FlagPersistent) != 0;
    }

    public readonly record struct V2Reconnect(ulong PersistentId, ulong VolatileId, Guid CreateGuid, uint Flags)
    {
        public bool IsPersistent => (Flags & FlagPersistent) != 0;
    }

    public const uint FlagPersistent = 2u;

    public static CreateContext BuildV1ResponseContext()
    {
        return new CreateContext
        {
            Name = NameBytes(1145597521u),
            Data = new byte[8],
        };
    }

    public static byte[] BuildReconnectData(ulong persistentId, ulong volatileId)
    {
        var array = new byte[16];
        BinaryPrimitives.WriteUInt64LittleEndian(array, persistentId);
        BinaryPrimitives.WriteUInt64LittleEndian(array.AsSpan(8), volatileId);
        return array;
    }

    public static (ulong persistentId, ulong volatileId) ParseReconnect(ReadOnlySpan<byte> data)
    {
        if (data.Length < 16)
        {
            throw new SmbWireFormatException($"Durable reconnect needs 16 bytes, has {data.Length}.");
        }

        return (persistentId: BinaryPrimitives.ReadUInt64LittleEndian(data), volatileId: BinaryPrimitives.ReadUInt64LittleEndian(data.Slice(8)));
    }

    public static V2Request ParseV2Request(ReadOnlySpan<byte> data)
    {
        if (data.Length < 32)
        {
            throw new SmbWireFormatException($"Durable v2 request needs 32 bytes, has {data.Length}.");
        }

        var timeoutMs = BinaryPrimitives.ReadUInt32LittleEndian(data);
        var flags = BinaryPrimitives.ReadUInt32LittleEndian(data.Slice(4));
        var createGuid = new Guid(data.Slice(16, 16));
        return new V2Request(timeoutMs, flags, createGuid);
    }

    public static CreateContext BuildV2ResponseContext(uint timeoutMs, bool persistent)
    {
        var array = new byte[8];
        BinaryPrimitives.WriteUInt32LittleEndian(array, timeoutMs);
        BinaryPrimitives.WriteUInt32LittleEndian(array.AsSpan(4), persistent ? FlagPersistent : 0u);
        return new CreateContext
        {
            Name = NameBytes(1145582161u),
            Data = array,
        };
    }

    public static V2Reconnect ParseV2Reconnect(ReadOnlySpan<byte> data)
    {
        if (data.Length < 36)
        {
            throw new SmbWireFormatException($"Durable v2 reconnect needs 36 bytes, has {data.Length}.");
        }

        var persistentId = BinaryPrimitives.ReadUInt64LittleEndian(data);
        var volatileId = BinaryPrimitives.ReadUInt64LittleEndian(data.Slice(8));
        var createGuid = new Guid(data.Slice(16, 16));
        var flags = BinaryPrimitives.ReadUInt32LittleEndian(data.Slice(32));
        return new V2Reconnect(persistentId, volatileId, createGuid, flags);
    }

    public static byte[] BuildV2ReconnectData(ulong persistentId, ulong volatileId, Guid createGuid, bool persistent)
    {
        var array = new byte[36];
        BinaryPrimitives.WriteUInt64LittleEndian(array, persistentId);
        BinaryPrimitives.WriteUInt64LittleEndian(array.AsSpan(8), volatileId);
        createGuid.TryWriteBytes(array.AsSpan(16, 16));
        BinaryPrimitives.WriteUInt32LittleEndian(array.AsSpan(32), persistent ? FlagPersistent : 0u);
        return array;
    }

    public static byte[] BuildV2RequestData(uint timeoutMs, Guid createGuid, bool persistent)
    {
        var array = new byte[32];
        BinaryPrimitives.WriteUInt32LittleEndian(array, timeoutMs);
        BinaryPrimitives.WriteUInt32LittleEndian(array.AsSpan(4), persistent ? FlagPersistent : 0u);
        createGuid.TryWriteBytes(array.AsSpan(16, 16));
        return array;
    }

    public static byte[] NameBytes(uint tag)
    {
        var array = new byte[4];
        BinaryPrimitives.WriteUInt32BigEndian(array, tag);
        return array;
    }
}
