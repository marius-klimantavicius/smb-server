using System;
using System.Collections.Concurrent;
using System.Collections.Generic;
using System.Linq;

namespace Smb.Server.Witness;

public sealed class WitnessRegistrationStore
{
    private readonly ConcurrentDictionary<Guid, WitnessRegistration> _byId = new ConcurrentDictionary<Guid, WitnessRegistration>();

    public WitnessRegistration Add(Guid connectionId, uint version, string? netName, string? shareName, string? ipAddress, string? clientComputerName)
    {
        var witnessRegistration = new WitnessRegistration
        {
            Id = Guid.NewGuid(),
            ConnectionId = connectionId,
            Version = version,
            NetName = netName,
            ShareName = shareName,
            IpAddress = ipAddress,
            ClientComputerName = clientComputerName,
        };
        _byId[witnessRegistration.Id] = witnessRegistration;
        return witnessRegistration;
    }

    public bool TryGet(Guid id, out WitnessRegistration registration)
    {
        return _byId.TryGetValue(id, out registration);
    }

    public bool Remove(Guid id)
    {
        return _byId.TryRemove(id, out _);
    }

    public IReadOnlyList<WitnessRegistration> Snapshot()
    {
        return _byId.Values.ToArray();
    }

    public int NotifyResourceChange(string? netName, WitnessResourceChange change, string resourceName)
    {
        return Notify(netName, WitnessNotifyType.ResourceChange, WitnessWire.EncodeResourceChange(change, resourceName));
    }

    public int NotifyClientMove(string? netName, IReadOnlyList<WitnessIpAddr> destination)
    {
        return Notify(netName, WitnessNotifyType.ClientMove, WitnessWire.EncodeIpAddrInfoList(destination));
    }

    public int NotifyShareMove(string? netName, IReadOnlyList<WitnessIpAddr> destination)
    {
        return Notify(netName, WitnessNotifyType.ShareMove, WitnessWire.EncodeIpAddrInfoList(destination));
    }

    public int NotifyIpChange(string? netName, IReadOnlyList<WitnessIpAddr> addresses)
    {
        return Notify(netName, WitnessNotifyType.IpChange, WitnessWire.EncodeIpAddrInfoList(addresses));
    }

    private int Notify(string? netName, WitnessNotifyType type, byte[] messageBuffer)
    {
        var num = 0;
        foreach (var value in _byId.Values)
        {
            if (string.IsNullOrEmpty(netName) || string.Equals(value.NetName, netName, StringComparison.OrdinalIgnoreCase))
            {
                value.Notifications.Push(new WitnessNotification
                {
                    Type = type,
                    MessageCount = 1,
                    MessageBuffer = messageBuffer,
                });
                num++;
            }
        }
        return num;
    }

    public int RemoveAllForConnection(Guid connectionId)
    {
        var num = 0;
        foreach (var value2 in _byId.Values)
        {
            if (value2.ConnectionId == connectionId && _byId.TryRemove(value2.Id, out _))
            {
                num++;
            }
        }
        return num;
    }

    public static bool TryReadContextHandle(ReadOnlySpan<byte> stub, out Guid id)
    {
        if (stub.Length < 20)
        {
            id = default;
            return false;
        }
        id = new Guid(stub.Slice(4, 16));
        return true;
    }
}
