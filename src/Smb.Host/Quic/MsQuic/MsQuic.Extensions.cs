using System;

namespace Managed.Transport;

partial class MsQuic
{
    // ReSharper disable once InconsistentNaming
    partial struct QUIC_ADDR
    {
        public int Family
        {
            get => Ip.sa_family;
            set => Ip.sa_family = (ushort)value;
        }
    }

    // ReSharper disable once InconsistentNaming
    partial struct QUIC_SETTINGS : IEquatable<QUIC_SETTINGS>
    {
        // Because QUIC_SETTINGS may contain gaps due to layout/alignment of individual
        // fields, we implement IEquatable<QUIC_SETTINGS> manually. If a new field is added,
        // then there is a unit test which should fail.

        public bool Equals(QUIC_SETTINGS other)
        {
            return IsSetFlags == other.IsSetFlags && MaxBytesPerKey == other.MaxBytesPerKey && HandshakeIdleTimeoutMs == other.HandshakeIdleTimeoutMs && IdleTimeoutMs == other.IdleTimeoutMs
                && MtuDiscoverySearchCompleteTimeoutUs == other.MtuDiscoverySearchCompleteTimeoutUs && TlsClientMaxSendBuffer == other.TlsClientMaxSendBuffer && TlsServerMaxSendBuffer == other.TlsServerMaxSendBuffer
                && StreamRecvWindowDefault == other.StreamRecvWindowDefault && StreamRecvBufferDefault == other.StreamRecvBufferDefault && ConnFlowControlWindow == other.ConnFlowControlWindow
                && MaxWorkerQueueDelayUs == other.MaxWorkerQueueDelayUs && MaxStatelessOperations == other.MaxStatelessOperations && InitialWindowPackets == other.InitialWindowPackets
                && SendIdleTimeoutMs == other.SendIdleTimeoutMs && InitialRttMs == other.InitialRttMs && MaxAckDelayMs == other.MaxAckDelayMs && DisconnectTimeoutMs == other.DisconnectTimeoutMs
                && KeepAliveIntervalMs == other.KeepAliveIntervalMs && CongestionControlAlgorithm == other.CongestionControlAlgorithm && PeerBidiStreamCount == other.PeerBidiStreamCount
                && PeerUnidiStreamCount == other.PeerUnidiStreamCount && MaxBindingStatelessOperations == other.MaxBindingStatelessOperations && StatelessOperationExpirationMs == other.StatelessOperationExpirationMs
                && MinimumMtu == other.MinimumMtu && MaximumMtu == other.MaximumMtu && __bf0 == other.__bf0 && MaxOperationsPerDrain == other.MaxOperationsPerDrain
                && MtuDiscoveryMissingProbeCount == other.MtuDiscoveryMissingProbeCount && DestCidUpdateIdleTimeoutMs == other.DestCidUpdateIdleTimeoutMs && Flags == other.Flags
                && StreamRecvWindowBidiLocalDefault == other.StreamRecvWindowBidiLocalDefault && StreamRecvWindowBidiRemoteDefault == other.StreamRecvWindowBidiRemoteDefault
                && StreamRecvWindowUnidiDefault == other.StreamRecvWindowUnidiDefault;
        }

        public override int GetHashCode()
        {
            HashCode hash = default;
            hash.Add(IsSetFlags);
            hash.Add(MaxBytesPerKey);
            hash.Add(HandshakeIdleTimeoutMs);
            hash.Add(IdleTimeoutMs);
            hash.Add(MtuDiscoverySearchCompleteTimeoutUs);
            hash.Add(TlsClientMaxSendBuffer);
            hash.Add(TlsServerMaxSendBuffer);
            hash.Add(StreamRecvWindowDefault);
            hash.Add(StreamRecvBufferDefault);
            hash.Add(ConnFlowControlWindow);
            hash.Add(MaxWorkerQueueDelayUs);
            hash.Add(MaxStatelessOperations);
            hash.Add(InitialWindowPackets);
            hash.Add(SendIdleTimeoutMs);
            hash.Add(InitialRttMs);
            hash.Add(MaxAckDelayMs);
            hash.Add(DisconnectTimeoutMs);
            hash.Add(KeepAliveIntervalMs);
            hash.Add(CongestionControlAlgorithm);
            hash.Add(PeerBidiStreamCount);
            hash.Add(PeerUnidiStreamCount);
            hash.Add(MaxBindingStatelessOperations);
            hash.Add(StatelessOperationExpirationMs);
            hash.Add(MinimumMtu);
            hash.Add(MaximumMtu);
            hash.Add(__bf0);
            hash.Add(MaxOperationsPerDrain);
            hash.Add(MtuDiscoveryMissingProbeCount);
            hash.Add(DestCidUpdateIdleTimeoutMs);
            hash.Add(Flags);
            hash.Add(StreamRecvWindowBidiLocalDefault);
            hash.Add(StreamRecvWindowBidiRemoteDefault);
            hash.Add(StreamRecvWindowUnidiDefault);
            return hash.ToHashCode();
        }

        public override bool Equals(object? obj) => obj is QUIC_SETTINGS other && Equals(other);
    }
}