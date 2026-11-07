// Licensed to the .NET Foundation under one or more agreements.
// The .NET Foundation licenses this file to you under the MIT license.

using System;
using Managed.Net.Quic;
using static Managed.Transport.MsQuic;

namespace Microsoft.Quic;

internal static unsafe class MsQuicExtensions
{
    extension(QUIC_BUFFER buffer)
    {
        public Span<byte> Span => new Span<byte>(buffer.Buffer, unchecked((int)buffer.Length));
    }

    extension(QUIC_NEW_CONNECTION_INFO self)
    {
        public string ToString()
            => $"{{ {nameof(self.QuicVersion)} = {self.QuicVersion}, {nameof(self.LocalAddress)} = {MsQuicHelpers.QuicAddrToIPEndPoint(self.LocalAddress)}, {nameof(self.RemoteAddress)} = {MsQuicHelpers.QuicAddrToIPEndPoint(self.RemoteAddress)} }}";
    }

    extension(QUIC_LISTENER_EVENT self)
    {
        public string ToString()
            => self.Type switch
            {
                QUIC_LISTENER_EVENT_TYPE.QUIC_LISTENER_EVENT_NEW_CONNECTION =>
                    $"{{ {nameof(self.NEW_CONNECTION.Info)} = {{ {nameof(QUIC_NEW_CONNECTION_INFO.QuicVersion)} = {self.NEW_CONNECTION.Info->QuicVersion}, {nameof(QUIC_NEW_CONNECTION_INFO.LocalAddress)} = {MsQuicHelpers.QuicAddrToIPEndPoint(self.NEW_CONNECTION.Info->LocalAddress)}, {nameof(QUIC_NEW_CONNECTION_INFO.RemoteAddress)} = {MsQuicHelpers.QuicAddrToIPEndPoint(self.NEW_CONNECTION.Info->RemoteAddress)} }}, {nameof(self.NEW_CONNECTION.Connection)} = 0x{(IntPtr)self.NEW_CONNECTION.Connection:X11} }}",
                _ => string.Empty
            };
    }

    extension(QUIC_CONNECTION_EVENT self)
    {
        public string ToString()
            => self.Type switch
            {
                QUIC_CONNECTION_EVENT_TYPE.QUIC_CONNECTION_EVENT_CONNECTED => $"{{ {nameof(self.CONNECTED.SessionResumed)} = {self.CONNECTED.SessionResumed} }}",
                QUIC_CONNECTION_EVENT_TYPE.QUIC_CONNECTION_EVENT_SHUTDOWN_INITIATED_BY_TRANSPORT =>
                    $"{{ {nameof(self.SHUTDOWN_INITIATED_BY_TRANSPORT.Status)} = {self.SHUTDOWN_INITIATED_BY_TRANSPORT.Status}, {nameof(self.SHUTDOWN_INITIATED_BY_TRANSPORT.ErrorCode)} = {self.SHUTDOWN_INITIATED_BY_TRANSPORT.ErrorCode} }}",
                QUIC_CONNECTION_EVENT_TYPE.QUIC_CONNECTION_EVENT_SHUTDOWN_INITIATED_BY_PEER => $"{{ {nameof(self.SHUTDOWN_INITIATED_BY_PEER.ErrorCode)} = {self.SHUTDOWN_INITIATED_BY_PEER.ErrorCode} }}",
                QUIC_CONNECTION_EVENT_TYPE.QUIC_CONNECTION_EVENT_SHUTDOWN_COMPLETE =>
                    $"{{ {nameof(self.SHUTDOWN_COMPLETE.HandshakeCompleted)} = {self.SHUTDOWN_COMPLETE.HandshakeCompleted}, {nameof(self.SHUTDOWN_COMPLETE.PeerAcknowledgedShutdown)} = {self.SHUTDOWN_COMPLETE.PeerAcknowledgedShutdown}, {nameof(self.SHUTDOWN_COMPLETE.AppCloseInProgress)} = {self.SHUTDOWN_COMPLETE.AppCloseInProgress} }}",
                QUIC_CONNECTION_EVENT_TYPE.QUIC_CONNECTION_EVENT_LOCAL_ADDRESS_CHANGED => $"{{ {nameof(self.LOCAL_ADDRESS_CHANGED.Address)} = {MsQuicHelpers.QuicAddrToIPEndPoint(self.LOCAL_ADDRESS_CHANGED.Address)} }}",
                QUIC_CONNECTION_EVENT_TYPE.QUIC_CONNECTION_EVENT_PEER_ADDRESS_CHANGED => $"{{ {nameof(self.PEER_ADDRESS_CHANGED.Address)} = {MsQuicHelpers.QuicAddrToIPEndPoint(self.PEER_ADDRESS_CHANGED.Address)} }}",
                QUIC_CONNECTION_EVENT_TYPE.QUIC_CONNECTION_EVENT_PEER_STREAM_STARTED =>
                    $"{{ {nameof(self.PEER_STREAM_STARTED.Stream)} = 0x{(IntPtr)self.PEER_STREAM_STARTED.Stream:X11} {nameof(self.PEER_STREAM_STARTED.Flags)} = {self.PEER_STREAM_STARTED.Flags} }}",
                QUIC_CONNECTION_EVENT_TYPE.QUIC_CONNECTION_EVENT_STREAMS_AVAILABLE =>
                    $"{{ {nameof(self.STREAMS_AVAILABLE.BidirectionalCount)} = {self.STREAMS_AVAILABLE.BidirectionalCount}, {nameof(self.STREAMS_AVAILABLE.UnidirectionalCount)} = {self.STREAMS_AVAILABLE.UnidirectionalCount} }}",
                QUIC_CONNECTION_EVENT_TYPE.QUIC_CONNECTION_EVENT_PEER_NEEDS_STREAMS => $"{{ {nameof(self.PEER_NEEDS_STREAMS.Bidirectional)} = {self.PEER_NEEDS_STREAMS.Bidirectional} }}",
                QUIC_CONNECTION_EVENT_TYPE.QUIC_CONNECTION_EVENT_IDEAL_PROCESSOR_CHANGED =>
                    $"{{ {nameof(self.IDEAL_PROCESSOR_CHANGED.IdealProcessor)} = {self.IDEAL_PROCESSOR_CHANGED.IdealProcessor}, {nameof(self.IDEAL_PROCESSOR_CHANGED.PartitionIndex)} = {self.IDEAL_PROCESSOR_CHANGED.PartitionIndex} }}",
                QUIC_CONNECTION_EVENT_TYPE.QUIC_CONNECTION_EVENT_DATAGRAM_STATE_CHANGED =>
                    $"{{ {nameof(self.DATAGRAM_STATE_CHANGED.SendEnabled)} = {self.DATAGRAM_STATE_CHANGED.SendEnabled}, {nameof(self.DATAGRAM_STATE_CHANGED.MaxSendLength)} = {self.DATAGRAM_STATE_CHANGED.MaxSendLength} }}",
                QUIC_CONNECTION_EVENT_TYPE.QUIC_CONNECTION_EVENT_DATAGRAM_RECEIVED => $"{{ {nameof(self.DATAGRAM_RECEIVED.Flags)} = {self.DATAGRAM_RECEIVED.Flags} }}",
                QUIC_CONNECTION_EVENT_TYPE.QUIC_CONNECTION_EVENT_DATAGRAM_SEND_STATE_CHANGED =>
                    $"{{ {nameof(self.DATAGRAM_SEND_STATE_CHANGED.ClientContext)} = 0x{(IntPtr)self.DATAGRAM_SEND_STATE_CHANGED.ClientContext:X11}, {nameof(self.DATAGRAM_SEND_STATE_CHANGED.State)} = {self.DATAGRAM_SEND_STATE_CHANGED.State} }}",
                QUIC_CONNECTION_EVENT_TYPE.QUIC_CONNECTION_EVENT_RESUMED => $"{{ {nameof(self.RESUMED.ResumptionStateLength)} = {self.RESUMED.ResumptionStateLength} }}",
                QUIC_CONNECTION_EVENT_TYPE.QUIC_CONNECTION_EVENT_RESUMPTION_TICKET_RECEIVED => $"{{ {nameof(self.RESUMPTION_TICKET_RECEIVED.ResumptionTicketLength)} = {self.RESUMPTION_TICKET_RECEIVED.ResumptionTicketLength} }}",
                QUIC_CONNECTION_EVENT_TYPE.QUIC_CONNECTION_EVENT_PEER_CERTIFICATE_RECEIVED =>
                    $"{{ {nameof(self.PEER_CERTIFICATE_RECEIVED.DeferredStatus)} = {self.PEER_CERTIFICATE_RECEIVED.DeferredStatus}, {nameof(self.PEER_CERTIFICATE_RECEIVED.DeferredErrorFlags)} = {self.PEER_CERTIFICATE_RECEIVED.DeferredErrorFlags}, {nameof(self.PEER_CERTIFICATE_RECEIVED.Certificate)} = 0x{(IntPtr)self.PEER_CERTIFICATE_RECEIVED.Certificate:X11} }}",
                QUIC_CONNECTION_EVENT_TYPE.QUIC_CONNECTION_EVENT_RELIABLE_RESET_NEGOTIATED => $"{{ {nameof(self.RELIABLE_RESET_NEGOTIATED.IsNegotiated)} = {self.RELIABLE_RESET_NEGOTIATED.IsNegotiated} }}",
                QUIC_CONNECTION_EVENT_TYPE.QUIC_CONNECTION_EVENT_ONE_WAY_DELAY_NEGOTIATED =>
                    $"{{ {nameof(self.ONE_WAY_DELAY_NEGOTIATED.SendNegotiated)} = {self.ONE_WAY_DELAY_NEGOTIATED.SendNegotiated}, {nameof(self.ONE_WAY_DELAY_NEGOTIATED.ReceiveNegotiated)} = {self.ONE_WAY_DELAY_NEGOTIATED.ReceiveNegotiated} }}",
                _ => string.Empty
            };
    }

    extension(QUIC_STREAM_EVENT self)
    {
        public string ToString()
            => self.Type switch
            {
                QUIC_STREAM_EVENT_TYPE.QUIC_STREAM_EVENT_START_COMPLETE => $"{{ {nameof(self.START_COMPLETE.Status)} = {self.START_COMPLETE.Status}, {nameof(self.START_COMPLETE.ID)} = {self.START_COMPLETE.ID}, {nameof(self.START_COMPLETE.PeerAccepted)} = {self.START_COMPLETE.PeerAccepted} }}",
                QUIC_STREAM_EVENT_TYPE.QUIC_STREAM_EVENT_RECEIVE => $"{{ {nameof(self.RECEIVE.AbsoluteOffset)} = {self.RECEIVE.AbsoluteOffset}, {nameof(self.RECEIVE.TotalBufferLength)} = {self.RECEIVE.TotalBufferLength}, {nameof(self.RECEIVE.Flags)} = {self.RECEIVE.Flags} }}",
                QUIC_STREAM_EVENT_TYPE.QUIC_STREAM_EVENT_SEND_COMPLETE => $"{{ {nameof(self.SEND_COMPLETE.Canceled)} = {self.SEND_COMPLETE.Canceled} }}",
                QUIC_STREAM_EVENT_TYPE.QUIC_STREAM_EVENT_PEER_SEND_ABORTED => $"{{ {nameof(self.PEER_SEND_ABORTED.ErrorCode)} = {self.PEER_SEND_ABORTED.ErrorCode} }}",
                QUIC_STREAM_EVENT_TYPE.QUIC_STREAM_EVENT_PEER_RECEIVE_ABORTED => $"{{ {nameof(self.PEER_RECEIVE_ABORTED.ErrorCode)} = {self.PEER_RECEIVE_ABORTED.ErrorCode} }}",
                QUIC_STREAM_EVENT_TYPE.QUIC_STREAM_EVENT_SEND_SHUTDOWN_COMPLETE => $"{{ {nameof(self.SEND_SHUTDOWN_COMPLETE.Graceful)} = {self.SEND_SHUTDOWN_COMPLETE.Graceful} }}",
                QUIC_STREAM_EVENT_TYPE.QUIC_STREAM_EVENT_SHUTDOWN_COMPLETE =>  $"{{ {nameof(self.SHUTDOWN_COMPLETE.ConnectionShutdown)} = {self.SHUTDOWN_COMPLETE.ConnectionShutdown}, {nameof(self.SHUTDOWN_COMPLETE.ConnectionShutdownByApp)} = {self.SHUTDOWN_COMPLETE.ConnectionShutdownByApp}, {nameof(self.SHUTDOWN_COMPLETE.ConnectionClosedRemotely)} = {self.SHUTDOWN_COMPLETE.ConnectionClosedRemotely}, {nameof(self.SHUTDOWN_COMPLETE.ConnectionErrorCode)} = {self.SHUTDOWN_COMPLETE.ConnectionErrorCode}, {nameof(self.SHUTDOWN_COMPLETE.ConnectionCloseStatus)} = {self.SHUTDOWN_COMPLETE.ConnectionCloseStatus} }}",
                QUIC_STREAM_EVENT_TYPE.QUIC_STREAM_EVENT_IDEAL_SEND_BUFFER_SIZE => $"{{ {nameof(self.IDEAL_SEND_BUFFER_SIZE.ByteCount)} = {self.IDEAL_SEND_BUFFER_SIZE.ByteCount} }}",
                _ => string.Empty
            };
    }
}