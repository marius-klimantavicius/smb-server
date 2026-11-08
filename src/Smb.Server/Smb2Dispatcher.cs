using System;
using System.Buffers.Binary;
using System.Collections.Generic;
using System.Diagnostics;
using System.Diagnostics.CodeAnalysis;
using System.IO;
using System.Linq;
using System.Runtime.CompilerServices;
using System.Security.Cryptography;
using System.Threading;
using System.Threading.Tasks;
using Smb.Auth;
using Smb.Crypto;
using Smb.FileSystem;
using Smb.FileSystem.Versioning;
using Smb.Protocol.Constants;
using Smb.Protocol.Enums;
using Smb.Protocol.Messages;
using Smb.Protocol.Messages.Fscc;
using Smb.Protocol.Security;
using Smb.Protocol.Wire;
using Smb.Server.Authorization;
using Smb.Server.Concurrency;
using Smb.Server.Diagnostics;
using Smb.Server.Durable;
using Smb.Server.Leases;
using Smb.Server.Locking;
using Smb.Server.Notification;
using Smb.Server.Oplocks;
using Smb.Server.Rpc;
using Smb.Server.Sharing;
using Smb.Server.State;
using Smb.Server.Witness;

namespace Smb.Server;

public sealed class Smb2Dispatcher
{
	internal sealed record ChannelAdmission(NtStatus Status, IDisposable? Ticket)
	{
		internal bool EnteredCore;
	}

	public readonly struct PreparedFrame
	{
		public ulong MessageId => Header.MessageId;
		internal Smb2Header Header { get; }

		internal ReadOnlyMemory<byte> Message { get; }

		internal bool Encrypted { get; }

		internal bool NeedsReservation { get; }

		internal (ulong Persistent, ulong Volatile) ScopeKey { get; }

		internal LockMode ScopeMode { get; }

		internal KeyedReaderWriterQueue<(ulong Persistent, ulong Volatile)>.Reservation? Reservation { get; }

		internal ChannelAdmission? SequenceAdmission { get; init; }

		internal PreparedFrame(Smb2Header header, ReadOnlyMemory<byte> message, bool encrypted, bool needsReservation, (ulong Persistent, ulong Volatile) scopeKey, LockMode scopeMode, KeyedReaderWriterQueue<(ulong Persistent, ulong Volatile)>.Reservation? reservation = null)
		{
			Header = header;
			Message = message;
			Encrypted = encrypted;
			NeedsReservation = needsReservation;
			ScopeKey = scopeKey;
			ScopeMode = scopeMode;
			Reservation = reservation;
		}

		internal PreparedFrame WithReservation(KeyedReaderWriterQueue<(ulong Persistent, ulong Volatile)>.Reservation reservation)
		{
			return new PreparedFrame(Header, Message, Encrypted, NeedsReservation, ScopeKey, ScopeMode, reservation) { SequenceAdmission = SequenceAdmission };
		}
	}

	private static readonly ConditionalWeakTable<IFileStore, StoreNamespace> StoreNamespaces = new ConditionalWeakTable<IFileStore, StoreNamespace>();

	private sealed class StoreNamespace
	{
		internal readonly string Key = Guid.NewGuid().ToString("N");
	}

	private static readonly KeyedAsyncLock<string> NamespaceOperations = new KeyedAsyncLock<string>();
	private static readonly KeyedAsyncLock<string> SecurityOperations = new KeyedAsyncLock<string>();
	public static int ActiveNamespaceCount => NamespaceOperations.TrackedKeyCount;
	private static string LegacyKey(IFileStore store) => "legacy:" + StoreNamespaces.GetValue(store, _ => new StoreNamespace()).Key;

	private static async ValueTask<string> ResolveShareKeyAsync(IFileStore store, string path, string stream)
	{
		if (store is not IFileIdentityStore identities) return LegacyKey(store);

		var id = await identities.ResolveIdentityAsync(path, stream).ConfigureAwait(false);
		return id?.Key ?? "name:" + LegacyKey(store) + ":" + path.Replace('\\', '/').Trim('/') + ":" + stream.ToUpperInvariant();
	}

	private readonly struct CommandRequest(ReadOnlyMemory<byte> wire, ReadOnlyMemory<byte> resolved)
	{
		public ReadOnlySpan<byte> Span => wire.Span;
		public ReadOnlySpan<byte> ParsingSpan => resolved.Span;
		public int Length => wire.Length;
	}

	private readonly struct ResponseSegment
	{
		public Smb2Header Header { get; }

		public byte[] Body { get; }

		public bool Sign { get; }

		public bool CreditsReserved { get; }

		public SmbSession? SigningSession { get; }

		public byte[]? SigningKey { get; }

		private ResponseSegment(Smb2Header header, byte[] body, bool sign, SmbSession? session, bool creditsReserved = false, byte[]? signingKey = null)
		{
			Header = header;
			Body = body;
			Sign = sign;
			SigningSession = session;
			SigningKey = signingKey;
			CreditsReserved = creditsReserved;
		}

		public static ResponseSegment Unsigned(Smb2Header header, byte[] body, bool creditsReserved = false)
		{
			return new ResponseSegment(header, body, sign: false, null, creditsReserved);
		}

		public static ResponseSegment Signed(Smb2Header header, byte[] body, SmbSession session, bool creditsReserved = false)
		{
			return new ResponseSegment(header, body, sign: true, session, creditsReserved);
		}

		public static ResponseSegment SignedWithKey(Smb2Header header, byte[] body, byte[] key)
		{
			return new ResponseSegment(header, body, sign: true, null, signingKey: key.ToArray());
		}
	}


	private readonly record struct ArmedBreaks(IReadOnlyList<OplockBreak> Oplocks, IReadOnlyList<LeaseBreak> Leases, Task<BreakOutcome[]>? Wait)
	{
		public static readonly ArmedBreaks None = new ArmedBreaks(Array.Empty<OplockBreak>(), Array.Empty<LeaseBreak>(), null);
	}

	private readonly KeyedReaderWriterQueue<(ulong Persistent, ulong Volatile)> _opScopes = new KeyedReaderWriterQueue<(ulong, ulong)>();

	private readonly SmbServerState _server;
	private bool CoordinateCaching => _server.Options.FeaturePolicy.Oplocks || _server.Options.CacheCoordinator.GrantCount != 0;

	private static readonly SecurityIdentity AnonymousIdentity = new SecurityIdentity
	{
		DomainName = string.Empty,
		UserName = string.Empty,
		IsAnonymous = true,
	};

	private readonly Action<string>? _log;

	private readonly BreakWaitTracker? _breaks;

	private const uint FileReadData = 1u;

	private const uint FileWriteData = 2u;

	private const uint FileAppendData = 4u;

	private const uint Delete = 65536u;

	private const uint GenericRead = 2147483648u;

	private const uint GenericWrite = 1073741824u;

	private const uint GenericAll = 268435456u;

	private const uint MaximumAllowed = 33554432u;

	private static readonly ushort[] SupportedDialects = [514, 528, 768, 770, 785];

	private const ulong UnsolicitedMessageId = ulong.MaxValue;

	public bool TryBeginConcurrentFrame(SmbConnection connection, ReadOnlyMemory<byte> message, bool transportEncrypted, out PreparedFrame frame)
	{
		frame = default;
		if (!connection.NegotiateDone)
		{
			return false;
		}

		if (!SmbProtocolIds.IsSmb2(message.Span))
		{
			return false;
		}

		Smb2Header smb2Header;
		try
		{
			smb2Header = Smb2Header.Read(message.Span);
		}
		catch (SmbWireFormatException)
		{
			return false;
		}

		if (smb2Header.NextCommand != 0)
		{
			return false;
		}

		if (smb2Header.Flags.HasFlag(Smb2HeaderFlags.RelatedOperations))
		{
			return false;
		}

		if (!TryClassifyConcurrent(smb2Header.Command, message.Span, out var needsReservation, out var scopeKey, out var scopeMode))
		{
			return false;
		}

		if (!transportEncrypted && RequiresEncryptedTransport(connection, smb2Header))
		{
			return false;
		}

		if (!ValidateSequence(connection, smb2Header))
		{
			return false;
		}

		if (smb2Header.Command is SmbCommand.Read or SmbCommand.Write) RegisterOrdinary(connection, smb2Header, message);
		var sequenceTicket = AdmitChannelSequence(connection, smb2Header, message.Span, message.Span, transportEncrypted, out var sequenceStatus);
		frame = new PreparedFrame(smb2Header, message, transportEncrypted, needsReservation, scopeKey, scopeMode)
			{ SequenceAdmission = new ChannelAdmission(sequenceStatus, sequenceTicket) };
		return true;
	}

	public PreparedFrame ReserveScope(PreparedFrame frame)
	{
		if (!frame.NeedsReservation)
		{
			return frame;
		}

		return frame.WithReservation(_opScopes.Reserve(frame.ScopeKey, frame.ScopeMode));
	}

	/// <summary>Retires an admitted frame cancelled before entering the execution gate.</summary>
	public async ValueTask AbandonPreparedFrameAsync(SmbConnection connection, PreparedFrame frame)
	{
		if (frame.Reservation is { } reservation)
		{
			try
			{
				using var scope = await reservation.AcquireAsync(new CancellationToken(true)).ConfigureAwait(false);
			}
			catch (OperationCanceledException) { }
		}

		frame.SequenceAdmission?.Ticket?.Dispose();
		RetireUnstartedFrame(connection, frame.MessageId);
	}

	private static void RetireUnstartedFrame(SmbConnection connection, ulong messageId)
	{
		if (connection.OrdinaryRequests.TryRemove(messageId, out var ordinary))
		{
			ordinary.Cancel();
			ordinary.Dispose();
		}
	}

	public async ValueTask<byte[]> ExecutePreparedFrameAsync(SmbConnection connection, PreparedFrame frame, CancellationToken cancellationToken = default(CancellationToken))
	{
		var header = frame.Header;
		_log?.Invoke($"[cmd] {header.Command} mid={header.MessageId} tid={header.TreeId} len={frame.Message.Length} (concurrent)");
		ResponseSegment? responseSegment;
		using (var trace = _server.Options.Metrics.BeginCommand(header.Command))
		{
			KeyedReaderWriterQueue<(ulong, ulong)>.Reservation? reservation = frame.Reservation;
			if (reservation.HasValue)
			{
				KeyedReaderWriterQueue<(ulong, ulong)>.Releaser scope;
				try { scope = await reservation.GetValueOrDefault().AcquireAsync(cancellationToken).ConfigureAwait(false); }
				catch
				{
					frame.SequenceAdmission?.Ticket?.Dispose();
					RetireUnstartedFrame(connection, header.MessageId);
					throw;
				}

				connection.OrdinaryRequests.TryGetValue(header.MessageId, out var ordinary);
				try { responseSegment = await DispatchPreparedAsync().ConfigureAwait(false); }
				finally
				{
					if (ordinary != null && !ordinary.PhysicalFinished.IsCompleted) _ = ReleasePhysicalScopeAsync(ordinary.PhysicalFinished, scope);
					else scope.Dispose();
				}
			}
			else
			{
				responseSegment = await DispatchPreparedAsync().ConfigureAwait(continueOnCapturedContext: false);
			}

			trace?.SetStatus(responseSegment?.Header.Status ?? NtStatus.Success);
		}

		_log?.Invoke($"[cmd] {header.Command} mid={header.MessageId} → {((!responseSegment.HasValue) ? "(no response)" : responseSegment.GetValueOrDefault().Header.Status.ToString())}");
		byte[] result;
		if (responseSegment.HasValue)
		{
			var valueOrDefault = responseSegment.GetValueOrDefault();
			result = AssembleResponse(connection, new List<ResponseSegment>(1) { SignIfRequestWasSigned(connection, header, valueOrDefault) });
		}
		else
		{
			result = Array.Empty<byte>();
		}

		return result;

		async ValueTask<ResponseSegment?> DispatchPreparedAsync()
		{
			try { return await DispatchOneAsync(connection, header, frame.Message, frame.Encrypted, preValidated: true, standalone: true, sequenceAdmission: frame.SequenceAdmission).ConfigureAwait(false); }
			finally
			{
				if (frame.SequenceAdmission is { EnteredCore: false } admission)
				{
					admission.Ticket?.Dispose();
					RetireUnstartedFrame(connection, header.MessageId);
				}
			}
		}
	}

	private static async Task ReleasePhysicalScopeAsync(Task physical, IDisposable scope)
	{
		try { await physical.ConfigureAwait(false); }
		finally { scope.Dispose(); }
	}

	private bool TryClassifyConcurrent(SmbCommand command, ReadOnlySpan<byte> message, out bool needsReservation, out (ulong, ulong) scopeKey, out LockMode scopeMode)
	{
		needsReservation = false;
		scopeKey = default;
		scopeMode = LockMode.Shared;
		var concurrentMetadataOps = _server.Options.ConcurrentMetadataOps;
		switch (command)
		{
			case SmbCommand.Read:
			case SmbCommand.Write:
				if (!concurrentMetadataOps)
				{
					return true;
				}

				scopeMode = LockMode.Shared;
				break;
			case SmbCommand.QueryInfo:
				if (!concurrentMetadataOps)
				{
					return false;
				}

				scopeMode = LockMode.Shared;
				break;
			case SmbCommand.Close:
			case SmbCommand.Flush:
			case SmbCommand.QueryDirectory:
			case SmbCommand.SetInfo:
				if (!concurrentMetadataOps)
				{
					return false;
				}

				scopeMode = LockMode.Exclusive;
				break;
			case SmbCommand.Create:
				return concurrentMetadataOps;
			case SmbCommand.TreeConnect:
				return concurrentMetadataOps;
			default:
				return false;
		}

		if (!TryReadFileId(command, message, out scopeKey))
		{
			return false;
		}

		needsReservation = true;
		return true;
	}

	private static bool TryReadFileId(SmbCommand command, ReadOnlySpan<byte> message, out (ulong, ulong) fileId)
	{
		try
		{
			switch (command)
			{
				case SmbCommand.Read:
				{
					var request4 = ReadMessage.ParseRequest(message, 64);
					fileId = (request4.PersistentId, request4.VolatileId);
					return true;
				}
				case SmbCommand.Write:
					if (message.Length >= 96 && BinaryPrimitives.ReadUInt16LittleEndian(message.Slice(64, 2)) == 49)
					{
						var item5 = BinaryPrimitives.ReadUInt64LittleEndian(message.Slice(80, 8));
						var item6 = BinaryPrimitives.ReadUInt64LittleEndian(message.Slice(88, 8));
						fileId = (item5, item6);
						return true;
					}

					break;
				case SmbCommand.Close:
				{
					var tuple = CloseMessage.ParseRequest(message, 64);
					var item3 = tuple.persistentId;
					var item4 = tuple.volatileId;
					fileId = (item3, item4);
					return true;
				}
				case SmbCommand.Flush:
					if (message.Length >= 88)
					{
						var item = BinaryPrimitives.ReadUInt64LittleEndian(message.Slice(72, 8));
						var item2 = BinaryPrimitives.ReadUInt64LittleEndian(message.Slice(80, 8));
						fileId = (item, item2);
						return true;
					}

					break;
				case SmbCommand.QueryDirectory:
				{
					var request3 = QueryDirectoryMessage.ParseRequest(message, 64);
					fileId = (request3.PersistentId, request3.VolatileId);
					return true;
				}
				case SmbCommand.QueryInfo:
				{
					var request2 = QueryInfoMessage.ParseRequest(message, 64);
					fileId = (request2.PersistentId, request2.VolatileId);
					return true;
				}
				case SmbCommand.SetInfo:
				{
					var request = SetInfoMessage.ParseRequest(message, 64);
					fileId = (request.PersistentId, request.VolatileId);
					return true;
				}
				case SmbCommand.Lock:
				case SmbCommand.Ioctl:
				case SmbCommand.Cancel:
				case SmbCommand.Echo:
				case SmbCommand.ChangeNotify:
					break;
			}
		}
		catch (SmbWireFormatException)
		{
		}

		fileId = default;
		return false;
	}

	public Smb2Dispatcher(SmbServerState server, Action<string>? logger = null)
	{
		_server = server;
		_log = logger;
		server.Options.CacheCoordinator.SendOplockBreakAsync = SendOplockBreakAsync;
		server.Options.CacheCoordinator.SendLeaseBreakAsync = SendLeaseBreakAsync;
		server.Options.CacheCoordinator.CloseDisconnectedAsync = open => CloseOpenAsync(open, CloseReason.Timeout).AsTask();
		_breaks = ((server.Options.OplockBreakTimeout > TimeSpan.Zero) ? new BreakWaitTracker(server.Options.TimeProvider, server.Options.OplockBreakTimeout, server.Options.Metrics) : null);
	}

	private void Audit(SmbAuditEventType type, SmbLogLevel level, SmbConnection? connection, string? user = null, string? share = null, string? path = null, NtStatus status = NtStatus.Success, string? message = null)
	{
		var auditLogger = _server.Options.AuditLogger;
		if (auditLogger.IsEnabled(level))
		{
			var auditEvent = new SmbAuditEvent
			{
				EventType = type,
				Level = level,
				Timestamp = _server.Options.TimeProvider.GetUtcNow(),
				User = user,
				ClientAddress = connection?.ClientAddress,
				Share = share,
				Path = path,
				Status = status,
				Message = message,
			};
			auditLogger.Log(in auditEvent);
		}
	}

	private static string DescribeIdentity(SecurityIdentity? identity)
	{
		if (identity == null || identity.IsAnonymous)
		{
			return "(anonymous)";
		}

		if (!string.IsNullOrEmpty(identity.UserPrincipalName))
		{
			return identity.UserPrincipalName;
		}

		if (!string.IsNullOrEmpty(identity.DomainName))
		{
			return identity.DomainName + "\\" + identity.UserName;
		}

		return identity.UserName;
	}

	public byte[] ProcessMessage(SmbConnection connection, ReadOnlySpan<byte> message, bool transportEncrypted = false)
	{
		return ProcessMessageAsync(connection, message.ToArray(), transportEncrypted).AsTask().GetAwaiter().GetResult();
	}

	public async ValueTask<byte[]> ProcessMessageAsync(SmbConnection connection, ReadOnlyMemory<byte> message, bool transportEncrypted = false)
	{
		connection.LastActivityTicks = _server.Options.TimeProvider.GetUtcNow().Ticks;
		var requestStart = Stopwatch.GetTimestamp();
		if (SmbProtocolIds.IsSmb1(message.Span) && message.Length > 4 && message.Span[4] == 114)
		{
			return BuildSmb1NegotiateResponse(connection, message.Span);
		}

		var segments = new List<ResponseSegment>();
		var offset = 0;
		var compound = new CompoundExecutionContext();
		int segmentLength;
		for (; offset < message.Length; offset += segmentLength)
		{
			Smb2Header header;
			try
			{
				header = Smb2Header.Read(message.Span.Slice(offset));
			}
			catch (SmbWireFormatException ex)
			{
				_log?.Invoke("[parse] invalid header → INVALID_PARAMETER: " + ex.Message + "; Bytes: " + Hex(message.Span.Slice(offset)));
				segments.Add(BuildError(new Smb2Header
				{
					Command = SmbCommand.Negotiate,
				}, NtStatus.InvalidParameter));
				break;
			}

			var num = message.Length - offset;
			segmentLength = ((header.NextCommand != 0) ? ((int)header.NextCommand) : num);
			if (segmentLength < 64 || segmentLength > num || (header.NextCommand != 0 && ((header.NextCommand & 7) != 0 || num - segmentLength < 64)))
			{
				_log?.Invoke($"[parse] invalid NextCommand={header.NextCommand} (remaining {num}) → INVALID_PARAMETER");
				segments.Add(BuildError(header, NtStatus.InvalidParameter));
				break;
			}

			var segment = message.Slice(offset, segmentLength);
			compound.SegmentStart = offset;
			compound.SegmentLength = segmentLength;
			var dependencyError = compound.Resolve(header, segment, out var resolved);

			_log?.Invoke($"[cmd] {header.Command} mid={header.MessageId} tid={header.TreeId} len={segment.Length} charge={header.CreditCharge}");
			ResponseSegment? responseSegment;
			using (var trace = _server.Options.Metrics.BeginCommand(header.Command))
			{
				var standalone = offset == 0 && header.NextCommand == 0 && !header.Flags.HasFlag(Smb2HeaderFlags.RelatedOperations);
				responseSegment = await DispatchOneAsync(connection, header, segment, transportEncrypted, preValidated: false, standalone, resolved, dependencyError).ConfigureAwait(continueOnCapturedContext: false);
				trace?.SetStatus(responseSegment?.Header.Status ?? NtStatus.Success);
			}

			_log?.Invoke($"[cmd] {header.Command} mid={header.MessageId} → {((!responseSegment.HasValue) ? "(no response)" : responseSegment.GetValueOrDefault().Header.Status.ToString())}");
			if (responseSegment.HasValue)
			{
				var valueOrDefault = responseSegment.GetValueOrDefault();
				if (valueOrDefault.Header.Status == NtStatus.Pending && valueOrDefault.Header.IsAsync && connection.PendingRequests.TryGetValue(header.MessageId, out var predecessor))
				{
					if (header.Flags.HasFlag(Smb2HeaderFlags.RelatedOperations)) valueOrDefault.Header.Flags |= Smb2HeaderFlags.RelatedOperations;
					segments.Add(valueOrDefault);
					var nextOffset = offset + segmentLength;
					var deferred = new List<DeferredCommand>();
					NtStatus? deferredRejection = null;
					while (header.NextCommand != 0 && nextOffset < message.Length)
					{
						Smb2Header nextHeader;
						try { nextHeader = Smb2Header.Read(message.Span.Slice(nextOffset)); }
						catch (SmbWireFormatException) { break; }

						if (!nextHeader.Flags.HasFlag(Smb2HeaderFlags.RelatedOperations)) break;

						var length = nextHeader.NextCommand == 0 ? message.Length - nextOffset : checked((int)nextHeader.NextCommand);
						if (length < 64 || length > message.Length - nextOffset || (nextHeader.NextCommand != 0 && ((length & 7) != 0 || message.Length - nextOffset - length < 64))) break;

						var wire = (ReadOnlyMemory<byte>)message.Slice(nextOffset, length).ToArray();
						NtStatus? admissionError = null;
						if (!ValidateSequence(connection, nextHeader)) admissionError = NtStatus.InvalidParameter;
						try
						{
							ValidateRequestStructure(nextHeader.Command, wire.Span);
							if (!ValidatePayloadCharge(connection, nextHeader, wire.Span)) admissionError = NtStatus.InvalidParameter;
						}
						catch (SmbWireFormatException) { admissionError = NtStatus.InvalidParameter; }

						nextHeader.SessionId = header.SessionId;
						nextHeader.TreeId = header.TreeId;
						if (!TryGetValidSession(connection, nextHeader.SessionId, out var nextSession) || !VerifyInboundSignature(connection, nextSession, nextHeader, wire.Span, transportEncrypted)) admissionError = NtStatus.AccessDenied;
						deferredRejection ??= admissionError;
						if (connection.PendingRequests.Count >= _server.Options.MaxOutstandingRequests) deferredRejection ??= NtStatus.InsufficientResources;
						if (deferredRejection is { } rejection)
						{
							var rejected = BuildError(nextHeader, rejection);
							rejected.Header.Flags |= Smb2HeaderFlags.RelatedOperations;
							segments.Add(SignIfRequestWasSigned(connection, nextHeader, rejected));
							nextOffset += length;
							if (nextHeader.NextCommand == 0) break;

							continue;
						}

						var child = new PendingAsyncRequest { MessageId = nextHeader.MessageId, AsyncId = connection.AllocateAsyncId(), ReservedForContinuation = true };
						if (!connection.RegisterPending(child))
						{
							connection.MustTerminate = true;
							break;
						}

						deferred.Add(new DeferredCommand(nextHeader, wire, nextOffset, length, child, admissionError));
						var childInterim = InterimResponse(nextHeader, nextSession ?? predecessor.Owner!.Session!, child.AsyncId);
						childInterim.Header.Flags |= Smb2HeaderFlags.RelatedOperations;
						segments.Add(childInterim);
						nextOffset += length;
						if (nextHeader.NextCommand == 0) break;
					}

					var chain = compound;
					var retainedResolved = (ReadOnlyMemory<byte>)resolved.ToArray();
					chain.PendingContinuation = () => ResumeCompoundAsync(connection, chain, header, retainedResolved, predecessor, deferred, transportEncrypted);
					_ = chain.PendingContinuation();
					compound = new CompoundExecutionContext();
					segmentLength = nextOffset - offset;
					continue;
				}

				compound.Complete(header, resolved, valueOrDefault.Header, valueOrDefault.Body);
				if (header.Flags.HasFlag(Smb2HeaderFlags.RelatedOperations)) valueOrDefault.Header.Flags |= Smb2HeaderFlags.RelatedOperations;
				segments.Add(SignIfRequestWasSigned(connection, header, valueOrDefault));
			}

			if (header.NextCommand == 0)
			{
				break;
			}
		}

		_server.Options.Metrics.OnRequestCompleted(Stopwatch.GetElapsedTime(requestStart).TotalMilliseconds);
		return AssembleResponse(connection, segments);
	}

	private sealed record DeferredCommand(Smb2Header Header, ReadOnlyMemory<byte> Wire, int Offset, int Length, PendingAsyncRequest Pending, NtStatus? AdmissionError);

	private async ValueTask ResumeCompoundAsync(SmbConnection connection, CompoundExecutionContext context, Smb2Header previousHeader, ReadOnlyMemory<byte> previousResolved, PendingAsyncRequest previous, List<DeferredCommand> deferred, bool encrypted)
	{
		try
		{
			await previous.Finished.ConfigureAwait(false);
			if (previous.State == PendingRequestState.Abandoned)
			{
				foreach (var item in deferred) item.Pending.Abandon();
				return;
			}

			var previousResponse = previousHeader.CreateResponse(previous.FinalStatus);
			context.Complete(previousHeader, previousResolved, previousResponse, previous.FinalBody);
			foreach (var item in deferred)
			{
				var pending = item.Pending;
				await pending.InterimTransmitted.ConfigureAwait(false);
				if (pending.State == PendingRequestState.Abandoned) continue;

				context.SegmentStart = item.Offset;
				context.SegmentLength = item.Length;
				var error = context.Resolve(item.Header, item.Wire, out var resolved);
				ResponseSegment? response;
				if (pending.Token.IsCancellationRequested) response = BuildError(item.Header, NtStatus.Cancelled);
				else response = await DispatchOneAsync(connection, item.Header, item.Wire, encrypted, true, false, resolved, item.AdmissionError ?? error).ConfigureAwait(false);
				if (response is { } final && final.Header.Status != NtStatus.Pending)
				{
					var session = connection.Sessions.GetValueOrDefault(item.Header.SessionId) ?? previous.Owner!.Session!;
					pending.Complete(final.Header.Status, final.Body, () => SendAsyncFinalAsync(connection, item.Header, session, pending.AsyncId, final.Header.Status, final.Body, ResponseNeedsEncryption(session, pending.Owner)));
				}

				await pending.Finished.ConfigureAwait(false);
				if (pending.State == PendingRequestState.Abandoned)
				{
					foreach (var rest in deferred) rest.Pending.Abandon();
					return;
				}

				context.Complete(item.Header, resolved, item.Header.CreateResponse(pending.FinalStatus), pending.FinalBody);
			}
		}
		catch
		{
			foreach (var item in deferred) item.Pending.Abandon();
			connection.RequestClose?.Invoke();
		}
		finally { context.PendingContinuation = null; }
	}

	private static OrdinaryRequest RegisterOrdinary(SmbConnection connection, Smb2Header header, ReadOnlyMemory<byte> segment)
	{
		SmbOpen? open = null;
		if (segment.Length >= 96 && connection.Sessions.TryGetValue(header.SessionId, out var session))
			session.Opens.TryGetValue((BinaryPrimitives.ReadUInt64LittleEndian(segment.Span.Slice(80)), BinaryPrimitives.ReadUInt64LittleEndian(segment.Span.Slice(88))), out open);
		return connection.OrdinaryRequests.GetOrAdd(header.MessageId, _ => new OrdinaryRequest(open));
	}

	private async ValueTask<ResponseSegment?> DispatchCachingAsync(SmbConnection connection, Smb2Header header, ReadOnlyMemory<byte> segment, bool encrypted, bool preValidated, bool standalone, ReadOnlyMemory<byte>? resolved, NtStatus? dependencyError, ChannelAdmission? sequenceAdmission = null)
	{
		if (!preValidated)
		{
			if (!encrypted && RequiresEncryptedTransport(connection, header)) return BuildError(header, NtStatus.AccessDenied);
			if (!ValidateSequence(connection, header)) return BuildError(header, NtStatus.InvalidParameter);
		}

		if (!connection.Sessions.TryGetValue(header.SessionId, out var session)) return BuildError(header, NtStatus.UserSessionDeleted);

		var continuation = connection.PendingRequests.TryGetValue(header.MessageId, out var pending) && pending.ReservedForContinuation;
		if (!continuation)
		{
			if (connection.PendingRequests.Count >= _server.Options.MaxOutstandingRequests) return BuildError(header, NtStatus.InsufficientResources);

			pending = new PendingAsyncRequest { MessageId = header.MessageId, AsyncId = connection.AllocateAsyncId() };
			if (!connection.RegisterPending(pending)) return BuildError(header, NtStatus.InsufficientResources);
		}
		else pending!.ReservedForContinuation = false;

		CreateReplayRegistry.PendingClaim? createClaim = null;
		if (header.Command == SmbCommand.Create && _server.Options.FeaturePolicy.SupportsDurable(connection.Dialect) &&
			TryGetValidSession(connection, header.SessionId, out var authenticated) && VerifyInboundSignature(connection, authenticated, header, segment.Span, encrypted))
		{
			try
			{
				var create = CreateRequest.Parse((resolved ?? segment).Span, 64);
				var durable = CreateContextList.Find(create.Contexts, 1145582161u);
				if (durable != null && session.TreeConnects.TryGetValue(header.TreeId, out var tree) && Caching.FileCacheCoordinator.Supports(tree.Share.FileStore))
				{
					var key = DurableHandleMessages.ParseV2Request(durable.Data);
					createClaim = _server.CreateReplays.TryBeginRequest(new Guid(connection.ClientGuid), key.CreateGuid);
					if (createClaim == null)
					{
						if (!continuation) pending!.Abandon();
						return BuildError(header, (NtStatus)0xc0000467);
					}
					var claim = createClaim;
					connection.ResponseCommitActions[header.MessageId] = (message => claim.Commit(message), claim.ResponseDone);
				}
			}
			catch (SmbWireFormatException)
			{
				if (!continuation) pending!.Abandon();
				return BuildError(header, NtStatus.InvalidParameter);
			}
		}
		var requestBytes = resolved ?? segment;
		var fileOffset = header.Command switch { SmbCommand.Read or SmbCommand.Write or SmbCommand.SetInfo => 80, SmbCommand.Ioctl => 72, SmbCommand.QueryInfo => 88, _ => -1 };
		SmbOpen? owner = null;
		if (fileOffset >= 0 && requestBytes.Length >= fileOffset + 16)
			session.Opens.TryGetValue((BinaryPrimitives.ReadUInt64LittleEndian(requestBytes.Span.Slice(fileOffset)), BinaryPrimitives.ReadUInt64LittleEndian(requestBytes.Span.Slice(fileOffset + 8))), out owner);
		pending!.Owner = owner;
		var ordinary = connection.OrdinaryRequests.GetOrAdd(header.MessageId, _ => new OrdinaryRequest(owner));
		pending.Attach(pending.Token.Register(ordinary.Cancel));
		var responseToken = ordinary.Token;
		var physical = ExecutePhysicalAsync();
		async Task<ResponseSegment?> ExecutePhysicalAsync()
		{
			try
			{
				var result = await DispatchOneCoreAsync(connection, header, segment, encrypted, true, standalone, resolved, dependencyError, ordinary.Token, sequenceAdmission).ConfigureAwait(false);
				if (result is { } final) createClaim?.Expect(final.Header.Status, final.Body);
				return result;
			}
			finally { createClaim?.ExecutionDone(); }
		}
		if (physical.IsCompleted || _server.Options.CacheCoordinator.BreakingCount == 0)
		{
			var delivered = new TaskCompletionSource<bool>(TaskCreationOptions.RunContinuationsAsynchronously);
			var retirement = RetirePhysicalAsync();
			try
			{
				var result = await physical.WaitAsync(responseToken).ConfigureAwait(false);
				delivered.TrySetResult(true);
				await retirement.ConfigureAwait(false);
				return result;
			}
			catch (OperationCanceledException)
			{
				delivered.TrySetResult(false);
				return BuildError(header, NtStatus.Cancelled);
			}
			finally
			{
				if (!continuation) pending.Abandon();
			}

			async Task RetirePhysicalAsync()
			{
				try
				{
					var result = await physical.ConfigureAwait(false);
					if (!await delivered.Task.ConfigureAwait(false)) await DiscardUnreturnedCreateAsync(session, header, result).ConfigureAwait(false);
				}
				finally
				{
					connection.OrdinaryRequests.TryRemove(new KeyValuePair<ulong, OrdinaryRequest>(header.MessageId, ordinary));
					ordinary.Dispose();
				}
			}
		}

		pending.Attach(pending.Token.Register(() =>
		{
			ordinary.Cancel();
			Complete(BuildError(header, pending.CancellationStatus));
		}));
		_ = FinishAsync();
		return InterimResponse(header, session, pending.AsyncId);

		bool Complete(ResponseSegment result) => pending.Complete(result.Header.Status, result.Body, () => SendAsyncFinalAsync(connection, header, session, pending.AsyncId, result.Header.Status, result.Body, ResponseNeedsEncryption(session, owner)));

		async Task FinishAsync()
		{
			try
			{
				if (await physical.ConfigureAwait(false) is { } result && !Complete(result)) await DiscardUnreturnedCreateAsync(session, header, result).ConfigureAwait(false);
			}
			catch { Complete(BuildError(header, (NtStatus)0xc0000001)); }
			finally
			{
				connection.OrdinaryRequests.TryRemove(new KeyValuePair<ulong, OrdinaryRequest>(header.MessageId, ordinary));
				ordinary.Dispose();
			}
		}
	}

	private async ValueTask DiscardUnreturnedCreateAsync(SmbSession session, Smb2Header request, ResponseSegment? result)
	{
		if (request.Command != SmbCommand.Create || result is not { Header.Status: NtStatus.Success, Body.Length: >= 80 } created) return;

		var key = (BinaryPrimitives.ReadUInt64LittleEndian(created.Body.AsSpan(64)), BinaryPrimitives.ReadUInt64LittleEndian(created.Body.AsSpan(72)));
		if (session.Opens.TryGetValue(key, out var open)) await CloseOpenAsync(open, CloseReason.FailedCreate).ConfigureAwait(false);
	}

	private async ValueTask<ResponseSegment?> DispatchOneAsync(SmbConnection connection, Smb2Header header, ReadOnlyMemory<byte> segment, bool frameEncrypted, bool preValidated = false, bool standalone = false, ReadOnlyMemory<byte>? resolved = null, NtStatus? dependencyError = null, ChannelAdmission? sequenceAdmission = null)
	{
		var parsing = resolved ?? segment;
		var cacheCommand = header.Command is SmbCommand.Create or SmbCommand.Read or SmbCommand.Write
			|| header.Command is SmbCommand.SetInfo or SmbCommand.QueryInfo && parsing.Length > 66 && parsing.Span[66] == (byte)InfoType.File
			|| header.Command == SmbCommand.Ioctl && parsing.Length >= 72 && BinaryPrimitives.ReadUInt32LittleEndian(parsing.Span.Slice(68)) is 0x1440f2 or 0x1480f2;
		if (CoordinateCaching && cacheCommand)
			return await DispatchCachingAsync(connection, header, segment, frameEncrypted, preValidated, standalone, resolved, dependencyError, sequenceAdmission).ConfigureAwait(false);
		if (header.Command is not (SmbCommand.Read or SmbCommand.Write))
			return await DispatchOneCoreAsync(connection, header, segment, frameEncrypted, preValidated, standalone, resolved, dependencyError, sequenceAdmission: sequenceAdmission);

		if (!preValidated)
		{
			if (!frameEncrypted && RequiresEncryptedTransport(connection, header)) return BuildError(header, NtStatus.AccessDenied);
			if (!ValidateSequence(connection, header)) return BuildError(header, NtStatus.InvalidParameter);

			preValidated = true;
		}

		var ordinary = RegisterOrdinary(connection, header, resolved ?? segment);
		var responseToken = ordinary.Token;
		var physical = DispatchOneCoreAsync(connection, header, segment, frameEncrypted, preValidated, standalone, resolved, dependencyError, ordinary.Token, sequenceAdmission).AsTask();
		_ = RetireOrdinaryAsync();
		try { return await physical.WaitAsync(responseToken).ConfigureAwait(false); }
		catch (OperationCanceledException) { return BuildError(header, NtStatus.Cancelled); }

		async Task RetireOrdinaryAsync()
		{
			try { await physical.ConfigureAwait(false); }
			finally
			{
				connection.OrdinaryRequests.TryRemove(new KeyValuePair<ulong, OrdinaryRequest>(header.MessageId, ordinary));
				ordinary.Dispose();
			}
		}
	}

	private async ValueTask<ResponseSegment?> DispatchOneCoreAsync(SmbConnection connection, Smb2Header header, ReadOnlyMemory<byte> segment, bool frameEncrypted, bool preValidated = false, bool standalone = false, ReadOnlyMemory<byte>? resolved = null, NtStatus? dependencyError = null, CancellationToken cancellationToken = default, ChannelAdmission? sequenceAdmission = null)
	{
		var channelTicket = sequenceAdmission?.Ticket;
		if (sequenceAdmission != null) sequenceAdmission.EnteredCore = true;
		try
		{
			if (!preValidated)
			{
				if (!frameEncrypted && RequiresEncryptedTransport(connection, header))
				{
					return BuildError(header, NtStatus.AccessDenied);
				}

				if (!ValidateSequence(connection, header))
				{
					return BuildError(header, NtStatus.InvalidParameter);
				}
			}

			ValidateRequestStructure(header.Command, segment.Span);
			if (!ValidatePayloadCharge(connection, header, segment.Span)) return BuildError(header, NtStatus.InvalidParameter);
			if (dependencyError.HasValue) return BuildError(header, dependencyError.Value);

			var request = new CommandRequest(segment, resolved ?? segment);
			SetAmbientCaller(connection, header);
			var channelStatus = sequenceAdmission?.Status ?? NtStatus.Success;
			if (sequenceAdmission == null) channelTicket = AdmitChannelSequence(connection, header, request.ParsingSpan, segment.Span, frameEncrypted, out channelStatus);
			if (channelStatus != NtStatus.Success) return BuildError(header, channelStatus);

			InvalidateCreateReplay(connection, header, request, frameEncrypted);
			using var operation = AcquireOperation(connection, header, request, out var lifecycleError);
			if (lifecycleError is { } status) return BuildError(header, status);

			var result = header.Command switch
			{
				SmbCommand.Negotiate => HandleNegotiate(connection, header, segment.Span),
				SmbCommand.SessionSetup => await HandleSessionSetupAsync(connection, header, segment, frameEncrypted).ConfigureAwait(false),
				SmbCommand.TreeConnect => await HandleTreeConnectAsync(connection, header, request, frameEncrypted).ConfigureAwait(continueOnCapturedContext: false),
				SmbCommand.TreeDisconnect => await HandleTreeDisconnectAsync(connection, header, request, frameEncrypted),
				SmbCommand.Logoff => await HandleLogoffAsync(connection, header, request, frameEncrypted),
				SmbCommand.Echo => HandleEcho(connection, header, segment.Span, frameEncrypted),
				SmbCommand.Create => await HandleCreateAsync(connection, header, request, frameEncrypted, standalone, cancellationToken).ConfigureAwait(continueOnCapturedContext: false),
				SmbCommand.Close => await HandleCloseAsync(connection, header, request, frameEncrypted).ConfigureAwait(continueOnCapturedContext: false),
				SmbCommand.Read => await HandleReadAsync(connection, header, request, frameEncrypted, cancellationToken).ConfigureAwait(continueOnCapturedContext: false),
				SmbCommand.Write => await HandleWriteAsync(connection, header, request, frameEncrypted, cancellationToken).ConfigureAwait(continueOnCapturedContext: false),
				SmbCommand.QueryDirectory => await HandleQueryDirectoryAsync(connection, header, request, frameEncrypted).ConfigureAwait(continueOnCapturedContext: false),
				SmbCommand.QueryInfo => await HandleQueryInfoAsync(connection, header, request, frameEncrypted, cancellationToken).ConfigureAwait(continueOnCapturedContext: false),
				SmbCommand.SetInfo => await HandleSetInfoAsync(connection, header, request, frameEncrypted, cancellationToken).ConfigureAwait(continueOnCapturedContext: false),
				SmbCommand.Flush => await HandleFlushAsync(connection, header, request, frameEncrypted).ConfigureAwait(continueOnCapturedContext: false),
				SmbCommand.Ioctl => await HandleIoctlAsync(connection, header, request, frameEncrypted, cancellationToken).ConfigureAwait(continueOnCapturedContext: false),
				SmbCommand.Lock => HandleLock(connection, header, segment.Span, request.ParsingSpan, frameEncrypted, standalone, channelTicket),
				SmbCommand.Cancel => HandleCancel(connection, header, segment.Span),
				SmbCommand.ChangeNotify => HandleChangeNotify(connection, header, segment.Span, request.ParsingSpan, frameEncrypted),
				SmbCommand.OplockBreak => HandleOplockBreak(connection, header, segment.Span, frameEncrypted),
				_ => BuildError(header, NtStatus.NotSupported),
			};
			if (result is { Header.Status: NtStatus.Pending } && channelTicket != null)
			{
				// LOCK's producer already owns the ticket, even if abandonment removed
				// its response maps before core dispatch returned.
				if (header.Command == SmbCommand.Lock) channelTicket = null;
				else if (connection.PendingRequests.TryGetValue(header.MessageId, out var pending))
				{
					pending.Attach(channelTicket);
					channelTicket = null;
				}
			}

			return result;
		}
		catch (SmbWireFormatException ex)
		{
			_log?.Invoke($"[parse] {header.Command} → INVALID_PARAMETER: {ex.Message}; Bytes: {Hex(segment.Span)}");
			return BuildError(header, NtStatus.InvalidParameter);
		}
		catch (OperationCanceledException) when (cancellationToken.IsCancellationRequested) { return BuildError(header, NtStatus.Cancelled); }
		catch (Exception ex2)
		{
			_log?.Invoke($"[error] {header.Command} mid={header.MessageId} → {ex2.GetType().Name}: {ex2.Message}");
			return BuildError(header, MapException(ex2));
		}
		finally
		{
			channelTicket?.Dispose();
			SmbCaller.Current = null;
		}
	}

	private static void SetAmbientCaller(SmbConnection connection, Smb2Header header)
	{
		CallerInfo? current;
		if (connection.Sessions.TryGetValue(header.SessionId, out var value))
		{
			var identity = value.Identity;
			if (identity != null)
			{
				current = new CallerInfo(identity.DomainName, identity.UserName);
				goto IL_0040;
			}
		}

		current = null;
		IL_0040:
		SmbCaller.Current = current;
	}

	private bool RequiresEncryptedTransport(SmbConnection connection, Smb2Header header)
	{
		if (!_server.Options.RejectUnencryptedAccess)
		{
			return false;
		}

		var command = header.Command;
		if (command <= SmbCommand.SessionSetup)
		{
			return false;
		}

		if (!connection.Sessions.TryGetValue(header.SessionId, out var value))
		{
			return false;
		}

		if (value.EncryptData)
		{
			return true;
		}

		if (value.TreeConnects.TryGetValue(header.TreeId, out var value2))
		{
			return value2.EncryptData;
		}

		return false;
	}

	private static void ValidateRequestStructure(SmbCommand command, ReadOnlySpan<byte> packet)
	{
		switch (command)
		{
			case SmbCommand.Read: ReadMessage.ParseRequest(packet, 64); break;
			case SmbCommand.Write: WriteMessage.ParseRequest(packet, 64); break;
			case SmbCommand.Create: CreateRequest.Parse(packet, 64); break;
			case SmbCommand.Close: CloseMessage.ParseRequest(packet, 64); break;
			case SmbCommand.QueryDirectory: QueryDirectoryMessage.ParseRequest(packet, 64); break;
			case SmbCommand.QueryInfo: QueryInfoMessage.ParseRequest(packet, 64); break;
			case SmbCommand.SetInfo: SetInfoMessage.ParseRequest(packet, 64); break;
			case SmbCommand.Ioctl: IoctlMessage.ParseRequest(packet, 64); break;
			case SmbCommand.Lock: LockMessage.ParseRequest(packet, 64); break;
			case SmbCommand.ChangeNotify: ChangeNotifyMessage.ParseRequest(packet, 64); break;
			case SmbCommand.Logoff:
			case SmbCommand.TreeDisconnect:
				if (packet.Length < 68 || BinaryPrimitives.ReadUInt16LittleEndian(packet.Slice(64)) != 4)
					throw new SmbWireFormatException("Incomplete/invalid teardown request.");

				break;
			case SmbCommand.Flush:
				if (packet.Length < 88 || BinaryPrimitives.ReadUInt16LittleEndian(packet.Slice(64)) != 24)
					throw new SmbWireFormatException("Incomplete/invalid FLUSH request.");

				break;
		}
	}

	private static bool ValidatePayloadCharge(SmbConnection connection, Smb2Header header, ReadOnlySpan<byte> packet)
	{
		uint send = 0, receive = 0;
		switch (header.Command)
		{
			case SmbCommand.ChangeNotify: receive = ChangeNotifyMessage.ParseRequest(packet, 64).OutputBufferLength; break;
			case SmbCommand.Read: receive = ReadMessage.ParseRequest(packet, 64).Length; break;
			case SmbCommand.Write: send = (uint)WriteMessage.ParseRequest(packet, 64).Data.Length; break;
			case SmbCommand.QueryDirectory: receive = QueryDirectoryMessage.ParseRequest(packet, 64).OutputBufferLength; break;
			case SmbCommand.QueryInfo:
				var query = QueryInfoMessage.ParseRequest(packet, 64);
				receive = query.OutputBufferLength;
				send = (uint)query.InputBuffer.Length;
				break;
			case SmbCommand.SetInfo: send = (uint)SetInfoMessage.ParseRequest(packet, 64).Buffer.Length; break;
			case SmbCommand.Ioctl:
				var ioctl = IoctlMessage.ParseRequest(packet, 64);
				send = (uint)ioctl.Input.Length;
				receive = ioctl.MaxOutputResponse;
				break;
		}

		ulong payload = Math.Max(send, receive);
		if (!connection.SupportsMultiCredit || connection.Dialect == SmbDialect.Smb202) return payload <= 65536;

		var required = Math.Max(1UL, (payload + 65535) / 65536);
		return header.CreditCharge == 0 ? payload <= 65536 : required <= header.CreditCharge;
	}

	private static bool ValidateSequence(SmbConnection connection, Smb2Header header)
	{
		if (header.Command == SmbCommand.Cancel) return true;

		var charge = connection.SupportsMultiCredit && connection.Dialect != SmbDialect.Smb202 ? header.CreditCharge : (ushort)1;
		return connection.Credits.TryConsume(header.MessageId, charge);
	}

	private static bool ResponseNeedsEncryption(SmbSession session, SmbOpen? open)
	{
		if (!session.EncryptData)
		{
			return open?.TreeConnect!.EncryptData ?? false;
		}

		return true;
	}

	private static NtStatus MapException(Exception ex)
	{
		if (!(ex is UnauthorizedAccessException))
		{
			if (!(ex is FileNotFoundException))
			{
				if (!(ex is DirectoryNotFoundException))
				{
					if (ex is PathTooLongException || ex is ArgumentException || ex is NotSupportedException)
					{
						return NtStatus.ObjectNameInvalid;
					}

					return NtStatus.InvalidParameter;
				}

				return NtStatus.ObjectPathNotFound;
			}

			return NtStatus.ObjectNameNotFound;
		}

		return NtStatus.AccessDenied;
	}

	private static string Hex(ReadOnlySpan<byte> data)
	{
		var num = Math.Min(data.Length, 96);
		return Convert.ToHexString(data.Slice(0, num)) + ((data.Length > num) ? "…" : "");
	}

	private byte[] BuildSmb1NegotiateResponse(SmbConnection connection, ReadOnlySpan<byte> smb1Message)
	{
		var tuple = ParseSmb1NegotiateDialects(smb1Message);
		var (flag, _) = tuple;
		if (!tuple.smb2002 || flag || 514 < (int)_server.Options.MinDialect || 514 > (int)_server.Options.MaxDialect)
		{
			return BuildSmb1WildcardNegotiateResponse();
		}

		return BuildSmb1Smb202FinalNegotiateResponse(connection);
	}

	private static (bool wildcard, bool smb2002) ParseSmb1NegotiateDialects(ReadOnlySpan<byte> smb1)
	{
		if (smb1.Length < 35)
		{
			return (wildcard: false, smb2002: false);
		}

		var num = smb1[33] | (smb1[34] << 8);
		var num2 = 35;
		var num3 = Math.Min(smb1.Length, num2 + num);
		var item = false;
		var item2 = false;
		var num4 = num2;
		while (num4 < num3)
		{
			if (smb1[num4] != 2)
			{
				num4++;
				continue;
			}

			var num5 = num4 + 1;
			int i;
			for (i = num5; i < num3 && smb1[i] != 0; i++)
			{
			}

			var num6 = num5;
			var span = smb1.Slice(num6, i - num6);
			if (span.SequenceEqual("SMB 2.???"u8))
			{
				item = true;
			}
			else if (span.SequenceEqual("SMB 2.002"u8))
			{
				item2 = true;
			}

			num4 = i + 1;
		}

		return (wildcard: item, smb2002: item2);
	}

	private byte[] BuildSmb1Smb202FinalNegotiateResponse(SmbConnection connection)
	{
		var request = new NegotiateRequest
		{
			SecurityMode = SmbSecurityMode.SigningEnabled,
			Capabilities = Smb2Capabilities.None,
			ClientGuid = new byte[16],
			Dialects = [SmbDialect.Smb202],
			NegotiateContexts = Array.Empty<NegotiateContext>(),
		};
		var securityBuffer = _server.Options.SpnegoNegotiator!.CreateInitialServerToken();
		var negotiateResponse = NegotiateProcessor.BuildResponse(connection, request, _server.Options, securityBuffer);
		connection.NegotiateDone = true;
		_server.RegisterClientConnection(connection);
		// SMB_COM_NEGOTIATE uses sequence zero; this response promises exactly one new ID.
		if (!connection.Credits.TryConsume(0, 1)) connection.MustTerminate = true;
		connection.Credits.Grant(1);

		return Concat(new Smb2Header
		{
			Command = SmbCommand.Negotiate,
			MessageId = 0uL,
			Flags = Smb2HeaderFlags.ServerToRedir,
			Status = NtStatus.Success,
			CreditRequestResponse = 1,
		}.ToArray(), negotiateResponse.ToBody());
	}

	private byte[] BuildSmb1WildcardNegotiateResponse()
	{
		var smbSecurityMode = SmbSecurityMode.SigningEnabled;
		if (_server.Options.RequireMessageSigning)
		{
			smbSecurityMode |= SmbSecurityMode.SigningRequired;
		}

		var securityBuffer = _server.Options.SpnegoNegotiator!.CreateInitialServerToken();
		var negotiateResponse = new NegotiateResponse
		{
			SecurityMode = smbSecurityMode,
			DialectRevision = SmbDialect.Wildcard2FF,
			ServerGuid = _server.Options.ServerGuid,
			Capabilities = Smb2Capabilities.None,
			MaxTransactSize = _server.Options.MaxTransactSize,
			MaxReadSize = _server.Options.MaxReadSize,
			MaxWriteSize = _server.Options.MaxWriteSize,
			SystemTime = DateTime.UtcNow.ToFileTimeUtc(),
			ServerStartTime = 0L,
			SecurityBuffer = securityBuffer,
			NegotiateContexts = Array.Empty<NegotiateContext>(),
		};
		return Concat(new Smb2Header
		{
			Command = SmbCommand.Negotiate,
			MessageId = 0uL,
			Flags = Smb2HeaderFlags.ServerToRedir,
			Status = NtStatus.Success,
			CreditRequestResponse = 1,
		}.ToArray(), negotiateResponse.ToBody());
	}

	private ResponseSegment? HandleNegotiate(SmbConnection connection, Smb2Header header, ReadOnlySpan<byte> segment)
	{
		if (header.Flags.HasFlag(Smb2HeaderFlags.Signed)) return BuildError(header, NtStatus.InvalidParameter);

		if (connection.NegotiateDone)
		{
			connection.MustTerminate = true;
			return null;
		}

		var negotiateRequest = NegotiateRequest.Parse(segment, 64);
		var dialect = NegotiateProcessor.SelectDialect(negotiateRequest.Dialects, _server.Options);
		if (dialect == SmbDialect.None) return BuildError(header, NtStatus.NotSupported);
		if (dialect == SmbDialect.Smb311)
		{
			var contexts = negotiateRequest.NegotiateContexts;
			if (contexts.Count(c => c.Type == NegotiateContextType.PreauthIntegrityCapabilities) != 1 ||
				contexts.Where(c => c.Type is NegotiateContextType.EncryptionCapabilities or NegotiateContextType.CompressionCapabilities or NegotiateContextType.SigningCapabilities || (ushort)c.Type == 7).GroupBy(c => c.Type).Any(g => g.Count() > 1) ||
				contexts.OfType<SigningContext>().Any(c => c.Algorithms.Count == 0) ||
				_server.Options.EnableCompression && contexts.OfType<CompressionContext>().Any(c => c.Algorithms.Count == 0))
				return BuildError(header, NtStatus.InvalidParameter);
			if (!HasSupportedPreauthContext(negotiateRequest)) return BuildError(header, (NtStatus)0xc05d0000);
		}

		var securityBuffer = _server.Options.SpnegoNegotiator!.CreateInitialServerToken();
		var negotiateResponse = NegotiateProcessor.BuildResponse(connection, negotiateRequest, _server.Options, securityBuffer);
		connection.NegotiateDone = true;
		_server.RegisterClientConnection(connection);


		var smb2Header = header.CreateResponse(NtStatus.Success);
		smb2Header.CreditRequestResponse = CreditManager.ComputeCreditGrant(header.CreditRequestResponse, _server.Options.MaxCreditsPerResponse);
		ReserveResponseCredits(connection, smb2Header);
		var array = negotiateResponse.ToBody();
		if (connection.Dialect == SmbDialect.Smb311)
		{
			connection.PreauthHash.Append(segment);
			var array2 = Concat(smb2Header.ToArray(), array);
			connection.PreauthHash.Append(array2);
		}

		return ResponseSegment.Unsigned(smb2Header, array, creditsReserved: true);
	}

	private static bool HasSupportedPreauthContext(NegotiateRequest request)
	{
		foreach (var negotiateContext in request.NegotiateContexts)
		{
			if (negotiateContext is PreauthIntegrityContext preauthIntegrityContext && preauthIntegrityContext.HashAlgorithms.Contains(PreauthHashAlgorithm.Sha512))
			{
				return true;
			}
		}

		return false;
	}

	private async ValueTask<ResponseSegment> HandleSessionSetupAsync(SmbConnection connection, Smb2Header header, ReadOnlyMemory<byte> segment, bool frameEncrypted)
	{
		if (!frameEncrypted && header.SessionId == 0 && header.Flags.HasFlag(Smb2HeaderFlags.Signed))
			return BuildError(header, NtStatus.UserSessionDeleted);

		if (!connection.NegotiateDone)
		{
			return BuildError(header, NtStatus.InvalidParameter);
		}

		var sessionSetupRequest = SessionSetupRequest.Parse(segment.Span, 64);
		var flag = connection.Dialect == SmbDialect.Smb311;
		if (sessionSetupRequest.Flags.HasFlag(SessionSetupFlags.Binding))
		{
			return HandleSessionBinding(connection, header, sessionSetupRequest, segment.Span, flag);
		}

		SmbSession value;
		if (header.SessionId == 0L)
		{
			var num = _server.AllocateSessionId();
			value = new SmbSession
			{
				SessionId = num,
				SessionGlobalId = _server.AllocateSessionGlobalId(),
				Connection = connection,
				AuthContext = _server.Options.SpnegoNegotiator!.CreateServerContext(),
				PreauthHash = (flag ? connection.PreauthHash.Clone() : null),
			};
			connection.Sessions[num] = value;
			_server.SessionGlobalList[num] = value;
		}
		else if (!connection.Sessions.TryGetValue(header.SessionId, out value))
		{
			return BuildError(header, NtStatus.UserSessionDeleted);
		}

		await value.AuthenticationGate.WaitAsync().ConfigureAwait(false);
		try
		{
			if (value.Lifetime.State != OpenState.Active || !connection.Sessions.ContainsKey(value.SessionId))
				return BuildError(header, NtStatus.UserSessionDeleted);
			var reauth = value.SessionKey.Length != 0;
			if (reauth)
			{
				if (!VerifyInboundSignature(connection, value, header, segment.Span, frameEncrypted))
					return BuildError(header, NtStatus.AccessDenied);
				value.AuthContext ??= _server.Options.SpnegoNegotiator!.CreateServerContext();
			}
			if (!reauth) value.PreauthHash?.Append(segment.Span);
			var gssResult = value.AuthContext!.Accept(sessionSetupRequest.SecurityBuffer);
			if (gssResult.NeedsMoreProcessing)
			{
				var sessionSetupResponse = new SessionSetupResponse
				{
					SecurityBuffer = (gssResult.OutToken ?? Array.Empty<byte>()),
				};
				var smb2Header = BuildSessionHeader(connection, header, value, NtStatus.MoreProcessingRequired);
				var array = sessionSetupResponse.ToBody();
				if (flag && !reauth)
				{
					var array2 = Concat(smb2Header.ToArray(), array);
					value.PreauthHash?.Append(array2);
				}

				return ResponseSegment.Unsigned(smb2Header, array, creditsReserved: true);
			}

			if (!gssResult.IsSuccess)
			{
				_server.Options.Metrics.OnAuthenticationFailed();
				Audit(SmbAuditEventType.AuthenticationFailed, SmbLogLevel.Warning, connection, null, null, null, gssResult.Status);
				return await FailSessionSetupAsync(gssResult.Status).ConfigureAwait(false);
			}

			// Reauthentication cannot replace the identity associated with existing opens.
			if (reauth && !SameIdentity(value.Identity, gssResult.Identity))
			{
				return await FailSessionSetupAsync(NtStatus.AccessDenied).ConfigureAwait(false);
			}
			if (!reauth) ApplyIdentity(value, gssResult);
			if (RejectByPolicy(value, out var status))
			{
				return await FailSessionSetupAsync(status).ConfigureAwait(false);
			}

			if (!_server.AcceptClientDialect(connection))
			{
				return await FailSessionSetupAsync(NtStatus.UserSessionDeleted).ConfigureAwait(false);
			}

			if (!reauth) DeriveSessionKeys(connection, value, gssResult.SessionKey!);
			value.AuthContext = null;
			if (_server.Options.RequireEncryption && (!connection.Dialect.IsSmb3OrLater() || !connection.SupportsEncryption))
			{
				return await FailSessionSetupAsync(NtStatus.AccessDenied).ConfigureAwait(false);
			}

			value.State = SessionState.Valid;
			value.LastActivityTicks = _server.Options.TimeProvider.GetUtcNow().Ticks;
			_server.Options.Metrics.OnAuthenticationSucceeded();
			Audit(SmbAuditEventType.AuthenticationSucceeded, SmbLogLevel.Information, connection, DescribeIdentity(value.Identity));
			if (!reauth && connection.Dialect.IsSmb3OrLater())
			{
				if (!value.TryAttachChannel(new SmbChannel { Connection = connection, SigningKey = value.SigningKey }))
				{
					return await FailSessionSetupAsync(NtStatus.RequestNotAccepted).ConfigureAwait(false);
				}
			}

			// MS-SMB2 3.3.5.5.3: only successful authentication by the same user
			// can retire the previous session. Unknown, foreign and self IDs are ignored.
			if (sessionSetupRequest.PreviousSessionId != 0 && sessionSetupRequest.PreviousSessionId != value.SessionId &&
				_server.SessionGlobalList.TryGetValue(sessionSetupRequest.PreviousSessionId, out var previous) &&
				SameIdentity(previous.Identity, value.Identity))
			{
				await CloseSessionAsync(previous, CloseReason.Logoff).ConfigureAwait(false);
				previous.Connection.Sessions.TryRemove(previous.SessionId, out _);
			}

			var sessionResponseFlags = SessionResponseFlags.None;
			if (value.IsGuest)
			{
				sessionResponseFlags |= SessionResponseFlags.IsGuest;
			}

			if (value.IsAnonymous)
			{
				sessionResponseFlags |= SessionResponseFlags.IsNull;
			}

			if (value.EncryptData)
			{
				sessionResponseFlags |= SessionResponseFlags.EncryptData;
			}

			var sessionSetupResponse2 = new SessionSetupResponse
			{
				SessionFlags = sessionResponseFlags,
				SecurityBuffer = (gssResult.OutToken ?? Array.Empty<byte>()),
			};
			var header2 = BuildSessionHeader(connection, header, value, NtStatus.Success);
			var body = sessionSetupResponse2.ToBody();
			if (!value.SigningRequired || value.IsGuest || value.IsAnonymous)
			{
				return ResponseSegment.Unsigned(header2, body, creditsReserved: true);
			}

			return ResponseSegment.Signed(header2, body, value, creditsReserved: true);

			async ValueTask<ResponseSegment> FailSessionSetupAsync(NtStatus failure)
			{
				var error = BuildError(header, failure);
				// Retain only this response's key while retiring all session resources.
				// Non-success SESSION_SETUP uses the original session key, not a
				// bound channel key (3.3.4.1.1). Initial unsigned auth has no signer.
				if (reauth && header.Flags.HasFlag(Smb2HeaderFlags.Signed))
					error = ResponseSegment.SignedWithKey(error.Header, error.Body, value.SigningKey);
				await CloseSessionAsync(value, CloseReason.Logoff).ConfigureAwait(false);
				CleanupFailedSession(connection, value);
				return error;
			}
		}
		finally { value.AuthenticationGate.Release(); }
	}

	private ResponseSegment HandleSessionBinding(SmbConnection connection, Smb2Header header, SessionSetupRequest request, ReadOnlySpan<byte> segment, bool is311)
	{
		if (!_server.Options.FeaturePolicy.SupportsMultichannel(connection.Dialect) || !_server.Options.EnableMultichannel)
		{
			return BuildError(header, NtStatus.RequestNotAccepted);
		}

		if (header.SessionId == 0L || !_server.SessionGlobalList.TryGetValue(header.SessionId, out var value))
		{
			return BuildError(header, NtStatus.UserSessionDeleted);
		}
		// Final channel loss claims retirement before physical I/O has drained.
		// A still-indexed session must not start a fresh binding at that point.
		if (value.Lifetime.State != OpenState.Active)
			return BuildError(header, NtStatus.UserSessionDeleted);

		if (connection.Sessions.ContainsKey(value.SessionId))
		{
			return BuildError(header, NtStatus.RequestNotAccepted);
		}

		if (value.State != SessionState.Valid)
		{
			return BuildError(header, value.State == SessionState.InProgress ? NtStatus.RequestNotAccepted : (NtStatus)0xc000035c);
		}

		if (connection.Dialect != value.Connection.Dialect)
		{
			return BuildError(header, NtStatus.InvalidParameter);
		}

		if (!connection.ClientGuid.AsSpan().SequenceEqual(value.Connection.ClientGuid))
		{
			return BuildError(header, NtStatus.AccessDenied);
		}

		if (!header.Flags.HasFlag(Smb2HeaderFlags.Signed))
		{
			return BuildError(header, NtStatus.InvalidParameter);
		}

		if (!Smb2Signer.Verify(Smb2Signer.ResolveAlgorithm(value.Connection.Dialect, value.Connection.SigningAlgorithmId), value.SigningKey, segment, header.MessageId, isServer: false, isCancel: false))
		{
			return BuildError(header, NtStatus.AccessDenied);
		}

		var orAdd = connection.PendingBindings.GetOrAdd(value.SessionId, _ => new ChannelBindInProgress
		{
			AuthContext = _server.Options.SpnegoNegotiator!.CreateServerContext(),
			PreauthHash = (is311 ? connection.PreauthHash.Clone() : null),
		});
		orAdd.PreauthHash?.Append(segment);
		var gssResult = orAdd.AuthContext.Accept(request.SecurityBuffer);
		if (gssResult.NeedsMoreProcessing)
		{
			var sessionSetupResponse = new SessionSetupResponse
			{
				SecurityBuffer = (gssResult.OutToken ?? Array.Empty<byte>()),
			};
			var smb2Header = BuildSessionHeader(connection, header, value, NtStatus.MoreProcessingRequired);
			var array = sessionSetupResponse.ToBody();
			if (is311)
			{
				orAdd.PreauthHash?.Append(Concat(smb2Header.ToArray(), array));
			}

			return ResponseSegment.Signed(smb2Header, array, value, creditsReserved: true);
		}

		if (!gssResult.IsSuccess)
		{
			connection.PendingBindings.TryRemove(value.SessionId, out _);
			return BuildError(header, gssResult.Status);
		}

		if (!SameIdentity(value.Identity, gssResult.Identity))
		{
			connection.PendingBindings.TryRemove(value.SessionId, out _);
			return BuildError(header, NtStatus.NotSupported);
		}

		connection.PendingBindings.TryRemove(value.SessionId, out _);
		var signingKey = DeriveChannelSigningKey(connection, gssResult.SessionKey!, orAdd.PreauthHash);
		if (!value.TryAttachChannel(new SmbChannel { Connection = connection, SigningKey = signingKey }))
			return BuildError(header, NtStatus.RequestNotAccepted);

		var sessionResponseFlags = SessionResponseFlags.None;
		if (value.EncryptData)
		{
			sessionResponseFlags |= SessionResponseFlags.EncryptData;
		}

		var sessionSetupResponse2 = new SessionSetupResponse
		{
			SessionFlags = sessionResponseFlags,
			SecurityBuffer = (gssResult.OutToken ?? Array.Empty<byte>()),
		};
		var header2 = BuildSessionHeader(connection, header, value, NtStatus.Success);
		var body = sessionSetupResponse2.ToBody();
		return ResponseSegment.Signed(header2, body, value, creditsReserved: true);
	}

	private static byte[] DeriveChannelSigningKey(SmbConnection connection, byte[] authenticationKey, PreauthIntegrityHash? channelPreauth)
	{
		var array = channelPreauth?.Value ?? new byte[64];
		var sessionKey = authenticationKey.Length >= 16 ? authenticationKey[..16] : Pad16(authenticationKey);
		return Smb3KeyDerivation.Derive(connection.Dialect, connection.CipherId, sessionKey, authenticationKey, array).SigningKey;
	}

	private static bool SameIdentity(SecurityIdentity? a, SecurityIdentity? b)
	{
		if (a == null || b == null)
		{
			return false;
		}

		if (a.IsAnonymous || b.IsAnonymous || a.IsGuest || b.IsGuest)
		{
			return false;
		}

		if (a.UserSid != null && b.UserSid != null)
		{
			return string.Equals(a.UserSid, b.UserSid, StringComparison.OrdinalIgnoreCase);
		}

		if (string.Equals(a.DomainName, b.DomainName, StringComparison.OrdinalIgnoreCase))
		{
			return string.Equals(a.UserName, b.UserName, StringComparison.OrdinalIgnoreCase);
		}

		return false;
	}

	private Smb2Header BuildSessionHeader(SmbConnection connection, Smb2Header request, SmbSession session, NtStatus status)
	{
		var smb2Header = request.CreateResponse(status);
		smb2Header.SessionId = session.SessionId;
		smb2Header.CreditRequestResponse = CreditManager.ComputeCreditGrant(request.CreditRequestResponse, _server.Options.MaxCreditsPerResponse);
		ReserveResponseCredits(connection, smb2Header);
		return smb2Header;
	}

	private static void ApplyIdentity(SmbSession session, GssResult auth)
	{
		var securityIdentity = (session.Identity = auth.Identity);
		session.IsAnonymous = securityIdentity!.IsAnonymous;
		session.IsGuest = securityIdentity.IsGuest;
	}

	private bool RejectByPolicy(SmbSession session, out NtStatus status)
	{
		status = NtStatus.Success;
		if (session.IsGuest && _server.Options.RejectGuestAccess)
		{
			status = NtStatus.AccessDenied;
			return true;
		}

		if (session.IsAnonymous && !_server.Options.AllowAnonymousAccess)
		{
			status = NtStatus.AccessDenied;
			return true;
		}

		return false;
	}

	private void DeriveSessionKeys(SmbConnection connection, SmbSession session, byte[] gssSessionKey)
	{
		session.FullSessionKey = gssSessionKey;
		session.SessionKey = ((gssSessionKey.Length >= 16) ? gssSessionKey[..16] : Pad16(gssSessionKey));
		session.SigningRequired = connection.ShouldSign && !session.IsGuest && !session.IsAnonymous;
		session.EncryptData = _server.Options.RequireEncryption && connection.SupportsEncryption && connection.Dialect.IsSmb3OrLater();
		if (connection.Dialect.IsSmb3OrLater())
		{
			var array = session.PreauthHash?.Value ?? new byte[64];
			var smb3SessionKeys = Smb3KeyDerivation.Derive(connection.Dialect, connection.CipherId, session.SessionKey, session.FullSessionKey, array);
			session.SigningKey = smb3SessionKeys.SigningKey;
			session.EncryptionKey = smb3SessionKeys.EncryptionKey;
			session.DecryptionKey = smb3SessionKeys.DecryptionKey;
			session.ApplicationKey = smb3SessionKeys.ApplicationKey;
		}
		else
		{
			session.SigningKey = session.FullSessionKey;
		}
	}

	private void CleanupFailedSession(SmbConnection connection, SmbSession session)
	{
		connection.Sessions.TryRemove(session.SessionId, out _);
		_server.SessionGlobalList.TryRemove(session.SessionId, out _);
	}

	private async ValueTask<ResponseSegment> HandleTreeConnectAsync(SmbConnection connection, Smb2Header header, CommandRequest segment, bool frameEncrypted)
	{
		if (!TryGetValidSession(connection, header.SessionId, out var session))
		{
			return BuildError(header, NtStatus.UserSessionDeleted);
		}

		if (!VerifyInboundSignature(connection, session, header, segment.Span, frameEncrypted))
		{
			return BuildError(header, NtStatus.AccessDenied);
		}

		using var sessionOperation = session.Lifetime.TryAcquire();
		if (sessionOperation == null) return BuildError(header, NtStatus.UserSessionDeleted);

		var treeConnectRequest = TreeConnectRequest.Parse(segment.ParsingSpan, 64);
		var shareName = treeConnectRequest.ShareName;
		if (!_server.Shares.TryGet(shareName, out var share))
		{
			return BuildError(header, NtStatus.BadNetworkName);
		}

		if (!_server.Options.FeaturePolicy.AllowsShare(share))
		{
			return BuildError(header, NtStatus.NotSupported);
		}

		var context = new ShareAccessContext
		{
			Identity = (session.Identity ?? AnonymousIdentity),
			Share = share,
			Connection = connection,
		};
		var shareAccessResult = await _server.Options.ShareAccessPolicy.AuthorizeConnectAsync(context).ConfigureAwait(continueOnCapturedContext: false);
		if (!shareAccessResult.Allowed)
		{
			Audit(SmbAuditEventType.ShareAccessDenied, SmbLogLevel.Warning, connection, DescribeIdentity(session.Identity), shareName, null, shareAccessResult.DenyStatus);
			return BuildError(header, shareAccessResult.DenyStatus);
		}

		var encryptData = share.EncryptData;
		if (encryptData && (!connection.Dialect.IsSmb3OrLater() || !connection.SupportsEncryption))
		{
			return BuildError(header, NtStatus.AccessDenied);
		}

		var num = session.AllocateTreeId();
		var smbTreeConnect = new SmbTreeConnect
		{
			TreeId = num,
			Session = session,
			Share = share,
			MaximalAccess = (uint)shareAccessResult.MaximalAccess,
			EncryptData = encryptData,
		};
		if (!session.TreeConnects.TryAdd(num, smbTreeConnect)) return BuildError(header, NtStatus.InsufficientResources);

		_server.Options.Metrics.OnTreeConnected();
		Audit(SmbAuditEventType.ShareAccessGranted, SmbLogLevel.Information, connection, DescribeIdentity(session.Identity), share.Name);
		var shareFlags = ShareFlags.None;
		if (smbTreeConnect.EncryptData)
		{
			shareFlags |= ShareFlags.EncryptData;
		}

		var shareCapabilities = ShareCapabilities.None;
		if (share.IsDfs)
		{
			shareFlags |= ShareFlags.Dfs | ShareFlags.DfsRoot;
			shareCapabilities |= ShareCapabilities.Dfs;
		}

		if (_server.Options.FeaturePolicy.ContinuousAvailability && share.ContinuousAvailability && connection.Dialect.IsSmb3OrLater())
		{
			shareCapabilities |= ShareCapabilities.ContinuousAvailability;
		}

		var treeConnectResponse = new TreeConnectResponse
		{
			ShareType = (byte)share.Type,
			ShareFlags = shareFlags,
			Capabilities = (uint)shareCapabilities,
			MaximalAccess = smbTreeConnect.MaximalAccess,
		};
		var smb2Header = header.CreateResponse(NtStatus.Success);
		smb2Header.TreeId = (uint)num;
		smb2Header.SessionId = session.SessionId;
		smb2Header.CreditRequestResponse = CreditManager.ComputeCreditGrant(header.CreditRequestResponse, _server.Options.MaxCreditsPerResponse);
		return MaybeSigned(session, smb2Header, treeConnectResponse.ToBody());
	}

	private async ValueTask<ResponseSegment> HandleTreeDisconnectAsync(SmbConnection connection, Smb2Header header, CommandRequest segment, bool frameEncrypted)
	{
		if (!TryGetValidSession(connection, header.SessionId, out var session))
		{
			return BuildError(header, NtStatus.UserSessionDeleted);
		}

		if (!VerifyInboundSignature(connection, session, header, segment.Span, frameEncrypted))
		{
			return BuildError(header, NtStatus.AccessDenied);
		}

		if (!session.TreeConnects.TryGetValue(header.TreeId, out var tree)) return BuildError(header, NtStatus.NetworkNameDeleted);

		await CloseTreeAsync(session, tree, CloseReason.TreeDisconnect).ConfigureAwait(false);

		var smb2Header = header.CreateResponse(NtStatus.Success);
		smb2Header.CreditRequestResponse = CreditManager.ComputeCreditGrant(header.CreditRequestResponse, _server.Options.MaxCreditsPerResponse);
		return MaybeSigned(session, smb2Header, TreeDisconnectMessage.BuildResponseBody());
	}

	private async ValueTask<ResponseSegment> HandleLogoffAsync(SmbConnection connection, Smb2Header header, CommandRequest segment, bool frameEncrypted)
	{
		if (!TryGetValidSession(connection, header.SessionId, out var session))
		{
			return BuildError(header, NtStatus.UserSessionDeleted);
		}

		if (!VerifyInboundSignature(connection, session, header, segment.Span, frameEncrypted))
		{
			return BuildError(header, NtStatus.AccessDenied);
		}

		Audit(SmbAuditEventType.SessionLogoff, SmbLogLevel.Information, connection, DescribeIdentity(session.Identity));
		await CloseSessionAsync(session, CloseReason.Logoff).ConfigureAwait(false);
		connection.Sessions.TryRemove(session.SessionId, out _);
		_server.SessionGlobalList.TryRemove(session.SessionId, out _);
		session.Channels.Clear();
		session.State = SessionState.Expired;
		var smb2Header = header.CreateResponse(NtStatus.Success);
		smb2Header.CreditRequestResponse = CreditManager.ComputeCreditGrant(header.CreditRequestResponse, _server.Options.MaxCreditsPerResponse);
		return MaybeSigned(session, smb2Header, LogoffMessage.BuildResponseBody());
	}

	private ResponseSegment HandleEcho(SmbConnection connection, Smb2Header header, ReadOnlySpan<byte> segment, bool frameEncrypted)
	{
		EchoMessage.ValidateRequest(segment.Slice(64));
		SmbSession smbSession = null;
		if (header.SessionId != 0L)
		{
			if (!TryGetValidSession(connection, header.SessionId, out var session))
			{
				return BuildError(header, NtStatus.UserSessionDeleted);
			}

			smbSession = session;
			if (!VerifyInboundSignature(connection, smbSession, header, segment, frameEncrypted))
			{
				return BuildError(header, NtStatus.AccessDenied);
			}
		}

		var smb2Header = header.CreateResponse(NtStatus.Success);
		smb2Header.CreditRequestResponse = CreditManager.ComputeCreditGrant(header.CreditRequestResponse, _server.Options.MaxCreditsPerResponse);
		var body = EchoMessage.BuildResponseBody();
		if (smbSession == null || !smbSession.SigningRequired)
		{
			return ResponseSegment.Unsigned(smb2Header, body);
		}

		return ResponseSegment.Signed(smb2Header, body, smbSession);
	}

	private bool TryGetValidSession(SmbConnection connection, ulong sessionId, [MaybeNullWhen(false)] out SmbSession session)
	{
		if (connection.Sessions.TryGetValue(sessionId, out session) && session.State == SessionState.Valid)
		{
			session.LastActivityTicks = _server.Options.TimeProvider.GetUtcNow().Ticks;
			return true;
		}

		session = null!;
		return false;
	}

	private static bool VerifyInboundSignature(SmbConnection connection, SmbSession session, Smb2Header header, ReadOnlySpan<byte> segment, bool frameEncrypted)
	{
		if (frameEncrypted)
		{
			return true;
		}

		if (!session.SigningRequired)
		{
			return true;
		}

		if (!header.Flags.HasFlag(Smb2HeaderFlags.Signed))
		{
			return false;
		}

		return Smb2Signer.Verify(Smb2Signer.ResolveAlgorithm(connection.Dialect, connection.SigningAlgorithmId), isCancel: header.Command == SmbCommand.Cancel, signingKey: session.SigningKeyFor(connection), message: segment, messageId: header.MessageId, isServer: false);
	}

	private ResponseSegment SignIfRequestWasSigned(SmbConnection connection, Smb2Header request, ResponseSegment response)
	{
		if (response.Sign)
		{
			return response;
		}

		if (!request.Flags.HasFlag(Smb2HeaderFlags.Signed))
		{
			return response;
		}

		if (response.Header.Status == NtStatus.Pending && response.Header.Flags.HasFlag(Smb2HeaderFlags.AsyncCommand))
		{
			return response;
		}

		if (!TryGetValidSession(connection, request.SessionId, out var session))
		{
			return response;
		}

		return ResponseSegment.Signed(response.Header, response.Body, session, response.CreditsReserved);
	}

	private static ResponseSegment SignedLikeRequest(SmbSession session, Smb2Header request, Smb2Header response, byte[] body)
	{
		if (!session.SigningRequired && !request.Flags.HasFlag(Smb2HeaderFlags.Signed))
		{
			return ResponseSegment.Unsigned(response, body);
		}

		return ResponseSegment.Signed(response, body, session);
	}

	private ResponseSegment MaybeSigned(SmbSession session, Smb2Header header, byte[] body)
	{
		if (!session.SigningRequired)
		{
			return ResponseSegment.Unsigned(header, body);
		}

		return ResponseSegment.Signed(header, body, session);
	}

	private static ResponseSegment BuildError(Smb2Header request, NtStatus status)
	{
		return ResponseSegment.Unsigned(request.CreateResponse(status), ErrorResponse.BuildBody());
	}

	private static ResponseSegment BuildError(SmbConnection connection, Smb2Header request, NtStatus status, ReadOnlySpan<byte> errorData)
	{
		var header = request.CreateResponse(status);
		var body = ((connection.Dialect == SmbDialect.Smb311) ? ErrorResponse.BuildBodyWithContext(errorData) : ErrorResponse.BuildBody(errorData));
		return ResponseSegment.Unsigned(header, body);
	}

	private static async Task SendOutOfBandAsync(SmbSession session, SmbConnection? preferred, ResponseSegment segment, bool encrypt, bool useSurvivingChannel = false)
	{
		while (true)
		{
			var connection = session.SelectSendChannel(preferred);
			var send = connection?.SendRawAsync;
			if (send == null) throw new IOException("No active response transport.");

			var bytes = AssembleResponse(connection!, new List<ResponseSegment>(1) { segment });
			try
			{
				await send(bytes, encrypt).ConfigureAwait(false);
				return;
			}
			catch
			{
				connection!.ResponseSendFailed = true;
				connection.AbandonPending();
				connection.CancelOrdinary();
				connection.RequestClose?.Invoke();
				// Each failed transport is excluded by SelectSendChannel. A live bound
				// channel still owns the caching promise and must receive its break.
				if (!useSurvivingChannel || session.SelectSendChannel() == null) throw;
				preferred = null;
			}
		}
	}


	// Called exactly once before serialization. Async finals and unsolicited messages grant nothing.
	// Reserving before handing bytes to the ordered sender is safe: send failure tears down the connection.
	private static void ReserveResponseCredits(SmbConnection connection, Smb2Header header)
	{
		var noGrant = (header.IsAsync && header.Status != NtStatus.Pending) || header.MessageId == ulong.MaxValue;
		header.CreditRequestResponse = noGrant ? (ushort)0 : connection.Credits.Grant(header.CreditRequestResponse);
		if (connection.Credits.Exhausted) connection.MustTerminate = true;
	}

	private static byte[] AssembleResponse(SmbConnection connection, List<ResponseSegment> segments)
	{
		var growableWriter = new GrowableWriter();
		for (var i = 0; i < segments.Count; i++)
		{
			var responseSegment = segments[i];
			if (!responseSegment.CreditsReserved) ReserveResponseCredits(connection, responseSegment.Header);
			var flag = i == segments.Count - 1;
			var position = growableWriter.Position;
			var num = 64 + responseSegment.Body.Length;
			var num2 = (segments.Count > 1 ? Align8(num) : num);
			responseSegment.Header.NextCommand = ((!flag) ? ((uint)num2) : 0u);
			growableWriter.WriteBytes(responseSegment.Header.ToArray());
			growableWriter.WriteBytes(responseSegment.Body);
			if (num2 > num)
			{
				growableWriter.WriteZeros(num2 - num);
			}

			if (responseSegment.Sign)
			{
				var signingSession = responseSegment.SigningSession;
				var signingKey = responseSegment.SigningKey ?? (responseSegment.Header.Command == SmbCommand.SessionSetup && responseSegment.Header.Status != NtStatus.Success
					? signingSession?.SigningKey : signingSession?.SigningKeyFor(connection));
				if (signingKey != null)
				{
					var message = growableWriter.WrittenSpan.Slice(position, num2);
					var header = responseSegment.Header;
					header.Flags |= Smb2HeaderFlags.Signed;
					growableWriter.PatchUInt32(position + 16, (uint)header.Flags);
					Smb2Signer.SignInPlace(Smb2Signer.ResolveAlgorithm(connection.Dialect, connection.SigningAlgorithmId), signingKey, message, header.MessageId, isServer: true, isCancel: false);
				}
			}
		}

		return growableWriter.ToArray();
	}

	private static int Align8(int v)
	{
		return (v + 7) & -8;
	}

	private static byte[] Concat(byte[] a, byte[] b)
	{
		var array = new byte[a.Length + b.Length];
		a.CopyTo(array, 0);
		b.CopyTo(array, a.Length);
		return array;
	}

	private static byte[] Pad16(byte[] input)
	{
		var array = new byte[16];
		Array.Copy(input, array, Math.Min(16, input.Length));
		return array;
	}

	private bool TryGetFileStore(SmbSession session, uint treeId, [NotNullWhen(true)] out IFileStore? store, out NtStatus error)
	{
		store = null;
		error = NtStatus.Success;
		if (!session.TreeConnects.TryGetValue(treeId, out var value))
		{
			error = NtStatus.NetworkNameDeleted;
			return false;
		}

		if (value.Share.FileStore == null)
		{
			error = NtStatus.NotSupported;
			return false;
		}

		store = value.Share.FileStore;
		return true;
	}

	private bool TryGetOpen(SmbSession session, ulong persistent, ulong volatileId, out SmbOpen open)
	{
		return session.Opens.TryGetValue((persistent, volatileId), out open);
	}

	private bool HasOtherCacheOpen(SmbOpen open, bool sameLease) => _server.SessionGlobalList.Values.SelectMany(session => session.Opens.Values)
		.Any(other => other != open && other.IdentityKey == open.IdentityKey && (!sameLease || open.LeaseKey.IsZero || other.LeaseKey != open.LeaseKey || !other.Session!.Connection.ClientGuid.AsSpan().SequenceEqual(open.Session!.Connection.ClientGuid)));

	private async ValueTask<ResponseSegment?> HandleCreateAsync(SmbConnection connection, Smb2Header header, CommandRequest segment, bool frameEncrypted, bool standalone, CancellationToken cancellationToken = default)
	{
		if (!TryGetValidSession(connection, header.SessionId, out var session))
		{
			return BuildError(header, NtStatus.UserSessionDeleted);
		}

		if (!VerifyInboundSignature(connection, session, header, segment.Span, frameEncrypted))
		{
			return BuildError(header, NtStatus.AccessDenied);
		}

		if (!session.TreeConnects.TryGetValue(header.TreeId, out var tree))
		{
			return BuildError(header, NtStatus.NetworkNameDeleted);
		}

		using var treeOperation = tree.Lifetime.TryAcquire();
		if (treeOperation == null || session.Lifetime.State != OpenState.Active) return BuildError(header, NtStatus.NetworkNameDeleted);

		var request = CreateRequest.Parse(segment.ParsingSpan, 64);
		if (request.Contexts.Any(c => c.Name.AsSpan().SequenceEqual("SecD"u8)))
			return BuildError(header, NtStatus.NotSupported);
		var policy = _server.Options.FeaturePolicy;
		var contextStatus = policy.ValidateCreateContexts(request.Contexts, connection.Dialect);
		if (contextStatus != NtStatus.Success)
			return BuildError(header, contextStatus);
		if (!policy.AllowsShare(tree.Share))
			return BuildError(header, NtStatus.NotSupported);

		// Reconnect is never an ordinary pathname open. No retained or supplied record may
		// bypass the lifecycle gate, and no disabled reconnect may consume such a record.
		if (!policy.DurableHandles && (CreateContextList.Find(request.Contexts, 1145582147u) != null ||
			    CreateContextList.Find(request.Contexts, 1145597507u) != null))
			return BuildError(header, NtStatus.ObjectNameNotFound);

		if (tree.Share.Type == ShareType.Pipe)
		{
			return await HandlePipeCreateAsync(connection, header, session, tree, segment).ConfigureAwait(continueOnCapturedContext: false);
		}

		var store = tree.Share.FileStore;
		if (store == null)
		{
			return BuildError(header, NtStatus.NotSupported);
		}

		var createContext = CreateContextList.Find(request.Contexts, 1145582147u);
		if (createContext != null)
		{
			return await HandleDurableReconnectAsync(header, session, tree, request, createContext, true).ConfigureAwait(continueOnCapturedContext: false);
		}

		var createContext2 = CreateContextList.Find(request.Contexts, 1145597507u);
		if (createContext2 != null)
		{
			return await HandleDurableReconnectAsync(header, session, tree, request, createContext2, false).ConfigureAwait(continueOnCapturedContext: false);
		}

		var durableV2 = CreateContextList.Find(request.Contexts, 1145582161u);
		var replayKey = durableV2 != null && policy.SupportsDurable(connection.Dialect) &&
			_server.Options.DurableHandleStore is InMemoryDurableHandleStore && Caching.FileCacheCoordinator.Supports(store)
				? DurableHandleMessages.ParseV2Request(durableV2.Data)
				: (DurableHandleMessages.V2Request?)null;
		using var replay = replayKey.HasValue ? await _server.CreateReplays.EnterAsync(new Guid(connection.ClientGuid), replayKey.Value.CreateGuid, cancellationToken).ConfigureAwait(false) : null;
		if (replay?.Open is { IsReplayEligible: true } existing)
		{
			if (!header.Flags.HasFlag(Smb2HeaderFlags.ReplayOperation)) return BuildError(header, (NtStatus)0xc000022a);

			var leaseContext = CreateContextList.Find(request.Contexts, 1383156851u);
			if (!string.Equals(existing.DurableOwnerKey, OwnerKey(session.Identity), StringComparison.Ordinal) ||
			    existing.OplockLevel == OplockLevel.Lease && (leaseContext == null || LeaseRequest.FromContext(leaseContext).Key != existing.LeaseKey))
				return BuildError(header, NtStatus.AccessDenied);
			if ((existing.Session?.SessionId ?? existing.CreateSessionId) != session.SessionId) return BuildError(header, (NtStatus)0xc000022a);

			using var replayOperation = existing.Lifetime.TryAcquire();
			if (replayOperation == null) return BuildError(header, NtStatus.FileClosed);

			var contexts = new List<CreateContext> { DurableHandleMessages.BuildV2ResponseContext((uint)existing.DurableTimeout.TotalMilliseconds, false) };
			if (existing.OplockLevel == OplockLevel.Lease && leaseContext != null)
			{
				var leaseRequest = new LeaseRequest
				{
					Key = existing.LeaseKey, RequestedState = existing.LeaseState,
					IsV2 = existing.DurableLeaseV2, ParentKey = existing.ParentLeaseKey
				};
				contexts.Add(new CreateContext
				{
					Name = leaseContext.Name, Data = leaseRequest.SerializeResponse(existing.LeaseState, existing.LeaseEpoch,
						(_server.Options.CacheCoordinator.IsBreaking(existing) ? LeaseFlags.BreakInProgress : LeaseFlags.None) |
						(existing.DurableLeaseV2 && !existing.ParentLeaseKey.IsZero ? LeaseFlags.ParentLeaseKeySet : LeaseFlags.None))
				});
			}

			return MaybeSigned(session, RespHeader(header, session), await BuildRetainedCreateBodyAsync(existing, existing.VolatileFileId, existing.OriginalCreateAction, contexts).ConfigureAwait(false));
		}

		if ((request.ShareAccess & ~7u) != 0) return BuildError(header, NtStatus.InvalidParameter);
		if (request.Name.StartsWith('\\')) return BuildError(header, NtStatus.InvalidParameter);
		if (BinaryPrimitives.ReadUInt32LittleEndian(segment.ParsingSpan.Slice(68, 4)) > 3)
			return BuildError(header, (NtStatus)0xc00000a5);
		if (request.Name.EndsWith('\\'))
		{
			if (request.Options.HasFlag(CreateOptions.NonDirectoryFile)) return BuildError(header, NtStatus.ObjectNameInvalid);
		}
		// Validate ordinary file CREATE semantics before admission or backend mutation.
		// Named pipes above must ignore CreateDisposition (MS-SMB2 2.2.13).
		if ((uint)request.Disposition > (uint)CreateDisposition.OverwriteIf ||
			((uint)request.Options & 0xff000000u) != 0 || (request.FileAttributes & 0x48u) != 0)
			return BuildError(header, NtStatus.InvalidParameter);
		if (((uint)request.Options & 0x00102000u) != 0) return BuildError(header, NtStatus.NotSupported);
		if ((request.DesiredAccess & 0x0ce0fe00u) != 0) return BuildError(header, NtStatus.AccessDenied);
		if (request.Options.HasFlag(CreateOptions.DirectoryFile) &&
			(((uint)request.Options & ~0x00a1f533u) != 0 ||
			 request.Disposition is not (CreateDisposition.Open or CreateDisposition.Create or CreateDisposition.OpenIf)))
			return BuildError(header, NtStatus.InvalidParameter);

		if (tree.Share.IsDfs)
		{
			var dfsNamespace = _server.Options.DfsNamespace;
			if (dfsNamespace != null && dfsNamespace.IsLinkCovered(BuildDfsPath(tree.Share.Name, request.Name)))
			{
				return BuildError(header, NtStatus.PathNotCovered);
			}
		}

		var fileAccessIntent = MapAccess(tree.MaximalAccess);
		var maximumAllowed = (request.DesiredAccess & MaximumAllowed) != 0;
		var access = (maximumAllowed ? fileAccessIntent : MapAccess(request.DesiredAccess));
		if (!maximumAllowed && (access & ~fileAccessIntent) != 0)
		{
			return BuildError(header, NtStatus.AccessDenied);
		}

		var grantedAccess = (maximumAllowed ? tree.MaximalAccess : request.DesiredAccess);
		var disposition = (CreateDispositionIntent)request.Disposition;
		var dirRequired = request.Options.HasFlag(CreateOptions.DirectoryFile);
		var nonDirRequired = request.Options.HasFlag(CreateOptions.NonDirectoryFile);
		if (request.Name.IndexOf(':') is var colon && colon >= 0 && request.Name.IndexOfAny(['\\', '/'], colon) >= 0)
			return BuildError(header, NtStatus.ObjectNameInvalid);
		var flag = TrySplitStreamName(request.Name, out var baseName, out var streamName);
		if (flag && nonDirRequired && (baseName.EndsWith('\\') || baseName.EndsWith('/')))
			return BuildError(header, NtStatus.ObjectNameInvalid);
		var effectiveName = (flag ? baseName : request.Name.TrimEnd('\\'));
		if (effectiveName.IndexOfAny(['*', '?', '<', '>']) >= 0) return BuildError(header, NtStatus.ObjectNameInvalid);
		var namedStream = flag && streamName.Length > 0;
		if (flag)
		{
			if (request.Name.EndsWith(':')) return BuildError(header, NtStatus.ObjectNameInvalid);
			var suffix = request.Name[(request.Name.IndexOf(':', request.Name.LastIndexOf('\\') + 1) + 1)..];
			var typeIndex = suffix.IndexOf(':');
			if (typeIndex >= 0 && !suffix[(typeIndex + 1)..].Equals("$DATA", StringComparison.OrdinalIgnoreCase))
				return BuildError(header, NtStatus.ObjectNameInvalid);
		}
		if (flag && dirRequired) return BuildError(header, NtStatus.NotADirectory);
		if (namedStream && streamName.IndexOfAny(['/', '\\']) >= 0) return BuildError(header, NtStatus.ObjectNameInvalid);
		if (namedStream && !(store is INamedStreamStore))
		{
			return BuildError(header, NtStatus.NotSupported);
		}

		// A historical open must never silently fall back to the live namespace.
		var timewarp = request.Contexts.FirstOrDefault(c => c.Name.AsSpan().SequenceEqual("TWrp"u8));
		if (timewarp != null)
		{
			if (timewarp.Data.Length != 8) return BuildError(header, NtStatus.InvalidParameter);
			if (store is not ISnapshotStore) return BuildError(header, NtStatus.ObjectNameNotFound);
			DateTime snapshot;
			try { snapshot = DateTime.FromFileTimeUtc(BinaryPrimitives.ReadInt64LittleEndian(timewarp.Data)); }
			catch (ArgumentOutOfRangeException) { return BuildError(header, NtStatus.InvalidParameter); }
			effectiveName = GmtToken.Format(snapshot) + "\\" + effectiveName;
		}
		var symlinkResolver = store as ISymlinkResolver;
		if (!request.Options.HasFlag(CreateOptions.OpenReparsePoint) && symlinkResolver != null)
		{
			var symlinkTarget = await symlinkResolver.ResolveSymlinkAsync(effectiveName).ConfigureAwait(continueOnCapturedContext: false);
			if (symlinkTarget.HasValue)
			{
				var valueOrDefault = symlinkTarget.GetValueOrDefault();
				var array = SymlinkErrorResponse.Build(valueOrDefault.SubstituteName, valueOrDefault.PrintName ?? valueOrDefault.SubstituteName, valueOrDefault.UnparsedPathLength, valueOrDefault.IsRelative);
				return BuildError(connection, header, NtStatus.StoppedOnSymlink, array);
			}
		}

		using var admission = session.TryReserveOpen(_server.Options.MaxOpenHandlesPerSession);
		if (admission == null) return BuildError(header, NtStatus.InsufficientResources);

		var volatileFileId = session.AllocateFileId();
		var open = new SmbOpen
		{
			PersistentFileId = 0uL,
			ChannelSequences = new ChannelSequenceState(connection.Dialect >= SmbDialect.Smb300 ? header.ChannelSequence : (ushort)0),
			VolatileFileId = volatileFileId,
			Session = session,
			TreeConnect = tree,
			GrantedAccess = grantedAccess,
			ShareAccess = request.ShareAccess,
			CreateOptions = request.Options,
			PathName = request.Name,
		};
		if (connection.PendingRequests.TryGetValue(header.MessageId, out var cachePending)) cachePending.Owner = open;
		if (connection.OrdinaryRequests.TryGetValue(header.MessageId, out var cacheOrdinary)) cacheOrdinary.BindOwner(open);
		var committed = false;
		try
		{
			var requestedLeaseContext = CreateContextList.Find(request.Contexts, 1383156851u);
			LeaseRequest? cacheLease = null;
			if (policy.Leasing && connection.ServerCapabilities.HasFlag(Smb2Capabilities.Leasing) && connection.Dialect >= SmbDialect.Smb210 && request.RequestedOplockLevel == OplockLevel.Lease && requestedLeaseContext != null)
			{
				cacheLease = LeaseRequest.FromContext(requestedLeaseContext);
				if (cacheLease.IsV2 && !connection.Dialect.IsSmb3OrLater()) cacheLease = null;
				if (cacheLease != null) open.LeaseKey = cacheLease.Key;
			}

			var callerSids = BuildCallerSids(session.Identity);
			var desiredAccess = AccessMask.MapGenericToSpecific(request.DesiredAccess);
			grantedAccess = AccessMask.MapGenericToSpecific(grantedAccess);
			var shareAccess = AccessMask.MapGenericToSpecific(tree.MaximalAccess) & AccessMask.FileAllAccess;
			if (((desiredAccess & ~MaximumAllowed) & ~shareAccess) != 0) return BuildError(header, NtStatus.AccessDenied);
			FileAccessIntent? AuthorizeExisting(SecurityDescriptor descriptor, uint supportedAccess)
			{
				if (!AccessCheck.IsGranted(descriptor, callerSids, desiredAccess, out var grant)) return null;
				grant &= shareAccess & supportedAccess;
				if (((desiredAccess & ~MaximumAllowed) & ~grant) != 0 || maximumAllowed && grant == 0) return null;
				// These rights are required by the disposition even for MAXIMUM_ALLOWED.
				var required = disposition == CreateDispositionIntent.Supersede ? Delete :
					disposition is CreateDispositionIntent.Overwrite or CreateDispositionIntent.OverwriteIf ? FileWriteData : 0u;
				if (required != 0 && ((required & ~(shareAccess & supportedAccess)) != 0 ||
					!AccessCheck.IsGranted(descriptor, callerSids, required, out _))) return null;
				grantedAccess = grant;
				return MapAccess(grant);
			}
			bool AuthorizeParent(SecurityDescriptor descriptor, bool directory)
				=> AccessCheck.IsGranted(descriptor, callerSids, directory ? 4u : 2u, out _);
			using var coordination = await AcquireAuthorizedCreateAsync(store, effectiveName, namedStream ? streamName : "", open, access, cacheLease,
				disposition is CreateDispositionIntent.Overwrite or CreateDispositionIntent.OverwriteIf or CreateDispositionIntent.Supersede || request.Options.HasFlag(CreateOptions.DeleteOnClose),
				disposition, dirRequired, nonDirRequired, request.FileAttributes, AuthorizeExisting, AuthorizeParent, cancellationToken).ConfigureAwait(false);
			if (coordination.Status != NtStatus.Success) return BuildError(header, coordination.Status);
			var shareKey = open.ShareModeKey!;
			var fileStoreResult = coordination.Acquisition;
			var fileStoreResult2 = fileStoreResult;
			if (!fileStoreResult2.IsSuccess)
			{
				return BuildError(header, fileStoreResult2.Status);
			}

			var handle = fileStoreResult2.Value.Handle;
			var outcome = fileStoreResult2.Value.Action;
			open.LocalOpen = handle;
			cancellationToken.ThrowIfCancellationRequested();
			open.AdmissionIdentity = handle.Identity;
			if (store is IFileIdentityStore && handle.Identity is { } acquiredIdentity && acquiredIdentity.Key != shareKey)
			{
				if (!_server.Options.ShareModeManager.TryOpen(acquiredIdentity.Key, open, access, MapShare(request.ShareAccess))) return BuildError(header, NtStatus.SharingViolation);

				_server.Options.ShareModeManager.Close(shareKey, open);
				shareKey = acquiredIdentity.Key;
				open.ShareModeKey = shareKey;
			}

			open.GrantedAccess = grantedAccess;
			if (request.Options.HasFlag(CreateOptions.DeleteOnClose))
			{
				if (store is not ISharedDeleteFileStore) return BuildError(header, NtStatus.NotSupported);

				var delStatus = await store.SetDeleteOnCloseAsync(handle, delete: true).ConfigureAwait(continueOnCapturedContext: false);
				if (delStatus != NtStatus.Success)
				{
					return BuildError(header, delStatus);
				}

				open.DeleteOnClose = true;
			}


			var responseCtxList = new List<CreateContext>();
			_ = ArmedBreaks.None;
			var createContext3 = CreateContextList.Find(request.Contexts, 1383156851u);
			ArmedBreaks armed;
			OplockLevel grantedOplock;
			if (policy.Leasing && cacheLease != null && Caching.FileCacheCoordinator.Supports(store) && !handle.IsDirectory)
			{
				var leaseRequest = cacheLease;
				if (HasOtherCacheOpen(open, sameLease: true)) leaseRequest = new LeaseRequest { Key = cacheLease.Key, RequestedState = cacheLease.RequestedState & LeaseState.Read, IsV2 = cacheLease.IsV2, Epoch = cacheLease.Epoch, ParentKey = cacheLease.ParentKey, Flags = cacheLease.Flags };
				open.LeaseKey = leaseRequest.Key;
				open.ParentLeaseKey = leaseRequest.ParentKey;
				var leaseGrant = _server.Options.CacheCoordinator.RequestLease(open, leaseRequest);
				open.LeaseState = leaseGrant.GrantedState;
				open.LeaseEpoch = leaseGrant.Epoch;
				armed = ArmLeaseBreaks(leaseGrant.Breaks, track: true);
				grantedOplock = OplockLevel.Lease;
				responseCtxList.Add(new CreateContext
				{
					Name = createContext3!.Name,
					Data = leaseRequest.SerializeResponse(leaseGrant.GrantedState, leaseGrant.Epoch,
						(_server.Options.CacheCoordinator.IsBreaking(open) ? LeaseFlags.BreakInProgress : LeaseFlags.None)
						| (leaseRequest.IsV2 && leaseRequest.Flags.HasFlag(LeaseFlags.ParentLeaseKeySet) && !leaseRequest.ParentKey.IsZero ? LeaseFlags.ParentLeaseKeySet : LeaseFlags.None)),
				});
			}
			else
			{
				if (policy.Oplocks)
				{
					var requestedLevel = request.RequestedOplockLevel;
					if (requestedLevel is OplockLevel.Exclusive or OplockLevel.Batch && HasOtherCacheOpen(open, sameLease: false)) requestedLevel = OplockLevel.LevelII;
					var oplockGrant = _server.Options.CacheCoordinator.RequestOplock(open, requestedLevel);
					grantedOplock = oplockGrant.GrantedLevel;
					armed = ArmOplockBreaks(oplockGrant.Breaks, track: true);
				}
				else
				{
					grantedOplock = OplockLevel.None;
					armed = ArmedBreaks.None;
				}
			}

			open.OplockLevel = grantedOplock;
			var createContext4 = CreateContextList.Find(request.Contexts, 1145582161u);
			var createContext5 = CreateContextList.Find(request.Contexts, 1145597521u);
			if (policy.SupportsDurable(connection.Dialect) && _server.Options.DurableHandleStore is InMemoryDurableHandleStore &&
			    Caching.FileCacheCoordinator.Supports(store) && !handle.IsDirectory && handle.Identity != null && (createContext4 != null || createContext5 != null) && DurabilityAllowed(grantedOplock, open.LeaseState))
			{
				open.PersistentFileId = _server.AllocatePersistentId();
				open.IsDurable = true;
				open.DurableOwnerKey = OwnerKey(session.Identity);
				open.CreateSessionId = session.SessionId;
				open.OriginalCreateAction = (CreateAction)outcome;
				open.DurableShare = tree.Share;
				open.DurableClientGuid = new Guid(connection.ClientGuid);
				open.DurableIsV2 = createContext4 != null;
				open.DurableLeaseV2 = cacheLease?.IsV2 == true;
				if (createContext4 != null)
				{
					var v2Request = DurableHandleMessages.ParseV2Request(createContext4.Data);
					open.DurableCreateGuid = v2Request.CreateGuid;
					open.IsPersistentHandle = policy.PersistentHandles && v2Request.IsPersistent && tree.Share.ContinuousAvailability;
					open.DurableTimeout = ResolveDurableTimeout(v2Request.TimeoutMs);
					responseCtxList.Add(DurableHandleMessages.BuildV2ResponseContext((uint)open.DurableTimeout.TotalMilliseconds, open.IsPersistentHandle));
				}
				else
				{
					open.DurableTimeout = _server.Options.DurableHandleTimeout;
					responseCtxList.Add(DurableHandleMessages.BuildV1ResponseContext());
				}

				if (open.IsPersistentHandle && _server.Options.DurableHandleStore is IPersistentHandleStore persistentHandleStore)
				{
					persistentHandleStore.Persist(new PersistentHandleRecord(open.PersistentFileId, open.VolatileFileId, OwnerKey(session.Identity), open.DurableCreateGuid, tree.Share.Name, open.PathName, open.GrantedAccess, open.ShareAccess));
				}
			}

			if (outcome == CreateOutcome.Created && !namedStream)
			{
				BreakParentDirectoryLease(handle.PhysicalPath);
			}

			var response = MaybeSigned(session, RespHeader(header, session), await BuildCreateBodyAsync().ConfigureAwait(false));
			cancellationToken.ThrowIfCancellationRequested();
			if (tree.Lifetime.State != OpenState.Active || session.Lifetime.State != OpenState.Active) return BuildError(header, NtStatus.NetworkNameDeleted);

			// Potentially fallible observer work precedes publication.
			_server.Options.Metrics.OnHandleOpened();
			open.MetricCounted = true;
			Audit(SmbAuditEventType.FileOpened, SmbLogLevel.Information, connection, DescribeIdentity(session.Identity), tree.Share.Name, request.Name);
			open.Lifetime.Activate();
			Interlocked.Increment(ref tree.OpenCount);
			open.Counted = true;
			if (!session.Opens.TryAdd(open.Key, open)) return BuildError(header, NtStatus.InsufficientResources);

			open.IsReplayEligible = open.DurableIsV2 && (open.GrantedAccess & (1u | 2u | 4u | 0x20u | 0x10000u)) != 0;
			if (replay != null && open.IsReplayEligible) replay.Open = open;
			committed = true;
			return response;

			async ValueTask<byte[]> BuildCreateBodyAsync()
			{
				var responseContexts = ((responseCtxList.Count > 0) ? CreateContextList.Serialize(responseCtxList) : null);
				var fileEntryInfo = await handle.GetInfoAsync().ConfigureAwait(continueOnCapturedContext: false);
				return new CreateResponse
				{
					OplockLevel = grantedOplock,
					CreateAction = (CreateAction)outcome,
					CreationTime = fileEntryInfo.CreationTime,
					LastAccessTime = fileEntryInfo.LastAccessTime,
					LastWriteTime = fileEntryInfo.LastWriteTime,
					ChangeTime = fileEntryInfo.ChangeTime,
					AllocationSize = fileEntryInfo.AllocationSize,
					EndOfFile = fileEntryInfo.EndOfFile,
					FileAttributes = (uint)fileEntryInfo.Attributes,
					PersistentFileId = open.PersistentFileId,
					VolatileFileId = open.VolatileFileId,
				}.ToBody(responseContexts);
			}
		}
		finally
		{
			if (!committed) await CloseOpenAsync(open, CloseReason.FailedCreate).ConfigureAwait(false);
		}

	}


	private async ValueTask<CreateCoordination> AcquireAuthorizedCreateAsync(IFileStore store, string path, string stream, SmbOpen open,
		FileAccessIntent access, LeaseRequest? lease, bool destructive, CreateDispositionIntent disposition, bool directory, bool nonDirectory,
		uint attributes, Func<SecurityDescriptor, uint, FileAccessIntent?> authorizeExisting, Func<SecurityDescriptor, bool, bool> authorizeParent, CancellationToken token)
	{
		while (true)
		{
			var coordination = await AcquireCreateCoordinationAsync(store, path, stream, open, access, lease, destructive, token).ConfigureAwait(false);
			try
			{
				if (coordination.Status != NtStatus.Success) return coordination;
				token.ThrowIfCancellationRequested();
				coordination.Acquisition = await CreateAuthorizedAsync(store, path, stream, access, disposition, directory, nonDirectory, attributes,
					authorizeExisting, authorizeParent, identity => store is not IFileIdentityStore || identity == open.AdmissionIdentity, token).ConfigureAwait(false);
				if (store is not IAuthorizedCreateStore || coordination.Acquisition.Status != NtStatus.Retry) return coordination;
				// The backend saw a namespace change after coordination. Nothing has
				// mutated: release sharing/cache/lease admission before choosing the new key.
				_server.Options.ShareModeManager.Close(open.ShareModeKey!, open);
				open.ShareModeKey = null;
				coordination.Dispose();
			}
			catch { coordination.Dispose(); throw; }
		}
	}

	private static async ValueTask<FileStoreResult<FileCreateResult>> CreateAuthorizedAsync(IFileStore store, string path, string stream,
		FileAccessIntent access, CreateDispositionIntent disposition, bool directory, bool nonDirectory, uint attributes,
		Func<SecurityDescriptor, uint, FileAccessIntent?> authorizeExisting, Func<SecurityDescriptor, bool, bool> authorizeParent, Func<FileIdentity?, bool> validateIdentity, CancellationToken token)
	{
		if (store is IAuthorizedCreateStore guarded)
			return await guarded.CreateAuthorizedAsync(path, stream, access, disposition, directory, nonDirectory, attributes, authorizeExisting, authorizeParent, validateIdentity, token).ConfigureAwait(false);

		// Legacy stores retain ordinary nonmutating opens. A descriptor-aware store
		// must opt into the atomic contract before it may create/truncate anything;
		// separate GetSecurity/Create calls cannot close its policy/namespace race.
		var probe = stream.Length > 0 && disposition == CreateDispositionIntent.Open
			? await ((INamedStreamStore)store).OpenNamedStreamAsync(path, stream, access, disposition, token).ConfigureAwait(false)
			: await store.CreateAsync(path, access, CreateDispositionIntent.Open, directory, nonDirectory, token).ConfigureAwait(false);
		if (probe.IsSuccess)
		{
			var retain = false;
			try
			{
				if (stream.Length == 0 && disposition == CreateDispositionIntent.Create)
					return FileStoreResult<FileCreateResult>.Fail(NtStatus.ObjectNameCollision);
				var security = await store.GetSecurityAsync(probe.Value.Handle, token).ConfigureAwait(false);
				if (security.IsSuccess && !authorizeExisting(security.Value, uint.MaxValue).HasValue) return FileStoreResult<FileCreateResult>.Fail(NtStatus.AccessDenied);
				if (!security.IsSuccess && security.Status != NtStatus.NotSupported) return FileStoreResult<FileCreateResult>.Fail(security.Status);
				if (disposition == CreateDispositionIntent.Open || stream.Length == 0 && disposition == CreateDispositionIntent.OpenIf)
				{
					token.ThrowIfCancellationRequested();
					retain = true;
					return probe;
				}
				if (security.IsSuccess) return FileStoreResult<FileCreateResult>.Fail(NtStatus.NotSupported);
			}
			finally { if (!retain) await probe.Value.Handle.DisposeAsync().ConfigureAwait(false); }
		}
		else
		{
			if (probe.Status is not (NtStatus.ObjectNameNotFound or NtStatus.ObjectPathNotFound) ||
				disposition is CreateDispositionIntent.Open or CreateDispositionIntent.Overwrite) return probe;
			var normalized = path.Replace('\\', '/').TrimEnd('/');
			var slash = normalized.LastIndexOf('/');
			var parent = await store.CreateAsync(slash < 0 ? "" : normalized[..slash], FileAccessIntent.None, CreateDispositionIntent.Open, true, false, token).ConfigureAwait(false);
			if (!parent.IsSuccess) return FileStoreResult<FileCreateResult>.Fail(parent.Status == NtStatus.ObjectNameNotFound ? NtStatus.ObjectPathNotFound : parent.Status);
			await using var parentHandle = parent.Value.Handle;
			var security = await store.GetSecurityAsync(parentHandle, token).ConfigureAwait(false);
			if (security.IsSuccess) return FileStoreResult<FileCreateResult>.Fail(authorizeParent(security.Value, directory) ? NtStatus.NotSupported : NtStatus.AccessDenied);
			if (security.Status != NtStatus.NotSupported) return FileStoreResult<FileCreateResult>.Fail(security.Status);
		}
		token.ThrowIfCancellationRequested();
		// NOT_SUPPORTED from GetSecurity is the existing no-descriptor backend contract.
		return stream.Length > 0
			? await ((INamedStreamStore)store).OpenNamedStreamAsync(path, stream, access, disposition, token).ConfigureAwait(false)
			: store is ICreateMetadataStore metadata
				? await metadata.CreateWithMetadataAsync(path, access, disposition, directory, nonDirectory, attributes, token).ConfigureAwait(false)
				: await store.CreateAsync(path, access, disposition, directory, nonDirectory, token).ConfigureAwait(false);
	}

	private sealed class CreateCoordination : IDisposable
	{
		private int _disposed;
		internal KeyedAsyncLock<string>.Releaser? Namespace;
		internal IDisposable? Cache, LeaseReservation;
		internal NtStatus Status;
		internal FileStoreResult<FileCreateResult> Acquisition;
		public void Dispose()
		{
			if (Interlocked.Exchange(ref _disposed, 1) != 0) return;
			Cache?.Dispose();
			LeaseReservation?.Dispose();
			Namespace?.Dispose();
		}
	}

	private async ValueTask<CreateCoordination> AcquireCreateCoordinationAsync(IFileStore store, string path, string stream, SmbOpen open, FileAccessIntent access, LeaseRequest? lease, bool destructive, CancellationToken token)
	{
		while (true)
		{
			var coordination = new CreateCoordination();
			try
			{
				var admission = await AcquireCreateNamespaceAsync(store, path, stream, token).ConfigureAwait(false);
				coordination.Namespace = admission.Scope;
				if (store is IFileIdentityStore identities)
					open.AdmissionIdentity = await identities.ResolveIdentityAsync(path, stream, token).ConfigureAwait(false);
				if (!_server.Options.ShareModeManager.TryOpen(admission.Key, open, access, MapShare(open.ShareAccess)))
				{
					coordination.Status = NtStatus.SharingViolation;
					return coordination;
				}
				open.ShareModeKey = admission.Key;
				if (lease != null && Caching.FileCacheCoordinator.Supports(store))
				{
					coordination.LeaseReservation = _server.Options.CacheCoordinator.ReserveLease(open, lease.Key);
					if (coordination.LeaseReservation == null)
					{
						coordination.Status = NtStatus.InvalidParameter;
						return coordination;
					}
				}

				var cache = _server.Options.CacheCoordinator.AcquireCreateAsync(open, destructive, token);
				if (!cache.IsCompletedSuccessfully)
				{
					// The lease owner must be able to reopen its own key while a
					// conflicting CREATE awaits its ACK. Keep sharing reserved, but
					// release namespace serialization for the duration of that wait.
					coordination.Namespace.Value.Dispose();
					coordination.Namespace = null;
					coordination.Cache = await cache.ConfigureAwait(false);
					var resumed = await AcquireCreateNamespaceAsync(store, path, stream, token).ConfigureAwait(false);
					coordination.Namespace = resumed.Scope;
					if (resumed.Key != admission.Key)
					{
						// Rename/replacement may have changed the pathname while we
						// waited. Retire the old reservations and admit the new object.
						_server.Options.ShareModeManager.Close(admission.Key, open);
						open.ShareModeKey = null;
						coordination.Dispose();
						continue;
					}
				}
				else coordination.Cache = cache.Result;
				return coordination;
			}
			catch
			{
				coordination.Dispose();
				throw;
			}
		}
	}

	private static async ValueTask<(string Key, KeyedAsyncLock<string>.Releaser Scope)> AcquireCreateNamespaceAsync(IFileStore store, string path, string stream, CancellationToken token)
	{
		// A creator may publish an identity while we wait on the missing-name key.
		// Release before changing keys so opposite rename/create orders cannot deadlock.
		while (true)
		{
			token.ThrowIfCancellationRequested();
			var key = await ResolveShareKeyAsync(store, path, stream).ConfigureAwait(false);
			var scope = await NamespaceOperations.AcquireAsync(key, token).ConfigureAwait(false);
			try
			{
				if (await ResolveShareKeyAsync(store, path, stream).ConfigureAwait(false) == key) return (key, scope);
			}
			catch { scope.Dispose(); throw; }
			scope.Dispose();
		}
	}

	private async ValueTask<ResponseSegment> HandlePipeCreateAsync(SmbConnection connection, Smb2Header header, SmbSession session, SmbTreeConnect tree, CommandRequest segment)
	{
		var request = CreateRequest.Parse(segment.ParsingSpan, 64);
		if (request.DesiredAccess == 0 || (request.DesiredAccess & 0x0ce0fe00u) != 0) return BuildError(header, NtStatus.AccessDenied);
		var pipeName = request.Name.TrimStart('\\');
		var rpcEndpoint = await OpenRpcEndpointAsync(connection, session, pipeName).ConfigureAwait(continueOnCapturedContext: false);
		if (rpcEndpoint == null)
		{
			return BuildError(header, NtStatus.ObjectNameNotFound);
		}

		var pipe = new RpcPipe(rpcEndpoint);
		var volatileFileId = session.AllocateFileId();
		var smbOpen = new SmbOpen
		{
			PersistentFileId = 0uL,
			ChannelSequences = new ChannelSequenceState(connection.Dialect >= SmbDialect.Smb300 ? header.ChannelSequence : (ushort)0),
			VolatileFileId = volatileFileId,
			Session = session,
			TreeConnect = tree,
			Pipe = pipe,
			GrantedAccess = request.DesiredAccess,
			PathName = pipeName,
		};
		var createResponse = new CreateResponse
		{
			OplockLevel = OplockLevel.None,
			CreateAction = CreateAction.Opened,
			FileAttributes = 128u,
			PersistentFileId = smbOpen.PersistentFileId,
			VolatileFileId = smbOpen.VolatileFileId,
		};
		var response = MaybeSigned(session, RespHeader(header, session), createResponse.ToBody());
		var committed = false;
		try
		{
			using var admission = session.TryReserveOpen(_server.Options.MaxOpenHandlesPerSession);
			if (admission == null || tree.Lifetime.State != OpenState.Active) return BuildError(header, NtStatus.InsufficientResources);

			_server.Options.Metrics.OnHandleOpened();
			smbOpen.MetricCounted = true;
			smbOpen.Lifetime.Activate();
			Interlocked.Increment(ref tree.OpenCount);
			smbOpen.Counted = true;
			if (!session.Opens.TryAdd(smbOpen.Key, smbOpen)) return BuildError(header, NtStatus.InsufficientResources);

			committed = true;
			return response;
		}
		finally
		{
			if (!committed) await CloseOpenAsync(smbOpen, CloseReason.FailedCreate).ConfigureAwait(false);
		}
	}

	private async ValueTask<IRpcEndpoint?> OpenRpcEndpointAsync(SmbConnection connection, SmbSession session, string pipeName)
	{
		if (pipeName.Equals("srvsvc", StringComparison.OrdinalIgnoreCase))
		{
			var entries = new List<ShareEntry>();
			foreach (var item in await _server.GetVisibleSharesAsync(session.Identity ?? AnonymousIdentity, connection).ConfigureAwait(continueOnCapturedContext: false))
			{
				entries.Add(new ShareEntry(item.Name, SrvsvcEndpoint.MapStype(item.Type), item.Remark));
			}

			return new SrvsvcEndpoint(entries);
		}

		if (pipeName.Equals("witness", StringComparison.OrdinalIgnoreCase))
		{
			var serverName = _server.Options.ServerName;
			var nicProvider = _server.Options.NetworkInterfaceProvider;
			return new WitnessEndpoint(_server.WitnessRegistrations, connection.ConnectionId, () => WitnessEndpoint.FromNetworkInterfaces(serverName, nicProvider.GetInterfaces()));
		}

		return null;
	}

	private async ValueTask<ResponseSegment?> HandleIoctlAsync(SmbConnection connection, Smb2Header header, CommandRequest segment, bool frameEncrypted, CancellationToken cancellationToken = default)
	{
		if (!TryGetValidSession(connection, header.SessionId, out var session))
		{
			return BuildError(header, NtStatus.UserSessionDeleted);
		}

		if (!VerifyInboundSignature(connection, session, header, segment.Span, frameEncrypted))
		{
			return BuildError(header, NtStatus.AccessDenied);
		}

		var req = IoctlMessage.ParseRequest(segment.ParsingSpan, 64);
		if (req.Flags != IoctlMessage.FlagIsFsctl) return BuildError(header, NtStatus.NotSupported);
		var serverControl = CompoundExecutionContext.RequestFileIdOffset(SmbCommand.Ioctl, segment.ParsingSpan) < 0;
		if (serverControl && (req.PersistentId != ulong.MaxValue || req.VolatileId != ulong.MaxValue))
			return BuildError(header, NtStatus.InvalidParameter);
		if (!serverControl && !TryGetOpen(session, req.PersistentId, req.VolatileId, out _))
			return BuildError(header, NtStatus.FileClosed);
		if (!_server.Options.FeaturePolicy.AllowsIoctl(req.CtlCode))
			return BuildError(header, NtStatus.NotSupported);

		if (req.CtlCode == 1311236)
		{
			return HandleValidateNegotiate(connection, header, session, req);
		}

		if (req.CtlCode == 1311228)
		{
			return HandleQueryNetworkInterfaceInfo(connection, header, session, req);
		}

		if (req.CtlCode == 1163287 && TryGetOpen(session, req.PersistentId, req.VolatileId, out var open))
		{
			var pipe = open.Pipe;
			if (pipe != null)
			{
				if (pipe.Endpoint is WitnessEndpoint witnessEndpoint && witnessEndpoint.TryBeginAsyncNotify(req.Input, out var registration, out var callId))
				{
					return BeginWitnessAsyncNotify(connection, header, session, open, registration, callId, req.PersistentId, req.VolatileId, req.MaxOutputResponse);
				}

				pipe.Transceive(req.Input);
				var array = pipe.TakeOutput((int)Math.Min(req.MaxOutputResponse, int.MaxValue), out _, out var more);
				var response = RespHeader(header, session);
				if (more) response.Status = NtStatus.BufferOverflow;
				return MaybeSigned(session, response, IoctlMessage.BuildResponseBody(req.CtlCode, req.PersistentId, req.VolatileId, array));
			}
		}

		if (req.CtlCode == 1327204)
		{
			return HandleEnumerateSnapshots(header, session, req);
		}

		if (req.CtlCode == 1310840)
		{
			return HandleRequestResumeKey(header, session, req);
		}

		var ctlCode = req.CtlCode;
		if (ctlCode == 1327346 || ctlCode == 1343730)
		{
			return await HandleCopyChunkAsync(header, session, req, cancellationToken).ConfigureAwait(continueOnCapturedContext: false);
		}

		switch (req.CtlCode)
		{
			case 590020u:
			case 606415u:
			case 622792u:
				return await HandleSparseFsctlAsync(header, session, req).ConfigureAwait(continueOnCapturedContext: false);
			case 589988u:
			case 589992u:
			case 589996u:
				return await HandleReparseFsctlAsync(header, session, req).ConfigureAwait(continueOnCapturedContext: false);
			case 393620u:
			case 393648u:
				return HandleDfsGetReferrals(header, session, req);
			default:
				return BuildError(header, NtStatus.InvalidDeviceRequest);
		}
	}

	private ResponseSegment HandleRequestResumeKey(Smb2Header header, SmbSession session, IoctlMessage.Request req)
	{
		if (!TryGetOpen(session, req.PersistentId, req.VolatileId, out var open) || open.LocalOpen == null)
		{
			return BuildError(header, NtStatus.FileClosed);
		}

		if (req.MaxOutputResponse < 32) return BuildError(header, NtStatus.InvalidParameter);

		var smbOpen = open;
		byte[] array;
		lock (smbOpen.ResumeKeyGate) array = CopyChunkMessage.BuildResumeKeyResponse(smbOpen.ResumeKey ??= RandomNumberGenerator.GetBytes(24));
		return MaybeSigned(session, RespHeader(header, session), IoctlMessage.BuildResponseBody(req.CtlCode, req.PersistentId, req.VolatileId, array));
	}

	private async ValueTask<ResponseSegment> HandleCopyChunkAsync(Smb2Header header, SmbSession session, IoctlMessage.Request req, CancellationToken cancellationToken = default)
	{
		if (!TryGetOpen(session, req.PersistentId, req.VolatileId, out var dest) || dest.LocalOpen == null)
		{
			return BuildError(header, NtStatus.FileClosed);
		}

		if (!TryGetFileStore(session, header.TreeId, out var destStore, out var error))
		{
			return BuildError(header, error);
		}

		if ((dest.GrantedAccess & FileWriteData) == 0 || req.CtlCode == 0x1440f2u && (dest.GrantedAccess & FileReadData) == 0)
		{
			return BuildError(header, NtStatus.AccessDenied);
		}

		if (req.MaxOutputResponse < 12) return BuildError(header, NtStatus.InvalidParameter);

		CopyChunkMessage.CopyRequest copyRequest;
		try { copyRequest = CopyChunkMessage.ParseCopyRequest(req.Input); }
		catch (SmbWireFormatException)
		{
			var response = RespHeader(header, session);
			response.Status = NtStatus.InvalidParameter;
			return MaybeSigned(session, response, IoctlMessage.BuildResponseBody(req.CtlCode, req.PersistentId, req.VolatileId, CopyChunkMessage.BuildLimitExceededResponse()));
		}

		if (!TryFindOpenByResumeKey(session, copyRequest.SourceKey, out var source) || source.LocalOpen == null)
		{
			return BuildError(header, NtStatus.ObjectNameNotFound);
		}

		if ((source.GrantedAccess & FileReadData) == 0)
		{
			return BuildError(header, NtStatus.AccessDenied);
		}

		var sourceStore = source.TreeConnect!.Share.FileStore;
		if (sourceStore == null)
		{
			return BuildError(header, NtStatus.ObjectNameNotFound);
		}

		if (!ValidateCopyLimits(copyRequest.Chunks))
		{
			var smb2Header = RespHeader(header, session);
			smb2Header.Status = NtStatus.InvalidParameter;
			return MaybeSigned(session, smb2Header, IoctlMessage.BuildResponseBody(req.CtlCode, req.PersistentId, req.VolatileId, CopyChunkMessage.BuildLimitExceededResponse()));
		}


		using var sourceReference = source.Lifetime.TryAcquire();
		if (sourceReference == null || source.TreeConnect!.Lifetime.State != OpenState.Active)
			return BuildError(header, NtStatus.ObjectNameNotFound);

		// Append offsets depend on writes flushed in response to the break. Revoke first,
		// then sample EOF and resolve the physical ranges for locks and the custom hook.
		var admissionRanges = copyRequest.Chunks.SelectMany(c => new[] { new FileIoRange(source, c.SourceOffset, c.Length, false), new FileIoRange(dest, c.TargetOffset == ulong.MaxValue ? 0 : c.TargetOffset, c.TargetOffset == ulong.MaxValue ? ulong.MaxValue : c.Length, true) }).ToArray();
		using var cacheScope = await _server.Options.CacheCoordinator.AcquireAsync(admissionRanges, cancellationToken).ConfigureAwait(false);
		var chunks = new List<CopyChunkMessage.Chunk>();
		var end = (ulong)(await dest.LocalOpen.GetInfoAsync().ConfigureAwait(false)).EndOfFile;
		foreach (var chunk in copyRequest.Chunks)
		{
			var target = chunk.TargetOffset == ulong.MaxValue ? end : chunk.TargetOffset;
			if (target > (ulong)long.MaxValue - chunk.Length) return Result(NtStatus.InvalidParameter, CopyChunkMessage.MaxChunks, CopyChunkMessage.MaxChunkSize, CopyChunkMessage.MaxTotalSize);

			chunks.Add(chunk with { TargetOffset = target });
			end = Math.Max(end, target + chunk.Length);
		}

		var ranges = chunks.SelectMany(c => new[] { new FileIoRange(source, c.SourceOffset, c.Length, false), new FileIoRange(dest, c.TargetOffset, c.Length, true) }).ToArray();
		using var coherence = _server.Options.FileIoCoordinator == null ? null : await _server.Options.FileIoCoordinator.AcquireAsync(ranges, cancellationToken).ConfigureAwait(false);
		// Check every range before the first mutation, including conflicts on later chunks.
		foreach (var range in ranges)
			if (!_server.Options.LockManager.IsRangeAccessible(range.Open, range.Offset, range.Length, range.ForWrite))
				return Result(NtStatus.FileLockConflict, 0, 0, 0);

		uint chunksWritten = 0, totalWritten = 0;
		foreach (var chunk in chunks)
		{
			var result = await CopyRangeAsync(sourceStore, source.LocalOpen, (long)chunk.SourceOffset, destStore, dest.LocalOpen, (long)chunk.TargetOffset, chunk.Length).ConfigureAwait(false);
			totalWritten += result.Written;
			if (result.Status != NtStatus.Success) return Result(result.Status, chunksWritten, result.Written, totalWritten);

			chunksWritten++;
		}

		return Result(NtStatus.Success, chunksWritten, 0, totalWritten);

		ResponseSegment Result(NtStatus status, uint chunks, uint partial, uint total)
		{
			var response = RespHeader(header, session);
			response.Status = status;
			return MaybeSigned(session, response, IoctlMessage.BuildResponseBody(req.CtlCode, req.PersistentId, req.VolatileId, CopyChunkMessage.BuildCopyResponse(chunks, partial, total)));
		}
	}

	private static bool ValidateCopyLimits(IReadOnlyList<CopyChunkMessage.Chunk> chunks)
	{
		if (chunks.Count > 16L)
		{
			return false;
		}

		var num = 0uL;
		foreach (var chunk in chunks)
		{
			if (chunk.Length == 0 || chunk.Length > 1048576 || chunk.SourceOffset > (ulong)long.MaxValue - chunk.Length || chunk.TargetOffset != ulong.MaxValue && chunk.TargetOffset > (ulong)long.MaxValue - chunk.Length)
			{
				return false;
			}

			num += chunk.Length;
		}

		return num <= 16777216;
	}

	private static bool TryFindOpenByResumeKey(SmbSession session, byte[] sourceKey, [NotNullWhen(true)] out SmbOpen? match)
	{
		foreach (var value in session.Opens.Values)
		{
			var resumeKey = value.ResumeKey;
			if (resumeKey != null && resumeKey.AsSpan().SequenceEqual(sourceKey))
			{
				match = value;
				return true;
			}
		}

		match = null;
		return false;
	}


	private static async ValueTask<(NtStatus Status, uint Written)> CopyRangeAsync(IFileStore sourceStore, IFileHandle source, long sourceOffset, IFileStore destStore, IFileHandle destination, long destOffset, uint length)
	{
		// At most MaxChunkSize (1 MiB). Snapshot one chunk before writing so same-object
		// overlaps cannot overwrite bytes still to be read. Chunk ordering remains on-wire order.
		uint written = 0;
		try
		{
			var buffer = new byte[length];
			var readCount = 0;
			while (readCount < buffer.Length)
			{
				var read = await sourceStore.ReadAsync(source, sourceOffset + readCount, buffer.AsMemory(readCount)).ConfigureAwait(false);
				if (!read.IsSuccess) return (read.Status, 0);
				if (read.Value <= 0 || read.Value > buffer.Length - readCount) return (NtStatus.EndOfFile, 0);

				readCount += read.Value;
			}

			while (written < length)
			{
				var result = await destStore.WriteAsync(destination, destOffset + written, buffer.AsMemory((int)written)).ConfigureAwait(false);
				if (!result.IsSuccess) return (result.Status, written);
				if (result.Value <= 0 || result.Value > length - written) return (NtStatus.DiskFull, written);

				written += (uint)result.Value;
			}

			return (NtStatus.Success, written);
		}
		catch (Exception ex) { return (MapException(ex), written); }

	}

	private async ValueTask<ResponseSegment> HandleSparseFsctlAsync(Smb2Header header, SmbSession session, IoctlMessage.Request req)
	{
		if (!TryGetOpen(session, req.PersistentId, req.VolatileId, out var open) || open.LocalOpen == null)
		{
			return BuildError(header, NtStatus.FileClosed);
		}

		if (!(open.TreeConnect!.Share.FileStore is ISparseFileStore sparseFileStore))
		{
			return BuildError(header, NtStatus.NotSupported);
		}

		switch (req.CtlCode)
		{
			case 590020u:
			{
				if ((open.GrantedAccess & 6) == 0)
				{
					return BuildError(header, NtStatus.AccessDenied);
				}

				var status2 = await sparseFileStore.SetSparseAsync(open.LocalOpen, FsctlMessage.ParseSetSparse(req.Input)).ConfigureAwait(continueOnCapturedContext: false);
				return IoctlResult(header, session, req, status2, default);
			}
			case 622792u:
			{
				if ((open.GrantedAccess & 6) == 0)
				{
					return BuildError(header, NtStatus.AccessDenied);
				}

				var fileRange2 = FsctlMessage.ParseZeroData(req.Input);
				var status = await sparseFileStore.SetZeroDataAsync(open.LocalOpen, fileRange2.Offset, fileRange2.Length).ConfigureAwait(continueOnCapturedContext: false);
				return IoctlResult(header, session, req, status, default);
			}
			default:
			{
				if ((open.GrantedAccess & FileReadData) == 0)
				{
					return BuildError(header, NtStatus.AccessDenied);
				}

				var fileRange = FsctlMessage.ParseAllocatedRangeQuery(req.Input);
				var fileStoreResult = await sparseFileStore.QueryAllocatedRangesAsync(open.LocalOpen, fileRange.Offset, fileRange.Length).ConfigureAwait(continueOnCapturedContext: false);
				if (!fileStoreResult.IsSuccess)
				{
					return BuildError(header, fileStoreResult.Status);
				}

				var array = FsctlMessage.BuildAllocatedRanges(fileStoreResult.Value);
				if (req.MaxOutputResponse < 16 && array.Length != 0) return BuildError(header, NtStatus.BufferTooSmall);

				var count = Math.Min(array.Length, (int)(req.MaxOutputResponse / 16) * 16);
				var response = RespHeader(header, session);
				if (count < array.Length) response.Status = NtStatus.BufferOverflow;
				return MaybeSigned(session, response, IoctlMessage.BuildResponseBody(req.CtlCode, req.PersistentId, req.VolatileId, array.AsSpan(0, count)));
			}
		}
	}

	private async ValueTask<ResponseSegment> HandleReparseFsctlAsync(Smb2Header header, SmbSession session, IoctlMessage.Request req)
	{
		if (!TryGetOpen(session, req.PersistentId, req.VolatileId, out var open) || open.LocalOpen == null)
		{
			return BuildError(header, NtStatus.FileClosed);
		}

		var reparsePointStore = open.TreeConnect!.Share.FileStore as IReparsePointStore;
		if (req.CtlCode == 589992)
		{
			if (reparsePointStore == null)
			{
				return BuildError(header, NtStatus.NotAReparsePoint);
			}

			var fileStoreResult = await reparsePointStore.GetReparsePointAsync(open.LocalOpen).ConfigureAwait(continueOnCapturedContext: false);
			if (!fileStoreResult.IsSuccess)
			{
				return BuildError(header, fileStoreResult.Status);
			}

			var value = fileStoreResult.Value;
			var fixedSize = value.Length >= 4 && (BinaryPrimitives.ReadUInt32LittleEndian(value) & 0x80000000) == 0 ? 24 : 8;
			if (req.MaxOutputResponse < fixedSize) return BuildError(header, NtStatus.BufferTooSmall);

			var count = (int)Math.Min((uint)value.Length, req.MaxOutputResponse);
			var response = RespHeader(header, session);
			if (count < value.Length) response.Status = NtStatus.BufferOverflow;
			return MaybeSigned(session, response, IoctlMessage.BuildResponseBody(req.CtlCode, req.PersistentId, req.VolatileId, value.AsSpan(0, count)));
		}

		if (reparsePointStore == null)
		{
			return BuildError(header, NtStatus.NotSupported);
		}

		if ((open.GrantedAccess & 6) == 0)
		{
			return BuildError(header, NtStatus.AccessDenied);
		}

		var ntStatus = ((req.CtlCode != 589988) ? (await reparsePointStore.DeleteReparsePointAsync(open.LocalOpen, req.Input).ConfigureAwait(continueOnCapturedContext: false)) : (await reparsePointStore.SetReparsePointAsync(open.LocalOpen, req.Input).ConfigureAwait(continueOnCapturedContext: false)));
		var status = ntStatus;
		return IoctlResult(header, session, req, status, default);
	}

	private ResponseSegment? HandleValidateNegotiate(SmbConnection connection, Smb2Header header, SmbSession session, IoctlMessage.Request req)
	{
		if (connection.Dialect == SmbDialect.Smb311 || req.MaxOutputResponse < 24)
		{
			connection.MustTerminate = true;
			return null;
		}
		var validateNegotiateRequest = IoctlMessage.ParseValidateNegotiate(req.Input);
		var num = PickDialect(validateNegotiateRequest.Dialects);
		if (connection.ClientCapabilities != (Smb2Capabilities)validateNegotiateRequest.Capabilities || !connection.ClientGuid.AsSpan().SequenceEqual(validateNegotiateRequest.Guid) || (uint)connection.ClientSecurityMode != validateNegotiateRequest.SecurityMode || num != (uint)connection.Dialect)
		{
			_log?.Invoke($"[validate-negotiate] mismatch on conn {connection.ConnectionId:N} → terminating");
			connection.MustTerminate = true;
			return null;
		}

		var array = IoctlMessage.BuildValidateNegotiateResponse((uint)connection.ServerCapabilities, _server.Options.ServerGuid, (ushort)connection.ServerSecurityMode, (ushort)connection.Dialect);
		return MaybeSigned(session, RespHeader(header, session), IoctlMessage.BuildResponseBody(req.CtlCode, req.PersistentId, req.VolatileId, array));
	}

	private ResponseSegment HandleQueryNetworkInterfaceInfo(SmbConnection connection, Smb2Header header, SmbSession session, IoctlMessage.Request req)
	{
		if (!_server.Options.FeaturePolicy.SupportsMultichannel(connection.Dialect) || !_server.Options.EnableMultichannel)
		{
			return BuildError(header, NtStatus.NotSupported);
		}

		var array = NetworkInterfaceInfoMessage.Build(_server.Options.NetworkInterfaceProvider.GetInterfaces());
		if (array.Length > req.MaxOutputResponse)
		{
			return BuildError(header, NtStatus.BufferTooSmall);
		}

		return MaybeSigned(session, RespHeader(header, session), IoctlMessage.BuildResponseBody(req.CtlCode, req.PersistentId, req.VolatileId, array));
	}

	private ResponseSegment HandleDfsGetReferrals(Smb2Header header, SmbSession session, IoctlMessage.Request req)
	{
		var dfsNamespace = _server.Options.DfsNamespace;
		if (dfsNamespace == null)
		{
			return BuildError(header, NtStatus.NotFound);
		}

		var result = dfsNamespace.Resolve(((req.CtlCode == 393648) ? DfsReferralMessage.ParseRequestEx(req.Input) : DfsReferralMessage.ParseRequest(req.Input)).RequestFileName);
		if (result == null || result.Targets.Count == 0)
		{
			return BuildError(header, NtStatus.NotFound);
		}

		var serverType = (result.IsRootReferral ? ((ushort)1) : ((ushort)0));
		var entries = result.Targets.Select(t => new DfsReferralMessage.ReferralEntry
		{
			DfsPath = result.ConsumedPath,
			TargetPath = t.TargetPath,
			TimeToLive = result.TimeToLiveSeconds,
			ServerType = serverType,
		}).ToList();
		var headerFlags = (result.IsRootReferral ? 1u : 2u);
		var array = DfsReferralMessage.BuildResponse((ushort)(result.ConsumedPath.Length * 2), headerFlags, entries);
		if (array.Length > req.MaxOutputResponse)
		{
			return BuildError(header, NtStatus.BufferTooSmall);
		}

		return MaybeSigned(session, RespHeader(header, session), IoctlMessage.BuildResponseBody(req.CtlCode, req.PersistentId, req.VolatileId, array));
	}

	private string BuildDfsPath(string shareName, string relativeName)
	{
		var text = relativeName.Replace('/', '\\').Trim('\\');
		var text2 = "\\" + _server.Options.ServerName + "\\" + shareName;
		if (text.Length != 0)
		{
			return text2 + "\\" + text;
		}

		return text2;
	}

	private static ushort PickDialect(ushort[] offered)
	{
		ushort num = 0;
		foreach (var num2 in offered)
		{
			if (Array.IndexOf(SupportedDialects, num2) >= 0 && num2 > num)
			{
				num = num2;
			}
		}

		return num;
	}

	private ResponseSegment IoctlResult(Smb2Header header, SmbSession session, IoctlMessage.Request req, NtStatus status, ReadOnlySpan<byte> output)
	{
		if (status != NtStatus.Success)
		{
			return BuildError(header, status);
		}

		return MaybeSigned(session, RespHeader(header, session), IoctlMessage.BuildResponseBody(req.CtlCode, req.PersistentId, req.VolatileId, output));
	}

	private ResponseSegment HandleEnumerateSnapshots(Smb2Header header, SmbSession session, IoctlMessage.Request req)
	{
		if (req.MaxOutputResponse < 16) return BuildError(header, NtStatus.InvalidParameter);

		if (!session.TreeConnects.TryGetValue(header.TreeId, out var value) || !(value.Share.FileStore is ISnapshotStore snapshotStore))
		{
			return BuildError(header, NtStatus.InvalidDeviceRequest);
		}

		var path = (TryGetOpen(session, req.PersistentId, req.VolatileId, out var open) ? open.PathName : string.Empty);
		var snapshots = snapshotStore.GetSnapshots(path);
		var list = new List<string>(snapshots.Count);
		foreach (var item in snapshots)
		{
			list.Add(GmtToken.Format(item));
		}

		var array = IoctlMessage.BuildEnumerateSnapshotsResponse(list, req.MaxOutputResponse);
		return MaybeSigned(session, RespHeader(header, session), IoctlMessage.BuildResponseBody(req.CtlCode, req.PersistentId, req.VolatileId, array));
	}

	private async ValueTask<ResponseSegment> HandleCloseAsync(SmbConnection connection, Smb2Header header, CommandRequest segment, bool frameEncrypted)
	{
		if (!TryGetValidSession(connection, header.SessionId, out var session))
		{
			return BuildError(header, NtStatus.UserSessionDeleted);
		}

		if (!VerifyInboundSignature(connection, session, header, segment.Span, frameEncrypted))
		{
			return BuildError(header, NtStatus.AccessDenied);
		}

		if (!session.TreeConnects.ContainsKey(header.TreeId)) return BuildError(header, NtStatus.NetworkNameDeleted);

		var (num, persistent, volatileId) = CloseMessage.ParseRequest(segment.ParsingSpan, 64);
		if (!TryGetOpen(session, persistent, volatileId, out var open))
		{
			return BuildError(header, NtStatus.FileClosed);
		}

		FileEntryInfo info = null;
		NtStatus closeStatus;
		try
		{
			// Metadata is sampled with an operation reference before closing admission.
			using var reference = open.Lifetime.TryAcquire();
			if (reference != null && (num & 1) != 0 && open.LocalOpen != null) info = await open.LocalOpen.GetInfoAsync().ConfigureAwait(false);
		}
		finally { closeStatus = await CloseOpenAsync(open, CloseReason.ExplicitClose).ConfigureAwait(false); }

		if (closeStatus != NtStatus.Success) return BuildError(header, closeStatus);

		var body = ((info == null) ? CloseMessage.BuildResponseBody(postQuery: false) : CloseMessage.BuildResponseBody(postQuery: true, new FileTimes(info.CreationTime, info.LastAccessTime, info.LastWriteTime, info.ChangeTime), info.AllocationSize, info.EndOfFile, (uint)info.Attributes));
		return MaybeSigned(session, RespHeader(header, session), body);
	}

	private async ValueTask<ResponseSegment> HandleReadAsync(SmbConnection connection, Smb2Header header, CommandRequest segment, bool frameEncrypted, CancellationToken cancellationToken)
	{
		if (!TryGetValidSession(connection, header.SessionId, out var session))
		{
			return BuildError(header, NtStatus.UserSessionDeleted);
		}

		if (!VerifyInboundSignature(connection, session, header, segment.Span, frameEncrypted))
		{
			return BuildError(header, NtStatus.AccessDenied);
		}

		var request = ReadMessage.ParseRequest(segment.ParsingSpan, 64);
		if (request.Length > connection.MaxReadSize) return BuildError(header, NtStatus.InvalidParameter);
		if (connection.Dialect >= SmbDialect.Smb300 && request.Channel != 0) return BuildError(header, NtStatus.InvalidParameter);

		if (!TryGetOpen(session, request.PersistentId, request.VolatileId, out var open))
		{
			return BuildError(header, NtStatus.FileClosed);
		}

		var pipe = open.Pipe;
		if (pipe != null && connection.Dialect >= SmbDialect.Smb302 && (request.Flags & 1) != 0)
			return BuildError(header, NtStatus.InvalidParameter);

		if (pipe != null)
		{
			var data = pipe.TakeOutput((int)request.Length, out _, out var more);
			if (data.Length < request.MinimumCount) return BuildError(header, NtStatus.EndOfFile);

			var response = RespHeader(header, session);
			if (more) response.Status = NtStatus.BufferOverflow;
			return MaybeSigned(session, response, ReadMessage.BuildResponseBody(data));
		}

		if (!TryGetFileStore(session, header.TreeId, out var store, out var error) || open.LocalOpen == null)
		{
			return BuildError(header, (error == NtStatus.Success) ? NtStatus.FileClosed : error);
		}

		if ((open.GrantedAccess & (FileReadData | 0x20u)) == 0)
		{
			return BuildError(header, NtStatus.AccessDenied);
		}
		if (open.LocalOpen.IsDirectory) return BuildError(header, NtStatus.InvalidDeviceRequest);

		if (request.Offset > long.MaxValue || request.Length > (ulong)long.MaxValue - request.Offset)
			return BuildError(header, NtStatus.InvalidParameter);
		var length = Math.Min(request.Length, connection.MaxReadSize);
		using var cacheScope = await _server.Options.CacheCoordinator.AcquireAsync([new FileIoRange(open, request.Offset, length, false)], cancellationToken).ConfigureAwait(false);
		using var coherence = _server.Options.FileIoCoordinator == null ? null : await _server.Options.FileIoCoordinator.AcquireAsync([new FileIoRange(open, request.Offset, length, false)], cancellationToken).ConfigureAwait(false);
		if (!_server.Options.LockManager.IsRangeAccessible(open, request.Offset, length, forWrite: false))
		{
			_server.Options.Metrics.OnLockContention();
			return BuildError(header, NtStatus.FileLockConflict);
		}

		var buffer = new byte[length];
		var fileStoreResult = await store.ReadWithOptionsAsync(open.LocalOpen, (long)request.Offset, buffer, new FileIoOptions(Unbuffered: connection.Dialect >= SmbDialect.Smb302 && (request.Flags & 1) != 0, RemainingBytes: request.RemainingBytes), cancellationToken).ConfigureAwait(continueOnCapturedContext: false);
		if (!fileStoreResult.IsSuccess)
		{
			return BuildError(header, fileStoreResult.Status);
		}

		if (fileStoreResult.Value < request.MinimumCount || fileStoreResult.Value == 0 && length != 0)
		{
			return BuildError(header, NtStatus.EndOfFile);
		}

		_server.Options.Metrics.OnBytesRead(open.TreeConnect!.Share.Name, fileStoreResult.Value);
		return MaybeSigned(session, RespHeader(header, session), ReadMessage.BuildResponseBody(buffer.AsSpan(0, fileStoreResult.Value)));
	}

	private async ValueTask<ResponseSegment> HandleWriteAsync(SmbConnection connection, Smb2Header header, CommandRequest segment, bool frameEncrypted, CancellationToken cancellationToken)
	{
		if (!TryGetValidSession(connection, header.SessionId, out var session))
		{
			return BuildError(header, NtStatus.UserSessionDeleted);
		}

		if (!VerifyInboundSignature(connection, session, header, segment.Span, frameEncrypted))
		{
			return BuildError(header, NtStatus.AccessDenied);
		}

		var req = WriteMessage.ParseRequest(segment.ParsingSpan, 64);
		if ((uint)req.Data.Length > connection.MaxWriteSize) return BuildError(header, NtStatus.InvalidParameter);
		if (connection.Dialect >= SmbDialect.Smb300 && req.Channel != 0) return BuildError(header, NtStatus.InvalidParameter);

		if (!TryGetOpen(session, req.PersistentId, req.VolatileId, out var open))
		{
			return BuildError(header, NtStatus.FileClosed);
		}

		if (req.Channel == 0 && req.DataOffset > 256) return BuildError(header, NtStatus.InvalidParameter);

		var through = connection.Dialect != SmbDialect.Smb202 && (req.Flags & 1) != 0;
		var unbuffered = connection.Dialect >= SmbDialect.Smb302 && (req.Flags & 2) != 0;
		var pipe = open.Pipe;
		if (pipe != null && connection.Dialect >= SmbDialect.Smb300 && (req.Flags & 3) != 0)
			return BuildError(header, NtStatus.InvalidParameter);
		if (through && !unbuffered && ((uint)open.CreateOptions & 8) == 0)
			return BuildError(header, NtStatus.InvalidParameter);

		if (pipe != null)
		{
			pipe.Transceive(req.Data);
			return MaybeSigned(session, RespHeader(header, session), WriteMessage.BuildResponseBody((uint)req.Data.Length));
		}

		if (!TryGetFileStore(session, header.TreeId, out var store, out var error) || open.LocalOpen == null)
		{
			return BuildError(header, (error == NtStatus.Success) ? NtStatus.FileClosed : error);
		}

		if ((open.GrantedAccess & 6) == 0)
		{
			return BuildError(header, NtStatus.AccessDenied);
		}

		if (req.Offset == ulong.MaxValue)
			req = req with { Offset = (ulong)(await open.LocalOpen.GetInfoAsync().ConfigureAwait(false)).EndOfFile };
		if (req.Offset > long.MaxValue || (ulong)req.Data.Length > (ulong)long.MaxValue - req.Offset)
			return BuildError(header, NtStatus.InvalidParameter);

		using var cacheScope = await _server.Options.CacheCoordinator.AcquireAsync([new FileIoRange(open, req.Offset, (ulong)req.Data.Length, true)], cancellationToken).ConfigureAwait(false);
		using var coherence = _server.Options.FileIoCoordinator == null ? null : await _server.Options.FileIoCoordinator.AcquireAsync([new FileIoRange(open, req.Offset, (ulong)req.Data.Length, true)], cancellationToken).ConfigureAwait(false);
		if (!_server.Options.LockManager.IsRangeAccessible(open, req.Offset, (ulong)req.Data.Length, forWrite: true))
		{
			_server.Options.Metrics.OnLockContention();
			return BuildError(header, NtStatus.FileLockConflict);
		}

		var quota = _server.Options.QuotaProvider;
		var quotaShare = open.TreeConnect!.Share;
		var quotaReserved = 0L;
		Sid quotaOwner = null;
		if (quota.IsSupported && Sid.TryParse(session.Identity?.UserSid, out var owner))
		{
			quotaOwner = owner;
			var endOfFile = ToStat(await open.LocalOpen.GetInfoAsync().ConfigureAwait(continueOnCapturedContext: false)).EndOfFile;
			var num = (long)req.Offset + req.Data.Length;
			quotaReserved = Math.Max(0L, num - endOfFile);
			if (quotaReserved > 0 && !quota.TryReserve(quotaShare, owner, quotaReserved))
			{
				return BuildError(header, NtStatus.DiskFull);
			}
		}

		var fileStoreResult = await store.WriteWithOptionsAsync(open.LocalOpen, (long)req.Offset, req.Data, new FileIoOptions(through, unbuffered, req.RemainingBytes), cancellationToken).ConfigureAwait(continueOnCapturedContext: false);
		if (!fileStoreResult.IsSuccess)
		{
			if (quotaReserved > 0 && (object)quotaOwner != null)
			{
				quota.Release(quotaShare, quotaOwner, quotaReserved);
			}

			return BuildError(header, fileStoreResult.Status);
		}

		_server.Options.Metrics.OnBytesWritten(open.TreeConnect.Share.Name, fileStoreResult.Value);
		return MaybeSigned(session, RespHeader(header, session), WriteMessage.BuildResponseBody((uint)fileStoreResult.Value));
	}

	private async ValueTask<ResponseSegment> HandleQueryDirectoryAsync(SmbConnection connection, Smb2Header header, CommandRequest segment, bool frameEncrypted)
	{
		if (!TryGetValidSession(connection, header.SessionId, out var session))
		{
			return BuildError(header, NtStatus.UserSessionDeleted);
		}

		if (!VerifyInboundSignature(connection, session, header, segment.Span, frameEncrypted))
		{
			return BuildError(header, NtStatus.AccessDenied);
		}

		if (!TryGetFileStore(session, header.TreeId, out var store, out var error))
		{
			return BuildError(header, error);
		}

		var req = QueryDirectoryMessage.ParseRequest(segment.ParsingSpan, 64);
		if (!TryGetOpen(session, req.PersistentId, req.VolatileId, out var open) || open.LocalOpen == null)
		{
			return BuildError(header, NtStatus.FileClosed);
		}


		if (req.InfoClass is not (FileInformationClass.FileNamesInformation or FileInformationClass.FileDirectoryInformation or FileInformationClass.FileFullDirectoryInformation or FileInformationClass.FileBothDirectoryInformation or FileInformationClass.FileIdFullDirectoryInformation or FileInformationClass.FileIdBothDirectoryInformation))
			return BuildError(header, (byte)req.InfoClass is 60 or 78 or 79 or 80 or 81 ? NtStatus.NotSupported : NtStatus.InvalidInfoClass);

		await open.EnumerationGate.WaitAsync().ConfigureAwait(false);
		try
		{
			if ((req.Flags & 17) != 0)
			{
				open.Enumeration?.Dispose();
				open.Enumeration = null;
				open.EnumerationStarted = false;
				open.DirectoryListing = null;
				open.DirectoryCursor = 0;
			}

			var first = !open.EnumerationStarted;
			if (first)
			{
				open.EnumerationPattern = string.IsNullOrEmpty(req.SearchPattern) ? "*" : req.SearchPattern;
				if (store is IDirectoryCursorStore cursors)
				{
					var result = await cursors.OpenDirectoryCursorAsync(open.LocalOpen, open.EnumerationPattern).ConfigureAwait(false);
					if (!result.IsSuccess) return BuildError(header, result.Status);

					open.Enumeration = result.Value;
				}

				open.EnumerationMore = true;
				open.EnumerationStarted = true;
			}

			if (open.DirectoryListing == null || open.DirectoryCursor >= open.DirectoryListing.Count)
			{
				if (!open.EnumerationMore) return BuildError(header, first ? NtStatus.NoSuchFile : NtStatus.NoMoreFiles);

				var cap = Math.Max(1, _server.Options.MaxDirectoryEnumerationEntries);
				var result = open.Enumeration != null
					? await open.Enumeration.ReadAsync(cap).ConfigureAwait(false)
					: await store.QueryDirectoryAsync(open.LocalOpen, open.EnumerationPattern, cap).ConfigureAwait(false);
				if (!result.IsSuccess) return BuildError(header, result.Status);

				// Legacy stores cannot resume a truncated batch; report this explicitly.
				if (open.Enumeration == null && result.Value.Truncated) return BuildError(header, NtStatus.InsufficientResources);

				open.DirectoryListing = result.Value.Entries;
				open.DirectoryCursor = 0;
				open.EnumerationMore = result.Value.Truncated;
				if (!open.EnumerationMore)
				{
					open.Enumeration?.Dispose();
					open.Enumeration = null;
				}

				if (open.DirectoryListing.Count == 0) return BuildError(header, first ? NtStatus.NoSuchFile : NtStatus.NoMoreFiles);
			}

			var count = (req.Flags & 2) != 0 ? 1 : Math.Min(open.DirectoryListing.Count - open.DirectoryCursor, (int)(req.OutputBufferLength / 12 + 2));
			var entries = open.DirectoryListing.Skip(open.DirectoryCursor).Take(count).Select(ToStat).ToList();
			var data = FsccStructures.BuildDirectoryListing(entries, req.InfoClass, (int)req.OutputBufferLength, out var written);
			if (written == 0) return BuildError(header, NtStatus.InfoLengthMismatch);

			open.DirectoryCursor += written;
			return MaybeSigned(session, RespHeader(header, session), QueryDirectoryMessage.BuildResponseBody(data));
		}
		finally { open.EnumerationGate.Release(); }
	}

	private async ValueTask<ResponseSegment> HandleQueryInfoAsync(SmbConnection connection, Smb2Header header, CommandRequest segment, bool frameEncrypted, CancellationToken cancellationToken = default)
	{
		if (!TryGetValidSession(connection, header.SessionId, out var session))
		{
			return BuildError(header, NtStatus.UserSessionDeleted);
		}

		if (!VerifyInboundSignature(connection, session, header, segment.Span, frameEncrypted))
		{
			return BuildError(header, NtStatus.AccessDenied);
		}

		var req = QueryInfoMessage.ParseRequest(segment.ParsingSpan, 64);
		if (!TryGetOpen(session, req.PersistentId, req.VolatileId, out var open) || open.LocalOpen == null)
		{
			return BuildError(header, NtStatus.FileClosed);
		}

		if (req.InfoType == InfoType.File && req.FileInfoClass is 4 or 18 or 34 or 35 && (open.GrantedAccess & 0x80u) == 0)
			return BuildError(header, NtStatus.AccessDenied);
		if (req.InfoType == InfoType.Security)
		{
			return await HandleQuerySecurityAsync(session, header, open, req).ConfigureAwait(continueOnCapturedContext: false);
		}

		if (req.InfoType == InfoType.Quota)
		{
			return HandleQueryQuota(session, header, open, req);
		}

		using var cacheScope = req.InfoType == InfoType.File ? await _server.Options.CacheCoordinator.AcquireAsync([new FileIoRange(open, 0, ulong.MaxValue, false)], cancellationToken).ConfigureAwait(false) : null;
		if (req.InfoType == InfoType.File)
		{
			switch ((FileInformationClass)req.FileInfoClass)
			{
				case (FileInformationClass)48:
					return BuildError(header, NtStatus.NotSupported);
				case FileInformationClass.FileStreamInformation:
					return await HandleQueryStreamsAsync(session, header, open, req).ConfigureAwait(continueOnCapturedContext: false);
				case FileInformationClass.FileFullEaInformation:
					return await HandleQueryEaAsync(session, header, open, req).ConfigureAwait(continueOnCapturedContext: false);
			}
		}

		var e = ToStat(await open.LocalOpen.GetInfoAsync().ConfigureAwait(continueOnCapturedContext: false));
		if (req.InfoType == InfoType.File && (FileInformationClass)req.FileInfoClass is FileInformationClass.FileEaInformation or FileInformationClass.FileAllInformation &&
			open.TreeConnect!.Share.FileStore is IExtendedAttributeStore eaStore)
		{
			var eas = await eaStore.GetExtendedAttributesAsync(open.LocalOpen).ConfigureAwait(false);
			if (!eas.IsSuccess) return BuildError(header, eas.Status);
			e.EaSize = FullEaInformation.ComputeEaSize(eas.Value.Select(ea => new FsccEaEntry(ea.Flags, ea.Name, ea.Value)).ToArray());
		}
		var array = req.InfoType switch
		{
			InfoType.File => FsccStructures.BuildFileInformation(e, (FileInformationClass)req.FileInfoClass),
			InfoType.FileSystem => BuildFsInfo(session, header.TreeId, (FsInformationClass)req.FileInfoClass),
			_ => null,
		};
		if (array != null && req.InfoType == InfoType.File)
		{
			if ((FileInformationClass)req.FileInfoClass == FileInformationClass.FilePositionInformation)
				BinaryPrimitives.WriteInt64LittleEndian(array, Interlocked.Read(ref open.CurrentByteOffset));
			else if ((FileInformationClass)req.FileInfoClass == FileInformationClass.FileAllInformation)
			{
				BinaryPrimitives.WriteUInt32LittleEndian(array.AsSpan(76), open.GrantedAccess);
				BinaryPrimitives.WriteInt64LittleEndian(array.AsSpan(80), Interlocked.Read(ref open.CurrentByteOffset));
			}
		}
		if (array == null)
		{
			return BuildError(header, NtStatus.InvalidInfoClass);
		}

		var fixedSize = req.InfoType == InfoType.FileSystem
			? req.FileInfoClass switch { 1 => 18, 3 => 24, 7 => 32, 4 => 8, 5 => 12, _ => array.Length }
			: req.FileInfoClass switch { 18 => 100, 9 => 4, _ => array.Length };
		return BoundedInfo(connection, session, header, req, array, fixedSize);
	}

	private ResponseSegment BoundedInfo(SmbConnection connection, SmbSession session, Smb2Header header, QueryInfoMessage.Request req, byte[] data, int fixedSize)
	{
		if (req.OutputBufferLength == 0 || req.OutputBufferLength < fixedSize)
			return BuildError(connection, header, NtStatus.InfoLengthMismatch, ReadOnlySpan<byte>.Empty);

		var response = RespHeader(header, session);
		if (data.Length > req.OutputBufferLength)
		{
			response.Status = NtStatus.BufferOverflow;
			data = data.AsSpan(0, (int)req.OutputBufferLength).ToArray();
		}

		return MaybeSigned(session, response, QueryInfoMessage.BuildResponseBody(data));
	}

	private async ValueTask<ResponseSegment> HandleSetInfoAsync(SmbConnection connection, Smb2Header header, CommandRequest segment, bool frameEncrypted, CancellationToken cancellationToken = default)
	{
		if (!TryGetValidSession(connection, header.SessionId, out var session))
		{
			return BuildError(header, NtStatus.UserSessionDeleted);
		}

		if (!VerifyInboundSignature(connection, session, header, segment.Span, frameEncrypted))
		{
			return BuildError(header, NtStatus.AccessDenied);
		}

		if (!TryGetFileStore(session, header.TreeId, out var store, out var error))
		{
			return BuildError(header, error);
		}

		var req = SetInfoMessage.ParseRequest(segment.ParsingSpan, 64);
		if (!TryGetOpen(session, req.PersistentId, req.VolatileId, out var open) || open.LocalOpen == null)
		{
			return BuildError(header, NtStatus.FileClosed);
		}

		if (req.InfoType == InfoType.Security)
		{
			return await HandleSetSecurityAsync(connection, session, header, store, open, req, cancellationToken).ConfigureAwait(continueOnCapturedContext: false);
		}

		if (req.InfoType == InfoType.Quota)
		{
			return HandleSetQuota(session, header, open, req);
		}

		if (req.InfoType != InfoType.File)
		{
			return BuildError(header, NtStatus.NotSupported);
		}

		if ((FileInformationClass)req.FileInfoClass == FileInformationClass.FileRenameInformation)
		{
			// MS-SMB2 3.3.5.21.1 / MS-FSCC 2.4.42.2 require minimum padding and a zero root.
			if (req.Buffer.Length < 24) return BuildError(header, NtStatus.InfoLengthMismatch);
			if (BinaryPrimitives.ReadUInt64LittleEndian(req.Buffer.AsSpan(8, 8)) != 0) return BuildError(header, NtStatus.InvalidParameter);
			var nameLength = BinaryPrimitives.ReadUInt32LittleEndian(req.Buffer.AsSpan(16, 4));
			if (nameLength == 0 || (nameLength & 1) != 0 || nameLength > req.Buffer.Length - 20)
				return BuildError(header, NtStatus.InvalidParameter);
		}

		var minimumSetSize = (FileInformationClass)req.FileInfoClass switch
		{
			FileInformationClass.FileBasicInformation => 40,
			FileInformationClass.FileEndOfFileInformation or FileInformationClass.FilePositionInformation or FileInformationClass.FileAllocationInformation => 8,
			FileInformationClass.FileDispositionInformation => 1,
			_ => 0
		};
		if (req.Buffer.Length < minimumSetSize) return BuildError(header, NtStatus.InfoLengthMismatch);
		if ((FileInformationClass)req.FileInfoClass == FileInformationClass.FileBasicInformation)
			for (var offset = 0; offset < 32; offset += 8)
				if (BinaryPrimitives.ReadInt64LittleEndian(req.Buffer.AsSpan(offset)) < -2) return BuildError(header, NtStatus.InvalidParameter);
		if ((FileInformationClass)req.FileInfoClass == FileInformationClass.FileEndOfFileInformation && open.LocalOpen.IsDirectory)
			return BuildError(header, NtStatus.InvalidParameter);

		var namespaceMutation = (FileInformationClass)req.FileInfoClass is FileInformationClass.FileRenameInformation or FileInformationClass.FileDispositionInformation or FileInformationClass.FileBasicInformation or FileInformationClass.FileFullEaInformation;
		using var cacheScope = namespaceMutation
			? await _server.Options.CacheCoordinator.AcquireNamespaceAsync(open, open.LocalOpen.Identity, cancellationToken).ConfigureAwait(false)
			: await _server.Options.CacheCoordinator.AcquireAsync([new FileIoRange(open, 0, ulong.MaxValue, true)], cancellationToken).ConfigureAwait(false);
		cancellationToken.ThrowIfCancellationRequested();
		var infoClass = (FileInformationClass)req.FileInfoClass;
		if (infoClass == FileInformationClass.FileFullEaInformation)
		{
			return await HandleSetEaAsync(session, header, store, open, req).ConfigureAwait(continueOnCapturedContext: false);
		}

		var num = infoClass switch
		{
			FileInformationClass.FileEndOfFileInformation => FileWriteData,
			FileInformationClass.FileDispositionInformation => Delete,
			FileInformationClass.FileRenameInformation => Delete,
			FileInformationClass.FileBasicInformation => 256u,
			_ => 0u,
		};
		if (num != 0 && (open.GrantedAccess & num) == 0)
		{
			return BuildError(header, NtStatus.AccessDenied);
		}

		if (infoClass is FileInformationClass.FileEndOfFileInformation or FileInformationClass.FilePositionInformation)
		{
			if (req.Buffer.Length < 8) return BuildError(header, NtStatus.InfoLengthMismatch);
			if (BinaryPrimitives.ReadInt64LittleEndian(req.Buffer) < 0) return BuildError(header, NtStatus.InvalidParameter);
		}

		var renameOldPhysicalPath = ((infoClass == FileInformationClass.FileRenameInformation) ? open.LocalOpen.PhysicalPath : null);
		var ntStatus = infoClass switch
		{
			FileInformationClass.FileEndOfFileInformation => await store.SetEndOfFileAsync(open.LocalOpen, BinaryPrimitives.ReadInt64LittleEndian(req.Buffer)).ConfigureAwait(continueOnCapturedContext: false),
			FileInformationClass.FileDispositionInformation when store is not ISharedDeleteFileStore => NtStatus.NotSupported,
			FileInformationClass.FileDispositionInformation => await store.SetDeleteOnCloseAsync(open.LocalOpen, req.Buffer.Length != 0 && req.Buffer[0] != 0).ConfigureAwait(continueOnCapturedContext: false),
			FileInformationClass.FileRenameInformation => await DoCoordinatedRenameAsync(store, open, req.Buffer, cancellationToken).ConfigureAwait(continueOnCapturedContext: false),
			FileInformationClass.FileBasicInformation => await DoSetBasicInfoAsync(store, open.LocalOpen, req.Buffer).ConfigureAwait(continueOnCapturedContext: false),
			FileInformationClass.FileAllocationInformation => await SetAllocationAsync(store, open.LocalOpen, req.Buffer).ConfigureAwait(false),
			FileInformationClass.FilePositionInformation => NtStatus.Success,
			_ => NtStatus.InvalidInfoClass,
		};
		if (ntStatus != NtStatus.Success)
		{
			return BuildError(header, ntStatus);
		}

		if (infoClass == FileInformationClass.FilePositionInformation)
			Interlocked.Exchange(ref open.CurrentByteOffset, BinaryPrimitives.ReadInt64LittleEndian(req.Buffer));
		if (infoClass == FileInformationClass.FileDispositionInformation)
		{
			open.DeleteOnClose = req.Buffer.Length != 0 && req.Buffer[0] != 0;
		}
		else if (renameOldPhysicalPath != null)
		{
			BreakParentDirectoryLease(renameOldPhysicalPath);
			BreakParentDirectoryLease(open.LocalOpen.PhysicalPath);
		}

		return MaybeSigned(session, RespHeader(header, session), SetInfoMessage.BuildResponseBody());
	}

	private async ValueTask<NtStatus> DoCoordinatedRenameAsync(IFileStore store, SmbOpen open, byte[] buffer, CancellationToken token)
	{
		if (store is not IFileIdentityStore identities) return await DoRenameAsync(store, open.LocalOpen!, buffer).ConfigureAwait(false);

		var (replace, target) = SetInfoMessage.ParseRename(buffer);
		var targetKey = await ResolveShareKeyAsync(store, target, "").ConfigureAwait(false);
		using var nameScope = await NamespaceOperations.AcquireAsync(targetKey, token).ConfigureAwait(false);
		if (targetKey != await ResolveShareKeyAsync(store, target, "").ConfigureAwait(false)) return NtStatus.SharingViolation;

		var identity = await identities.ResolveIdentityAsync(target, cancellationToken: token).ConfigureAwait(false);
		var targetOpen = new SmbOpen { VolatileFileId = open.VolatileFileId, ShareModeKey = targetKey, Session = open.Session, TreeConnect = open.TreeConnect };
		using var destination = await _server.Options.CacheCoordinator.AcquireNamespaceAsync(targetOpen, identity, token).ConfigureAwait(false);
		token.ThrowIfCancellationRequested();
		return await store.RenameAsync(open.LocalOpen!, target, replace, token).ConfigureAwait(false);
	}

	private static ValueTask<NtStatus> SetAllocationAsync(IFileStore store, IFileHandle handle, byte[] buffer)
	{
		if (buffer.Length != 8) return new ValueTask<NtStatus>(NtStatus.InfoLengthMismatch);

		var length = BinaryPrimitives.ReadInt64LittleEndian(buffer);
		if (length < 0 || length > long.MaxValue - 4095 || handle.IsDirectory) return new ValueTask<NtStatus>(NtStatus.InvalidParameter);

		return store is IAllocationFileStore allocation ? allocation.SetAllocationSizeAsync(handle, length) : new ValueTask<NtStatus>(NtStatus.NotSupported);
	}

	private static ValueTask<NtStatus> DoRenameAsync(IFileStore store, IFileHandle handle, byte[] buffer)
	{
		var (replaceIfExists, newPath) = SetInfoMessage.ParseRename(buffer);
		return store.RenameAsync(handle, newPath, replaceIfExists);
	}

	private static ValueTask<NtStatus> DoSetBasicInfoAsync(IFileStore store, IFileHandle handle, byte[] buffer)
	{
		if (!(store is IBasicInfoStore basicInfoStore))
		{
			return new ValueTask<NtStatus>(NtStatus.Success);
		}

		return basicInfoStore.SetBasicInfoAsync(handle, SetInfoMessage.ParseBasicInfo(buffer));
	}

	private async ValueTask<ResponseSegment> HandleQuerySecurityAsync(SmbSession session, Smb2Header header, SmbOpen open, QueryInfoMessage.Request req)
	{
		if (((SecurityInformation)req.AdditionalInformation & (SecurityInformation.Owner | SecurityInformation.Group | SecurityInformation.Dacl)) != 0 &&
			(open.GrantedAccess & 0x20000u) == 0) return BuildError(header, NtStatus.AccessDenied);

		if (!TryGetFileStore(session, header.TreeId, out var store, out var error))
		{
			return BuildError(header, error);
		}

		var fileStoreResult = await store.GetSecurityAsync(open.LocalOpen!).ConfigureAwait(continueOnCapturedContext: false);
		if (!fileStoreResult.IsSuccess)
		{
			return BuildError(header, fileStoreResult.Status);
		}

		var additionalInformation = (SecurityInformation)req.AdditionalInformation;
		var array = FilterSecurityDescriptor(fileStoreResult.Value, additionalInformation).ToBytes();
		if (array.Length > req.OutputBufferLength)
		{
			return BuildError(header, NtStatus.BufferTooSmall);
		}

		return MaybeSigned(session, RespHeader(header, session), QueryInfoMessage.BuildResponseBody(array));
	}

	private async ValueTask<ResponseSegment> HandleSetSecurityAsync(SmbConnection connection, SmbSession session, Smb2Header header, IFileStore store, SmbOpen open, SetInfoMessage.Request req, CancellationToken cancellationToken)
	{
		var security = (SecurityInformation)req.AdditionalInformation;
		if (security.HasFlag(SecurityInformation.Dacl) && (open.GrantedAccess & 0x40000u) == 0 ||
			(security & (SecurityInformation.Owner | SecurityInformation.Group)) != 0 && (open.GrantedAccess & 0x80000u) == 0 ||
			security.HasFlag(SecurityInformation.Sacl) && (open.GrantedAccess & 0x01000000u) == 0)
			return BuildError(header, NtStatus.AccessDenied);

		SecurityDescriptor incoming;
		try
		{
			incoming = SecurityDescriptor.Parse(req.Buffer);
		}
		catch (SmbWireFormatException)
		{
			return BuildError(header, NtStatus.InvalidParameter);
		}

		// Partial updates must merge against the latest descriptor across FileIds,
		// aliases and named streams of this base object.
		var securityKey = LegacyKey(store) + ":" + (open.LocalOpen!.Identity is { } identity ? (identity with { StreamId = "" }).Key : "");
		using var securityScope = await SecurityOperations.AcquireAsync(securityKey, cancellationToken).ConfigureAwait(false);
		var fileStoreResult = await store.GetSecurityAsync(open.LocalOpen!).ConfigureAwait(continueOnCapturedContext: false);
		if (!fileStoreResult.IsSuccess)
		{
			return BuildError(header, fileStoreResult.Status);
		}

		var additionalInformation = (SecurityInformation)req.AdditionalInformation;
		var descriptor = MergeSecurityDescriptor(fileStoreResult.Value, incoming, additionalInformation);
		var ntStatus = await store.SetSecurityAsync(open.LocalOpen, descriptor).ConfigureAwait(continueOnCapturedContext: false);
		if (ntStatus != NtStatus.Success)
		{
			return BuildError(header, ntStatus);
		}

		Audit(SmbAuditEventType.PermissionChanged, SmbLogLevel.Information, connection, DescribeIdentity(session.Identity), open.TreeConnect!.Share.Name, open.PathName);
		return MaybeSigned(session, RespHeader(header, session), SetInfoMessage.BuildResponseBody());
	}

	private const SecurityDescriptorControl DaclStoredControl = SecurityDescriptorControl.DaclPresent |
		SecurityDescriptorControl.DaclDefaulted | SecurityDescriptorControl.DaclProtected | SecurityDescriptorControl.DaclAutoInherited;

	private static SecurityDescriptor FilterSecurityDescriptor(SecurityDescriptor sd, SecurityInformation which)
	{
		return SecurityDescriptor.Create(which.HasFlag(SecurityInformation.Owner) ? sd.Owner : null, which.HasFlag(SecurityInformation.Group) ? sd.Group : null, which.HasFlag(SecurityInformation.Dacl) ? sd.Dacl : null, which.HasFlag(SecurityInformation.Sacl) ? sd.Sacl : null,
			which.HasFlag(SecurityInformation.Dacl) ? sd.Control & DaclStoredControl : SecurityDescriptorControl.None);
	}

	private static SecurityDescriptor MergeSecurityDescriptor(SecurityDescriptor existing, SecurityDescriptor incoming, SecurityInformation which)
	{
		var control = existing.Control & DaclStoredControl;
		if (which.HasFlag(SecurityInformation.Dacl))
		{
			control = incoming.Control & (DaclStoredControl & ~SecurityDescriptorControl.DaclAutoInherited);
			// MS-DTYP 2.4.6: a computed-inheritance request is consumed; both
			// request and auto-inherited input bits retain the resulting DI bit.
			if (incoming.Control.HasFlag(SecurityDescriptorControl.DaclAutoInheritReq | SecurityDescriptorControl.DaclAutoInherited))
				control |= SecurityDescriptorControl.DaclAutoInherited;
		}
		return SecurityDescriptor.Create(which.HasFlag(SecurityInformation.Owner) ? incoming.Owner : existing.Owner, which.HasFlag(SecurityInformation.Group) ? incoming.Group : existing.Group, which.HasFlag(SecurityInformation.Dacl) ? incoming.Dacl : existing.Dacl, which.HasFlag(SecurityInformation.Sacl) ? incoming.Sacl : existing.Sacl,
			control);
	}

	private ResponseSegment BoundedRecords(SmbSession session, Smb2Header header, QueryInfoMessage.Request req, byte[] data, bool streams, out int written)
	{
		written = 0;
		var minimum = streams ? 24 : 8;
		if (req.OutputBufferLength < minimum) return BuildError(session.Connection, header, NtStatus.InfoLengthMismatch, ReadOnlySpan<byte>.Empty);

		int offset = 0, end = 0, last = -1;
		while (offset < data.Length)
		{
			var next = (int)BinaryPrimitives.ReadUInt32LittleEndian(data.AsSpan(offset));
			var size = streams
				? 24 + (int)BinaryPrimitives.ReadUInt32LittleEndian(data.AsSpan(offset + 4))
				: 9 + data[offset + 5] + BinaryPrimitives.ReadUInt16LittleEndian(data.AsSpan(offset + 6));
			if ((long)offset + size > req.OutputBufferLength) break;

			written++;
			last = offset;
			end = offset + size;
			if (next == 0) break;

			offset += next;
		}

		if (!streams && data.Length != 0 && end == 0) return BuildError(header, NtStatus.BufferTooSmall);

		var response = RespHeader(header, session);
		if (end < data.Length) response.Status = NtStatus.BufferOverflow;
		var result = data.AsSpan(0, end).ToArray();
		if (last >= 0) BinaryPrimitives.WriteUInt32LittleEndian(result.AsSpan(last), 0);
		return MaybeSigned(session, response, QueryInfoMessage.BuildResponseBody(result));
	}

	private async ValueTask<ResponseSegment> HandleQueryStreamsAsync(SmbSession session, Smb2Header header, SmbOpen open, QueryInfoMessage.Request req)
	{
		if (!TryGetFileStore(session, header.TreeId, out var store, out var error))
		{
			return BuildError(header, error);
		}

		IReadOnlyList<FsccStreamEntry> streams;
		if (store is INamedStreamStore namedStreamStore)
		{
			var fileStoreResult = await namedStreamStore.QueryStreamsAsync(open.LocalOpen!).ConfigureAwait(continueOnCapturedContext: false);
			if (!fileStoreResult.IsSuccess)
			{
				return BuildError(header, fileStoreResult.Status);
			}

			streams = fileStoreResult.Value.Select(s => new FsccStreamEntry(s.Name, s.Size, s.AllocationSize)).ToList();
		}
		else
		{
			var fileEntryInfo = await open.LocalOpen!.GetInfoAsync().ConfigureAwait(continueOnCapturedContext: false);
			streams = fileEntryInfo.IsDirectory
				? Array.Empty<FsccStreamEntry>()
				:
				[
					new FsccStreamEntry(string.Empty, fileEntryInfo.EndOfFile, fileEntryInfo.AllocationSize),
				];
		}

		var array = StreamInformation.Build(streams);
		return BoundedRecords(session, header, req, array, true, out _);
	}

	private async ValueTask<ResponseSegment> HandleQueryEaAsync(SmbSession session, Smb2Header header, SmbOpen open, QueryInfoMessage.Request req)
	{
		if (!TryGetFileStore(session, header.TreeId, out var store, out var error))
		{
			return BuildError(header, error);
		}

		IReadOnlyList<FsccEaEntry> eas = Array.Empty<FsccEaEntry>();
		if (store is IExtendedAttributeStore extendedAttributeStore)
		{
			if ((open.GrantedAccess & 8) == 0)
			{
				return BuildError(header, NtStatus.AccessDenied);
			}

			var fileStoreResult = await extendedAttributeStore.GetExtendedAttributesAsync(open.LocalOpen!).ConfigureAwait(continueOnCapturedContext: false);
			if (!fileStoreResult.IsSuccess)
			{
				return BuildError(header, fileStoreResult.Status);
			}

			eas = fileStoreResult.Value.Select(e => new FsccEaEntry(e.Flags, e.Name, e.Value)).ToList();
		}


		await open.EaGate.WaitAsync().ConfigureAwait(false);
		try
		{
			var named = req.InputBuffer.Length > 0;
			if (!named && (req.Flags & 4) != 0 && (req.AdditionalInformation == 0 || req.AdditionalInformation > eas.Count)) return BuildError(header, (NtStatus)0xc0000051);

			var start = (req.Flags & 4) != 0 ? Math.Max(0, (int)req.AdditionalInformation - 1) : (req.Flags & 1) != 0 ? 0 : open.EaCursor;
			var selected = eas.Skip(start);
			if (named)
			{
				var names = new List<string>();
				var offset = 0;
				while (offset < req.InputBuffer.Length)
				{
					var data = req.InputBuffer.AsSpan(offset);
					if (data.Length < 6 || data.Length < 6 + data[4]) return BuildError(header, NtStatus.InvalidParameter);

					names.Add(System.Text.Encoding.ASCII.GetString(data.Slice(5, data[4])));
					var next = (int)BinaryPrimitives.ReadUInt32LittleEndian(data);
					if (next == 0) break;

					if (next < 6 + data[4] || next >= data.Length) return BuildError(header, NtStatus.InvalidParameter);

					offset += next;
				}

				selected = names.SelectMany(n => eas.Where(e => string.Equals(e.Name, n, StringComparison.OrdinalIgnoreCase)));
			}

			if ((req.Flags & 2) != 0) selected = selected.Take(1);
			var array = FullEaInformation.Build(selected.ToArray());
			var response = BoundedRecords(session, header, req, array, false, out var written);
			if (!named && written != 0) open.EaCursor = start + written;
			return response;
		}
		finally { open.EaGate.Release(); }

	}

	private async ValueTask<ResponseSegment> HandleSetEaAsync(SmbSession session, Smb2Header header, IFileStore store, SmbOpen open, SetInfoMessage.Request req)
	{
		if (!(store is IExtendedAttributeStore extendedAttributeStore))
		{
			return BuildError(header, NtStatus.NotSupported);
		}

		if ((open.GrantedAccess & 0x10) == 0)
		{
			return BuildError(header, NtStatus.AccessDenied);
		}

		IReadOnlyList<FsccEaEntry> source;
		try
		{
			source = FullEaInformation.Parse(req.Buffer);
		}
		catch (SmbWireFormatException)
		{
			return BuildError(header, NtStatus.InvalidParameter);
		}

		if (source.Any(e => (e.Flags & ~0x80) != 0 || e.Name.Length == 0 ||
			e.Name.Any(c => c < 0x20 || "\\/:*?\"<>|,+=[];".Contains(c))))
			return BuildError(header, (NtStatus)0xc0000054);
		var entries = source.Select(e => new ExtendedAttribute(e.Name, e.Value, e.Flags)).ToList();
		var ntStatus = await extendedAttributeStore.SetExtendedAttributesAsync(open.LocalOpen!, entries).ConfigureAwait(continueOnCapturedContext: false);
		if (ntStatus != NtStatus.Success)
		{
			return BuildError(header, ntStatus);
		}

		return MaybeSigned(session, RespHeader(header, session), SetInfoMessage.BuildResponseBody());
	}

	private async ValueTask<ResponseSegment> HandleFlushAsync(SmbConnection connection, Smb2Header header, CommandRequest segment, bool frameEncrypted)
	{
		if (!TryGetValidSession(connection, header.SessionId, out var session))
		{
			return BuildError(header, NtStatus.UserSessionDeleted);
		}

		if (!VerifyInboundSignature(connection, session, header, segment.Span, frameEncrypted))
		{
			return BuildError(header, NtStatus.AccessDenied);
		}

		var persistent = BinaryPrimitives.ReadUInt64LittleEndian(segment.ParsingSpan.Slice(72, 8));
		var volatileId = BinaryPrimitives.ReadUInt64LittleEndian(segment.ParsingSpan.Slice(80, 8));
		if (!TryGetOpen(session, persistent, volatileId, out var open)) return BuildError(header, NtStatus.FileClosed);
		if (open.LocalOpen != null)
		{
			if (!TryGetFileStore(session, header.TreeId, out var store, out var error)) return BuildError(header, error);
			var status = await store.FlushAsync(open.LocalOpen).ConfigureAwait(false);
			if (status != NtStatus.Success) return BuildError(header, status);
		}

		var array = new byte[4];
		new SpanWriter(array).WriteUInt16(4);
		return MaybeSigned(session, RespHeader(header, session), array);
	}

	private Smb2Header RespHeader(Smb2Header request, SmbSession session)
	{
		var smb2Header = request.CreateResponse(NtStatus.Success);
		smb2Header.SessionId = session.SessionId;
		smb2Header.CreditRequestResponse = CreditManager.ComputeCreditGrant(request.CreditRequestResponse, _server.Options.MaxCreditsPerResponse);
		return smb2Header;
	}

	private static FileAccessIntent MapAccess(uint desiredAccess)
	{
		var fileAccessIntent = FileAccessIntent.None;
		if ((desiredAccess & (GenericRead | GenericAll | MaximumAllowed | FileReadData | 0x20000020u)) != 0)
		{
			fileAccessIntent |= FileAccessIntent.Read;
		}

		if ((desiredAccess & (GenericWrite | GenericAll | FileWriteData | FileAppendData)) != 0)
		{
			fileAccessIntent |= FileAccessIntent.Write;
		}

		if ((desiredAccess & (GenericAll | Delete)) != 0)
		{
			fileAccessIntent |= FileAccessIntent.Delete;
		}

		return fileAccessIntent;
	}

	internal static bool TrySplitStreamName(string name, out string baseName, out string streamName)
	{
		baseName = name;
		streamName = string.Empty;
		var num = name.LastIndexOf('\\');
		var num2 = name.IndexOf(':', num + 1);
		if (num2 < 0)
		{
			return false;
		}

		baseName = name.Substring(0, num2);
		var text = name.Substring(num2 + 1);
		var num3 = text.IndexOf(':');
		streamName = ((num3 >= 0) ? text.Substring(0, num3) : text);
		return true;
	}

	private ResponseSegment HandleQueryQuota(SmbSession session, Smb2Header header, SmbOpen open, QueryInfoMessage.Request req)
	{
		var quotaProvider = _server.Options.QuotaProvider;
		if (!quotaProvider.IsSupported)
		{
			return BuildError(header, NtStatus.NotSupported);
		}

		var queryRequest = QuotaMessage.ParseQueryInfo(req.InputBuffer);
		var readOnlyList = quotaProvider.Query(open.TreeConnect!.Share, queryRequest.SidFilter);
		if (readOnlyList.Count == 0)
		{
			return BuildError(header, NtStatus.NoMoreEntries);
		}

		if (queryRequest.ReturnSingle && readOnlyList.Count > 1)
		{
			readOnlyList = [readOnlyList[0]];
		}

		var array = QuotaMessage.BuildQuotaInformation(readOnlyList, (int)req.OutputBufferLength);
		if (array.Length == 0)
		{
			return BuildError(header, NtStatus.BufferTooSmall);
		}

		return MaybeSigned(session, RespHeader(header, session), QueryInfoMessage.BuildResponseBody(array));
	}

	private ResponseSegment HandleSetQuota(SmbSession session, Smb2Header header, SmbOpen open, SetInfoMessage.Request req)
	{
		var quotaProvider = _server.Options.QuotaProvider;
		if (!quotaProvider.IsSupported)
		{
			return BuildError(header, NtStatus.NotSupported);
		}

		var entries = QuotaMessage.ParseQuotaInformation(req.Buffer);
		var ntStatus = quotaProvider.Set(open.TreeConnect!.Share, entries);
		if (ntStatus != NtStatus.Success)
		{
			return BuildError(header, ntStatus);
		}

		return MaybeSigned(session, RespHeader(header, session), SetInfoMessage.BuildResponseBody());
	}

	private static IReadOnlyList<Sid> BuildCallerSids(SecurityIdentity? identity)
	{
		var list = new List<Sid> { WellKnownSids.Everyone };
		if (identity == null || identity.IsAnonymous)
		{
			return list;
		}

		list.Add(WellKnownSids.AuthenticatedUsers);
		if (Sid.TryParse(identity.UserSid, out var result))
		{
			list.Add(result);
		}

		foreach (var groupSid in identity.GroupSids)
		{
			if (Sid.TryParse(groupSid, out var result2))
			{
				list.Add(result2);
			}
		}

		return list;
	}

	private static FileShareMode MapShare(uint shareAccess)
	{
		var fileShareMode = FileShareMode.None;
		if ((shareAccess & 1) != 0)
		{
			fileShareMode |= FileShareMode.Read;
		}

		if ((shareAccess & 2) != 0)
		{
			fileShareMode |= FileShareMode.Write;
		}

		if ((shareAccess & 4) != 0)
		{
			fileShareMode |= FileShareMode.Delete;
		}

		return fileShareMode;
	}

	private static string ShareModeKey(SmbTreeConnect tree, string name)
	{
		return tree.Share.Name + "\0" + name.Replace('\\', '/').Trim('/').ToLowerInvariant();
	}

	public enum CloseReason
	{
		ExplicitClose,
		TreeDisconnect,
		Logoff,
		ConnectionLoss,
		Timeout,
		Shutdown,
		FailedCreate,
		SendFailure
	}

	public async ValueTask OnConnectionClosedAsync(SmbConnection connection, CloseReason reason = CloseReason.ConnectionLoss)
	{
		connection.CancelOrdinary();
		connection.AbandonPending();
		var finalSessions = new List<SmbSession>();
		foreach (var session in connection.Sessions.Values)
			if (session.DetachChannel(connection))
				finalSessions.Add(session);
		foreach (var session in finalSessions)
		{
			await CloseSessionAsync(session, reason).ConfigureAwait(false);
			_server.SessionGlobalList.TryRemove(session.SessionId, out _);
			session.State = SessionState.Expired;
		}

		connection.CancelAllPending();
		connection.Sessions.Clear();
		_server.WitnessRegistrations.RemoveAllForConnection(connection.ConnectionId);
		_server.UnregisterClientConnection(connection);
	}

	public void OnConnectionClosed(SmbConnection connection) => OnConnectionClosedAsync(connection).AsTask().GetAwaiter().GetResult();

	private async ValueTask CloseSessionAsync(SmbSession session, CloseReason reason)
	{
		session.StopChannelAdmission();
		if (!session.Lifetime.BeginClose(out var drained))
		{
			await drained.ConfigureAwait(false);
			return;
		}

		try
		{
			await drained.ConfigureAwait(false);
			foreach (var tree in session.TreeConnects.Values) await CloseTreeAsync(session, tree, reason).ConfigureAwait(false);
			foreach (var open in session.Opens.Values) await CloseOpenAsync(open, reason).ConfigureAwait(false);
		}
		finally
		{
			session.State = SessionState.Expired;
			_server.SessionGlobalList.TryRemove(session.SessionId, out _);
			foreach (var connection in _server.Connections.Values) connection.Sessions.TryRemove(session.SessionId, out _);
			session.Channels.Clear();
			SafeCleanup(() => _server.Options.Metrics.OnSessionClosed());
			session.Lifetime.CompleteClose();
		}
	}

	private async ValueTask CloseTreeAsync(SmbSession session, SmbTreeConnect tree, CloseReason reason)
	{
		if (!tree.Lifetime.BeginClose(out var drained))
		{
			await drained.ConfigureAwait(false);
			return;
		}

		try
		{
			foreach (var connection in _server.Connections.Values)
			foreach (var pending in connection.PendingRequests.Values)
				if (pending.Owner?.TreeConnect == tree)
					SafeCleanup(pending.CancelForClose);
			foreach (var pending in session.Connection.PendingRequests.Values)
				if (pending.Owner?.TreeConnect == tree)
					SafeCleanup(pending.CancelForClose);
			await drained.ConfigureAwait(false); // drains provisional CREATEs
			foreach (var open in session.Opens.Values)
				if (open.TreeConnect == tree)
					await CloseOpenAsync(open, reason).ConfigureAwait(false);
			if (session.TreeConnects.TryRemove(tree.TreeId, out _)) SafeCleanup(() => _server.Options.Metrics.OnTreeDisconnected());
		}
		finally { tree.Lifetime.CompleteClose(); }
	}

	private void SafeCleanup(Action cleanup)
	{
		try { cleanup(); }
		catch (Exception ex)
		{
			try { _log?.Invoke("[cleanup] " + ex.Message); }
			catch { }
		}
	}

	private async ValueTask<NtStatus> CloseOpenAsync(SmbOpen open, CloseReason reason)
	{
		await open.RecoveryGate.WaitAsync().ConfigureAwait(false);
		try { return await CloseOpenCoreAsync(open, reason).ConfigureAwait(false); }
		finally { open.RecoveryGate.Release(); }
	}

	private async ValueTask<NtStatus> CloseOpenCoreAsync(SmbOpen open, CloseReason reason)
	{
		if (reason is CloseReason.ConnectionLoss or CloseReason.SendFailure && open.IsDurable &&
		    DurabilityAllowed(open.OplockLevel, open.LeaseState) && !_server.Options.CacheCoordinator.IsBreaking(open))
		{
			if (open.Lifetime.BeginDisconnect(out var physical))
			{
				open.Notifications?.Dispose();
				await physical.ConfigureAwait(false);
				if (DurabilityAllowed(open.OplockLevel, open.LeaseState) && !_server.Options.CacheCoordinator.IsBreaking(open) && open.Lifetime.CompleteDisconnect())
				{
					var oldSession = open.Session;
					var record = new DurableHandle
					{
						PersistentId = open.PersistentFileId, VolatileId = open.VolatileFileId,
						Open = open, OwnerKey = OwnerKey(oldSession?.Identity), ClientGuid = oldSession is null ? Guid.Empty : new Guid(oldSession.Connection.ClientGuid),
						IsV2 = open.DurableIsV2, CreateGuid = open.DurableCreateGuid, Deadline = _server.Options.TimeProvider.GetUtcNow() + open.DurableTimeout
					};
					if (oldSession != null) oldSession.Opens.TryRemove(new KeyValuePair<(ulong, ulong), SmbOpen>(open.Key, open));
					if (open.Counted)
					{
						open.Counted = false;
						if (open.TreeConnect != null) Interlocked.Decrement(ref open.TreeConnect.OpenCount);
					}

					open.Session = null;
					open.TreeConnect = null;
					try
					{
						_server.Options.DurableHandleStore.Add(record);
						return NtStatus.Success;
					}
					catch
					{
						/* Registration failed; the terminal cleanup below owns the resources. */
					}
				}
			}
		}

		var provisionalRollback = reason == CloseReason.FailedCreate && open.Lifetime.State == OpenState.Provisional;
		if (!open.Lifetime.BeginClose(out var drained))
		{
			await drained.ConfigureAwait(false);
			return NtStatus.FileClosed;
		}

		var status = NtStatus.Success;
		try
		{
			open.IsReplayEligible = false;
			_server.CreateReplays.Retire(open);
			if (_server.Options.DurableHandleStore is InMemoryDurableHandleStore retained) retained.Retire(open);
			foreach (var conn in _server.Connections.Values)
			foreach (var ordinary in conn.OrdinaryRequests.Values)
				if (!provisionalRollback && ordinary.Owner == open)
					ordinary.Cancel();
			if (open.Session is { } ordinarySession)
				foreach (var ordinary in ordinarySession.Connection.OrdinaryRequests.Values)
					if (!provisionalRollback && ordinary.Owner == open)
						ordinary.Cancel();
			// Cancel existing pending work on every channel before draining ordinary operations.
			foreach (var conn in _server.Connections.Values)
			foreach (var pending in conn.PendingRequests.Values)
				if (!provisionalRollback && pending.Owner == open)
					SafeCleanup(pending.CancelForClose);
			if (open.Session is { } session)
				foreach (var pending in session.Connection.PendingRequests.Values)
					if (!provisionalRollback && pending.Owner == open)
						SafeCleanup(pending.CancelForClose);
			open.Notifications?.Dispose();
			await drained.ConfigureAwait(false);
			_server.Options.CacheCoordinator.ReleaseOwner(open);
			try { open.Enumeration?.Dispose(); }
			catch (Exception ex) { status = MapException(ex); }
			finally
			{
				open.Enumeration = null;
				open.DirectoryListing = null;
				open.ResumeKey = null;
			}

			if (open.Session is { } owner) ((ICollection<KeyValuePair<(ulong, ulong), SmbOpen>>)owner.Opens).Remove(new KeyValuePair<(ulong, ulong), SmbOpen>(open.Key, open));
			SafeCleanup(() => _server.Options.LockManager.ReleaseOwner(open));
			SafeCleanup(() => _server.Options.OplockManager.ReleaseOwner(open));
			SafeCleanup(() => _server.Options.LeaseManager.ReleaseOwner(open));
			if (open.LocalOpen is { } handle)
			{
				try
				{
					var closeStatus = await handle.CloseAsync().ConfigureAwait(false);
					if (status == NtStatus.Success) status = closeStatus;
				}
				catch (Exception ex) { status = MapException(ex); }
				finally
				{
					try { await handle.DisposeAsync().ConfigureAwait(false); }
					catch (Exception ex)
					{
						if (status == NtStatus.Success) status = MapException(ex);
					}
				}
			}

			if (open.ShareModeKey is { } key) SafeCleanup(() => _server.Options.ShareModeManager.Close(key, open));
			if (open.IsPersistentHandle && _server.Options.DurableHandleStore is IPersistentHandleStore persistent)
				SafeCleanup(() => persistent.RemovePersisted(open.PersistentFileId, open.VolatileFileId));
			if (open.Counted)
			{
				open.Counted = false;
				if (open.TreeConnect != null) Interlocked.Decrement(ref open.TreeConnect.OpenCount);
			}

			if (open.MetricCounted)
			{
				open.MetricCounted = false;
				SafeCleanup(() => _server.Options.Metrics.OnHandleClosed());
			}
		}
		finally { open.Lifetime.CompleteClose(); }

		return status;
	}

	private static IDisposable? AdmitChannelSequence(SmbConnection connection, Smb2Header header, ReadOnlySpan<byte> request, ReadOnlySpan<byte> original, bool frameEncrypted, out NtStatus status)
	{
		status = NtStatus.Success;
		if (connection.Dialect is SmbDialect.Smb202 or SmbDialect.Smb210) return null;

		var offset = CompoundExecutionContext.RequestFileIdOffset(header.Command, request);
		// Classic oplock ACK carries FileId; the 36-byte lease ACK carries a LeaseKey.
		if (header.Command == SmbCommand.OplockBreak && request.Length >= 88
		    && BinaryPrimitives.ReadUInt16LittleEndian(request.Slice(64)) == 24) offset = 72;
		if (offset < 0 || request.Length < offset + 16 || !connection.Sessions.TryGetValue(header.SessionId, out var session)) return null;

		// Preserve the existing prerequisites without changing their rejection paths.
		// Resolved bytes identify the open; only original signed wire bytes may be verified.
		if (session.State != SessionState.Valid || !VerifyInboundSignature(connection, session, header, original, frameEncrypted)) return null;

		var key = (BinaryPrimitives.ReadUInt64LittleEndian(request.Slice(offset)), BinaryPrimitives.ReadUInt64LittleEndian(request.Slice(offset + 8)));
		if (!session.Opens.TryGetValue(key, out var open) || open.TreeConnect?.TreeId != header.TreeId) return null;

		status = open.ChannelSequences.TryAdmit(header.ChannelSequence, header.Flags.HasFlag(Smb2HeaderFlags.ReplayOperation), header.Command, out var ticket);
		return ticket;
	}

	private void InvalidateCreateReplay(SmbConnection connection, Smb2Header header, CommandRequest request, bool encrypted)
	{
		if (!connection.Dialect.IsSmb3OrLater() || !TryGetValidSession(connection, header.SessionId, out var session) ||
		    !VerifyInboundSignature(connection, session, header, request.Span, encrypted) ||
		    !session.TreeConnects.ContainsKey(header.TreeId)) return;

		var offset = CompoundExecutionContext.RequestFileIdOffset(header.Command, request.ParsingSpan);
		if (header.Command == SmbCommand.OplockBreak && request.Length >= 88 && BinaryPrimitives.ReadUInt16LittleEndian(request.ParsingSpan.Slice(64)) == 24) offset = 72;
		if (offset < 0 || request.Length < offset + 16) return;

		var key = (BinaryPrimitives.ReadUInt64LittleEndian(request.ParsingSpan.Slice(offset)), BinaryPrimitives.ReadUInt64LittleEndian(request.ParsingSpan.Slice(offset + 8)));
		if (session.Opens.TryGetValue(key, out var open) && open.TreeConnect?.TreeId == header.TreeId)
		{
			open.IsReplayEligible = false;
			_server.CreateReplays.Retire(open);
		}
	}

	private static IDisposable? AcquireOperation(SmbConnection connection, Smb2Header header, CommandRequest segment, out NtStatus? error)
	{
		error = null;
		var offset = header.Command switch
		{
			SmbCommand.Read or SmbCommand.Write => 80,
			SmbCommand.Flush or SmbCommand.Lock or SmbCommand.QueryDirectory or SmbCommand.ChangeNotify => 72,
			SmbCommand.Ioctl => CompoundExecutionContext.RequestFileIdOffset(header.Command, segment.ParsingSpan),
			SmbCommand.QueryInfo => 88,
			SmbCommand.SetInfo => 80,
			_ => -1
		};
		if (offset < 0 || segment.Length < offset + 16 || !connection.Sessions.TryGetValue(header.SessionId, out var session)) return null;

		var key = (BinaryPrimitives.ReadUInt64LittleEndian(segment.ParsingSpan.Slice(offset)), BinaryPrimitives.ReadUInt64LittleEndian(segment.ParsingSpan.Slice(offset + 8)));
		if (!session.Opens.TryGetValue(key, out var open)) return null;

		if (open.TreeConnect?.TreeId != header.TreeId)
		{
			error = NtStatus.FileClosed;
			return null;
		}

		if (open.TreeConnect.Lifetime.State != OpenState.Active)
		{
			error = NtStatus.NetworkNameDeleted;
			return null;
		}

		var reference = open.Lifetime.TryAcquire();
		if (reference == null) error = NtStatus.FileClosed;
		return reference;
	}

	private async ValueTask<ResponseSegment> HandleDurableReconnectAsync(Smb2Header header, SmbSession session, SmbTreeConnect tree, CreateRequest request, CreateContext context, bool v2)
	{
		if (!_server.Options.FeaturePolicy.SupportsDurable(session.Connection.Dialect) ||
		    _server.Options.DurableHandleStore is not InMemoryDurableHandleStore store)
			return BuildError(header, NtStatus.ObjectNameNotFound);

		var reconnect = v2 ? DurableHandleMessages.ParseV2Reconnect(context.Data) : default;
		var persistent = v2 ? reconnect.PersistentId : DurableHandleMessages.ParseReconnect(context.Data).persistentId;
		if (!store.TryGetPersistent(persistent, out var record)) return BuildError(header, NtStatus.ObjectNameNotFound);

		var open = record.Open;
		await open.RecoveryGate.WaitAsync().ConfigureAwait(false);
		try
		{
			if (!store.TryGetPersistent(persistent, out var current) || !ReferenceEquals(record, current)) return BuildError(header, NtStatus.ObjectNameNotFound);

			if (record.Deadline <= _server.Options.TimeProvider.GetUtcNow())
			{
				if (store.TryClaim(record.PersistentId, record.VolatileId, out _)) await CloseOpenCoreAsync(open, CloseReason.Timeout).ConfigureAwait(false);
				return BuildError(header, NtStatus.ObjectNameNotFound);
			}

			var leaseContext = CreateContextList.Find(request.Contexts, 1383156851u);
			var lease = leaseContext is null ? null : LeaseRequest.FromContext(leaseContext);
			var leased = open.OplockLevel == OplockLevel.Lease;
			if (!v2 && leased && record.ClientGuid == new Guid(session.Connection.ClientGuid) && !open.DeleteOnClose &&
			    !string.Equals(open.PathName, request.Name, StringComparison.OrdinalIgnoreCase)) return BuildError(header, NtStatus.InvalidParameter);
			if (v2 && record.CreateGuid != reconnect.CreateGuid || !open.IsDurable || open.Session != null ||
			    open.Lifetime.State != OpenState.Disconnected || !ReferenceEquals(open.DurableShare, tree.Share) ||
			    !DurabilityAllowed(open.OplockLevel, open.LeaseState) || _server.Options.CacheCoordinator.IsBreaking(open) ||
			    leased != (lease != null) || leased && (record.ClientGuid != new Guid(session.Connection.ClientGuid) ||
				    lease!.Key != open.LeaseKey || lease.IsV2 != open.DurableLeaseV2 ||
				    !open.DeleteOnClose && !string.Equals(open.PathName, request.Name, StringComparison.OrdinalIgnoreCase)))
				return BuildError(header, NtStatus.ObjectNameNotFound);
			if (v2 && reconnect.IsPersistent) return BuildError(header, NtStatus.InvalidParameter);
			if (!string.Equals(record.OwnerKey, OwnerKey(session.Identity), StringComparison.Ordinal)) return BuildError(header, NtStatus.AccessDenied);

			using var admission = session.TryReserveOpen(_server.Options.MaxOpenHandlesPerSession);
			if (admission == null) return BuildError(header, NtStatus.InsufficientResources);

			ulong volatileId;
			do { volatileId = session.AllocateFileId(); } while (volatileId == record.VolatileId);

			var contexts = new List<CreateContext> { v2 ? DurableHandleMessages.BuildV2ResponseContext((uint)open.DurableTimeout.TotalMilliseconds, false) : DurableHandleMessages.BuildV1ResponseContext() };
			if (lease != null) contexts.Add(new CreateContext { Name = leaseContext!.Name, Data = lease.SerializeResponse(open.LeaseState, open.LeaseEpoch) });
			// All fallible preparation precedes consuming the retained record or attaching ownership.
			var body = await BuildRetainedCreateBodyAsync(open, volatileId, CreateAction.Opened, contexts).ConfigureAwait(false);
			var response = MaybeSigned(session, RespHeader(header, session), body);
			if (tree.Lifetime.State != OpenState.Active || session.Lifetime.State != OpenState.Active || !open.Lifetime.BeginReconnect()) return BuildError(header, NtStatus.ObjectNameNotFound);

			var committed = false;
			try
			{
				var newKey = (open.PersistentFileId, volatileId);
				if (session.Opens.ContainsKey(newKey)) return BuildError(header, NtStatus.InsufficientResources);
				if (!store.TryClaim(record.PersistentId, record.VolatileId, out var claimed) || !ReferenceEquals(claimed, record)) return BuildError(header, NtStatus.ObjectNameNotFound);

				var oldVolatile = open.VolatileFileId;
				open.VolatileFileId = volatileId;
				open.Session = session;
				open.TreeConnect = tree;
				if (!session.Opens.TryAdd(newKey, open))
				{
					open.VolatileFileId = oldVolatile;
					open.Session = null;
					open.TreeConnect = null;
					store.Add(record);
					return BuildError(header, NtStatus.InsufficientResources);
				}

				Interlocked.Increment(ref tree.OpenCount);
				open.Counted = true;
				committed = true;
				return response;
			}
			finally { open.Lifetime.CompleteReconnect(committed); }
		}
		finally { open.RecoveryGate.Release(); }
	}

	private static async ValueTask<byte[]> BuildRetainedCreateBodyAsync(SmbOpen open, ulong volatileId, CreateAction action, IReadOnlyList<CreateContext> contexts)
	{
		var info = await open.LocalOpen!.GetInfoAsync().ConfigureAwait(false);
		return new CreateResponse
		{
			OplockLevel = open.OplockLevel, CreateAction = action,
			CreationTime = info.CreationTime, LastAccessTime = info.LastAccessTime, LastWriteTime = info.LastWriteTime,
			ChangeTime = info.ChangeTime, AllocationSize = info.AllocationSize, EndOfFile = info.EndOfFile, FileAttributes = (uint)info.Attributes,
			PersistentFileId = open.PersistentFileId, VolatileFileId = volatileId
		}.ToBody(CreateContextList.Serialize(contexts));
	}

	private TimeSpan ResolveDurableTimeout(uint requestedMs)
	{
		if (requestedMs == 0)
		{
			return _server.Options.DurableHandleTimeout;
		}

		var timeSpan = TimeSpan.FromMilliseconds(requestedMs, 0L);
		if (!(timeSpan > TimeSpan.FromMilliseconds(Math.Min(300000, _server.Options.MaxDurableHandleTimeout.TotalMilliseconds))))
		{
			return timeSpan;
		}

		return TimeSpan.FromMilliseconds(Math.Min(300000, _server.Options.MaxDurableHandleTimeout.TotalMilliseconds));
	}

	private static bool DurabilityAllowed(OplockLevel oplock, LeaseState lease) =>
		oplock == OplockLevel.Batch || oplock == OplockLevel.Lease && lease.HasFlag(LeaseState.Handle);

	private static string OwnerKey(SecurityIdentity? identity)
	{
		var text = identity?.UserSid;
		if (text == null)
		{
			if (identity != null)
			{
				return identity.DomainName + "\\" + identity.UserName;
			}

			text = "<none>";
		}

		return text;
	}

	public void ScavengeDurableHandles()
	{
		foreach (var item in _server.Options.DurableHandleStore.TakeExpired(_server.Options.TimeProvider.GetUtcNow()))
		{
			ReleaseDurable(item);
		}
	}

	public async ValueTask CloseRetainedHandlesAsync()
	{
		foreach (var record in _server.Options.DurableHandleStore.TakeAll())
			await CloseOpenAsync(record.Open, CloseReason.Shutdown).ConfigureAwait(false);
	}

	public void SweepIdleTimeouts()
	{
		var options = _server.Options;
		var ticks = options.TimeProvider.GetUtcNow().Ticks;
		if (options.SessionIdleTimeout > TimeSpan.Zero)
		{
			var ticks2 = options.SessionIdleTimeout.Ticks;
			foreach (var value in _server.SessionGlobalList.Values)
			{
				if (value.State == SessionState.Valid && ticks - value.LastActivityTicks > ticks2)
				{
					ExpireSession(value);
				}
			}
		}

		var ticks3 = options.AuthenticationTimeout.Ticks;
		var ticks4 = options.ConnectionIdleTimeout.Ticks;
		foreach (var value2 in _server.Connections.Values)
		{
			var num = !value2.Sessions.Values.Any(s => s.State == SessionState.Valid) && options.AuthenticationTimeout > TimeSpan.Zero && ticks - value2.CreatedTicks > ticks3;
			var flag = options.ConnectionIdleTimeout > TimeSpan.Zero && ticks - value2.LastActivityTicks > ticks4;
			if (num | flag)
			{
				value2.RequestClose?.Invoke();
			}
		}
	}

	private void ExpireSession(SmbSession session)
	{
		Audit(SmbAuditEventType.SessionLogoff, SmbLogLevel.Information, null, DescribeIdentity(session.Identity), null, null, NtStatus.Success, "idle timeout");
		CloseSessionAsync(session, CloseReason.Timeout).AsTask().GetAwaiter().GetResult();
		_server.SessionGlobalList.TryRemove(session.SessionId, out _);
		foreach (var value2 in _server.Connections.Values)
		{
			value2.Sessions.TryRemove(session.SessionId, out _);
		}

		session.Channels.Clear();
		session.State = SessionState.Expired;
	}

	private void ReleaseDurable(DurableHandle dh) => CloseOpenAsync(dh.Open, CloseReason.Timeout).AsTask().GetAwaiter().GetResult();

	private byte[]? BuildFsInfo(SmbSession session, uint treeId, FsInformationClass infoClass)
	{
		if (TryGetFileStore(session, treeId, out var store, out _) && store is IVolumeInfoProvider volumeInfoProvider)
		{
			var volumeInfo = volumeInfoProvider.GetVolumeInfo();
			return FsccStructures.BuildFileSystemInformation(infoClass, volumeInfo.Label, volumeInfo.SerialNumber, volumeInfo.TotalBytes, volumeInfo.AvailableBytes);
		}

		return FsccStructures.BuildFileSystemInformation(infoClass, "SHARE", 305419896u);
	}

	private static FsccFileStat ToStat(FileEntryInfo info)
	{
		return new FsccFileStat
		{
			Name = info.Name,
			DeletePending = info.DeletePending,
			FileAttributes = (uint)info.Attributes,
			EndOfFile = info.EndOfFile,
			AllocationSize = info.AllocationSize,
			CreationTime = info.CreationTime,
			LastAccessTime = info.LastAccessTime,
			LastWriteTime = info.LastWriteTime,
			ChangeTime = info.ChangeTime,
			IsDirectory = info.IsDirectory,
			IndexNumber = info.IndexNumber,
		};
	}

	private ArmedBreaks ArmLeaseBreaks(IReadOnlyList<LeaseBreak> breaks, bool track)
	{
		if (breaks.Count == 0)
		{
			return ArmedBreaks.None;
		}

		List<Task<BreakOutcome>> list = null;
		foreach (var @break in breaks)
		{
			@break.Holder.LeaseState = @break.ToState;
			if (track && LeaseAckRequired(@break))
			{
				var breaks2 = _breaks;
				if (breaks2 != null)
				{
					(list ??= new List<Task<BreakOutcome>>()).Add(breaks2.RegisterLeaseBreak(@break.Key));
				}
			}
		}

		return new ArmedBreaks(Array.Empty<OplockBreak>(), breaks, (list == null) ? null : Task.WhenAll(list));
	}

	private static bool LeaseAckRequired(LeaseBreak brk)
	{
		return (brk.FromState & ~brk.ToState & (LeaseState.Handle | LeaseState.Write)) != 0;
	}

	private void DispatchLeaseBreaks(IReadOnlyList<LeaseBreak> breaks)
	{
		_ = SendArmedBreaksAsync(ArmLeaseBreaks(breaks, track: false));
	}

	private void BreakParentDirectoryLease(string? childPhysicalPath)
	{
		if (string.IsNullOrEmpty(childPhysicalPath))
		{
			return;
		}

		var directoryName = Path.GetDirectoryName(childPhysicalPath);
		if (!string.IsNullOrEmpty(directoryName))
		{
			var readOnlyList = _server.Options.CacheCoordinator.BreakDirectoryLease(directoryName);
			if (readOnlyList.Count != 0)
			{
				DispatchLeaseBreaks(readOnlyList);
			}
		}
	}

	private async Task SendLeaseBreakAsync(LeaseBreak brk)
	{
		var holder = brk.Holder;
		var session = holder.Session;
		var header = new Smb2Header
		{
			Command = SmbCommand.OplockBreak,
			MessageId = UnsolicitedMessageId,
			Flags = Smb2HeaderFlags.ServerToRedir,
			Status = NtStatus.Success,
			SessionId = 0,
			TreeId = 0,
			CreditRequestResponse = 0,
		};
		var body = LeaseBreakMessage.BuildNotificationBody(brk.Key, brk.FromState, brk.ToState, brk.Epoch, LeaseAckRequired(brk));
		await SendOutOfBandAsync(session, session.Connection, MaybeSigned(session, header, body), ResponseNeedsEncryption(session, holder), useSurvivingChannel: true).ConfigureAwait(continueOnCapturedContext: false);
	}

	private ResponseSegment HandleLeaseBreakAck(SmbConnection connection, Smb2Header header, ReadOnlySpan<byte> segment, bool frameEncrypted)
	{
		if (!TryGetValidSession(connection, header.SessionId, out var session))
		{
			return BuildError(header, NtStatus.UserSessionDeleted);
		}

		if (!VerifyInboundSignature(connection, session, header, segment, frameEncrypted))
		{
			return BuildError(header, NtStatus.AccessDenied);
		}

		var acknowledgment = LeaseBreakMessage.ParseAcknowledgment(segment, 64);
		foreach (var owner in _server.SessionGlobalList.Values.SelectMany(s => s.Opens.Values))
			if (owner.LeaseKey == acknowledgment.Key && owner.Session!.Connection.ClientGuid.AsSpan().SequenceEqual(connection.ClientGuid))
			{
				owner.IsReplayEligible = false;
				_server.CreateReplays.Retire(owner);
			}

		var status = _server.Options.CacheCoordinator.Acknowledge(connection, acknowledgment.Key, acknowledgment.State, out var state);
		if (status != NtStatus.Success) return BuildError(header, status);

		var body = LeaseBreakMessage.BuildResponseBody(acknowledgment.Key, state);
		return MaybeSigned(session, RespHeader(header, session), body);
	}

	private ResponseSegment HandleLock(SmbConnection connection, Smb2Header header, ReadOnlySpan<byte> segment, ReadOnlySpan<byte> resolved, bool frameEncrypted, bool standalone, IDisposable? channelTicket)
	{
		if (!TryGetValidSession(connection, header.SessionId, out var session))
		{
			return BuildError(header, NtStatus.UserSessionDeleted);
		}

		if (!VerifyInboundSignature(connection, session, header, segment, frameEncrypted))
		{
			return BuildError(header, NtStatus.AccessDenied);
		}

		var request = LockMessage.ParseRequest(resolved, 64);
		if (!TryGetOpen(session, request.PersistentId, request.VolatileId, out var open))
		{
			return BuildError(header, NtStatus.FileClosed);
		}

		var isUnlock = request.Locks[0].IsUnlock;
		var array = new LockElement[request.Locks.Count];
		for (var i = 0; i < request.Locks.Count; i++)
		{
			var lockEntry = request.Locks[i];
			if (!isUnlock && lockEntry.IsUnlock)
			{
				return BuildError(header, NtStatus.InvalidParameter);
			}

			array[i] = new LockElement(lockEntry.Offset, lockEntry.Length, (LockFlags)lockEntry.Flags);
		}

		var failImmediately = request.Locks[0].FailImmediately;
		var pending = RegisterPending(connection, header, open);
		if (pending == null) return BuildError(header, NtStatus.InsufficientResources);

		var sequenceEnabled = connection.Dialect != SmbDialect.Smb202 &&
			(open.IsDurable || open.IsPersistentHandle || connection.Dialect.IsSmb3OrLater() && connection.ServerCapabilities.HasFlag(Smb2Capabilities.MultiChannel));
		var task = ApplySequencedLockAsync();

		async Task<LockOutcome> ApplySequencedLockAsync()
		{
			// Physical ownership outlives pending-map abandonment and cancellation responses.
			using var physical = open.Lifetime.TryAcquire();
			if (physical == null) return LockOutcome.Cancelled;

			try
			{
				return sequenceEnabled
					? await open.LockSequences.ApplyAsync(request.LockSequence, () => ApplyCoordinatedLockAsync(open, array, failImmediately, pending.Token).AsTask(), pending.Token).ConfigureAwait(false)
					: await ApplyCoordinatedLockAsync(open, array, failImmediately, pending.Token).ConfigureAwait(false);
			}
			catch (OperationCanceledException) { return LockOutcome.Cancelled; }
		}

		if (task.IsCompleted)
		{
			if (pending.State == PendingRequestState.Registered) pending.Abandon();
			return LockResultSegment(header, session, task.IsCompletedSuccessfully ? task.Result : LockOutcome.Conflict);
		}

		_ = CompleteLockAsync();
		return InterimResponse(header, session, pending.AsyncId);

		async Task CompleteLockAsync()
		{
			LockOutcome outcome;
			try { outcome = await task.ConfigureAwait(false); }
			catch { outcome = LockOutcome.Cancelled; }
			finally { channelTicket?.Dispose(); }

			var status = outcome switch { LockOutcome.Granted => NtStatus.Success, LockOutcome.Cancelled => NtStatus.Cancelled, LockOutcome.RangeNotLocked => NtStatus.RangeNotLocked, LockOutcome.InvalidParameter => NtStatus.InvalidParameter, _ => NtStatus.LockNotGranted };
			var body = outcome == LockOutcome.Granted ? LockMessage.BuildResponseBody() : ErrorResponse.BuildBody();
			pending.Complete(status, body, () => SendAsyncFinalAsync(connection, header, session, pending.AsyncId, status, body, ResponseNeedsEncryption(session, open)));
		}
	}

	private async ValueTask<LockOutcome> ApplyCoordinatedLockAsync(SmbOpen open, LockElement[] elements, bool failImmediately, CancellationToken token)
	{
		using var cacheScope = !elements[0].Unlock ? await _server.Options.CacheCoordinator.AcquireAsync([new FileIoRange(open, 0, ulong.MaxValue, true)], token).ConfigureAwait(false) : null;
		return await _server.Options.LockManager.ApplyAsync(open, elements, failImmediately, token).ConfigureAwait(false);
	}

	private ResponseSegment? HandleCancel(SmbConnection connection, Smb2Header header, ReadOnlySpan<byte> segment)
	{
		CancelMessage.ParseRequest(segment, 64);
		if (!header.IsAsync && connection.OrdinaryRequests.TryGetValue(header.MessageId, out var ordinary)) SafeCleanup(ordinary.Cancel);
		var pending = header.IsAsync ? FindPendingByAsyncId(connection, header.AsyncId) : connection.PendingRequests.GetValueOrDefault(header.MessageId);
		if (pending != null) SafeCleanup(pending.Cancel);
		return null;
	}

	private static PendingAsyncRequest? FindPendingByAsyncId(SmbConnection connection, ulong asyncId)
	{
		return connection.AsyncRequests.GetValueOrDefault(asyncId);
	}

	private ResponseSegment LockResultSegment(Smb2Header header, SmbSession session, LockOutcome outcome)
	{
		return outcome switch
		{
			LockOutcome.Granted => MaybeSigned(session, RespHeader(header, session), LockMessage.BuildResponseBody()),
			LockOutcome.RangeNotLocked => BuildError(header, NtStatus.RangeNotLocked),
			LockOutcome.Cancelled => BuildError(header, NtStatus.Cancelled),
			LockOutcome.InvalidParameter => BuildError(header, NtStatus.InvalidParameter),
			_ => BuildError(header, NtStatus.LockNotGranted),
		};
	}

	private ResponseSegment InterimResponse(Smb2Header header, SmbSession session, ulong asyncId)
	{
		var smb2Header = header.CreateResponse(NtStatus.Pending);
		smb2Header.Flags |= Smb2HeaderFlags.AsyncCommand;
		smb2Header.AsyncId = asyncId;
		smb2Header.SessionId = session.SessionId;
		smb2Header.CreditRequestResponse = CreditManager.ComputeCreditGrant(header.CreditRequestResponse, _server.Options.MaxCreditsPerResponse);
		return ResponseSegment.Unsigned(smb2Header, ErrorResponse.BuildBody());
	}


	private void ReleaseLocks(SmbConnection connection, SmbOpen open)
	{
		_server.Options.LockManager.ReleaseOwner(open);
		foreach (var pendingRequest in connection.PendingRequests)
		{
			if (pendingRequest.Value.Owner == open)
			{
				pendingRequest.Value.Cancel();
			}
		}
	}

	private ResponseSegment HandleChangeNotify(SmbConnection connection, Smb2Header header, ReadOnlySpan<byte> segment, ReadOnlySpan<byte> resolved, bool frameEncrypted)
	{
		if (!TryGetValidSession(connection, header.SessionId, out var session))
		{
			return BuildError(header, NtStatus.UserSessionDeleted);
		}

		if (!VerifyInboundSignature(connection, session, header, segment, frameEncrypted))
		{
			return BuildError(header, NtStatus.AccessDenied);
		}

		var req = ChangeNotifyMessage.ParseRequest(resolved, 64);
		if (req.OutputBufferLength > connection.MaxTransactSize) return BuildError(header, NtStatus.InvalidParameter);

		if (!TryGetOpen(session, req.PersistentId, req.VolatileId, out var open))
		{
			return BuildError(header, NtStatus.FileClosed);
		}

		if (open.LocalOpen == null || !open.LocalOpen.IsDirectory)
		{
			return BuildError(header, NtStatus.InvalidParameter);
		}

		if ((open.GrantedAccess & FileReadData) == 0) return BuildError(header, NtStatus.AccessDenied);
		var physicalPath = open.LocalOpen.PhysicalPath;
		if (physicalPath == null)
		{
			return BuildError(header, NtStatus.NotSupported);
		}

		DirectoryNotificationState state;
		lock (open.NotificationGate)
			state = open.Notifications ??= new DirectoryNotificationState(_server.Options.DirectoryWatcher, physicalPath, req.WatchTree, req.CompletionFilter, req.OutputBufferLength);
		if (state.TryTake(req.OutputBufferLength, out var immediate))
		{
			var responseHeader = RespHeader(header, session);
			responseHeader.Status = immediate.Status;
			return MaybeSigned(session, responseHeader, immediate.Body);
		}

		var pending = RegisterPending(connection, header, open, (NtStatus)0x10b);
		if (pending == null) return BuildError(header, NtStatus.InsufficientResources);

		pending.Attach(pending.Token.Register(() => Complete(pending.CancellationStatus, ErrorResponse.BuildBody())));
		pending.Attach(state.Wait(req.OutputBufferLength, result => Complete(result.Status, result.Body)));
		if (!state.Initialize())
		{
			pending.Abandon();
			return BuildError(header, NtStatus.NotSupported);
		}

		return InterimResponse(header, session, pending.AsyncId);

		void Complete(NtStatus status, byte[] body) => pending.Complete(status, body, () => SendAsyncFinalAsync(connection, header, session, pending.AsyncId, status, body, ResponseNeedsEncryption(session, open)));
	}

	private PendingAsyncRequest? RegisterPending(SmbConnection connection, Smb2Header header, SmbOpen open, NtStatus? closeStatus = null)
	{
		if (connection.PendingRequests.TryGetValue(header.MessageId, out var reserved) && reserved.ReservedForContinuation)
		{
			reserved.ReservedForContinuation = false;
			reserved.Owner = open;
			return reserved;
		}

		if (connection.PendingRequests.Count >= _server.Options.MaxOutstandingRequests) return null;

		var pending = new PendingAsyncRequest { MessageId = header.MessageId, AsyncId = connection.AllocateAsyncId(), Owner = open, CloseStatus = closeStatus };
		if (!connection.RegisterPending(pending)) return null;

		if (open.Lifetime.State != OpenState.Active) pending.CancelForClose();
		return pending;
	}

	private ResponseSegment BeginWitnessAsyncNotify(SmbConnection connection, Smb2Header header, SmbSession session, SmbOpen open, WitnessRegistration registration, uint callId, ulong persistentId, ulong volatileId, uint maxOutput)
	{
		var pending = RegisterPending(connection, header, open);
		if (pending == null) return BuildError(header, NtStatus.InsufficientResources);

		pending.Attach(pending.Token.Register(() => Complete(pending.CancellationStatus, ErrorResponse.BuildBody())));
		pending.Attach(registration.Notifications.Wait(n =>
		{
			open.Pipe!.QueueOutput(WitnessEndpoint.BuildAsyncNotifyPdu(callId, n));
			var data = open.Pipe.TakeOutput((int)Math.Min(maxOutput, int.MaxValue), out _, out var more);
			Complete(more ? NtStatus.BufferOverflow : NtStatus.Success, IoctlMessage.BuildResponseBody(1163287u, persistentId, volatileId, data));
		}));
		return InterimResponse(header, session, pending.AsyncId);

		void Complete(NtStatus status, byte[] body) => pending.Complete(status, body, () => SendAsyncFinalAsync(connection, header, session, pending.AsyncId, status, body, ResponseNeedsEncryption(session, open)));
	}

	private async Task SendAsyncFinalAsync(SmbConnection connection, Smb2Header request, SmbSession session, ulong asyncId, NtStatus status, byte[] body, bool encrypt)
	{
		var smb2Header = request.CreateResponse(status);
		smb2Header.Flags |= Smb2HeaderFlags.AsyncCommand | (request.Flags & Smb2HeaderFlags.RelatedOperations);
		smb2Header.AsyncId = asyncId;
		smb2Header.SessionId = session.SessionId;
		smb2Header.CreditRequestResponse = 0;
		var segment = SignedLikeRequest(session, request, smb2Header, body);
		await SendOutOfBandAsync(session, connection, segment, encrypt).ConfigureAwait(continueOnCapturedContext: false);
	}

	private ArmedBreaks ArmOplockBreaks(IReadOnlyList<OplockBreak> breaks, bool track)
	{
		if (breaks.Count == 0)
		{
			return ArmedBreaks.None;
		}

		List<Task<BreakOutcome>> list = null;
		foreach (var @break in breaks)
		{
			var flag = OplockAckRequired(@break.Holder.OplockLevel);
			@break.Holder.OplockLevel = @break.NewLevel;
			if (track & flag)
			{
				var breaks2 = _breaks;
				if (breaks2 != null)
				{
					(list ??= new List<Task<BreakOutcome>>()).Add(breaks2.RegisterOplockBreak(@break.Holder));
				}
			}
		}

		return new ArmedBreaks(breaks, Array.Empty<LeaseBreak>(), (list == null) ? null : Task.WhenAll(list));
	}

	private static bool OplockAckRequired(OplockLevel fromLevel)
	{
		if (fromLevel - 8 <= OplockLevel.LevelII)
		{
			return true;
		}

		return false;
	}

	private async Task SendArmedBreaksAsync(ArmedBreaks armed)
	{
		foreach (var oplock in armed.Oplocks)
		{
			await SendOplockBreakAsync(oplock).ConfigureAwait(continueOnCapturedContext: false);
		}

		foreach (var lease in armed.Leases)
		{
			await SendLeaseBreakAsync(lease).ConfigureAwait(continueOnCapturedContext: false);
		}
	}

	private void DispatchOplockBreaks(IReadOnlyList<OplockBreak> breaks)
	{
		_ = SendArmedBreaksAsync(ArmOplockBreaks(breaks, track: false));
	}

	public async Task SendShutdownBreaksAsync()
	{
		var list = new List<Task>();
		foreach (var value in _server.SessionGlobalList.Values)
		{
			if (value.State != SessionState.Valid)
			{
				continue;
			}

			foreach (var value2 in value.Opens.Values)
			{
				switch (value2.OplockLevel)
				{
					case OplockLevel.LevelII:
					case OplockLevel.Exclusive:
					case OplockLevel.Batch:
						list.Add(SendOplockBreakAsync(new OplockBreak(value2, OplockLevel.None)));
						break;
					case OplockLevel.Lease:
						if (value2.LeaseState != LeaseState.None)
						{
							list.Add(SendLeaseBreakAsync(new LeaseBreak(value2.LeaseKey, value2.LeaseState, LeaseState.None, (ushort)(value2.LeaseEpoch + 1), value2)));
						}

						break;
				}
			}
		}

		if (list.Count > 0)
		{
			await Task.WhenAll(list).ConfigureAwait(continueOnCapturedContext: false);
		}
	}

	private async Task SendOplockBreakAsync(OplockBreak brk)
	{
		var holder = brk.Holder;
		var session = holder.Session;
		var header = new Smb2Header
		{
			Command = SmbCommand.OplockBreak,
			MessageId = UnsolicitedMessageId,
			Flags = Smb2HeaderFlags.ServerToRedir,
			Status = NtStatus.Success,
			SessionId = session!.SessionId,
			TreeId = 0,
			CreditRequestResponse = 0,
		};
		var body = OplockBreakMessage.BuildBody(brk.NewLevel, holder.PersistentFileId, holder.VolatileFileId);
		await SendOutOfBandAsync(session, session.Connection, MaybeSigned(session, header, body), ResponseNeedsEncryption(session, holder), useSurvivingChannel: true).ConfigureAwait(continueOnCapturedContext: false);
	}

	private ResponseSegment HandleOplockBreak(SmbConnection connection, Smb2Header header, ReadOnlySpan<byte> segment, bool frameEncrypted)
	{
		if (segment.Length >= 66 && BinaryPrimitives.ReadUInt16LittleEndian(segment.Slice(64, 2)) == 36)
		{
			return HandleLeaseBreakAck(connection, header, segment, frameEncrypted);
		}

		if (!TryGetValidSession(connection, header.SessionId, out var session))
		{
			return BuildError(header, NtStatus.UserSessionDeleted);
		}

		if (!VerifyInboundSignature(connection, session, header, segment, frameEncrypted))
		{
			return BuildError(header, NtStatus.AccessDenied);
		}

		OplockBreakMessage.Acknowledgment acknowledgment;
		try
		{
			acknowledgment = OplockBreakMessage.ParseAcknowledgment(segment, 64);
		}
		catch (SmbWireFormatException)
		{
			return BuildError(header, NtStatus.NotSupported);
		}

		if (!TryGetOpen(session, acknowledgment.PersistentId, acknowledgment.VolatileId, out var open))
		{
			return BuildError(header, NtStatus.FileClosed);
		}

		var status = _server.Options.CacheCoordinator.Acknowledge(open, acknowledgment.OplockLevel, out var oplockLevel);
		if (status != NtStatus.Success) return BuildError(header, status);

		var body = OplockBreakMessage.BuildBody(oplockLevel, open.PersistentFileId, open.VolatileFileId);
		return MaybeSigned(session, RespHeader(header, session), body);
	}
}
