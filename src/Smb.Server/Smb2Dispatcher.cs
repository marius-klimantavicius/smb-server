using System;
using System.Buffers.Binary;
using System.Collections.Generic;
using System.Diagnostics;
using System.Diagnostics.CodeAnalysis;
using System.IO;
using System.Linq;
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
	public readonly struct PreparedFrame
	{
		internal Smb2Header Header { get; }

		internal ReadOnlyMemory<byte> Message { get; }

		internal bool Encrypted { get; }

		internal bool NeedsReservation { get; }

		internal (ulong Persistent, ulong Volatile) ScopeKey { get; }

		internal LockMode ScopeMode { get; }

		internal KeyedReaderWriterQueue<(ulong Persistent, ulong Volatile)>.Reservation? Reservation { get; }

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
			return new PreparedFrame(Header, Message, Encrypted, NeedsReservation, ScopeKey, ScopeMode, reservation);
		}
	}

	private readonly struct ResponseSegment
	{
		public Smb2Header Header { get; }

		public byte[] Body { get; }

		public bool Sign { get; }

		public SmbSession? SigningSession { get; }

		private ResponseSegment(Smb2Header header, byte[] body, bool sign, SmbSession? session)
		{
			Header = header;
			Body = body;
			Sign = sign;
			SigningSession = session;
		}

		public static ResponseSegment Unsigned(Smb2Header header, byte[] body)
		{
			return new ResponseSegment(header, body, sign: false, null);
		}

		public static ResponseSegment Signed(Smb2Header header, byte[] body, SmbSession session)
		{
			return new ResponseSegment(header, body, sign: true, session);
		}
	}

	private sealed class NotifyOnce
	{
		private readonly Lock _gate = new Lock();

		private int _fired;

		private IDisposable? _subscription;

		private bool _disposeRequested;

		public bool TryFire()
		{
			if (Interlocked.Exchange(ref _fired, 1) != 0)
			{
				return false;
			}

			lock (_gate)
			{
				_disposeRequested = true;
				_subscription?.Dispose();
				_subscription = null;
			}

			return true;
		}

		public void Attach(IDisposable? subscription)
		{
			lock (_gate)
			{
				if (_disposeRequested)
				{
					subscription?.Dispose();
				}
				else
				{
					_subscription = subscription;
				}
			}
		}
	}

	private readonly record struct ArmedBreaks(IReadOnlyList<OplockBreak> Oplocks, IReadOnlyList<LeaseBreak> Leases, Task<BreakOutcome[]>? Wait)
	{
		public static readonly ArmedBreaks None = new ArmedBreaks(Array.Empty<OplockBreak>(), Array.Empty<LeaseBreak>(), null);
	}

	private readonly KeyedReaderWriterQueue<(ulong Persistent, ulong Volatile)> _opScopes = new KeyedReaderWriterQueue<(ulong, ulong)>();

	private readonly SmbServerState _server;

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

		frame = new PreparedFrame(smb2Header, message, transportEncrypted, needsReservation, scopeKey, scopeMode);
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
				using (await reservation.GetValueOrDefault().AcquireAsync(cancellationToken).ConfigureAwait(continueOnCapturedContext: false))
				{
					responseSegment = await DispatchOneAsync(connection, header, frame.Message, frame.Encrypted, preValidated: true, standalone: true).ConfigureAwait(continueOnCapturedContext: false);
				}
			}
			else
			{
				responseSegment = await DispatchOneAsync(connection, header, frame.Message, frame.Encrypted, preValidated: true, standalone: true).ConfigureAwait(continueOnCapturedContext: false);
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
		var relatedSessionId = 0uL;
		var relatedTreeId = 0u;
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
			if (segmentLength < 64 || segmentLength > num)
			{
				_log?.Invoke($"[parse] invalid NextCommand={header.NextCommand} (remaining {num}) → INVALID_PARAMETER");
				segments.Add(BuildError(header, NtStatus.InvalidParameter));
				break;
			}

			var segment = message.Slice(offset, segmentLength);
			if (header.Flags.HasFlag(Smb2HeaderFlags.RelatedOperations))
			{
				header.SessionId = relatedSessionId;
				header.TreeId = relatedTreeId;
			}
			else
			{
				relatedSessionId = header.SessionId;
				relatedTreeId = header.TreeId;
			}

			_log?.Invoke($"[cmd] {header.Command} mid={header.MessageId} tid={header.TreeId} len={segment.Length} charge={header.CreditCharge}");
			ResponseSegment? responseSegment;
			using (var trace = _server.Options.Metrics.BeginCommand(header.Command))
			{
				var standalone = offset == 0 && header.NextCommand == 0 && !header.Flags.HasFlag(Smb2HeaderFlags.RelatedOperations);
				responseSegment = await DispatchOneAsync(connection, header, segment, transportEncrypted, preValidated: false, standalone).ConfigureAwait(continueOnCapturedContext: false);
				trace?.SetStatus(responseSegment?.Header.Status ?? NtStatus.Success);
			}

			_log?.Invoke($"[cmd] {header.Command} mid={header.MessageId} → {((!responseSegment.HasValue) ? "(no response)" : responseSegment.GetValueOrDefault().Header.Status.ToString())}");
			if (responseSegment.HasValue)
			{
				var valueOrDefault = responseSegment.GetValueOrDefault();
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

	private async ValueTask<ResponseSegment?> DispatchOneAsync(SmbConnection connection, Smb2Header header, ReadOnlyMemory<byte> segment, bool frameEncrypted, bool preValidated = false, bool standalone = false)
	{
		_ = 9;
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

			SetAmbientCaller(connection, header);
			return header.Command switch
			{
				SmbCommand.Negotiate => HandleNegotiate(connection, header, segment.Span),
				SmbCommand.SessionSetup => HandleSessionSetup(connection, header, segment.Span),
				SmbCommand.TreeConnect => await HandleTreeConnectAsync(connection, header, segment, frameEncrypted).ConfigureAwait(continueOnCapturedContext: false),
				SmbCommand.TreeDisconnect => HandleTreeDisconnect(connection, header, segment.Span, frameEncrypted),
				SmbCommand.Logoff => HandleLogoff(connection, header, segment.Span, frameEncrypted),
				SmbCommand.Echo => HandleEcho(connection, header, segment.Span, frameEncrypted),
				SmbCommand.Create => await HandleCreateAsync(connection, header, segment, frameEncrypted, standalone).ConfigureAwait(continueOnCapturedContext: false),
				SmbCommand.Close => await HandleCloseAsync(connection, header, segment, frameEncrypted).ConfigureAwait(continueOnCapturedContext: false),
				SmbCommand.Read => await HandleReadAsync(connection, header, segment, frameEncrypted).ConfigureAwait(continueOnCapturedContext: false),
				SmbCommand.Write => await HandleWriteAsync(connection, header, segment, frameEncrypted).ConfigureAwait(continueOnCapturedContext: false),
				SmbCommand.QueryDirectory => await HandleQueryDirectoryAsync(connection, header, segment, frameEncrypted).ConfigureAwait(continueOnCapturedContext: false),
				SmbCommand.QueryInfo => await HandleQueryInfoAsync(connection, header, segment, frameEncrypted).ConfigureAwait(continueOnCapturedContext: false),
				SmbCommand.SetInfo => await HandleSetInfoAsync(connection, header, segment, frameEncrypted).ConfigureAwait(continueOnCapturedContext: false),
				SmbCommand.Flush => await HandleFlushAsync(connection, header, segment, frameEncrypted).ConfigureAwait(continueOnCapturedContext: false),
				SmbCommand.Ioctl => await HandleIoctlAsync(connection, header, segment, frameEncrypted).ConfigureAwait(continueOnCapturedContext: false),
				SmbCommand.Lock => HandleLock(connection, header, segment.Span, frameEncrypted),
				SmbCommand.Cancel => HandleCancel(connection, header, segment.Span),
				SmbCommand.ChangeNotify => HandleChangeNotify(connection, header, segment.Span, frameEncrypted),
				SmbCommand.OplockBreak => HandleOplockBreak(connection, header, segment.Span, frameEncrypted),
				_ => BuildError(header, NtStatus.NotSupported),
			};
		}
		catch (SmbWireFormatException ex)
		{
			_log?.Invoke($"[parse] {header.Command} → INVALID_PARAMETER: {ex.Message}; Bytes: {Hex(segment.Span)}");
			return BuildError(header, NtStatus.InvalidParameter);
		}
		catch (Exception ex2)
		{
			_log?.Invoke($"[error] {header.Command} mid={header.MessageId} → {ex2.GetType().Name}: {ex2.Message}");
			return BuildError(header, MapException(ex2));
		}
		finally
		{
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

	private static bool ValidateSequence(SmbConnection connection, Smb2Header header)
	{
		if (!connection.NegotiateDone)
		{
			return true;
		}

		var command = header.Command;
		if ((command == SmbCommand.Negotiate || command == SmbCommand.Cancel))
		{
			return true;
		}

		if (header.Flags.HasFlag(Smb2HeaderFlags.RelatedOperations))
		{
			return true;
		}

		var num = Math.Max(header.CreditCharge, (ushort)1);
		var sequenceWindowStart = connection.SequenceWindowStart;
		var windowSize = (connection.SequenceWindowSize == 0L) ? 1 : connection.SequenceWindowSize;
		if (!CreditManager.IsWithinWindow(header.MessageId, sequenceWindowStart, windowSize) || !CreditManager.IsWithinWindow(header.MessageId + num - 1, sequenceWindowStart, windowSize))
		{
			return false;
		}

		var num2 = header.MessageId + num;
		if (num2 > connection.SequenceWindowStart)
		{
			connection.SequenceWindowStart = num2;
		}

		return true;
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
		connection.SequenceWindowStart = 1uL;
		connection.SequenceWindowSize = _server.Options.MaxCreditsPerResponse;
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

	private ResponseSegment HandleNegotiate(SmbConnection connection, Smb2Header header, ReadOnlySpan<byte> segment)
	{
		if (connection.NegotiateDone)
		{
			return BuildError(header, NtStatus.InvalidParameter);
		}

		var negotiateRequest = NegotiateRequest.Parse(segment, 64);
		if (negotiateRequest.OffersSmb311 && !HasSupportedPreauthContext(negotiateRequest))
		{
			return BuildError(header, NtStatus.InvalidParameter);
		}

		var securityBuffer = _server.Options.SpnegoNegotiator!.CreateInitialServerToken();
		var negotiateResponse = NegotiateProcessor.BuildResponse(connection, negotiateRequest, _server.Options, securityBuffer);
		connection.NegotiateDone = true;
		connection.SequenceWindowStart = header.MessageId + 1;
		connection.SequenceWindowSize = _server.Options.MaxCreditsPerResponse;
		var smb2Header = header.CreateResponse(NtStatus.Success);
		smb2Header.CreditRequestResponse = CreditManager.ComputeCreditGrant(header.CreditRequestResponse, _server.Options.MaxCreditsPerResponse);
		var array = negotiateResponse.ToBody();
		if (connection.Dialect == SmbDialect.Smb311)
		{
			connection.PreauthHash.Append(segment);
			var array2 = Concat(smb2Header.ToArray(), array);
			connection.PreauthHash.Append(array2);
		}

		return ResponseSegment.Unsigned(smb2Header, array);
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

	private ResponseSegment HandleSessionSetup(SmbConnection connection, Smb2Header header, ReadOnlySpan<byte> segment)
	{
		if (!connection.NegotiateDone)
		{
			return BuildError(header, NtStatus.InvalidParameter);
		}

		var sessionSetupRequest = SessionSetupRequest.Parse(segment, 64);
		var flag = connection.Dialect == SmbDialect.Smb311;
		if (sessionSetupRequest.Flags.HasFlag(SessionSetupFlags.Binding))
		{
			return HandleSessionBinding(connection, header, sessionSetupRequest, segment, flag);
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

		if (header.SessionId != 0L && value.State == SessionState.Valid)
		{
			return BuildError(header, NtStatus.AccessDenied);
		}

		value.PreauthHash?.Append(segment);
		var gssResult = value.AuthContext!.Accept(sessionSetupRequest.SecurityBuffer);
		if (gssResult.NeedsMoreProcessing)
		{
			var sessionSetupResponse = new SessionSetupResponse
			{
				SecurityBuffer = (gssResult.OutToken ?? Array.Empty<byte>()),
			};
			var smb2Header = BuildSessionHeader(header, value, NtStatus.MoreProcessingRequired);
			var array = sessionSetupResponse.ToBody();
			if (flag)
			{
				var array2 = Concat(smb2Header.ToArray(), array);
				value.PreauthHash?.Append(array2);
			}

			return ResponseSegment.Unsigned(smb2Header, array);
		}

		if (!gssResult.IsSuccess)
		{
			_server.Options.Metrics.OnAuthenticationFailed();
			Audit(SmbAuditEventType.AuthenticationFailed, SmbLogLevel.Warning, connection, null, null, null, gssResult.Status);
			CleanupFailedSession(connection, value);
			return BuildError(header, gssResult.Status);
		}

		ApplyIdentity(value, gssResult);
		if (RejectByPolicy(value, out var status))
		{
			CleanupFailedSession(connection, value);
			return BuildError(header, status);
		}

		DeriveSessionKeys(connection, value, gssResult.SessionKey!);
		if (_server.Options.RequireEncryption && (!connection.Dialect.IsSmb3OrLater() || !connection.SupportsEncryption))
		{
			CleanupFailedSession(connection, value);
			return BuildError(header, NtStatus.AccessDenied);
		}

		value.State = SessionState.Valid;
		value.LastActivityTicks = _server.Options.TimeProvider.GetUtcNow().Ticks;
		_server.Options.Metrics.OnAuthenticationSucceeded();
		Audit(SmbAuditEventType.AuthenticationSucceeded, SmbLogLevel.Information, connection, DescribeIdentity(value.Identity));
		if (connection.Dialect.IsSmb3OrLater())
		{
			value.Channels[connection.ConnectionId] = new SmbChannel
			{
				Connection = connection,
				SigningKey = value.SigningKey,
			};
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
		var header2 = BuildSessionHeader(header, value, NtStatus.Success);
		var body = sessionSetupResponse2.ToBody();
		if (!value.SigningRequired || value.IsGuest || value.IsAnonymous)
		{
			return ResponseSegment.Unsigned(header2, body);
		}

		return ResponseSegment.Signed(header2, body, value);
	}

	private ResponseSegment HandleSessionBinding(SmbConnection connection, Smb2Header header, SessionSetupRequest request, ReadOnlySpan<byte> segment, bool is311)
	{
		if (!connection.Dialect.IsSmb3OrLater())
		{
			return BuildError(header, NtStatus.RequestNotAccepted);
		}

		if (header.SessionId == 0L || !_server.SessionGlobalList.TryGetValue(header.SessionId, out var value))
		{
			return BuildError(header, NtStatus.UserSessionDeleted);
		}

		if (connection.Sessions.ContainsKey(value.SessionId))
		{
			return BuildError(header, NtStatus.RequestNotAccepted);
		}

		if (value.State != SessionState.Valid)
		{
			return BuildError(header, NtStatus.InvalidParameter);
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
			return BuildError(header, NtStatus.AccessDenied);
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
			var smb2Header = BuildSessionHeader(header, value, NtStatus.MoreProcessingRequired);
			var array = sessionSetupResponse.ToBody();
			if (is311)
			{
				orAdd.PreauthHash?.Append(Concat(smb2Header.ToArray(), array));
			}

			return ResponseSegment.Signed(smb2Header, array, value);
		}

		if (!gssResult.IsSuccess)
		{
			connection.PendingBindings.TryRemove(value.SessionId, out _);
			return BuildError(header, gssResult.Status);
		}

		if (!SameIdentity(value.Identity, gssResult.Identity))
		{
			connection.PendingBindings.TryRemove(value.SessionId, out _);
			return BuildError(header, NtStatus.AccessDenied);
		}

		connection.PendingBindings.TryRemove(value.SessionId, out _);
		var signingKey = DeriveChannelSigningKey(connection, value, orAdd.PreauthHash);
		value.Channels[connection.ConnectionId] = new SmbChannel
		{
			Connection = connection,
			SigningKey = signingKey,
		};
		connection.Sessions[value.SessionId] = value;
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
		var header2 = BuildSessionHeader(header, value, NtStatus.Success);
		var body = sessionSetupResponse2.ToBody();
		return ResponseSegment.Signed(header2, body, value);
	}

	private static byte[] DeriveChannelSigningKey(SmbConnection connection, SmbSession session, PreauthIntegrityHash? channelPreauth)
	{
		var array = channelPreauth?.Value ?? new byte[64];
		return Smb3KeyDerivation.Derive(connection.Dialect, connection.CipherId, session.SessionKey, session.FullSessionKey, array).SigningKey;
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

	private Smb2Header BuildSessionHeader(Smb2Header request, SmbSession session, NtStatus status)
	{
		var smb2Header = request.CreateResponse(status);
		smb2Header.SessionId = session.SessionId;
		smb2Header.CreditRequestResponse = CreditManager.ComputeCreditGrant(request.CreditRequestResponse, _server.Options.MaxCreditsPerResponse);
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

	private async ValueTask<ResponseSegment> HandleTreeConnectAsync(SmbConnection connection, Smb2Header header, ReadOnlyMemory<byte> segment, bool frameEncrypted)
	{
		if (!TryGetValidSession(connection, header.SessionId, out var session))
		{
			return BuildError(header, NtStatus.UserSessionDeleted);
		}

		if (!VerifyInboundSignature(connection, session, header, segment.Span, frameEncrypted))
		{
			return BuildError(header, NtStatus.AccessDenied);
		}

		var treeConnectRequest = TreeConnectRequest.Parse(segment.Span, 64);
		var shareName = treeConnectRequest.ShareName;
		if (!_server.Shares.TryGet(shareName, out var share))
		{
			return BuildError(header, NtStatus.BadNetworkName);
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

		var num = connection.AllocateTreeId();
		var smbTreeConnect = new SmbTreeConnect
		{
			TreeId = num,
			Session = session,
			Share = share,
			MaximalAccess = (uint)shareAccessResult.MaximalAccess,
			EncryptData = encryptData,
		};
		session.TreeConnects[num] = smbTreeConnect;
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

		if (share.ContinuousAvailability && connection.Dialect.IsSmb3OrLater())
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

	private ResponseSegment HandleTreeDisconnect(SmbConnection connection, Smb2Header header, ReadOnlySpan<byte> segment, bool frameEncrypted)
	{
		if (!TryGetValidSession(connection, header.SessionId, out var session))
		{
			return BuildError(header, NtStatus.UserSessionDeleted);
		}

		if (!VerifyInboundSignature(connection, session, header, segment, frameEncrypted))
		{
			return BuildError(header, NtStatus.AccessDenied);
		}

		if (session.TreeConnects.TryRemove(header.TreeId, out _))
		{
			_server.Options.Metrics.OnTreeDisconnected();
		}

		var smb2Header = header.CreateResponse(NtStatus.Success);
		smb2Header.CreditRequestResponse = CreditManager.ComputeCreditGrant(header.CreditRequestResponse, _server.Options.MaxCreditsPerResponse);
		return MaybeSigned(session, smb2Header, TreeDisconnectMessage.BuildResponseBody());
	}

	private ResponseSegment HandleLogoff(SmbConnection connection, Smb2Header header, ReadOnlySpan<byte> segment, bool frameEncrypted)
	{
		if (!TryGetValidSession(connection, header.SessionId, out var session))
		{
			return BuildError(header, NtStatus.UserSessionDeleted);
		}

		if (!VerifyInboundSignature(connection, session, header, segment, frameEncrypted))
		{
			return BuildError(header, NtStatus.AccessDenied);
		}

		Audit(SmbAuditEventType.SessionLogoff, SmbLogLevel.Information, connection, DescribeIdentity(session.Identity));
		_server.Options.Metrics.OnSessionClosed();
		CloseSessionOpens(session);
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

		return ResponseSegment.Signed(response.Header, response.Body, session);
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

	private static async Task SendOutOfBandAsync(SmbSession session, SmbConnection? preferred, ResponseSegment segment, bool encrypt)
	{
		var smbConnection = session.SelectSendChannel(preferred);
		var func = smbConnection?.SendRawAsync;
		if (func == null)
		{
			return;
		}

		var arg = AssembleResponse(smbConnection, new List<ResponseSegment>(1) { segment });
		try
		{
			await func(arg, encrypt).ConfigureAwait(continueOnCapturedContext: false);
		}
		catch
		{
			// ignored
		}
	}

	private static byte[] AssembleResponse(SmbConnection connection, List<ResponseSegment> segments)
	{
		var growableWriter = new GrowableWriter();
		for (var i = 0; i < segments.Count; i++)
		{
			var responseSegment = segments[i];
			var flag = i == segments.Count - 1;
			var position = growableWriter.Position;
			var num = 64 + responseSegment.Body.Length;
			var num2 = (flag ? num : Align8(num));
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
				if (signingSession != null)
				{
					var message = growableWriter.WrittenSpan.Slice(position, num2);
					var header = responseSegment.Header;
					header.Flags |= Smb2HeaderFlags.Signed;
					growableWriter.PatchUInt32(position + 16, (uint)header.Flags);
					Smb2Signer.SignInPlace(Smb2Signer.ResolveAlgorithm(connection.Dialect, connection.SigningAlgorithmId), signingSession.SigningKeyFor(connection), message, header.MessageId, isServer: true, isCancel: false);
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

	private async ValueTask<ResponseSegment?> HandleCreateAsync(SmbConnection connection, Smb2Header header, ReadOnlyMemory<byte> segment, bool frameEncrypted, bool standalone)
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

		if (tree.Share.Type == ShareType.Pipe)
		{
			return await HandlePipeCreateAsync(connection, header, session, tree, segment).ConfigureAwait(continueOnCapturedContext: false);
		}

		var store = tree.Share.FileStore;
		if (store == null)
		{
			return BuildError(header, NtStatus.NotSupported);
		}

		var request = CreateRequest.Parse(segment.Span, 64);
		var createContext = CreateContextList.Find(request.Contexts, 1145582147u);
		if (createContext != null)
		{
			return await HandleDurableReconnectV2Async(header, session, tree, createContext).ConfigureAwait(continueOnCapturedContext: false);
		}

		var createContext2 = CreateContextList.Find(request.Contexts, 1145597507u);
		if (createContext2 != null)
		{
			return await HandleDurableReconnectAsync(header, session, tree, createContext2).ConfigureAwait(continueOnCapturedContext: false);
		}

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
		var flag = TrySplitStreamName(request.Name, out var baseName, out var streamName);
		var effectiveName = (flag ? baseName : request.Name);
		var namedStream = flag && streamName.Length > 0;
		if (namedStream && !(store is INamedStreamStore))
		{
			return BuildError(header, NtStatus.NotSupported);
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

		var maxOpenHandlesPerSession = _server.Options.MaxOpenHandlesPerSession;
		if (maxOpenHandlesPerSession > 0 && session.Opens.Count >= maxOpenHandlesPerSession)
		{
			return BuildError(header, NtStatus.InsufficientResources);
		}

		var volatileFileId = connection.AllocateFileId();
		var open = new SmbOpen
		{
			PersistentFileId = 0uL,
			VolatileFileId = volatileFileId,
			Session = session,
			TreeConnect = tree,
			GrantedAccess = grantedAccess,
			ShareAccess = request.ShareAccess,
			PathName = request.Name,
		};
		var shareKey = ShareModeKey(tree, request.Name);
		if (!_server.Options.ShareModeManager.TryOpen(shareKey, open, access, MapShare(request.ShareAccess)))
		{
			return BuildError(header, NtStatus.SharingViolation);
		}

		open.ShareModeKey = shareKey;
		var fileStoreResult = ((!namedStream) ? (await store.CreateAsync(effectiveName, access, disposition, dirRequired, nonDirRequired).ConfigureAwait(continueOnCapturedContext: false)) : (await ((INamedStreamStore)store).OpenNamedStreamAsync(baseName, streamName, access, disposition).ConfigureAwait(continueOnCapturedContext: false)));
		var fileStoreResult2 = fileStoreResult;
		if (!fileStoreResult2.IsSuccess)
		{
			_server.Options.ShareModeManager.Close(shareKey, open);
			return BuildError(header, fileStoreResult2.Status);
		}

		var handle = fileStoreResult2.Value.Handle;
		var outcome = fileStoreResult2.Value.Action;
		open.LocalOpen = handle;
		var fileStoreResult3 = await store.GetSecurityAsync(handle).ConfigureAwait(continueOnCapturedContext: false);
		if (fileStoreResult3.IsSuccess)
		{
			var callerSids = BuildCallerSids(session.Identity);
			var desiredAccess = (maximumAllowed ? MaximumAllowed : AccessMask.MapGenericToSpecific(request.DesiredAccess));
			if (!AccessCheck.IsGranted(fileStoreResult3.Value, callerSids, desiredAccess, out var grantedAccess2))
			{
				await handle.DisposeAsync().ConfigureAwait(continueOnCapturedContext: false);
				_server.Options.ShareModeManager.Close(shareKey, open);
				return BuildError(header, NtStatus.AccessDenied);
			}

			grantedAccess = grantedAccess2;
		}
		else
		{
			grantedAccess = AccessMask.MapGenericToSpecific(grantedAccess);
		}

		open.GrantedAccess = grantedAccess;
		if (request.Options.HasFlag(CreateOptions.DeleteOnClose))
		{
			var delStatus = await store.SetDeleteOnCloseAsync(handle, delete: true).ConfigureAwait(continueOnCapturedContext: false);
			if (delStatus != NtStatus.Success)
			{
				await handle.DisposeAsync().ConfigureAwait(continueOnCapturedContext: false);
				_server.Options.ShareModeManager.Close(shareKey, open);
				return BuildError(header, delStatus);
			}

			open.DeleteOnClose = true;
		}

		session.Opens[open.Key] = open;
		Interlocked.Increment(ref tree.OpenCount);
		var responseCtxList = new List<CreateContext>();
		_ = ArmedBreaks.None;
		var createContext3 = CreateContextList.Find(request.Contexts, 1383156851u);
		ArmedBreaks armed;
		OplockLevel grantedOplock;
		if (createContext3 != null)
		{
			var leaseRequest = LeaseRequest.FromContext(createContext3);
			open.LeaseKey = leaseRequest.Key;
			open.ParentLeaseKey = leaseRequest.ParentKey;
			var leaseGrant = _server.Options.LeaseManager.RequestLease(open, leaseRequest);
			open.LeaseState = leaseGrant.GrantedState;
			open.LeaseEpoch = leaseGrant.Epoch;
			armed = ArmLeaseBreaks(leaseGrant.Breaks, track: true);
			grantedOplock = OplockLevel.Lease;
			responseCtxList.Add(new CreateContext
			{
				Name = createContext3.Name,
				Data = leaseRequest.SerializeResponse(leaseGrant.GrantedState, leaseGrant.Epoch),
			});
		}
		else
		{
			var oplockGrant = _server.Options.OplockManager.RequestOplock(open, request.RequestedOplockLevel);
			grantedOplock = oplockGrant.GrantedLevel;
			armed = ArmOplockBreaks(oplockGrant.Breaks, track: true);
		}

		open.OplockLevel = grantedOplock;
		var createContext4 = CreateContextList.Find(request.Contexts, 1145582161u);
		var createContext5 = CreateContextList.Find(request.Contexts, 1145597521u);
		if ((createContext4 != null || createContext5 != null) && DurabilityAllowed(grantedOplock, open.LeaseState))
		{
			session.Opens.TryRemove(open.Key, out _);
			open.PersistentFileId = _server.AllocatePersistentId();
			open.IsDurable = true;
			if (createContext4 != null)
			{
				var v2Request = DurableHandleMessages.ParseV2Request(createContext4.Data);
				open.DurableCreateGuid = v2Request.CreateGuid;
				open.IsPersistentHandle = v2Request.IsPersistent && tree.Share.ContinuousAvailability;
				open.DurableTimeout = ResolveDurableTimeout(v2Request.TimeoutMs);
				responseCtxList.Add(DurableHandleMessages.BuildV2ResponseContext((uint)open.DurableTimeout.TotalMilliseconds, open.IsPersistentHandle));
			}
			else
			{
				open.DurableTimeout = _server.Options.DurableHandleTimeout;
				responseCtxList.Add(DurableHandleMessages.BuildV1ResponseContext());
			}

			session.Opens[open.Key] = open;
			if (open.IsPersistentHandle && _server.Options.DurableHandleStore is IPersistentHandleStore persistentHandleStore)
			{
				persistentHandleStore.Persist(new PersistentHandleRecord(open.PersistentFileId, open.VolatileFileId, OwnerKey(session.Identity), open.DurableCreateGuid, tree.Share.Name, open.PathName, open.GrantedAccess, open.ShareAccess));
			}
		}

		if (outcome == CreateOutcome.Created && !namedStream)
		{
			BreakParentDirectoryLease(handle.PhysicalPath);
		}

		_server.Options.Metrics.OnHandleOpened();
		Audit(SmbAuditEventType.FileOpened, SmbLogLevel.Information, connection, DescribeIdentity(session.Identity), tree.Share.Name, request.Name);
		var wait = armed.Wait;
		if ((wait != null) & standalone)
		{
			return await ParkCreateBehindBreakAsync(connection, header, session, open, armed, wait, BuildCreateBodyAsync).ConfigureAwait(continueOnCapturedContext: false);
		}

		_ = SendArmedBreaksAsync(armed);
		var session2 = session;
		var header2 = RespHeader(header, session);
		return MaybeSigned(session2, header2, await BuildCreateBodyAsync().ConfigureAwait(continueOnCapturedContext: false));

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

	private async ValueTask<ResponseSegment?> ParkCreateBehindBreakAsync(SmbConnection connection, Smb2Header header, SmbSession session, SmbOpen open, ArmedBreaks armed, Task<BreakOutcome[]> breakWait, Func<ValueTask<byte[]>> buildBody)
	{
		if (connection.PendingRequests.Count >= _server.Options.MaxOutstandingRequests)
		{
			_ = SendArmedBreaksAsync(armed);
			var header2 = RespHeader(header, session);
			return MaybeSigned(session, header2, await buildBody().ConfigureAwait(continueOnCapturedContext: false));
		}

		var asyncId = connection.AllocateAsyncId();
		var pending = new PendingAsyncRequest
		{
			MessageId = header.MessageId,
			AsyncId = asyncId,
			Owner = open,
		};
		connection.PendingRequests[header.MessageId] = pending;
		var encrypt = ResponseNeedsEncryption(session, open);
		await SendOutOfBandAsync(session, connection, InterimResponse(header, session, asyncId), encrypt).ConfigureAwait(continueOnCapturedContext: false);
		await SendArmedBreaksAsync(armed).ConfigureAwait(continueOnCapturedContext: false);
		_ = CompleteParkedCreateAsync(connection, header, session, asyncId, pending, breakWait, buildBody, encrypt);
		return null;
	}

	private async Task CompleteParkedCreateAsync(SmbConnection connection, Smb2Header header, SmbSession session, ulong asyncId, PendingAsyncRequest pending, Task<BreakOutcome[]> breakWait, Func<ValueTask<byte[]>> buildBody, bool encrypt)
	{
		try
		{
			var array = await breakWait.ConfigureAwait(continueOnCapturedContext: false);
			if (!connection.PendingRequests.TryRemove(pending.MessageId, out _))
			{
				return;
			}

			if (Array.IndexOf(array, BreakOutcome.TimedOut) >= 0)
			{
				_log?.Invoke($"[oplock] break not acknowledged within {_server.Options.OplockBreakTimeout}; proceeding with CREATE mid={header.MessageId} (coherency degraded for the holder)");
			}

			await SendAsyncFinalAsync(connection, header, session, asyncId, NtStatus.Success, await buildBody().ConfigureAwait(continueOnCapturedContext: false), encrypt).ConfigureAwait(continueOnCapturedContext: false);
		}
		catch (Exception ex)
		{
			connection.PendingRequests.TryRemove(pending.MessageId, out _);
			_log?.Invoke($"[error] parked CREATE mid={header.MessageId} → {ex.GetType().Name}: {ex.Message}");
			try
			{
				await SendAsyncFinalAsync(connection, header, session, asyncId, MapException(ex), ErrorResponse.BuildBody(), encrypt).ConfigureAwait(continueOnCapturedContext: false);
			}
			catch
			{
				// ignored
			}
		}
	}

	private async ValueTask<ResponseSegment> HandlePipeCreateAsync(SmbConnection connection, Smb2Header header, SmbSession session, SmbTreeConnect tree, ReadOnlyMemory<byte> segment)
	{
		var request = CreateRequest.Parse(segment.Span, 64);
		var pipeName = request.Name.TrimStart('\\');
		var rpcEndpoint = await OpenRpcEndpointAsync(connection, session, pipeName).ConfigureAwait(continueOnCapturedContext: false);
		if (rpcEndpoint == null)
		{
			return BuildError(header, NtStatus.ObjectNameNotFound);
		}

		var pipe = new RpcPipe(rpcEndpoint);
		var volatileFileId = connection.AllocateFileId();
		var smbOpen = new SmbOpen
		{
			PersistentFileId = 0uL,
			VolatileFileId = volatileFileId,
			Session = session,
			TreeConnect = tree,
			Pipe = pipe,
			GrantedAccess = request.DesiredAccess,
			PathName = pipeName,
		};
		session.Opens[smbOpen.Key] = smbOpen;
		var createResponse = new CreateResponse
		{
			OplockLevel = OplockLevel.None,
			CreateAction = CreateAction.Opened,
			FileAttributes = 128u,
			PersistentFileId = smbOpen.PersistentFileId,
			VolatileFileId = smbOpen.VolatileFileId,
		};
		return MaybeSigned(session, RespHeader(header, session), createResponse.ToBody());
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

	private async ValueTask<ResponseSegment?> HandleIoctlAsync(SmbConnection connection, Smb2Header header, ReadOnlyMemory<byte> segment, bool frameEncrypted)
	{
		if (!TryGetValidSession(connection, header.SessionId, out var session))
		{
			return BuildError(header, NtStatus.UserSessionDeleted);
		}

		if (!VerifyInboundSignature(connection, session, header, segment.Span, frameEncrypted))
		{
			return BuildError(header, NtStatus.AccessDenied);
		}

		var req = IoctlMessage.ParseRequest(segment.Span, 64);
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
					return BeginWitnessAsyncNotify(connection, header, session, open, registration, callId, req.PersistentId, req.VolatileId);
				}

				var array = pipe.Transceive(req.Input);
				return MaybeSigned(session, RespHeader(header, session), IoctlMessage.BuildResponseBody(req.CtlCode, req.PersistentId, req.VolatileId, array));
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
			return await HandleCopyChunkAsync(header, session, req).ConfigureAwait(continueOnCapturedContext: false);
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

		var smbOpen = open;
		var array = CopyChunkMessage.BuildResumeKeyResponse(smbOpen.ResumeKey ?? (smbOpen.ResumeKey = RandomNumberGenerator.GetBytes(24)));
		return MaybeSigned(session, RespHeader(header, session), IoctlMessage.BuildResponseBody(req.CtlCode, req.PersistentId, req.VolatileId, array));
	}

	private async ValueTask<ResponseSegment> HandleCopyChunkAsync(Smb2Header header, SmbSession session, IoctlMessage.Request req)
	{
		if (!TryGetOpen(session, req.PersistentId, req.VolatileId, out var dest) || dest.LocalOpen == null)
		{
			return BuildError(header, NtStatus.FileClosed);
		}

		if (!TryGetFileStore(session, header.TreeId, out var destStore, out var error))
		{
			return BuildError(header, error);
		}

		if ((dest.GrantedAccess & 6) == 0)
		{
			return BuildError(header, NtStatus.AccessDenied);
		}

		var copyRequest = CopyChunkMessage.ParseCopyRequest(req.Input);
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

		var chunksWritten = 0u;
		var totalWritten = 0u;
		foreach (var chunk in copyRequest.Chunks)
		{
			var fileStoreResult = await CopyRangeAsync(sourceStore, source.LocalOpen, (long)chunk.SourceOffset, destStore, dest.LocalOpen, (long)chunk.TargetOffset, chunk.Length).ConfigureAwait(continueOnCapturedContext: false);
			if (!fileStoreResult.IsSuccess)
			{
				var smb2Header2 = RespHeader(header, session);
				smb2Header2.Status = fileStoreResult.Status;
				return MaybeSigned(session, smb2Header2, IoctlMessage.BuildResponseBody(req.CtlCode, req.PersistentId, req.VolatileId, CopyChunkMessage.BuildCopyResponse(chunksWritten, 0u, totalWritten)));
			}

			chunksWritten++;
			totalWritten += (uint)(int)fileStoreResult.Value;
		}

		var array = CopyChunkMessage.BuildCopyResponse(chunksWritten, 0u, totalWritten);
		return MaybeSigned(session, RespHeader(header, session), IoctlMessage.BuildResponseBody(req.CtlCode, req.PersistentId, req.VolatileId, array));
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
			if (chunk.Length > 1048576)
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

	private static async ValueTask<FileStoreResult<long>> CopyRangeAsync(IFileStore sourceStore, IFileHandle source, long sourceOffset, IFileStore destStore, IFileHandle destination, long destOffset, long length)
	{
		if (length <= 0)
		{
			return FileStoreResult<long>.Ok(0L);
		}

		if (sourceStore == destStore)
		{
			var result = await destStore.CopyRangeAsync(source, sourceOffset, destination, destOffset, length).ConfigureAwait(continueOnCapturedContext: false);
			if (result.Status != NtStatus.NotSupported)
			{
				return result;
			}
		}

		var buffer = new byte[(int)Math.Min(length, 65536L)];
		var remaining = length;
		var copied = 0L;
		while (remaining > 0)
		{
			var length2 = (int)Math.Min(remaining, buffer.Length);
			var read = await sourceStore.ReadAsync(source, sourceOffset + copied, buffer.AsMemory(0, length2)).ConfigureAwait(continueOnCapturedContext: false);
			if (!read.IsSuccess)
			{
				return FileStoreResult<long>.Fail(read.Status);
			}

			if (read.Value == 0)
			{
				break;
			}

			FileStoreResult<int> fileStoreResult;
			for (var off = 0; off < read.Value; off += fileStoreResult.Value)
			{
				fileStoreResult = await destStore.WriteAsync(destination, destOffset + copied + off, buffer.AsMemory(off, read.Value - off)).ConfigureAwait(continueOnCapturedContext: false);
				if (!fileStoreResult.IsSuccess)
				{
					return FileStoreResult<long>.Fail(fileStoreResult.Status);
				}

				if (fileStoreResult.Value == 0)
				{
					return FileStoreResult<long>.Fail(NtStatus.DiskFull);
				}
			}

			copied += read.Value;
			remaining -= read.Value;
		}

		return FileStoreResult<long>.Ok(copied);
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
				if ((uint)array.Length > req.MaxOutputResponse)
				{
					return BuildError(header, NtStatus.BufferTooSmall);
				}

				return IoctlResult(header, session, req, NtStatus.Success, array);
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
			if ((uint)value.Length > req.MaxOutputResponse)
			{
				return BuildError(header, NtStatus.BufferTooSmall);
			}

			return IoctlResult(header, session, req, NtStatus.Success, value);
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
		if (!_server.Options.EnableMultichannel || !connection.Dialect.IsSmb3OrLater())
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

	private async ValueTask<ResponseSegment> HandleCloseAsync(SmbConnection connection, Smb2Header header, ReadOnlyMemory<byte> segment, bool frameEncrypted)
	{
		if (!TryGetValidSession(connection, header.SessionId, out var session))
		{
			return BuildError(header, NtStatus.UserSessionDeleted);
		}

		if (!VerifyInboundSignature(connection, session, header, segment.Span, frameEncrypted))
		{
			return BuildError(header, NtStatus.AccessDenied);
		}

		var (num, persistent, volatileId) = CloseMessage.ParseRequest(segment.Span, 64);
		if (!TryGetOpen(session, persistent, volatileId, out var open))
		{
			return BuildError(header, NtStatus.FileClosed);
		}

		FileEntryInfo info = null;
		if ((num & 1) != 0 && open.LocalOpen != null)
		{
			info = await open.LocalOpen.GetInfoAsync().ConfigureAwait(continueOnCapturedContext: false);
		}

		session.Opens.TryRemove(open.Key, out _);
		ReleaseLocks(connection, open);
		_server.Options.OplockManager.ReleaseOwner(open);
		_server.Options.LeaseManager.ReleaseOwner(open);
		var shareModeKey = open.ShareModeKey;
		if (shareModeKey != null)
		{
			_server.Options.ShareModeManager.Close(shareModeKey, open);
		}

		if (open.IsPersistentHandle && _server.Options.DurableHandleStore is IPersistentHandleStore persistentHandleStore)
		{
			persistentHandleStore.RemovePersisted(open.PersistentFileId, open.VolatileFileId);
		}

		var removedPhysicalPath = ((!open.DeleteOnClose) ? null : open.LocalOpen?.PhysicalPath);
		if (open.LocalOpen != null)
		{
			await open.LocalOpen.DisposeAsync().ConfigureAwait(continueOnCapturedContext: false);
		}

		if (removedPhysicalPath != null)
		{
			BreakParentDirectoryLease(removedPhysicalPath);
		}

		_server.Options.Metrics.OnHandleClosed();
		if (open.DeleteOnClose)
		{
			Audit(SmbAuditEventType.FileDeleted, SmbLogLevel.Information, connection, DescribeIdentity(session.Identity), open.TreeConnect!.Share.Name, open.PathName);
		}

		Audit(SmbAuditEventType.FileClosed, SmbLogLevel.Information, connection, DescribeIdentity(session.Identity), open.TreeConnect!.Share.Name, open.PathName);
		var body = ((info == null) ? CloseMessage.BuildResponseBody(postQuery: false) : CloseMessage.BuildResponseBody(postQuery: true, new FileTimes(info.CreationTime, info.LastAccessTime, info.LastWriteTime, info.ChangeTime), info.AllocationSize, info.EndOfFile, (uint)info.Attributes));
		return MaybeSigned(session, RespHeader(header, session), body);
	}

	private async ValueTask<ResponseSegment> HandleReadAsync(SmbConnection connection, Smb2Header header, ReadOnlyMemory<byte> segment, bool frameEncrypted)
	{
		if (!TryGetValidSession(connection, header.SessionId, out var session))
		{
			return BuildError(header, NtStatus.UserSessionDeleted);
		}

		if (!VerifyInboundSignature(connection, session, header, segment.Span, frameEncrypted))
		{
			return BuildError(header, NtStatus.AccessDenied);
		}

		var request = ReadMessage.ParseRequest(segment.Span, 64);
		if (!TryGetOpen(session, request.PersistentId, request.VolatileId, out var open))
		{
			return BuildError(header, NtStatus.FileClosed);
		}

		var pipe = open.Pipe;
		if (pipe != null)
		{
			return MaybeSigned(session, RespHeader(header, session), ReadMessage.BuildResponseBody(pipe.TakeOutput()));
		}

		if (!TryGetFileStore(session, header.TreeId, out var store, out var error) || open.LocalOpen == null)
		{
			return BuildError(header, (error == NtStatus.Success) ? NtStatus.FileClosed : error);
		}

		if ((open.GrantedAccess & FileReadData) == 0)
		{
			return BuildError(header, NtStatus.AccessDenied);
		}

		var length = Math.Min(request.Length, connection.MaxReadSize);
		if (!_server.Options.LockManager.IsRangeAccessible(open, request.Offset, length, forWrite: false))
		{
			_server.Options.Metrics.OnLockContention();
			return BuildError(header, NtStatus.FileLockConflict);
		}

		var buffer = new byte[length];
		var fileStoreResult = await store.ReadAsync(open.LocalOpen, (long)request.Offset, buffer).ConfigureAwait(continueOnCapturedContext: false);
		if (!fileStoreResult.IsSuccess)
		{
			return BuildError(header, fileStoreResult.Status);
		}

		if (fileStoreResult.Value == 0 && length != 0)
		{
			return BuildError(header, NtStatus.EndOfFile);
		}

		_server.Options.Metrics.OnBytesRead(open.TreeConnect!.Share.Name, fileStoreResult.Value);
		return MaybeSigned(session, RespHeader(header, session), ReadMessage.BuildResponseBody(buffer.AsSpan(0, fileStoreResult.Value)));
	}

	private async ValueTask<ResponseSegment> HandleWriteAsync(SmbConnection connection, Smb2Header header, ReadOnlyMemory<byte> segment, bool frameEncrypted)
	{
		if (!TryGetValidSession(connection, header.SessionId, out var session))
		{
			return BuildError(header, NtStatus.UserSessionDeleted);
		}

		if (!VerifyInboundSignature(connection, session, header, segment.Span, frameEncrypted))
		{
			return BuildError(header, NtStatus.AccessDenied);
		}

		var req = WriteMessage.ParseRequest(segment.Span, 64);
		if (!TryGetOpen(session, req.PersistentId, req.VolatileId, out var open))
		{
			return BuildError(header, NtStatus.FileClosed);
		}

		var pipe = open.Pipe;
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

		var fileStoreResult = await store.WriteAsync(open.LocalOpen, (long)req.Offset, req.Data).ConfigureAwait(continueOnCapturedContext: false);
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

	private async ValueTask<ResponseSegment> HandleQueryDirectoryAsync(SmbConnection connection, Smb2Header header, ReadOnlyMemory<byte> segment, bool frameEncrypted)
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

		var req = QueryDirectoryMessage.ParseRequest(segment.Span, 64);
		if (!TryGetOpen(session, req.PersistentId, req.VolatileId, out var open) || open.LocalOpen == null)
		{
			return BuildError(header, NtStatus.FileClosed);
		}

		if ((req.Flags & 1) != 0)
		{
			open.DirectoryListing = null;
			open.DirectoryCursor = 0;
		}

		if (open.DirectoryListing == null)
		{
			var maxDirectoryEnumerationEntries = _server.Options.MaxDirectoryEnumerationEntries;
			var fileStoreResult = await store.QueryDirectoryAsync(open.LocalOpen, req.SearchPattern, maxDirectoryEnumerationEntries).ConfigureAwait(continueOnCapturedContext: false);
			if (!fileStoreResult.IsSuccess)
			{
				return BuildError(header, fileStoreResult.Status);
			}

			if (fileStoreResult.Value.Truncated)
			{
				return BuildError(header, NtStatus.InsufficientResources);
			}

			if (fileStoreResult.Value.Entries.Count == 0)
			{
				return BuildError(header, NtStatus.NoSuchFile);
			}

			open.DirectoryListing = fileStoreResult.Value.Entries;
			open.DirectoryCursor = 0;
		}

		var directoryListing = open.DirectoryListing;
		if (open.DirectoryCursor >= directoryListing.Count)
		{
			return BuildError(header, NtStatus.NoMoreFiles);
		}

		var flag = (req.Flags & 2) != 0;
		var val = directoryListing.Count - open.DirectoryCursor;
		var num = (flag ? 1 : Math.Min(val, (int)(req.OutputBufferLength / 12 + 2)));
		var list = new List<FsccFileStat>(num);
		for (var i = 0; i < num; i++)
		{
			list.Add(ToStat(directoryListing[open.DirectoryCursor + i]));
		}

		var array = FsccStructures.BuildDirectoryListing(list, req.InfoClass, (int)req.OutputBufferLength, out var written);
		if (written == 0)
		{
			return BuildError(header, NtStatus.InfoLengthMismatch);
		}

		open.DirectoryCursor += written;
		return MaybeSigned(session, RespHeader(header, session), QueryDirectoryMessage.BuildResponseBody(array));
	}

	private async ValueTask<ResponseSegment> HandleQueryInfoAsync(SmbConnection connection, Smb2Header header, ReadOnlyMemory<byte> segment, bool frameEncrypted)
	{
		if (!TryGetValidSession(connection, header.SessionId, out var session))
		{
			return BuildError(header, NtStatus.UserSessionDeleted);
		}

		if (!VerifyInboundSignature(connection, session, header, segment.Span, frameEncrypted))
		{
			return BuildError(header, NtStatus.AccessDenied);
		}

		var req = QueryInfoMessage.ParseRequest(segment.Span, 64);
		if (!TryGetOpen(session, req.PersistentId, req.VolatileId, out var open) || open.LocalOpen == null)
		{
			return BuildError(header, NtStatus.FileClosed);
		}

		if (req.InfoType == InfoType.Security)
		{
			return await HandleQuerySecurityAsync(session, header, open, req).ConfigureAwait(continueOnCapturedContext: false);
		}

		if (req.InfoType == InfoType.Quota)
		{
			return HandleQueryQuota(session, header, open, req);
		}

		if (req.InfoType == InfoType.File)
		{
			switch ((FileInformationClass)req.FileInfoClass)
			{
				case FileInformationClass.FileStreamInformation:
					return await HandleQueryStreamsAsync(session, header, open, req).ConfigureAwait(continueOnCapturedContext: false);
				case FileInformationClass.FileFullEaInformation:
					return await HandleQueryEaAsync(session, header, open, req).ConfigureAwait(continueOnCapturedContext: false);
			}
		}

		var e = ToStat(await open.LocalOpen.GetInfoAsync().ConfigureAwait(continueOnCapturedContext: false));
		var array = req.InfoType switch
		{
			InfoType.File => FsccStructures.BuildFileInformation(e, (FileInformationClass)req.FileInfoClass),
			InfoType.FileSystem => BuildFsInfo(session, header.TreeId, (FsInformationClass)req.FileInfoClass),
			_ => null,
		};
		if (array == null)
		{
			return BuildError(header, NtStatus.InvalidInfoClass);
		}

		return MaybeSigned(session, RespHeader(header, session), QueryInfoMessage.BuildResponseBody(array));
	}

	private async ValueTask<ResponseSegment> HandleSetInfoAsync(SmbConnection connection, Smb2Header header, ReadOnlyMemory<byte> segment, bool frameEncrypted)
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

		var req = SetInfoMessage.ParseRequest(segment.Span, 64);
		if (!TryGetOpen(session, req.PersistentId, req.VolatileId, out var open) || open.LocalOpen == null)
		{
			return BuildError(header, NtStatus.FileClosed);
		}

		if (req.InfoType == InfoType.Security)
		{
			return await HandleSetSecurityAsync(connection, session, header, store, open, req).ConfigureAwait(continueOnCapturedContext: false);
		}

		if (req.InfoType == InfoType.Quota)
		{
			return HandleSetQuota(session, header, open, req);
		}

		if (req.InfoType != InfoType.File)
		{
			return BuildError(header, NtStatus.NotSupported);
		}

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

		var renameOldPhysicalPath = ((infoClass == FileInformationClass.FileRenameInformation) ? open.LocalOpen.PhysicalPath : null);
		var ntStatus = infoClass switch
		{
			FileInformationClass.FileEndOfFileInformation => await store.SetEndOfFileAsync(open.LocalOpen, BinaryPrimitives.ReadInt64LittleEndian(req.Buffer)).ConfigureAwait(continueOnCapturedContext: false),
			FileInformationClass.FileDispositionInformation => await store.SetDeleteOnCloseAsync(open.LocalOpen, req.Buffer.Length != 0 && req.Buffer[0] != 0).ConfigureAwait(continueOnCapturedContext: false),
			FileInformationClass.FileRenameInformation => await DoRenameAsync(store, open.LocalOpen, req.Buffer).ConfigureAwait(continueOnCapturedContext: false),
			FileInformationClass.FileBasicInformation => await DoSetBasicInfoAsync(store, open.LocalOpen, req.Buffer).ConfigureAwait(continueOnCapturedContext: false),
			FileInformationClass.FileAllocationInformation => NtStatus.Success,
			FileInformationClass.FilePositionInformation => NtStatus.Success,
			_ => NtStatus.InvalidInfoClass,
		};
		if (ntStatus != NtStatus.Success)
		{
			return BuildError(header, ntStatus);
		}

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

	private async ValueTask<ResponseSegment> HandleSetSecurityAsync(SmbConnection connection, SmbSession session, Smb2Header header, IFileStore store, SmbOpen open, SetInfoMessage.Request req)
	{
		SecurityDescriptor incoming;
		try
		{
			incoming = SecurityDescriptor.Parse(req.Buffer);
		}
		catch (SmbWireFormatException)
		{
			return BuildError(header, NtStatus.InvalidParameter);
		}

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

	private static SecurityDescriptor FilterSecurityDescriptor(SecurityDescriptor sd, SecurityInformation which)
	{
		return SecurityDescriptor.Create(which.HasFlag(SecurityInformation.Owner) ? sd.Owner : null, which.HasFlag(SecurityInformation.Group) ? sd.Group : null, which.HasFlag(SecurityInformation.Dacl) ? sd.Dacl : null, which.HasFlag(SecurityInformation.Sacl) ? sd.Sacl : null);
	}

	private static SecurityDescriptor MergeSecurityDescriptor(SecurityDescriptor existing, SecurityDescriptor incoming, SecurityInformation which)
	{
		return SecurityDescriptor.Create(which.HasFlag(SecurityInformation.Owner) ? incoming.Owner : existing.Owner, which.HasFlag(SecurityInformation.Group) ? incoming.Group : existing.Group, which.HasFlag(SecurityInformation.Dacl) ? incoming.Dacl : existing.Dacl, which.HasFlag(SecurityInformation.Sacl) ? incoming.Sacl : existing.Sacl);
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
		if ((uint)array.Length > req.OutputBufferLength)
		{
			return BuildError(header, NtStatus.BufferTooSmall);
		}

		return MaybeSigned(session, RespHeader(header, session), QueryInfoMessage.BuildResponseBody(array));
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

		var array = FullEaInformation.Build(eas);
		if ((uint)array.Length > req.OutputBufferLength)
		{
			return BuildError(header, NtStatus.BufferTooSmall);
		}

		return MaybeSigned(session, RespHeader(header, session), QueryInfoMessage.BuildResponseBody(array));
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

		var entries = source.Select(e => new ExtendedAttribute(e.Name, e.Value, e.Flags)).ToList();
		var ntStatus = await extendedAttributeStore.SetExtendedAttributesAsync(open.LocalOpen!, entries).ConfigureAwait(continueOnCapturedContext: false);
		if (ntStatus != NtStatus.Success)
		{
			return BuildError(header, ntStatus);
		}

		return MaybeSigned(session, RespHeader(header, session), SetInfoMessage.BuildResponseBody());
	}

	private async ValueTask<ResponseSegment> HandleFlushAsync(SmbConnection connection, Smb2Header header, ReadOnlyMemory<byte> segment, bool frameEncrypted)
	{
		if (!TryGetValidSession(connection, header.SessionId, out var session))
		{
			return BuildError(header, NtStatus.UserSessionDeleted);
		}

		if (!VerifyInboundSignature(connection, session, header, segment.Span, frameEncrypted))
		{
			return BuildError(header, NtStatus.AccessDenied);
		}

		var persistent = BinaryPrimitives.ReadUInt64LittleEndian(segment.Span.Slice(72, 8));
		var volatileId = BinaryPrimitives.ReadUInt64LittleEndian(segment.Span.Slice(80, 8));
		if (TryGetOpen(session, persistent, volatileId, out var open) && open.LocalOpen != null && TryGetFileStore(session, header.TreeId, out var store, out _))
		{
			await store.FlushAsync(open.LocalOpen).ConfigureAwait(continueOnCapturedContext: false);
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
		if ((desiredAccess & (GenericRead | GenericAll | MaximumAllowed | FileReadData)) != 0)
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

	public async ValueTask OnConnectionClosedAsync(SmbConnection connection)
	{
		foreach (var value in connection.Sessions.Values)
		{
			foreach (var item in DetachOnConnectionClose(connection, value))
			{
				await item.DisposeAsync().ConfigureAwait(continueOnCapturedContext: false);
			}
		}

		CancelNonSurvivingPending(connection);
		_server.WitnessRegistrations.RemoveAllForConnection(connection.ConnectionId);
	}

	public void OnConnectionClosed(SmbConnection connection)
	{
		foreach (var value in connection.Sessions.Values)
		{
			foreach (var item in DetachOnConnectionClose(connection, value))
			{
				item.Dispose();
			}
		}

		CancelNonSurvivingPending(connection);
		_server.WitnessRegistrations.RemoveAllForConnection(connection.ConnectionId);
	}

	private List<IFileHandle> DetachOnConnectionClose(SmbConnection connection, SmbSession session)
	{
		session.Channels.TryRemove(connection.ConnectionId, out _);
		if (!session.Channels.IsEmpty)
		{
			return new List<IFileHandle>();
		}

		var result = DetachSessionOpens(session);
		_server.SessionGlobalList.TryRemove(session.SessionId, out _);
		return result;
	}

	private static void CancelNonSurvivingPending(SmbConnection connection)
	{
		foreach (var value2 in connection.PendingRequests.Values)
		{
			var smbSession = value2.Owner?.Session;
			if (smbSession == null || smbSession.Channels.IsEmpty)
			{
				value2.Cancel();
				connection.PendingRequests.TryRemove(value2.MessageId, out _);
			}
		}
	}

	private List<IFileHandle> DetachSessionOpens(SmbSession session)
	{
		var list = new List<IFileHandle>();
		foreach (var value in session.Opens.Values)
		{
			if (value.IsDurable && value.LocalOpen != null)
			{
				_server.Options.DurableHandleStore.Add(new DurableHandle
				{
					PersistentId = value.PersistentFileId,
					VolatileId = value.VolatileFileId,
					Open = value,
					Deadline = _server.Options.TimeProvider.GetUtcNow() + value.DurableTimeout,
					OwnerKey = OwnerKey(session.Identity),
					CreateGuid = value.DurableCreateGuid,
					IsPersistent = value.IsPersistentHandle,
				});
				continue;
			}

			_server.Options.LockManager.ReleaseOwner(value);
			_server.Options.OplockManager.ReleaseOwner(value);
			_server.Options.LeaseManager.ReleaseOwner(value);
			var shareModeKey = value.ShareModeKey;
			if (shareModeKey != null)
			{
				_server.Options.ShareModeManager.Close(shareModeKey, value);
			}

			var localOpen = value.LocalOpen;
			if (localOpen != null)
			{
				list.Add(localOpen);
			}
		}

		session.Opens.Clear();
		return list;
	}

	private void CloseSessionOpens(SmbSession session)
	{
		foreach (var item in DetachSessionOpens(session))
		{
			item.Dispose();
		}
	}

	private async ValueTask<ResponseSegment> HandleDurableReconnectAsync(Smb2Header header, SmbSession session, SmbTreeConnect tree, CreateContext reconnectCtx)
	{
		var (persistentId, volatileId) = DurableHandleMessages.ParseReconnect(reconnectCtx.Data);
		var (durableHandle, responseSegment) = await TryClaimForReconnectAsync(header, session, tree, persistentId, volatileId, null).ConfigureAwait(continueOnCapturedContext: false);
		if (durableHandle == null)
		{
			return responseSegment.Value;
		}

		return await RestoreDurableOpenAsync(header, session, tree, durableHandle, DurableHandleMessages.BuildV1ResponseContext()).ConfigureAwait(continueOnCapturedContext: false);
	}

	private async ValueTask<ResponseSegment> HandleDurableReconnectV2Async(Smb2Header header, SmbSession session, SmbTreeConnect tree, CreateContext reconnectCtx)
	{
		var v2Reconnect = DurableHandleMessages.ParseV2Reconnect(reconnectCtx.Data);
		var (durableHandle, responseSegment) = await TryClaimForReconnectAsync(header, session, tree, v2Reconnect.PersistentId, v2Reconnect.VolatileId, v2Reconnect.CreateGuid).ConfigureAwait(continueOnCapturedContext: false);
		if (durableHandle == null)
		{
			return responseSegment.Value;
		}

		var responseContext = DurableHandleMessages.BuildV2ResponseContext((uint)durableHandle.Open.DurableTimeout.TotalMilliseconds, durableHandle.IsPersistent);
		return await RestoreDurableOpenAsync(header, session, tree, durableHandle, responseContext).ConfigureAwait(continueOnCapturedContext: false);
	}

	private async ValueTask<(DurableHandle? Handle, ResponseSegment? Error)> TryClaimForReconnectAsync(Smb2Header header, SmbSession session, SmbTreeConnect tree, ulong persistentId, ulong volatileId, Guid? expectedGuid)
	{
		if (_server.Options.DurableHandleStore.TryClaim(persistentId, volatileId, out var handle))
		{
			if (!handle.IsPersistent && handle.Deadline <= _server.Options.TimeProvider.GetUtcNow())
			{
				ReleaseDurable(handle);
				return (null, BuildError(header, NtStatus.ObjectNameNotFound));
			}

			if (expectedGuid.HasValue)
			{
				var valueOrDefault = expectedGuid.GetValueOrDefault();
				if (handle.CreateGuid != valueOrDefault)
				{
					_server.Options.DurableHandleStore.Add(handle);
					return (null, BuildError(header, NtStatus.ObjectNameNotFound));
				}
			}

			if (!string.Equals(handle.OwnerKey, OwnerKey(session.Identity), StringComparison.Ordinal))
			{
				_server.Options.DurableHandleStore.Add(handle);
				return (null, BuildError(header, NtStatus.AccessDenied));
			}

			return (handle, null);
		}

		var durableHandleStore = _server.Options.DurableHandleStore;
		if (durableHandleStore is IPersistentHandleStore persistent && persistent.TryClaimColdRecord(persistentId, volatileId, out var record))
		{
			if (expectedGuid.HasValue)
			{
				var valueOrDefault2 = expectedGuid.GetValueOrDefault();
				if (record.CreateGuid != valueOrDefault2)
				{
					persistent.ReturnColdRecord(record);
					return (null, BuildError(header, NtStatus.ObjectNameNotFound));
				}
			}

			if (!string.Equals(record.OwnerKey, OwnerKey(session.Identity), StringComparison.Ordinal))
			{
				persistent.ReturnColdRecord(record);
				return (null, BuildError(header, NtStatus.AccessDenied));
			}

			var durableHandle = await RehydrateColdRecordAsync(tree, record).ConfigureAwait(continueOnCapturedContext: false);
			if (durableHandle == null)
			{
				persistent.ReturnColdRecord(record);
				return (null, BuildError(header, NtStatus.ObjectNameNotFound));
			}

			return (durableHandle, null);
		}

		return (null, BuildError(header, NtStatus.ObjectNameNotFound));
	}

	private async ValueTask<DurableHandle?> RehydrateColdRecordAsync(SmbTreeConnect tree, PersistentHandleRecord record)
	{
		if (!string.Equals(record.ShareName, tree.Share.Name, StringComparison.OrdinalIgnoreCase) || tree.Share.FileStore == null)
		{
			return null;
		}

		var open = new SmbOpen
		{
			PersistentFileId = record.PersistentId,
			VolatileFileId = record.VolatileId,
			GrantedAccess = record.GrantedAccess,
			ShareAccess = record.ShareAccess,
			PathName = record.Path,
			IsDurable = true,
			IsPersistentHandle = true,
			DurableCreateGuid = record.CreateGuid,
			DurableTimeout = _server.Options.DurableHandleTimeout,
		};
		var access = MapAccess(record.GrantedAccess);
		var shareKey = ShareModeKey(tree, record.Path);
		if (!_server.Options.ShareModeManager.TryOpen(shareKey, open, access, MapShare(record.ShareAccess)))
		{
			return null;
		}

		open.ShareModeKey = shareKey;
		var fileStoreResult = await tree.Share.FileStore.CreateAsync(record.Path, access, CreateDispositionIntent.Open, directoryRequired: false, nonDirectoryRequired: false).ConfigureAwait(continueOnCapturedContext: false);
		if (!fileStoreResult.IsSuccess)
		{
			_server.Options.ShareModeManager.Close(shareKey, open);
			return null;
		}

		open.LocalOpen = fileStoreResult.Value.Handle;
		return new DurableHandle
		{
			PersistentId = record.PersistentId,
			VolatileId = record.VolatileId,
			Open = open,
			Deadline = DateTimeOffset.MaxValue,
			OwnerKey = record.OwnerKey,
			CreateGuid = record.CreateGuid,
			IsPersistent = true,
		};
	}

	private async ValueTask<ResponseSegment> RestoreDurableOpenAsync(Smb2Header header, SmbSession session, SmbTreeConnect tree, DurableHandle dh, CreateContext responseContext)
	{
		var open = dh.Open;
		open.Session = session;
		open.TreeConnect = tree;
		session.Opens[open.Key] = open;
		Interlocked.Increment(ref tree.OpenCount);
		var fileEntryInfo = await open.LocalOpen!.GetInfoAsync().ConfigureAwait(continueOnCapturedContext: false);
		var createResponse = new CreateResponse
		{
			OplockLevel = open.OplockLevel,
			CreateAction = CreateAction.Opened,
			CreationTime = fileEntryInfo.CreationTime,
			LastAccessTime = fileEntryInfo.LastAccessTime,
			LastWriteTime = fileEntryInfo.LastWriteTime,
			ChangeTime = fileEntryInfo.ChangeTime,
			AllocationSize = fileEntryInfo.AllocationSize,
			EndOfFile = fileEntryInfo.EndOfFile,
			FileAttributes = (uint)fileEntryInfo.Attributes,
			PersistentFileId = open.PersistentFileId,
			VolatileFileId = open.VolatileFileId,
		};
		var contexts = CreateContextList.Serialize([responseContext]);
		return MaybeSigned(session, RespHeader(header, session), createResponse.ToBody(contexts));
	}

	private TimeSpan ResolveDurableTimeout(uint requestedMs)
	{
		if (requestedMs == 0)
		{
			return _server.Options.DurableHandleTimeout;
		}

		var timeSpan = TimeSpan.FromMilliseconds(requestedMs, 0L);
		if (!(timeSpan > _server.Options.MaxDurableHandleTimeout))
		{
			return timeSpan;
		}

		return _server.Options.MaxDurableHandleTimeout;
	}

	private static bool DurabilityAllowed(OplockLevel oplock, LeaseState lease)
	{
		if (oplock - 8 > OplockLevel.LevelII)
		{
			return lease.HasFlag(LeaseState.Handle);
		}

		return true;
	}

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
		_server.Options.Metrics.OnSessionClosed();
		CloseSessionOpens(session);
		_server.SessionGlobalList.TryRemove(session.SessionId, out _);
		foreach (var value2 in _server.Connections.Values)
		{
			value2.Sessions.TryRemove(session.SessionId, out _);
		}

		session.Channels.Clear();
		session.State = SessionState.Expired;
	}

	private void ReleaseDurable(DurableHandle dh)
	{
		var open = dh.Open;
		_server.Options.LockManager.ReleaseOwner(open);
		_server.Options.OplockManager.ReleaseOwner(open);
		_server.Options.LeaseManager.ReleaseOwner(open);
		var shareModeKey = open.ShareModeKey;
		if (shareModeKey != null)
		{
			_server.Options.ShareModeManager.Close(shareModeKey, open);
		}

		open.LocalOpen?.Dispose();
	}

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
			var readOnlyList = _server.Options.LeaseManager.BreakDirectoryLease(directoryName);
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
			SessionId = session!.SessionId,
			TreeId = (uint)holder.TreeConnect!.TreeId,
			CreditRequestResponse = 0,
		};
		var body = LeaseBreakMessage.BuildNotificationBody(brk.Key, brk.FromState, brk.ToState, brk.Epoch, LeaseAckRequired(brk));
		await SendOutOfBandAsync(session, session.Connection, MaybeSigned(session, header, body), ResponseNeedsEncryption(session, holder)).ConfigureAwait(continueOnCapturedContext: false);
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
		var state = _server.Options.LeaseManager.Acknowledge(acknowledgment.Key, acknowledgment.State);
		_breaks?.CompleteLeaseBreak(acknowledgment.Key);
		var body = LeaseBreakMessage.BuildResponseBody(acknowledgment.Key, state);
		return MaybeSigned(session, RespHeader(header, session), body);
	}

	private ResponseSegment HandleLock(SmbConnection connection, Smb2Header header, ReadOnlySpan<byte> segment, bool frameEncrypted)
	{
		if (!TryGetValidSession(connection, header.SessionId, out var session))
		{
			return BuildError(header, NtStatus.UserSessionDeleted);
		}

		if (!VerifyInboundSignature(connection, session, header, segment, frameEncrypted))
		{
			return BuildError(header, NtStatus.AccessDenied);
		}

		var request = LockMessage.ParseRequest(segment, 64);
		if (!TryGetOpen(session, request.PersistentId, request.VolatileId, out var open))
		{
			return BuildError(header, NtStatus.FileClosed);
		}

		var isUnlock = request.Locks[0].IsUnlock;
		var array = new LockElement[request.Locks.Count];
		for (var i = 0; i < request.Locks.Count; i++)
		{
			var lockEntry = request.Locks[i];
			if (lockEntry.IsUnlock != isUnlock)
			{
				return BuildError(header, NtStatus.InvalidParameter);
			}

			array[i] = new LockElement(lockEntry.Offset, lockEntry.Length, lockEntry.IsExclusive, lockEntry.IsUnlock);
		}

		var failImmediately = request.Locks[0].FailImmediately;
		var asyncId = connection.AllocateAsyncId();
		var pendingAsyncRequest = new PendingAsyncRequest
		{
			MessageId = header.MessageId,
			AsyncId = asyncId,
			Owner = open,
		};
		var task = _server.Options.LockManager.ApplyAsync(open, array, failImmediately, pendingAsyncRequest.Token);
		if (task.IsCompleted)
		{
			pendingAsyncRequest.Cancel();
			var outcome = ((!task.IsCompletedSuccessfully) ? LockOutcome.Conflict : task.Result);
			return LockResultSegment(header, session, outcome);
		}

		if (connection.PendingRequests.Count >= _server.Options.MaxOutstandingRequests)
		{
			pendingAsyncRequest.Cancel();
			return BuildError(header, NtStatus.InsufficientResources);
		}

		connection.PendingRequests[header.MessageId] = pendingAsyncRequest;
		_ = SendFinalLockResponseAsync(connection, header, session, asyncId, task, pendingAsyncRequest);
		return InterimResponse(header, session, asyncId);
	}

	private ResponseSegment? HandleCancel(SmbConnection connection, Smb2Header header, ReadOnlySpan<byte> segment)
	{
		CancelMessage.ParseRequest(segment, 64);
		(header.Flags.HasFlag(Smb2HeaderFlags.AsyncCommand) ? FindPendingByAsyncId(connection, header.AsyncId) : (connection.PendingRequests.GetValueOrDefault(header.MessageId)))?.Cancel();
		return null;
	}

	private static PendingAsyncRequest? FindPendingByAsyncId(SmbConnection connection, ulong asyncId)
	{
		foreach (var value in connection.PendingRequests.Values)
		{
			if (value.AsyncId == asyncId)
			{
				return value;
			}
		}

		return null;
	}

	private ResponseSegment LockResultSegment(Smb2Header header, SmbSession session, LockOutcome outcome)
	{
		return outcome switch
		{
			LockOutcome.Granted => MaybeSigned(session, RespHeader(header, session), LockMessage.BuildResponseBody()),
			LockOutcome.RangeNotLocked => BuildError(header, NtStatus.RangeNotLocked),
			LockOutcome.Cancelled => BuildError(header, NtStatus.Cancelled),
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

	private async Task SendFinalLockResponseAsync(SmbConnection connection, Smb2Header header, SmbSession session, ulong asyncId, Task<LockOutcome> task, PendingAsyncRequest pending)
	{
		LockOutcome lockOutcome;
		try
		{
			lockOutcome = await task.ConfigureAwait(continueOnCapturedContext: false);
		}
		catch
		{
			lockOutcome = LockOutcome.Cancelled;
		}

		connection.PendingRequests.TryRemove(pending.MessageId, out _);
		var smb2Header = header.CreateResponse(lockOutcome switch
		{
			LockOutcome.Granted => NtStatus.Success,
			LockOutcome.RangeNotLocked => NtStatus.RangeNotLocked,
			LockOutcome.Cancelled => NtStatus.Cancelled,
			_ => NtStatus.LockNotGranted,
		});
		smb2Header.Flags |= Smb2HeaderFlags.AsyncCommand;
		smb2Header.AsyncId = asyncId;
		smb2Header.SessionId = session.SessionId;
		smb2Header.CreditRequestResponse = 0;
		var segment = SignedLikeRequest(session, header, smb2Header, (lockOutcome == LockOutcome.Granted) ? LockMessage.BuildResponseBody() : ErrorResponse.BuildBody());
		await SendOutOfBandAsync(session, connection, segment, ResponseNeedsEncryption(session, pending.Owner)).ConfigureAwait(continueOnCapturedContext: false);
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

	private ResponseSegment HandleChangeNotify(SmbConnection connection, Smb2Header header, ReadOnlySpan<byte> segment, bool frameEncrypted)
	{
		if (!TryGetValidSession(connection, header.SessionId, out var session))
		{
			return BuildError(header, NtStatus.UserSessionDeleted);
		}

		if (!VerifyInboundSignature(connection, session, header, segment, frameEncrypted))
		{
			return BuildError(header, NtStatus.AccessDenied);
		}

		var req = ChangeNotifyMessage.ParseRequest(segment, 64);
		if (!TryGetOpen(session, req.PersistentId, req.VolatileId, out var open))
		{
			return BuildError(header, NtStatus.FileClosed);
		}

		if (open.LocalOpen == null || !open.LocalOpen.IsDirectory)
		{
			return BuildError(header, NtStatus.InvalidParameter);
		}

		var physicalPath = open.LocalOpen.PhysicalPath;
		if (physicalPath == null)
		{
			return BuildError(header, NtStatus.NotSupported);
		}

		if (connection.PendingRequests.Count >= _server.Options.MaxOutstandingRequests)
		{
			return BuildError(header, NtStatus.InsufficientResources);
		}

		var asyncId = connection.AllocateAsyncId();
		var pending = new PendingAsyncRequest
		{
			MessageId = header.MessageId,
			AsyncId = asyncId,
			Owner = open,
		};
		var once = new NotifyOnce();
		IDisposable disposable;
		try
		{
			disposable = _server.Options.DirectoryWatcher.Watch(physicalPath, req.WatchTree, (ChangeNotifyFilter)req.CompletionFilter, changes =>
			{
				var list = new List<(uint, string)>(changes.Count);
				foreach (var change in changes)
				{
					list.Add(((uint)change.Action, change.RelativeName));
				}

				var (body, flag) = ChangeNotifyMessage.BuildResponseBody(list, req.OutputBufferLength);
				Complete(flag ? NtStatus.NotifyEnumDir : NtStatus.Success, body);
			});
		}
		catch
		{
			return BuildError(header, NtStatus.NotSupported);
		}

		if (disposable == null)
		{
			return BuildError(header, NtStatus.NotSupported);
		}

		once.Attach(disposable);
		connection.PendingRequests[header.MessageId] = pending;
		pending.Token.Register(() =>
		{
			Complete(NtStatus.Cancelled, ErrorResponse.BuildBody());
		});
		return InterimResponse(header, session, asyncId);

		void Complete(NtStatus status, byte[] body)
		{
			if (once.TryFire())
			{
				connection.PendingRequests.TryRemove(pending.MessageId, out _);
				_ = SendAsyncFinalAsync(connection, header, session, asyncId, status, body, ResponseNeedsEncryption(session, open));
			}
		}
	}

	private ResponseSegment BeginWitnessAsyncNotify(SmbConnection connection, Smb2Header header, SmbSession session, SmbOpen open, WitnessRegistration registration, uint callId, ulong persistentId, ulong volatileId)
	{
		if (connection.PendingRequests.Count >= _server.Options.MaxOutstandingRequests)
		{
			return BuildError(header, NtStatus.InsufficientResources);
		}

		var asyncId = connection.AllocateAsyncId();
		var pending = new PendingAsyncRequest
		{
			MessageId = header.MessageId,
			AsyncId = asyncId,
			Owner = open,
		};
		var once = new NotifyOnce();
		var encrypt = ResponseNeedsEncryption(session, open);
		var subscription = registration.Notifications.Wait(n =>
		{
			var array = WitnessEndpoint.BuildAsyncNotifyPdu(callId, n);
			var body = IoctlMessage.BuildResponseBody(1163287u, persistentId, volatileId, array);
			Complete(NtStatus.Success, body);
		});
		once.Attach(subscription);
		connection.PendingRequests[header.MessageId] = pending;
		pending.Token.Register(() =>
		{
			Complete(NtStatus.Cancelled, ErrorResponse.BuildBody());
		});
		return InterimResponse(header, session, asyncId);

		void Complete(NtStatus status, byte[] body)
		{
			if (once.TryFire())
			{
				connection.PendingRequests.TryRemove(pending.MessageId, out _);
				_ = SendAsyncFinalAsync(connection, header, session, asyncId, status, body, encrypt);
			}
		}
	}

	private async Task SendAsyncFinalAsync(SmbConnection connection, Smb2Header request, SmbSession session, ulong asyncId, NtStatus status, byte[] body, bool encrypt)
	{
		var smb2Header = request.CreateResponse(status);
		smb2Header.Flags |= Smb2HeaderFlags.AsyncCommand;
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
			TreeId = (uint)holder.TreeConnect!.TreeId,
			CreditRequestResponse = 0,
		};
		var body = OplockBreakMessage.BuildBody(brk.NewLevel, holder.PersistentFileId, holder.VolatileFileId);
		await SendOutOfBandAsync(session, session.Connection, MaybeSigned(session, header, body), ResponseNeedsEncryption(session, holder)).ConfigureAwait(continueOnCapturedContext: false);
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

		var oplockLevel = (open.OplockLevel = _server.Options.OplockManager.Acknowledge(open, acknowledgment.OplockLevel));
		_breaks?.CompleteOplockBreak(open);
		var body = OplockBreakMessage.BuildBody(oplockLevel, open.PersistentFileId, open.VolatileFileId);
		return MaybeSigned(session, RespHeader(header, session), body);
	}
}
