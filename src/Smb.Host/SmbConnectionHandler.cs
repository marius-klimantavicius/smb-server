using System;
using System.Buffers.Binary;
using System.Collections.Generic;
using System.IO;
using System.Net;
using System.Net.Security;
using System.Net.Sockets;
using System.Security.Cryptography.X509Certificates;
using System.Threading;
using System.Threading.Tasks;
using Smb.Crypto;
using Smb.Protocol.Compression;
using Smb.Protocol.Constants;
using Smb.Protocol.Enums;
using Smb.Protocol.Messages;
using Smb.Protocol.Transport;
using Smb.Server;
using Smb.Server.Diagnostics;
using Smb.Server.State;

namespace Smb.Host;

/// <summary>
/// Read loop for a single TCP connection (Context §3, §19.1). Decodes NBSS frames,
/// decrypts transform frames, calls the dispatcher and writes the (optionally encrypted,
/// NBSS-framed) response back. Write operations are serialized via
/// <see cref="F:Smb.Host.SmbConnectionHandler._writeLock" /> — so asynchronously pending operations (e.g. blocking
/// LOCKs) can send their final response out-of-band without interleaving with read responses.
/// <para>
/// Concurrent file I/O (docs/ASYNC_IO_ROADMAP.md, A4): individual READ/WRITE frames are —
/// capped via <see cref="P:Smb.Server.SmbServerOptions.MaxConcurrentFileOpsPerConnection" /> — processed
/// concurrently; their responses may go out-of-order via the serialized writer.
/// Every other frame acts as a barrier: all outstanding I/Os are drained first, then it is
/// retain their operation scopes; CANCEL and teardown progress independently of the I/O drain.
/// </para>
/// </summary>
internal sealed class SmbConnectionHandler
{
	private readonly SmbServerState _server;

	private readonly Smb2Dispatcher _dispatcher;

	private readonly Action<string>? _log;

	private readonly SmbTlsOptions? _tls;

	private readonly SemaphoreSlim _writeLock = new SemaphoreSlim(1, 1);

	/// <summary>Caps physical READ/WRITE work. A cap of one still allows control frames to progress.</summary>
	private readonly SemaphoreSlim? _ioGate;

	internal SemaphoreSlim? ConcurrentOperations => _ioGate;

	private readonly List<Task> _inflight = new List<Task>();

	public SmbConnectionHandler(SmbServerState server, Action<string>? log, SmbTlsOptions? tls = null)
	{
		_server = server;
		_dispatcher = new Smb2Dispatcher(server, log);
		_log = log;
		_tls = tls;
		var maxConcurrentFileOpsPerConnection = server.Options.MaxConcurrentFileOpsPerConnection;
		_ioGate = new SemaphoreSlim(Math.Max(1, maxConcurrentFileOpsPerConnection), Math.Max(1, maxConcurrentFileOpsPerConnection));
	}

	/// <summary>
	/// Serves a plain-TCP (or TCP+TLS) connection. Establishes the transport stream — wrapping it in
	/// TLS when configured (M10.1) — and runs the SMB2 frame loop. Thin adapter over
	/// <see cref="M:Smb.Host.SmbConnectionHandler.ServeAsync(System.String,System.Func{Smb.Server.State.SmbConnection,System.Threading.CancellationToken,System.Threading.Tasks.Task{System.IO.Stream}},System.Boolean,System.Func{System.Threading.Tasks.ValueTask},System.Threading.CancellationToken,System.Threading.CancellationToken)" />; the QUIC listener (M10.2) drives the same core with an already-secure
	/// <see cref="T:Managed.Net.Quic.QuicStream" />.
	/// </summary>
	public Task RunAsync(TcpClient client, CancellationToken hardCt, CancellationToken drainToken = default(CancellationToken))
	{
		var clientAddress = (client.Client.RemoteEndPoint as IPEndPoint)?.ToString();
		return ServeAsync(clientAddress, async (connection, ct) =>
		{
			Stream stream = client.GetStream();
			return (_tls == null) ? stream : (await EstablishTlsAsync((NetworkStream)stream, connection, ct).ConfigureAwait(continueOnCapturedContext: false));
		}, transportPreSecured: false, () =>
		{
			client.Dispose();
			return ValueTask.CompletedTask;
		}, hardCt, drainToken);
	}

	/// <summary>
	/// Transport-agnostic core: creates the connection state, obtains the ready-to-use SMB2 byte stream
	/// via <paramref name="establishStream" /> (null return = the transport handshake failed → drop),
	/// runs the frame loop, and tears everything down. <paramref name="transportPreSecured" /> marks a
	/// transport that is already encrypted/authenticated at its own layer (QUIC's mandatory TLS 1.3);
	/// <paramref name="disposeTransport" /> releases the underlying transport object after the stream.
	/// </summary>
	internal async Task ServeAsync(string? clientAddress, Func<SmbConnection, CancellationToken, Task<Stream?>> establishStream, bool transportPreSecured, Func<ValueTask> disposeTransport, CancellationToken hardCt, CancellationToken drainToken)
	{
		var ticks = _server.Options.TimeProvider.GetUtcNow().Ticks;
		var connection = new SmbConnection
		{
			ClientAddress = clientAddress,
			CreatedTicks = ticks,
			LastActivityTicks = ticks,
		};
		var connCts = CancellationTokenSource.CreateLinkedTokenSource(hardCt);
		try
		{
			var connCt = connCts.Token;
			connection.RequestClose = () =>
			{
				try
				{
					// ReSharper disable once AccessToDisposedClosure
					connCts.Cancel();
				}
				catch (ObjectDisposedException)
				{
				}
			};
			using var readCts = CancellationTokenSource.CreateLinkedTokenSource(connCt, drainToken);
			var readCt = readCts.Token;
			_server.Connections[connection.ConnectionId] = connection;
			_server.Options.Metrics.OnConnectionAccepted();
			AuditConnection(SmbAuditEventType.ConnectionAccepted, connection);
			Stream stream = null;
			try
			{
				_ = 6;
				try
				{
					stream = await establishStream(connection, readCt).ConfigureAwait(continueOnCapturedContext: false);
					if (stream == null)
					{
						goto end_IL_01c2;
					}

					if (transportPreSecured)
					{
						connection.IsTransportSecured = true;
					}

					var prefix = new byte[4];
					var sendStream = stream;
					connection.SendRawAsync = (raw, forceEncrypt) => SendFramedAsync(sendStream, connection, raw, forceEncrypt, connCt);
					while (!readCt.IsCancellationRequested && await TryReadExactAsync(stream, prefix, readCt))
					{
						var num = NbssFrame.ReadLength(prefix);
						if (num <= 0 || num > 16777215)
						{
							break;
						}

						var payload = new byte[num];
						if (!(await TryReadExactAsync(stream, payload, readCt)))
						{
							break;
						}

						(ReadOnlyMemory<byte>, bool)? tuple = DecodeInboundFrame(connection, payload);
						if (!tuple.HasValue)
						{
							continue;
						}

						var (message, transportEncrypted) = tuple.Value;
						var controlHeader = SmbProtocolIds.IsSmb2(message.Span) ? Smb2Header.Read(message.Span) : null;
						if (controlHeader != null && controlHeader.NextCommand == 0 && controlHeader.Command is SmbCommand.Cancel or SmbCommand.Close or SmbCommand.TreeDisconnect or SmbCommand.Logoff)
						{
							var control = RunControlFrameAsync(stream, connection, message, transportEncrypted, connCt);
							lock (_inflight)
							{
								_inflight.RemoveAll(t => t.IsCompleted);
								_inflight.Add(control);
							}

							continue;
						}

						if (_ioGate != null && _dispatcher.TryBeginConcurrentFrame(connection, message, transportEncrypted, out var prepared))
						{
							prepared = _dispatcher.ReserveScope(prepared);
							lock (_inflight)
							{
								_inflight.RemoveAll(t => t.IsCompleted);
								_inflight.Add(RunQueuedFrameAsync(stream, connection, prepared, connCt));
							}

							continue;
						}

						await DrainInflightAsync().ConfigureAwait(continueOnCapturedContext: false);
						var array = await _dispatcher.ProcessMessageAsync(connection, message, transportEncrypted).ConfigureAwait(continueOnCapturedContext: false);
						if (array.Length != 0)
						{
							await SendFramedAsync(stream, connection, array, forceEncrypt: false, connCt);
						}

						if (!connection.MustTerminate)
						{
							continue;
						}

						break;
					}

					goto end_IL_019b;

					end_IL_01c2: ;
				}
				catch (Exception ex) when (ex is IOException || ex is OperationCanceledException || ex is SocketException)
				{
					goto end_IL_019b;
				}
				catch (Exception ex2)
				{
					_log?.Invoke($"[conn {connection.ConnectionId:N}] Error: {ex2.Message}");
					goto end_IL_019b;
				}

				return;

				end_IL_019b: ;
			}
			finally
			{
				connection.AbandonPending();
				connection.CancelOrdinary();
				connection.SendRawAsync = null;
				connection.RequestClose = null;
				var retirement = _dispatcher.OnConnectionClosedAsync(connection, connection.ResponseSendFailed ? Smb2Dispatcher.CloseReason.SendFailure : (hardCt.IsCancellationRequested || drainToken.IsCancellationRequested) ? Smb2Dispatcher.CloseReason.Shutdown : Smb2Dispatcher.CloseReason.ConnectionLoss).AsTask();
				await DrainInflightAsync().ConfigureAwait(false);
				await retirement.ConfigureAwait(false);
				_server.Connections.TryRemove(connection.ConnectionId, out _);
				_server.Options.Metrics.OnConnectionClosed();
				AuditConnection(SmbAuditEventType.ConnectionClosed, connection);
				connection.ClientCertificate?.Dispose();
				_writeLock.Dispose();
				_ioGate?.Dispose();
				if (stream != null)
				{
					try
					{
						await stream.DisposeAsync().ConfigureAwait(continueOnCapturedContext: false);
					}
					catch
					{
						// ignored
					}
				}

				try
				{
					await disposeTransport().ConfigureAwait(continueOnCapturedContext: false);
				}
				catch
				{
					// ignored
				}
			}
		}
		finally
		{
			if (connCts != null)
			{
				((IDisposable)connCts).Dispose();
			}
		}
	}

	/// <summary>
	/// [M10.1] Performs the server-side TLS handshake for a new connection, bounded by
	/// <see cref="P:Smb.Host.SmbTlsOptions.HandshakeTimeout" />. Returns the authenticated <see cref="T:System.Net.Security.SslStream" />
	/// on success, or <c>null</c> if the handshake failed/timed out (the caller then drops the
	/// connection). The <see cref="T:System.Net.Security.SslStream" /> owns and disposes the inner network stream.
	/// </summary>
	private async Task<Stream?> EstablishTlsAsync(NetworkStream inner, SmbConnection connection, CancellationToken ct)
	{
		var ssl = new SslStream(inner, leaveInnerStreamOpen: false);
		try
		{
			var sslServerAuthenticationOptions = _tls!.BuildAuthenticationOptions();
			using var handshakeCts = CancellationTokenSource.CreateLinkedTokenSource(ct);
			handshakeCts.CancelAfter(_tls.HandshakeTimeout);
			await ssl.AuthenticateAsServerAsync(sslServerAuthenticationOptions, handshakeCts.Token).ConfigureAwait(continueOnCapturedContext: false);
			connection.IsTransportSecured = true;
			CaptureClientCertificate(ssl, connection);
			return ssl;
		}
		catch (Exception ex)
		{
			_log?.Invoke($"[conn {connection.ConnectionId:N}] TLS handshake failed: {ex.GetType().Name}: {ex.Message}");
			await ssl.DisposeAsync().ConfigureAwait(continueOnCapturedContext: false);
			return null;
		}
	}

	/// <summary>
	/// [M10.1] Records the validated mutual-TLS client certificate on the connection and, when a
	/// <see cref="T:Smb.Host.ITlsClientIdentityMapper" /> is configured, the identity it maps to. Best-effort: a
	/// throwing mapper is logged and treated as "no identity" so it never fails the connection.
	/// </summary>
	private void CaptureClientCertificate(SslStream ssl, SmbConnection connection)
	{
		var remoteCertificate = ssl.RemoteCertificate;
		if (remoteCertificate == null)
		{
			return;
		}

		var clientCertificate = (connection.ClientCertificate = X509CertificateLoader.LoadCertificate(remoteCertificate.Export(X509ContentType.Cert)));
		var clientIdentityMapper = _tls!.ClientIdentityMapper;
		if (clientIdentityMapper == null)
		{
			return;
		}

		try
		{
			connection.TransportAssertedIdentity = clientIdentityMapper.Map(clientCertificate);
		}
		catch (Exception ex)
		{
			_log?.Invoke($"[conn {connection.ConnectionId:N}] TLS client-identity mapper threw: {ex.GetType().Name}: {ex.Message}");
		}
	}

	/// <summary>[M8.1] Emits a connection-lifecycle audit event (accept/close) if the logger is enabled.</summary>
	private void AuditConnection(SmbAuditEventType type, SmbConnection connection)
	{
		var auditLogger = _server.Options.AuditLogger;
		if (auditLogger.IsEnabled(SmbLogLevel.Information))
		{
			var auditEvent = new SmbAuditEvent
			{
				EventType = type,
				Level = SmbLogLevel.Information,
				Timestamp = _server.Options.TimeProvider.GetUtcNow(),
				ClientAddress = connection.ClientAddress,
				User = connection.TransportAssertedIdentity?.ToString(),
			};
			auditLogger.Log(in auditEvent);
		}
	}

	/// <summary>
	/// Executes a prepared READ/WRITE frame and sends the response. Errors stay in the
	/// task; it requests connection teardown so a failed CREATE response cannot retain an ordinary open. The I/O slot is always released.
	/// </summary>
	private async Task RunQueuedFrameAsync(Stream stream, SmbConnection connection, Smb2Dispatcher.PreparedFrame frame, CancellationToken ct)
	{
		try { await _ioGate!.WaitAsync(ct).ConfigureAwait(false); }
		catch (OperationCanceledException)
		{
			await _dispatcher.AbandonPreparedFrameAsync(connection, frame).ConfigureAwait(false);
			return;
		}

		await RunConcurrentFrameAsync(stream, connection, frame, ct).ConfigureAwait(false);
	}

	private async Task RunControlFrameAsync(Stream stream, SmbConnection connection, ReadOnlyMemory<byte> message, bool encrypted, CancellationToken ct)
	{
		try
		{
			var response = await _dispatcher.ProcessMessageAsync(connection, message, encrypted).ConfigureAwait(false);
			if (response.Length != 0) await SendFramedAsync(stream, connection, response, false, ct).ConfigureAwait(false);
		}
		catch
		{
			connection.ResponseSendFailed = true;
			connection.AbandonPending();
			connection.CancelOrdinary();
			connection.RequestClose?.Invoke();
		}
	}

	internal async Task RunConcurrentFrameAsync(Stream stream, SmbConnection connection, Smb2Dispatcher.PreparedFrame frame, CancellationToken ct)
	{
		connection.OrdinaryRequests.TryGetValue(frame.MessageId, out var physical);
		try
		{
			var array = await _dispatcher.ExecutePreparedFrameAsync(connection, frame, ct).ConfigureAwait(continueOnCapturedContext: false);
			if (array.Length != 0)
			{
				await SendFramedAsync(stream, connection, array, forceEncrypt: false, ct).ConfigureAwait(continueOnCapturedContext: false);
			}
		}
		catch (Exception ex) when (ex is IOException || ex is OperationCanceledException || ex is SocketException || ex is ObjectDisposedException)
		{
			connection.ResponseSendFailed = true;
			connection.RequestClose?.Invoke();
		}
		catch (Exception ex2)
		{
			_log?.Invoke($"[conn {connection.ConnectionId:N}] Error in concurrent frame: {ex2.GetType().Name}: {ex2.Message}");
			connection.ResponseSendFailed = true;
			connection.RequestClose?.Invoke();
		}
		finally
		{
			if (physical != null) await physical.PhysicalFinished.ConfigureAwait(false);
			_ioGate!.Release();
		}
	}

	/// <summary>Barrier: drains all concurrent READ/WRITE frames for this connection.</summary>
	private async Task DrainInflightAsync()
	{
		Task[] tasks;
		lock (_inflight)
		{
			_inflight.RemoveAll(t => t.IsCompleted);
			if (_inflight.Count == 0)
			{
				return;
			}

			tasks = _inflight.ToArray();
		}

		await Task.WhenAll(tasks).ConfigureAwait(continueOnCapturedContext: false);
		lock (_inflight)
		{
			_inflight.RemoveAll(t => t.IsCompleted);
		}
	}

	/// <summary>
	/// Decodes the transport wrappers of an inbound frame — a compression transform frame (M10.3) is
	/// decompressed, an encryption transform frame is decrypted (and, if it wraps a compressed message,
	/// decompressed). Returns the SMB2 plaintext message plus the encrypted flag — or <c>null</c> if the
	/// frame should be discarded (unknown session, auth tag error, malformed compression).
	/// </summary>
	private (ReadOnlyMemory<byte> Message, bool Encrypted)? DecodeInboundFrame(SmbConnection connection, byte[] payload)
	{
		if (SmbProtocolIds.IsCompression(payload))
		{
			try
			{
				return (SmbCompressor.Decompress(payload), false);
			}
			catch
			{
				return null;
			}
		}

		if (!SmbProtocolIds.IsTransform(payload))
		{
			return (payload, false);
		}

		var transformHeader = TransformHeader.Read(payload);
		if (!_server.SessionGlobalList.TryGetValue(transformHeader.SessionId, out var value))
		{
			return null;
		}

		byte[] array;
		try
		{
			array = Smb2Transform.Decrypt(connection.CipherId, value.DecryptionKey, payload);
			if (SmbProtocolIds.IsCompression(array))
			{
				array = SmbCompressor.Decompress(array);
			}
		}
		catch
		{
			return null;
		}

		value.EncryptData = true;
		return (array, true);
	}

	/// <summary>Encrypts or compresses the response if needed, frames it as NBSS and writes it in serialized fashion.</summary>
	private async Task SendFramedAsync(Stream stream, SmbConnection connection, byte[] rawResponse, bool forceEncrypt, CancellationToken ct)
	{
		var array = EncodeOutbound(connection, rawResponse, forceEncrypt);
		var framed = NbssFrame.Wrap(array);
		await _writeLock.WaitAsync(ct).ConfigureAwait(continueOnCapturedContext: false);
		try
		{
			await stream.WriteAsync(framed, ct).ConfigureAwait(continueOnCapturedContext: false);
			await stream.FlushAsync(ct).ConfigureAwait(continueOnCapturedContext: false);
		}
		catch
		{
			connection.ResponseSendFailed = true;
			connection.AbandonPending();
			connection.CancelOrdinary();
			throw;
		}
		finally
		{
			_writeLock.Release();
		}

		connection.ResponseSent(rawResponse);
	}

	/// <summary>
	/// Applies the outbound transport wrappers. Encryption takes priority: the response is encrypted
	/// when the addressed session requires it globally, when its tree requires it (per-share encryption,
	/// §3.3.4.1.4 — includes the TREE_CONNECT response of an encrypted share), or when forced (ASYNC).
	/// Otherwise, if compression was negotiated (M10.3) and the frame is large enough to benefit, the
	/// response is compressed. The two are never combined — compressing is always the sender's choice.
	/// </summary>
	private byte[] EncodeOutbound(SmbConnection connection, byte[] response, bool forceEncrypt)
	{
		var num = ReadResponseSessionId(response);
		if (num != 0L && _server.SessionGlobalList.TryGetValue(num, out var value) && (forceEncrypt || value.EncryptData || (TryReadResponseTreeId(response, out var treeId) && value.TreeConnects.TryGetValue(treeId, out var value2) && value2.EncryptData)))
		{
			var array = BuildNonce(connection.CipherId, value.NextEncryptionNonce());
			return Smb2Transform.Encrypt(connection.CipherId, value.EncryptionKey, num, array, response);
		}

		return MaybeCompress(connection, response);
	}

	/// <summary>
	/// Compresses the response into an unchained compression transform frame when an algorithm was
	/// negotiated and the plaintext is at least <see cref="P:Smb.Server.SmbServerOptions.CompressionMinSize" /> bytes
	/// and actually shrinks; otherwise the response is returned unchanged.
	/// </summary>
	private byte[] MaybeCompress(SmbConnection connection, byte[] response)
	{
		var compressionAlgorithm = connection.CompressionAlgorithm;
		if (compressionAlgorithm == SmbCompressionAlgorithm.None)
		{
			return response;
		}

		return SmbCompressor.TryCompressUnchained(compressionAlgorithm, response, _server.Options.CompressionMinSize) ?? response;
	}

	private static ulong ReadResponseSessionId(ReadOnlySpan<byte> response)
	{
		if (response.Length < 64)
		{
			return 0uL;
		}

		return BinaryPrimitives.ReadUInt64LittleEndian(response.Slice(40, 8));
	}

	/// <summary>
	/// Reads the TreeId from a SYNC response header (offset 36). ASYNC responses
	/// (flag SMB2_FLAGS_ASYNC_COMMAND) carry the AsyncId at this position — there is
	/// no TreeId there, so false is returned (session-global encryption still applies).
	/// </summary>
	private static bool TryReadResponseTreeId(ReadOnlySpan<byte> response, out uint treeId)
	{
		treeId = 0u;
		if (response.Length < 64)
		{
			return false;
		}

		var smb2HeaderFlags = (Smb2HeaderFlags)BinaryPrimitives.ReadUInt32LittleEndian(response.Slice(16, 4));
		if (smb2HeaderFlags.HasFlag(Smb2HeaderFlags.AsyncCommand))
		{
			return false;
		}

		treeId = BinaryPrimitives.ReadUInt32LittleEndian(response.Slice(36, 4));
		return true;
	}

	/// <summary>
	/// [AUDIT-2026-06] Builds the AEAD nonce from a monotonically increasing session counter (NOT random).
	/// MS-SMB2 §3.3.4.1.4 requires a nonce value unique per EncryptionKey; a random
	/// 11/12-byte value runs into the birthday bound (with AES-GCM, nonce reuse is fatal).
	/// The counter (LE in the first 8 bytes; remainder 0) guarantees uniqueness per session/key.
	/// </summary>
	private static byte[] BuildNonce(SmbCipherId cipher, ulong counter)
	{
		var array = new byte[Smb2Transform.NonceLength(cipher)];
		BinaryPrimitives.WriteUInt64LittleEndian(array.AsSpan(0, 8), counter);
		return array;
	}

	private static async Task<bool> TryReadExactAsync(Stream stream, Memory<byte> buffer, CancellationToken ct)
	{
		try
		{
			await stream.ReadExactlyAsync(buffer, ct);
			return true;
		}
		catch (EndOfStreamException)
		{
			return false;
		}
		catch (OperationCanceledException)
		{
			return false;
		}
	}
}
