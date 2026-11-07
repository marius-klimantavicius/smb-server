using System;
using System.Collections.Concurrent;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Net;
using Managed.Net.Quic;
using System.Threading;
using System.Threading.Tasks;
using Smb.Server.State;

namespace Smb.Host;

/// <summary>
/// [M10.2] SMB-over-QUIC listener. Accepts QUIC connections (UDP, mandatory TLS 1.3) and serves each
/// inbound bidirectional stream as one SMB2 connection through the shared
/// <see cref="T:Smb.Host.SmbConnectionHandler" /> core — the on-stream framing is identical to direct TCP, so the
/// whole dispatcher/frame loop is reused unchanged. The transport is already encrypted and
/// authenticated by QUIC, so no <see cref="T:Smb.Host.SmbTlsOptions" /> wrapping is applied.
/// <para>
/// Kept entirely in the host layer so <c>Smb.Server</c>/<c>Smb.Protocol</c> stay transport-agnostic and
/// fully cross-platform; only this listener touches the native-MsQuic-backed <c>Managed.Net.Quic</c> API.
/// </para>
/// </summary>
internal sealed class SmbQuicListener
{
	private readonly SmbServerState _server;

	private readonly SmbQuicOptions _options;

	private readonly IPEndPoint _endpoint;

	private readonly Action<string>? _log;

	private readonly ConcurrentDictionary<Task, byte> _connectionTasks = new ConcurrentDictionary<Task, byte>();

	private QuicListener? _listener;

	private Task? _acceptLoop;

	private CancellationTokenSource? _listenCts;

	/// <summary>The bound UDP endpoint (with the actual port after <see cref="M:Smb.Host.SmbQuicListener.StartAsync(System.Threading.CancellationToken,System.Threading.CancellationToken)" />).</summary>
	public IPEndPoint? LocalEndPoint => _listener?.LocalEndPoint ?? _endpoint;

	public SmbQuicListener(SmbServerState server, SmbQuicOptions options, IPEndPoint endpoint, Action<string>? log)
	{
		_server = server;
		_options = options;
		_endpoint = endpoint;
		_log = log;
	}

	/// <summary>
	/// Binds the QUIC listener and starts accepting. Throws if QUIC is not supported on this platform
	/// (missing MsQuic) — callers should check <see cref="P:Managed.Net.Quic.QuicListener.IsSupported" /> or catch this and
	/// fall back to TCP only.
	/// </summary>
	public async Task StartAsync(CancellationToken hardCt, CancellationToken drainToken)
	{
		if (!QuicListener.IsSupported)
		{
			throw new PlatformNotSupportedException("SMB over QUIC requires MsQuic (built into Windows 11 / Server 2022+; install libmsquic on Linux). QuicListener.IsSupported is false on this platform.");
		}

		_listenCts = CancellationTokenSource.CreateLinkedTokenSource(hardCt);
		_listener = await QuicListener.ListenAsync(new QuicListenerOptions
		{
			ListenEndPoint = _endpoint,
			ApplicationProtocols = _options.ApplicationProtocols.ToList(),
			ConnectionOptionsCallback = (_, _, _) => ValueTask.FromResult(_options.BuildServerConnectionOptions()),
		}, _listenCts.Token).ConfigureAwait(continueOnCapturedContext: false);
		_log?.Invoke($"SMB-over-QUIC listening on {_listener.LocalEndPoint} (UDP).");
		_acceptLoop = AcceptLoopAsync(hardCt, drainToken, _listenCts.Token);
	}

	private async Task AcceptLoopAsync(CancellationToken hardCt, CancellationToken drainToken, CancellationToken listenCt)
	{
		try
		{
			while (!listenCt.IsCancellationRequested)
			{
				var task = ServeConnectionAsync(await _listener!.AcceptConnectionAsync(listenCt).ConfigureAwait(continueOnCapturedContext: false), hardCt, drainToken);
				_connectionTasks.TryAdd(task, 0);
				_ = task.ContinueWith(t => _connectionTasks.TryRemove(t, out _), TaskScheduler.Default);
			}
		}
		catch (OperationCanceledException)
		{
		}
		catch (ObjectDisposedException)
		{
		}
		catch (QuicException)
		{
		}
	}

	/// <summary>
	/// Serves one QUIC connection: accepts its inbound bidirectional streams, each handled as an
	/// independent SMB2 connection, and disposes the connection once all streams have ended.
	/// </summary>
	private async Task ServeConnectionAsync(QuicConnection connection, CancellationToken hardCt, CancellationToken drainToken)
	{
		var streamTasks = new List<Task>();
		try
		{
			while (true)
			{
				QuicStream stream;
				try
				{
					stream = await connection.AcceptInboundStreamAsync(drainToken).ConfigureAwait(continueOnCapturedContext: false);
				}
				catch
				{
					break;
				}

				var item = new SmbConnectionHandler(_server, _log).ServeAsync(connection.RemoteEndPoint?.ToString(), (_, _) => Task.FromResult((Stream)stream), transportPreSecured: true, () => ValueTask.CompletedTask, hardCt, drainToken);
				streamTasks.Add(item);
			}
		}
		finally
		{
			try
			{
				await Task.WhenAll(streamTasks).ConfigureAwait(continueOnCapturedContext: false);
			}
			catch
			{
				// ignored
			}

			try
			{
				await connection.DisposeAsync().ConfigureAwait(continueOnCapturedContext: false);
			}
			catch
			{
				// ignored
			}
		}
	}

	/// <summary>Stops accepting, waits for the accept loop and drains outstanding connections.</summary>
	public async Task StopAsync()
	{
		try
		{
			if (_listenCts != null)
			{
				await _listenCts.CancelAsync().ConfigureAwait(continueOnCapturedContext: false);
			}
		}
		catch
		{
			// ignored
		}

		if (_listener != null)
		{
			try
			{
				await _listener.DisposeAsync().ConfigureAwait(continueOnCapturedContext: false);
			}
			catch
			{
				// ignored
			}
		}

		if (_acceptLoop != null)
		{
			try
			{
				await _acceptLoop.ConfigureAwait(continueOnCapturedContext: false);
			}
			catch
			{
				// ignored
			}
		}

		var array = _connectionTasks.Keys.ToArray();
		if (array.Length != 0)
		{
			try
			{
				await Task.WhenAll(array).ConfigureAwait(continueOnCapturedContext: false);
			}
			catch
			{
				// ignored
			}
		}

		_listenCts?.Dispose();
		_listener = null;
	}
}
