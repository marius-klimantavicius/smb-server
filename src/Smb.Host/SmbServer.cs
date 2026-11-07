using System;
using System.Collections.Concurrent;
using System.Collections.Generic;
using System.Linq;
using System.Net;
using System.Net.Sockets;
using System.Threading;
using System.Threading.Tasks;
using Smb.FileSystem;
using Smb.Server;
using Smb.Server.Diagnostics;
using Smb.Server.State;
using Smb.Server.Witness;

namespace Smb.Host;

/// <summary>
/// Public SMB-2/3 server host (Context §3, §19). Listens on TCP (default 445),
/// accepts connections and serves them concurrently. Simple usage:
/// <code>
/// await using var server = SmbServerBuilder.Create()
///     .WithEndpoint(IPAddress.Any, 445)
///     .UseDevAuthentication()        // test/dev only; use a real negotiator in production
///     .AddShare(new Share { Name = "Data", FileStore = myStore })
///     .Build();
/// await server.StartAsync();
/// </code>
/// </summary>
public sealed class SmbServer : IAsyncDisposable
{
	private readonly SmbServerState _state;

	private readonly IPEndPoint _endpoint;

	private readonly Action<string>? _log;

	private readonly ConnectionLimiter _limiter;

	private readonly SmbTlsOptions? _tls;

	private readonly SmbQuicOptions? _quicOptions;

	private readonly IPEndPoint? _quicEndpoint;

	private readonly WsDiscoveryOptions? _wsDiscoveryOptions;

	private TcpListener? _listener;

	private SmbQuicListener? _quicListener;

	private WsDiscoveryListener? _wsDiscoveryListener;

	private CancellationTokenSource? _hardCts;

	private CancellationTokenSource? _drainCts;

	private Task? _acceptLoop;

	private Task? _sweepLoop;

	private readonly ConcurrentDictionary<Task, byte> _connectionTasks = new ConcurrentDictionary<Task, byte>();

	/// <summary>The local TCP endpoint on which the server is listening (after <see cref="M:Smb.Host.SmbServer.StartAsync(System.Threading.CancellationToken)" /> with the actual port).</summary>
	public IPEndPoint Endpoint => (IPEndPoint)(_listener?.LocalEndpoint ?? _endpoint);

	/// <summary>[M10.2] The local UDP endpoint of the SMB-over-QUIC listener, or <c>null</c> when QUIC is not configured.</summary>
	public IPEndPoint? QuicEndpoint => _quicListener?.LocalEndPoint ?? _quicEndpoint;

	/// <summary>[M11.3] The local UDP endpoint of the WS-Discovery responder, or <c>null</c> when it is not enabled.</summary>
	public IPEndPoint? WsDiscoveryEndpoint => _wsDiscoveryListener?.LocalEndPoint;

	/// <summary>Server state (shares, sessions) — for tests/diagnostics.</summary>
	public SmbServerState State => _state;

	/// <summary>[M8.5] Live health &amp; performance counters. Read <c>Metrics.Snapshot()</c> for a health endpoint.</summary>
	public SmbServerMetrics Metrics => _state.Options.Metrics;

	/// <summary>Currently published shares (snapshot); reflects runtime add/remove.</summary>
	public IReadOnlyCollection<IShare> Shares => _state.Shares.All;

	internal SmbServer(SmbServerOptions options, IPEndPoint endpoint, Action<string>? log, SmbTlsOptions? tls = null, SmbQuicOptions? quic = null, int quicPort = 443, WsDiscoveryOptions? wsDiscovery = null)
	{
		options.Validate();
		tls?.Validate();
		quic?.Validate();
		wsDiscovery?.Validate();
		EnsureIpcShare(options.Shares);
		_state = new SmbServerState(options);
		_endpoint = endpoint;
		_log = log;
		_tls = tls;
		_quicOptions = quic;
		_quicEndpoint = ((quic != null) ? new IPEndPoint(endpoint.Address, quicPort) : null);
		_wsDiscoveryOptions = wsDiscovery;
		_limiter = new ConnectionLimiter(options.MaxConnections, options.MaxConnectionsPerClient);
	}

	/// <summary>
	/// [C1.4] Signals a resource/node availability change to witness-registered clients (MS-SWN): every client
	/// that registered on <paramref name="netName" /> (case-insensitive; null/empty targets all) is asynchronously
	/// notified so it can fail over. Returns the number of clients notified. Call this when a clustered resource
	/// moves or a node goes down. Requires the affected share to advertise continuous availability (C1.0).
	/// </summary>
	public int NotifyWitnessResourceChange(string? netName, WitnessResourceChange change, string resourceName)
	{
		return _state.WitnessRegistrations.NotifyResourceChange(netName, change, resourceName);
	}

	/// <summary>
	/// Adds (or replaces) a share at runtime. New TREE_CONNECTs see it immediately; existing tree
	/// connections are unaffected. No restart required.
	/// </summary>
	public void AddShare(IShare share)
	{
		_state.Shares.Add(share);
	}

	/// <summary>
	/// Removes a share at runtime. New TREE_CONNECTs to it are refused (<c>STATUS_BAD_NETWORK_NAME</c>);
	/// existing tree connections keep working until the client disconnects. Returns false if it was
	/// not present.
	/// </summary>
	public bool RemoveShare(string name)
	{
		return _state.Shares.Remove(name);
	}

	/// <summary>Starts the listener and the accept loop (Context §3.3.3: open listener on 445).</summary>
	public async Task StartAsync(CancellationToken ct = default(CancellationToken))
	{
		if (_listener != null)
		{
			throw new InvalidOperationException("Server is already running.");
		}

		_hardCts = CancellationTokenSource.CreateLinkedTokenSource(ct);
		_drainCts = new CancellationTokenSource();
		_listener = new TcpListener(_endpoint);
		_listener.Start();
		_log?.Invoke($"SMB server listening on {_listener.LocalEndpoint}.");
		_acceptLoop = AcceptLoopAsync(_hardCts.Token);
		_sweepLoop = SweepLoopAsync(_hardCts.Token);
		if (_quicOptions != null)
		{
			_quicListener = new SmbQuicListener(_state, _quicOptions, _quicEndpoint!, _log);
			await _quicListener.StartAsync(_hardCts.Token, _drainCts.Token).ConfigureAwait(continueOnCapturedContext: false);
		}

		if (_wsDiscoveryOptions != null)
		{
			_wsDiscoveryListener = new WsDiscoveryListener(_wsDiscoveryOptions, _log);
			_wsDiscoveryListener.Start(_hardCts.Token);
		}
	}

	/// <summary>
	/// [M8.2] Background timeout sweep: periodically expires idle sessions and drops idle / slow-auth
	/// connections (via the dispatcher's <see cref="M:Smb.Server.Smb2Dispatcher.SweepIdleTimeouts" />) and scavenges
	/// expired durable handles. Disabled when <see cref="P:Smb.Server.SmbServerOptions.TimeoutSweepInterval" /> is zero.
	/// </summary>
	private async Task SweepLoopAsync(CancellationToken ct)
	{
		var options = _state.Options;
		if (options.TimeoutSweepInterval <= TimeSpan.Zero)
		{
			return;
		}

		var dispatcher = new Smb2Dispatcher(_state, _log);
		try
		{
			while (!ct.IsCancellationRequested)
			{
				await Task.Delay(options.TimeoutSweepInterval, options.TimeProvider, ct).ConfigureAwait(continueOnCapturedContext: false);
				try
				{
					dispatcher.SweepIdleTimeouts();
					dispatcher.ScavengeDurableHandles();
				}
				catch (Exception ex)
				{
					_log?.Invoke("[sweep] error: " + ex.GetType().Name + ": " + ex.Message);
				}
			}
		}
		catch (OperationCanceledException)
		{
		}
	}

	private async Task AcceptLoopAsync(CancellationToken ct)
	{
		try
		{
			while (!ct.IsCancellationRequested)
			{
				var tcpClient = await _listener!.AcceptTcpClientAsync(ct);
				tcpClient.NoDelay = true;
				var clientIp = (tcpClient.Client.RemoteEndPoint as IPEndPoint)?.Address.ToString() ?? "unknown";
				if (!_limiter.TryAdmit(clientIp))
				{
					_log?.Invoke("Connection from " + clientIp + " rejected (connection limit reached).");
					try
					{
						tcpClient.Dispose();
					}
					catch
					{
						// ignored
					}

					continue;
				}

				var task = new SmbConnectionHandler(_state, _log, _tls).RunAsync(tcpClient, _hardCts!.Token, _drainCts!.Token);
				_connectionTasks.TryAdd(task, 0);
				_ = task.ContinueWith(t =>
				{
					_connectionTasks.TryRemove(t, out _);
					_limiter.Release(clientIp);
				}, TaskScheduler.Default);
			}
		}
		catch (OperationCanceledException)
		{
		}
		catch (ObjectDisposedException)
		{
		}
	}

	/// <summary>
	/// [M8.4] Graceful shutdown with connection draining. Stops accepting new connections, sends
	/// oplock/lease breaks to caching holders, then lets in-flight operations finish for up to
	/// <paramref name="drainTimeout" /> (default <see cref="P:Smb.Server.SmbServerOptions.ShutdownDrainTimeout" />)
	/// before force-closing the remainder.
	/// </summary>
	public async Task StopAsync(TimeSpan? drainTimeout = null)
	{
		if (_hardCts == null)
		{
			return;
		}

		var drain = drainTimeout ?? _state.Options.ShutdownDrainTimeout;
		_listener?.Stop();
		try
		{
			await new Smb2Dispatcher(_state, _log).SendShutdownBreaksAsync();
		}
		catch
		{
			// ignored
		}

		if (_drainCts != null)
		{
			await _drainCts.CancelAsync();
		}

		var array = _connectionTasks.Keys.ToArray();
		if (array.Length == 0)
		{
			await _hardCts.CancelAsync();
		}
		else
		{
			_log?.Invoke($"Draining {array.Length} connection(s), timeout {drain.TotalSeconds:0}s.");
			var all = Task.WhenAll(array);
			if (await Task.WhenAny(all, Task.Delay(drain)).ConfigureAwait(continueOnCapturedContext: false) != all)
			{
				_log?.Invoke("Drain timeout reached — forcing remaining connections closed.");
				await _hardCts.CancelAsync();
			}

			try
			{
				await all;
			}
			catch
			{
				// ignored
			}
		}

		if (_quicListener != null)
		{
			try
			{
				await _quicListener.StopAsync();
			}
			catch
			{
				// ignored
			}
		}

		if (_wsDiscoveryListener != null)
		{
			try
			{
				await _wsDiscoveryListener.StopAsync();
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
				await _acceptLoop;
			}
			catch
			{
				// ignored
			}
		}

		if (!_hardCts.IsCancellationRequested)
		{
			await _hardCts.CancelAsync();
		}

		if (_sweepLoop != null)
		{
			try
			{
				await _sweepLoop;
			}
			catch
			{
				// ignored
			}
		}

		_listener = null;
	}

	public async ValueTask DisposeAsync()
	{
		await StopAsync();
		_hardCts?.Dispose();
		_drainCts?.Dispose();
	}

	private static void EnsureIpcShare(ShareCollection shares)
	{
		if (!shares.Contains("IPC$"))
		{
			shares.Add(Share.CreateIpc());
		}
	}
}
