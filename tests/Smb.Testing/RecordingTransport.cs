using System.Collections.Concurrent;
using Smb.Server.State;

namespace Smb.Testing;

public sealed record RecordedSend(byte[] Message, bool Encrypt);
public sealed class RecordingTransport
{
    private readonly ConcurrentQueue<RecordedSend> _sends = new ConcurrentQueue<RecordedSend>();
    private readonly SemaphoreSlim _available = new SemaphoreSlim(0);
    public OperationControl Control { get; } = new OperationControl();
    public RecordedSend[] Sends => _sends.ToArray();
    private SmbConnection? _connection;
    public void Attach(SmbConnection connection) { _connection = connection; connection.SendRawAsync = SendAsync; }
    public async Task SendAsync(byte[] message, bool encrypt)
    {
        await Control.BeforeAsync("Send");
        _sends.Enqueue(new RecordedSend(message.ToArray(), encrypt));
        _available.Release();
        _connection?.ResponseSent(message);
    }
    public async Task WaitForSendAsync(CancellationToken token = default)
    {
        if (!await _available.WaitAsync(Check.Timeout, token)) throw new TimeoutException("No recorded send");
    }
}
