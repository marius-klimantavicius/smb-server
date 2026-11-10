using System;
using Smb.Auth.Oids;

namespace Smb.Auth;

public sealed class DevSpnegoNegotiator : ISpnegoNegotiator
{
    private sealed class Context : ISpnegoServerContext
    {
        private readonly byte[] _key;

        private readonly SecurityIdentity _identity;

        public Context(byte[] key, SecurityIdentity identity)
        {
            _key = key;
            _identity = identity;
        }

        public GssResult Accept(ReadOnlySpan<byte> spnegoToken)
        {
            return GssResult.Succeeded((byte[])_key.Clone(), _identity);
        }
    }

    private readonly byte[] _sessionKey;

    private readonly SecurityIdentity _identity;

    public DevSpnegoNegotiator(byte[]? sessionKey = null, SecurityIdentity? identity = null)
    {
        _sessionKey = sessionKey ?? CreateDeterministicKey();
        _identity = identity ?? new SecurityIdentity
        {
            DomainName = "WORKGROUP",
            UserName = "dev",
            IsAnonymous = true,
        };
    }

    public byte[] CreateInitialServerToken()
    {
        return SpnegoTokens.CreateNegTokenInit2(["1.3.6.1.4.1.311.2.2.10"]);
    }

    public ISpnegoServerContext CreateServerContext()
    {
        return new Context(_sessionKey, _identity);
    }

    private static byte[] CreateDeterministicKey()
    {
        var array = new byte[16];
        for (var i = 0; i < array.Length; i++)
        {
            array[i] = (byte)(i + 1);
        }

        return array;
    }
}
