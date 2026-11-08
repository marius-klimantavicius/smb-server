using System;
using System.Collections.Generic;
using System.Linq;
using System.Security.Cryptography;
using Smb.Protocol.Compression;
using Smb.Protocol.Enums;
using Smb.Protocol.Messages;
using Smb.Server.State;

namespace Smb.Server;

public static class NegotiateProcessor
{
	public static SmbDialect SelectDialect(IReadOnlyList<SmbDialect> clientDialects, SmbServerOptions options)
	{
		var smbDialect = SmbDialect.None;
		foreach (var clientDialect in clientDialects)
		{
			if (clientDialect != SmbDialect.Wildcard2FF && IsKnown(clientDialect) && (int)clientDialect >= (int)options.MinDialect && (int)clientDialect <= (int)options.MaxDialect && (int)clientDialect > (int)smbDialect)
			{
				smbDialect = clientDialect;
			}
		}

		return smbDialect;
	}

	public static NegotiateResponse BuildResponse(SmbConnection connection, NegotiateRequest request, SmbServerOptions options, byte[] securityBuffer)
	{
		var smbDialect = SelectDialect(request.Dialects, options);
		if (smbDialect == SmbDialect.None)
		{
			throw new InvalidOperationException("No common dialect with the client.");
		}

		connection.Dialect = smbDialect;
		connection.ClientGuid = request.ClientGuid;
		connection.ClientCapabilities = request.Capabilities;
		connection.ClientSecurityMode = request.SecurityMode;
		var smbSecurityMode = SmbSecurityMode.SigningEnabled;
		if (options.RequireMessageSigning)
		{
			smbSecurityMode |= SmbSecurityMode.SigningRequired;
		}

		connection.ServerSecurityMode = smbSecurityMode;
		connection.ShouldSign = options.RequireMessageSigning || request.SecurityMode.HasFlag(SmbSecurityMode.SigningRequired);
		var flag = (connection.SupportsMultiCredit = smbDialect.SupportsLargeMtu() && request.Capabilities.HasFlag(Smb2Capabilities.LargeMtu));
		connection.MaxReadSize = (flag ? options.MaxReadSize : Math.Min(options.MaxReadSize, 65536u));
		connection.MaxWriteSize = (flag ? options.MaxWriteSize : Math.Min(options.MaxWriteSize, 65536u));
		connection.MaxTransactSize = (flag ? options.MaxTransactSize : Math.Min(options.MaxTransactSize, 65536u));
		var smb2Capabilities = Smb2Capabilities.None;
		if (flag)
		{
			smb2Capabilities |= Smb2Capabilities.LargeMtu;
		}

		if (options.FeaturePolicy.Leasing && smbDialect >= SmbDialect.Smb210 && options.Shares.All.Any(share => Caching.FileCacheCoordinator.Supports(share.FileStore)))
			smb2Capabilities |= Smb2Capabilities.Leasing;
		if (options.FeaturePolicy.SupportsMultichannel(smbDialect) && options.EnableMultichannel)
		{
			smb2Capabilities |= Smb2Capabilities.MultiChannel;
		}

		if (options.DfsNamespace != null)
		{
			smb2Capabilities |= Smb2Capabilities.Dfs;
		}

		var list = new List<NegotiateContext>();
		if (smbDialect == SmbDialect.Smb311)
		{
			NegotiateSmb311Contexts(connection, request, options, list);
		}
		else if (smbDialect == SmbDialect.Smb300 || smbDialect == SmbDialect.Smb302)
		{
			if (request.Capabilities.HasFlag(Smb2Capabilities.Encryption) || options.RequireEncryption)
			{
				smb2Capabilities |= Smb2Capabilities.Encryption;
				connection.CipherId = SmbCipherId.Aes128Ccm;
				connection.SupportsEncryption = true;
			}

			connection.SigningAlgorithmId = SmbSigningAlgorithmId.AesCmac;
		}
		else
		{
			connection.SigningAlgorithmId = SmbSigningAlgorithmId.HmacSha256;
		}

		connection.ServerCapabilities = smb2Capabilities;
		return new NegotiateResponse
		{
			SecurityMode = smbSecurityMode,
			DialectRevision = smbDialect,
			ServerGuid = options.ServerGuid,
			Capabilities = smb2Capabilities,
			MaxTransactSize = connection.MaxTransactSize,
			MaxReadSize = connection.MaxReadSize,
			MaxWriteSize = connection.MaxWriteSize,
			SystemTime = DateTime.UtcNow.ToFileTimeUtc(),
			ServerStartTime = 0L,
			SecurityBuffer = securityBuffer,
			NegotiateContexts = list,
		};
	}

	private static void NegotiateSmb311Contexts(SmbConnection connection, NegotiateRequest request, SmbServerOptions options, List<NegotiateContext> responseContexts)
	{
		connection.PreauthIntegrityHashId = PreauthHashAlgorithm.Sha512;
		responseContexts.Add(new PreauthIntegrityContext
		{
			HashAlgorithms = [PreauthHashAlgorithm.Sha512],
			Salt = RandomNumberGenerator.GetBytes(32),
		});
		var encryptionContext = request.NegotiateContexts.OfType<EncryptionContext>().FirstOrDefault();
		if (encryptionContext != null)
		{
			var smbCipherId = PickByPreference(options.CipherPreference, encryptionContext.Ciphers);
			if (smbCipherId != SmbCipherId.None)
			{
				connection.CipherId = smbCipherId;
				connection.SupportsEncryption = true;
				responseContexts.Add(new EncryptionContext
				{
					Ciphers = [smbCipherId],
				});
			}
		}

		var signingContext = request.NegotiateContexts.OfType<SigningContext>().FirstOrDefault();
		if (signingContext != null)
		{
			var item = (connection.SigningAlgorithmId = PickSigning(options.SigningPreference, signingContext.Algorithms));
			responseContexts.Add(new SigningContext
			{
				Algorithms = [item],
			});
		}
		else
		{
			connection.SigningAlgorithmId = SmbSigningAlgorithmId.AesCmac;
		}

		var compressionContext = request.NegotiateContexts.OfType<CompressionContext>().FirstOrDefault();
		if (options.EnableCompression && compressionContext != null)
		{
			var list = PickCompression(options.CompressionPreference, compressionContext.Algorithms);
			if (list.Count > 0)
			{
				connection.CompressionAlgorithm = list.FirstOrDefault(SmbCompressor.IsEncodable, SmbCompressionAlgorithm.None);
				responseContexts.Add(new CompressionContext
				{
					Flags = 0u,
					Algorithms = list,
				});
			}
		}
	}

	private static List<SmbCompressionAlgorithm> PickCompression(IReadOnlyList<SmbCompressionAlgorithm> serverPref, IReadOnlyList<SmbCompressionAlgorithm> clientList)
	{
		var list = new List<SmbCompressionAlgorithm>();
		foreach (var item in serverPref)
		{
			if (SmbCompressor.IsDecodable(item) && clientList.Contains(item) && !list.Contains(item))
			{
				list.Add(item);
			}
		}

		return list;
	}

	private static SmbCipherId PickByPreference(IReadOnlyList<SmbCipherId> serverPref, IReadOnlyList<SmbCipherId> clientList)
	{
		foreach (var item in serverPref)
		{
			if (clientList.Contains(item))
			{
				return item;
			}
		}

		return SmbCipherId.None;
	}

	private static SmbSigningAlgorithmId PickSigning(IReadOnlyList<SmbSigningAlgorithmId> serverPref, IReadOnlyList<SmbSigningAlgorithmId> clientList)
	{
		foreach (var item in serverPref)
		{
			if (clientList.Contains(item))
			{
				return item;
			}
		}

		if (clientList.Count <= 0)
		{
			return SmbSigningAlgorithmId.AesCmac;
		}

		return clientList[0];
	}

	private static bool IsKnown(SmbDialect d)
	{
		switch (d)
		{
			case SmbDialect.Smb202:
			case SmbDialect.Smb210:
			case SmbDialect.Smb300:
			case SmbDialect.Smb302:
			case SmbDialect.Smb311:
				return true;
			default:
				return false;
		}
	}
}
