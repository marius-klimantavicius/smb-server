using System;
using System.Collections.Generic;
using System.Formats.Asn1;
using System.Text;

namespace Smb.Auth.Oids;

public static class SpnegoTokens
{
	private enum NegStateValue
	{
	}

	public const int NegStateAcceptCompleted = 0;

	public const int NegStateAcceptIncomplete = 1;

	public const int NegStateReject = 2;

	private const string DefaultHintName = "not_defined_in_RFC4178@please_ignore";

	private static readonly Asn1Tag ContextTag0 = new Asn1Tag(TagClass.ContextSpecific, 0);

	private static readonly Asn1Tag ContextTag1 = new Asn1Tag(TagClass.ContextSpecific, 1);

	private static readonly Asn1Tag ContextTag2 = new Asn1Tag(TagClass.ContextSpecific, 2);

	private static readonly Asn1Tag ContextTag3 = new Asn1Tag(TagClass.ContextSpecific, 3);

	private static readonly Asn1Tag ApplicationTag0 = new Asn1Tag(TagClass.Application, 0, isConstructed: true);

	public static byte[] CreateNegTokenInit2(IReadOnlyList<string> mechTypes, string? hintName = "not_defined_in_RFC4178@please_ignore")
	{
		var asnWriter = new AsnWriter(AsnEncodingRules.DER);
		using (asnWriter.PushSequence(ApplicationTag0))
		{
			asnWriter.WriteObjectIdentifier("1.3.6.1.5.5.2");
			using (asnWriter.PushSequence(ContextTag0))
			{
				using (asnWriter.PushSequence())
				{
					using (asnWriter.PushSequence(ContextTag0))
					{
						using (asnWriter.PushSequence())
						{
							foreach (var mechType in mechTypes)
							{
								asnWriter.WriteObjectIdentifier(mechType);
							}
						}
					}

					if (hintName != null)
					{
						using (asnWriter.PushSequence(ContextTag3))
						{
							using (asnWriter.PushSequence())
							{
								using (asnWriter.PushSequence(ContextTag0))
								{
									asnWriter.WriteEncodedValue(EncodeGeneralString(hintName));
								}
							}
						}
					}
				}
			}
		}

		return asnWriter.Encode();
	}

	public static byte[] CreateNegTokenInit(IReadOnlyList<string> mechTypes, byte[]? mechToken = null)
	{
		var asnWriter = new AsnWriter(AsnEncodingRules.DER);
		using (asnWriter.PushSequence(ApplicationTag0))
		{
			asnWriter.WriteObjectIdentifier("1.3.6.1.5.5.2");
			using (asnWriter.PushSequence(ContextTag0))
			{
				using (asnWriter.PushSequence())
				{
					using (asnWriter.PushSequence(ContextTag0))
					{
						using (asnWriter.PushSequence())
						{
							foreach (var mechType in mechTypes)
							{
								asnWriter.WriteObjectIdentifier(mechType);
							}
						}
					}

					if (mechToken != null)
					{
						using (asnWriter.PushSequence(ContextTag2))
						{
							asnWriter.WriteOctetString(mechToken);
						}
					}
				}
			}
		}

		return asnWriter.Encode();
	}

	public static byte[] CreateNegTokenResp(int negState, string? supportedMech = null, byte[]? responseToken = null, byte[]? mechListMic = null)
	{
		var asnWriter = new AsnWriter(AsnEncodingRules.DER);
		using (asnWriter.PushSequence(ContextTag1))
		{
			using (asnWriter.PushSequence())
			{
				using (asnWriter.PushSequence(ContextTag0))
				{
					asnWriter.WriteEnumeratedValue((NegStateValue)negState);
				}

				if (supportedMech != null)
				{
					using (asnWriter.PushSequence(ContextTag1))
					{
						asnWriter.WriteObjectIdentifier(supportedMech);
					}
				}

				if (responseToken != null)
				{
					using (asnWriter.PushSequence(ContextTag2))
					{
						asnWriter.WriteOctetString(responseToken);
					}
				}

				if (mechListMic != null)
				{
					using (asnWriter.PushSequence(ContextTag3))
					{
						asnWriter.WriteOctetString(mechListMic);
					}
				}
			}
		}

		return asnWriter.Encode();
	}

	public static byte[] EncodeMechList(IReadOnlyList<string> mechTypes)
	{
		var asnWriter = new AsnWriter(AsnEncodingRules.DER);
		using (asnWriter.PushSequence())
		{
			foreach (var mechType in mechTypes)
			{
				asnWriter.WriteObjectIdentifier(mechType);
			}
		}

		return asnWriter.Encode();
	}

	private static byte[] EncodeGeneralString(string value)
	{
		var bytes = Encoding.ASCII.GetBytes(value);
		if (bytes.Length < 128)
		{
			var array = new byte[2 + bytes.Length];
			array[0] = 27;
			array[1] = (byte)bytes.Length;
			bytes.CopyTo(array, 2);
			return array;
		}

		var list = new List<byte>();
		for (var num = bytes.Length; num > 0; num >>= 8)
		{
			list.Insert(0, (byte)(num & 0xFF));
		}

		var array2 = new byte[2 + list.Count + bytes.Length];
		array2[0] = 27;
		array2[1] = (byte)(0x80 | list.Count);
		list.CopyTo(array2, 2);
		bytes.CopyTo(array2, 2 + list.Count);
		return array2;
	}

	public static SpnegoParseResult Parse(ReadOnlySpan<byte> token)
	{
		var asnReader = new AsnReader(token.ToArray(), AsnEncodingRules.DER);
		var asn1Tag = asnReader.PeekTag();
		if (asn1Tag.TagClass == TagClass.Application && asn1Tag.TagValue == 0)
		{
			return ParseNegTokenInit(asnReader);
		}

		if (asn1Tag.TagClass == TagClass.ContextSpecific && asn1Tag.TagValue == 1)
		{
			return ParseNegTokenResp(asnReader);
		}

		throw new FormatException($"Unexpected SPNEGO top-level tag {asn1Tag.TagClass}/{asn1Tag.TagValue}.");
	}

	private static SpnegoParseResult ParseNegTokenInit(AsnReader reader)
	{
		var asnReader = reader.ReadSequence(ApplicationTag0);
		var text = asnReader.ReadObjectIdentifier();
		if (text != "1.3.6.1.5.5.2")
		{
			throw new FormatException("Expected SPNEGO OID, found " + text + ".");
		}

		var asnReader2 = asnReader.ReadSequence(ContextTag0).ReadSequence();
		var list = new List<string>();
		byte[] mechToken = null;
		byte[] mechListBytes = null;
		while (asnReader2.HasData)
		{
			var asn1Tag = asnReader2.PeekTag();
			if (asn1Tag.TagClass != TagClass.ContextSpecific)
			{
				asnReader2.ReadEncodedValue();
				continue;
			}

			switch (asn1Tag.TagValue)
			{
				case 0:
				{
					var data = asnReader2.ReadSequence(ContextTag0).ReadEncodedValue();
					mechListBytes = data.ToArray();
					var asnReader3 = new AsnReader(data, AsnEncodingRules.DER).ReadSequence();
					while (asnReader3.HasData)
					{
						list.Add(asnReader3.ReadObjectIdentifier());
					}

					break;
				}
				case 2:
					mechToken = asnReader2.ReadSequence(ContextTag2).ReadOctetString();
					break;
				default:
					asnReader2.ReadEncodedValue();
					break;
			}
		}

		return new SpnegoParseResult
		{
			MechTypes = list,
			MechToken = mechToken,
			MechListBytes = mechListBytes,
			IsResponseToken = false,
		};
	}

	private static SpnegoParseResult ParseNegTokenResp(AsnReader reader)
	{
		var asnReader = reader.ReadSequence(ContextTag1).ReadSequence();
		int? negState = null;
		string supportedMech = null;
		byte[] mechToken = null;
		byte[] mechListMic = null;
		while (asnReader.HasData)
		{
			var asn1Tag = asnReader.PeekTag();
			if (asn1Tag.TagClass != TagClass.ContextSpecific)
			{
				asnReader.ReadEncodedValue();
				continue;
			}

			switch (asn1Tag.TagValue)
			{
				case 0:
					negState = (int)asnReader.ReadSequence(ContextTag0).ReadEnumeratedValue<NegStateValue>();
					break;
				case 1:
					supportedMech = asnReader.ReadSequence(ContextTag1).ReadObjectIdentifier();
					break;
				case 2:
					mechToken = asnReader.ReadSequence(ContextTag2).ReadOctetString();
					break;
				case 3:
					mechListMic = asnReader.ReadSequence(ContextTag3).ReadOctetString();
					break;
				default:
					asnReader.ReadEncodedValue();
					break;
			}
		}

		return new SpnegoParseResult
		{
			MechToken = mechToken,
			SupportedMech = supportedMech,
			NegState = negState,
			MechListMic = mechListMic,
			IsResponseToken = true,
		};
	}
}
