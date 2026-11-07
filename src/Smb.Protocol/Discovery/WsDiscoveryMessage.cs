using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Text;
using System.Xml;
using System.Xml.Linq;

namespace Smb.Protocol.Discovery;

public static class WsDiscoveryMessage
{
	private static readonly XNamespace Soap = "http://www.w3.org/2003/05/soap-envelope";

	private static readonly XNamespace Wsa = "http://schemas.xmlsoap.org/ws/2004/08/addressing";

	private static readonly XNamespace Wsd = "http://schemas.xmlsoap.org/ws/2005/04/discovery";

	public static string? TryGetAction(ReadOnlySpan<byte> datagram)
	{
		return (TryParse(datagram)?.Root?.Element(Soap + "Header"))?.Element(Wsa + "Action")?.Value.Trim();
	}

	public static bool TryParseProbe(ReadOnlySpan<byte> datagram, out WsDiscoveryProbe probe)
	{
		probe = default;
		var xElement = TryParse(datagram)?.Root;
		var xElement2 = xElement?.Element(Soap + "Header");
		if (xElement2 == null)
		{
			return false;
		}

		if (xElement2.Element(Wsa + "Action")?.Value.Trim() != "http://schemas.xmlsoap.org/ws/2005/04/discovery/Probe")
		{
			return false;
		}

		var messageId = xElement2.Element(Wsa + "MessageID")?.Value.Trim() ?? string.Empty;
		var types = ParseTypes((xElement.Element(Soap + "Body")?.Element(Wsd + "Probe"))?.Element(Wsd + "Types"));
		probe = new WsDiscoveryProbe(messageId, types);
		return true;
	}

	public static byte[] BuildProbeMatches(string relatesToMessageId, Guid endpointId, IReadOnlyList<WsDiscoveryQName> types, IReadOnlyList<string> xAddrs, ulong instanceId, ulong messageNumber, uint metadataVersion = 1u)
	{
		var body = new XElement(Soap + "Body", new XElement(Wsd + "ProbeMatches", new XElement(Wsd + "ProbeMatch", new XElement(Wsa + "EndpointReference", new XElement(Wsa + "Address", EndpointUri(endpointId))), TypesElement(types), new XElement(Wsd + "XAddrs", string.Join(' ', xAddrs)), new XElement(Wsd + "MetadataVersion", metadataVersion))));
		return Serialize(Envelope("http://schemas.xmlsoap.org/ws/2004/08/addressing/role/anonymous", "http://schemas.xmlsoap.org/ws/2005/04/discovery/ProbeMatches", relatesToMessageId, instanceId, messageNumber, body));
	}

	public static byte[] BuildHello(Guid endpointId, IReadOnlyList<WsDiscoveryQName> types, IReadOnlyList<string> xAddrs, ulong instanceId, ulong messageNumber, uint metadataVersion = 1u)
	{
		return BuildPresence("http://schemas.xmlsoap.org/ws/2005/04/discovery/Hello", endpointId, types, xAddrs, instanceId, messageNumber, metadataVersion);
	}

	public static byte[] BuildBye(Guid endpointId, IReadOnlyList<WsDiscoveryQName> types, IReadOnlyList<string> xAddrs, ulong instanceId, ulong messageNumber, uint metadataVersion = 1u)
	{
		return BuildPresence("http://schemas.xmlsoap.org/ws/2005/04/discovery/Bye", endpointId, types, xAddrs, instanceId, messageNumber, metadataVersion);
	}

	private static byte[] BuildPresence(string action, Guid endpointId, IReadOnlyList<WsDiscoveryQName> types, IReadOnlyList<string> xAddrs, ulong instanceId, ulong messageNumber, uint metadataVersion)
	{
		var text = ((action == "http://schemas.xmlsoap.org/ws/2005/04/discovery/Hello") ? "Hello" : "Bye");
		var body = new XElement(Soap + "Body", new XElement(Wsd + text, new XElement(Wsa + "EndpointReference", new XElement(Wsa + "Address", EndpointUri(endpointId))), TypesElement(types), new XElement(Wsd + "XAddrs", string.Join(' ', xAddrs)), new XElement(Wsd + "MetadataVersion", metadataVersion)));
		return Serialize(Envelope("urn:schemas-xmlsoap-org:ws:2005:04:discovery", action, null, instanceId, messageNumber, body));
	}

	private static XElement Envelope(string to, string action, string? relatesTo, ulong instanceId, ulong messageNumber, XElement body)
	{
		var xElement = new XElement(Soap + "Header", new XElement(Wsa + "To", to), new XElement(Wsa + "Action", action), new XElement(Wsa + "MessageID", EndpointUri(Guid.NewGuid())));
		if (relatesTo != null)
		{
			xElement.Add(new XElement(Wsa + "RelatesTo", relatesTo));
		}

		xElement.Add(new XElement(Wsd + "AppSequence", new XAttribute("InstanceId", instanceId), new XAttribute("MessageNumber", messageNumber)));
		return new XElement(Soap + "Envelope", new XAttribute(XNamespace.Xmlns + "soap", "http://www.w3.org/2003/05/soap-envelope"), new XAttribute(XNamespace.Xmlns + "wsa", "http://schemas.xmlsoap.org/ws/2004/08/addressing"), new XAttribute(XNamespace.Xmlns + "wsd", "http://schemas.xmlsoap.org/ws/2005/04/discovery"), xElement, body);
	}

	private static XElement TypesElement(IReadOnlyList<WsDiscoveryQName> types)
	{
		var el = new XElement(Wsd + "Types");
		foreach (var type in types)
		{
			if (el.GetPrefixOfNamespace(type.Namespace) == null)
			{
				el.Add(new XAttribute(XNamespace.Xmlns + type.Prefix, type.Namespace));
			}
		}

		el.Value = string.Join(' ', types.Select(t => (el.GetPrefixOfNamespace(t.Namespace) ?? t.Prefix) + ":" + t.LocalName));
		return el;
	}

	private static IReadOnlyList<string> ParseTypes(XElement? typesEl)
	{
		if (typesEl == null || string.IsNullOrWhiteSpace(typesEl.Value))
		{
			return Array.Empty<string>();
		}

		var list = new List<string>();
		var array = typesEl.Value.Split((char[]?)null, StringSplitOptions.RemoveEmptyEntries);
		foreach (var text in array)
		{
			var num = text.IndexOf(':');
			if (num < 0)
			{
				var defaultNamespace = typesEl.GetDefaultNamespace();
				list.Add("{" + defaultNamespace.NamespaceName + "}" + text);
			}
			else
			{
				var text2 = text.Substring(0, num);
				var text3 = text.Substring(num + 1);
				list.Add("{" + (typesEl.GetNamespaceOfPrefix(text2)?.NamespaceName ?? text2) + "}" + text3);
			}
		}

		return list;
	}

	private static string EndpointUri(Guid id)
	{
		return "urn:uuid:" + id.ToString("D");
	}

	private static XDocument? TryParse(ReadOnlySpan<byte> datagram)
	{
		try
		{
			var s = Encoding.UTF8.GetString(datagram);
			using var reader = XmlReader.Create(settings: new XmlReaderSettings
			{
				DtdProcessing = DtdProcessing.Prohibit,
				XmlResolver = null,
			}, input: new StringReader(s));
			return XDocument.Load(reader);
		}
		catch (XmlException)
		{
			return null;
		}
		catch (ArgumentException)
		{
			return null;
		}
	}

	private static byte[] Serialize(XElement envelope)
	{
		var xDocument = new XDocument(new XDeclaration("1.0", "utf-8", null), envelope);
		using var memoryStream = new MemoryStream();
		var settings = new XmlWriterSettings
		{
			Encoding = new UTF8Encoding(encoderShouldEmitUTF8Identifier: false),
			OmitXmlDeclaration = false,
		};
		using (var writer = XmlWriter.Create(memoryStream, settings))
		{
			xDocument.Save(writer);
		}

		return memoryStream.ToArray();
	}
}
