using System;
using System.Collections.Generic;
using System.Text;

namespace Smb.Auth.Ldap;

public sealed class LdapEntry
{
    private readonly IReadOnlyDictionary<string, IReadOnlyList<byte[]>> _attributes;

    public string DistinguishedName { get; }

    public LdapEntry(string distinguishedName, IReadOnlyDictionary<string, IReadOnlyList<byte[]>> attributes)
    {
        DistinguishedName = distinguishedName;
        _attributes = new Dictionary<string, IReadOnlyList<byte[]>>(attributes, StringComparer.OrdinalIgnoreCase);
    }

    public byte[]? GetBytes(string attribute)
    {
        if (!_attributes.TryGetValue(attribute, out var value) || value.Count <= 0)
        {
            return null;
        }

        return value[0];
    }

    public IReadOnlyList<byte[]> GetByteValues(string attribute)
    {
        if (!_attributes.TryGetValue(attribute, out var value))
        {
            return Array.Empty<byte[]>();
        }

        return value;
    }

    public string? GetString(string attribute)
    {
        var bytes = GetBytes(attribute);
        if (bytes != null)
        {
            return Encoding.UTF8.GetString(bytes);
        }

        return null;
    }

    public IReadOnlyList<string> GetStrings(string attribute)
    {
        var byteValues = GetByteValues(attribute);
        if (byteValues.Count == 0)
        {
            return Array.Empty<string>();
        }

        var array = new string[byteValues.Count];
        for (var i = 0; i < byteValues.Count; i++)
        {
            array[i] = Encoding.UTF8.GetString(byteValues[i]);
        }

        return array;
    }
}
