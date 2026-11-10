using System.Globalization;
using System.Text;

namespace Smb.Auth.Ldap;

public static class LdapFilter
{
    public static string Escape(string value)
    {
        var stringBuilder = new StringBuilder(value.Length + 8);
        foreach (var c in value)
        {
            if (c != '\0')
            {
                switch (c)
                {
                    case '*':
                        stringBuilder.Append("\\2a");
                        continue;
                    case '(':
                        stringBuilder.Append("\\28");
                        continue;
                    case ')':
                        stringBuilder.Append("\\29");
                        continue;
                }

                if (c == '\\')
                {
                    stringBuilder.Append("\\5c");
                }
                else if (c < ' ')
                {
                    var stringBuilder2 = stringBuilder.Append('\\');
                    int num = c;
                    stringBuilder2.Append(num.ToString("x2", CultureInfo.InvariantCulture));
                }
                else
                {
                    stringBuilder.Append(c);
                }
            }
            else
            {
                stringBuilder.Append("\\00");
            }
        }

        return stringBuilder.ToString();
    }
}
