using System.Collections.Generic;

namespace Smb.Protocol.Security;

public static class AclInheritance
{
	public static SecurityDescriptor? ComputeInherited(SecurityDescriptor parent, bool childIsContainer)
	{
		if (parent.Dacl == null)
		{
			return null;
		}

		var list = new List<Ace>();
		foreach (var ace in parent.Dacl.Aces)
		{
			if (!ace.IsBasic || (object)ace.Sid == null)
			{
				continue;
			}

			var flag = ace.Flags.HasFlag(AceFlags.ObjectInherit);
			var flag2 = ace.Flags.HasFlag(AceFlags.ContainerInherit);
			if (!flag && !flag2)
			{
				continue;
			}

			var flag3 = ace.Flags.HasFlag(AceFlags.NoPropagateInherit);
			if (!childIsContainer)
			{
				if (flag)
				{
					list.Add(Rewrite(ace, AceFlags.Inherited));
				}
			}
			else if (flag2)
			{
				var aceFlags = AceFlags.Inherited;
				if (!flag3)
				{
					aceFlags |= ace.Flags & (AceFlags.ObjectInherit | AceFlags.ContainerInherit);
				}

				list.Add(Rewrite(ace, aceFlags));
			}
			else if (!flag3)
			{
				list.Add(Rewrite(ace, AceFlags.ObjectInherit | AceFlags.InheritOnly | AceFlags.Inherited));
			}
		}

		if (list.Count == 0)
		{
			return null;
		}

		return SecurityDescriptor.Create(parent.Owner, parent.Group, new Acl
		{
			Aces = list,
		});
	}

	private static Ace Rewrite(Ace source, AceFlags flags)
	{
		return new Ace
		{
			Type = source.Type,
			Flags = flags,
			AccessMask = source.AccessMask,
			Sid = source.Sid,
		};
	}
}
