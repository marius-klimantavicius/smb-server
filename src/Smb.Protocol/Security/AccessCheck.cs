using System.Collections.Generic;

namespace Smb.Protocol.Security;

public static class AccessCheck
{
	private const uint AllAccess = uint.MaxValue;

	public static uint MaximalAccess(SecurityDescriptor descriptor, IReadOnlyCollection<Sid> callerSids)
	{
		if (!descriptor.Control.HasFlag(SecurityDescriptorControl.DaclPresent) || descriptor.Dacl == null)
		{
			return AllAccess;
		}

		var owner = descriptor.Owner != null && Contains(callerSids, descriptor.Owner);
		var ownerRights = false;
		foreach (var ace in descriptor.Dacl.Aces)
			if (!ace.Flags.HasFlag(AceFlags.InheritOnly) && WellKnownSids.OwnerRights.Equals(ace.Sid)) ownerRights = true;

		var num = owner && !ownerRights ? AccessMask.ReadControl | AccessMask.WriteDac : 0u;
		var num2 = num;
		foreach (var ace in descriptor.Dacl.Aces)
		{
			if (ace.Flags.HasFlag(AceFlags.InheritOnly) || (object)ace.Sid == null ||
				!(Contains(callerSids, ace.Sid) || owner && WellKnownSids.OwnerRights.Equals(ace.Sid)))
			{
				continue;
			}

			var num3 = ace.AccessMask & ~num2;
			if (num3 != 0)
			{
				if (ace.Type == AceType.AccessAllowed)
				{
					num |= num3;
				}

				var type = ace.Type;
				if (type <= AceType.AccessDenied)
				{
					num2 |= ace.AccessMask;
				}
			}
		}

		return num;
	}

	public static bool IsGranted(SecurityDescriptor descriptor, IReadOnlyCollection<Sid> callerSids, uint desiredAccess, out uint grantedAccess)
	{
		var num = MaximalAccess(descriptor, callerSids);
		if ((desiredAccess & 0x2000000) != 0)
		{
			grantedAccess = num;
			return num != 0 && ((desiredAccess & ~AccessMask.MaximumAllowed) & ~num) == 0;
		}

		grantedAccess = desiredAccess & num;
		return grantedAccess == desiredAccess;
	}

	private static bool Contains(IReadOnlyCollection<Sid> sids, Sid target)
	{
		foreach (var sid in sids)
		{
			if (sid.Equals(target))
			{
				return true;
			}
		}

		return false;
	}
}
