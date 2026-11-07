namespace Smb.Server.Dfs;

public interface IDfsNamespace
{
	DfsReferralResult? Resolve(string requestFileName);

	bool IsLinkCovered(string dfsPath)
	{
		var dfsReferralResult = Resolve(dfsPath);
		if (dfsReferralResult != null)
		{
			return !dfsReferralResult.IsRootReferral;
		}

		return false;
	}
}
