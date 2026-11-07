namespace Smb.Protocol.Security;

public static class WellKnownSids
{
	public static Sid Null { get; } = Sid.Create(0uL, 0);

	public static Sid Everyone { get; } = Sid.Create(1uL, 0);

	public static Sid CreatorOwner { get; } = Sid.Create(3uL, 0);

	public static Sid CreatorGroup { get; } = Sid.Create(3uL, 1u);

	public static Sid AuthenticatedUsers { get; } = Sid.Create(5uL, 11u);

	public static Sid LocalSystem { get; } = Sid.Create(5uL, 18u);

	public static Sid BuiltinAdministrators { get; } = Sid.Create(5uL, 32u, 544u);

	public static Sid BuiltinUsers { get; } = Sid.Create(5uL, 32u, 545u);
}
