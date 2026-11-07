using System;

namespace Smb.Protocol.Enums;

[Flags]
public enum Smb2HeaderFlags : uint
{
	None = 0u,
	ServerToRedir = 1u,
	AsyncCommand = 2u,
	RelatedOperations = 4u,
	Signed = 8u,
	PriorityMask = 0x70u,
	DfsOperations = 0x10000000u,
	ReplayOperation = 0x20000000u,
}
