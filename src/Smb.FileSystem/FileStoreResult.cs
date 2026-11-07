using Smb.Protocol.Enums;

namespace Smb.FileSystem;

public readonly struct FileStoreResult<T>
{
	public NtStatus Status { get; }

	public T? Value { get; }

	public bool IsSuccess => Status == NtStatus.Success;

	private FileStoreResult(NtStatus status, T? value)
	{
		Status = status;
		Value = value;
	}

	public static FileStoreResult<T> Ok(T value)
	{
		return new FileStoreResult<T>(NtStatus.Success, value);
	}

	public static FileStoreResult<T> Fail(NtStatus status)
	{
		return new FileStoreResult<T>(status, default);
	}
}
