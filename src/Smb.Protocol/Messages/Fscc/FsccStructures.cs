using System;
using System.Collections.Generic;
using System.Text;
using Smb.Protocol.Enums;
using Smb.Protocol.Wire;

namespace Smb.Protocol.Messages.Fscc;

public static class FsccStructures
{
    private const long BytesPerSector = 512L;

    private const long SectorsPerUnit = 8L;

    private const long BytesPerUnit = 4096L;

    public static byte[] BuildDirectoryListing(IReadOnlyList<FsccFileStat> entries, FileInformationClass infoClass)
    {
        return BuildDirectoryListing(entries, infoClass, int.MaxValue, out _);
    }

    public static byte[] BuildDirectoryListing(IReadOnlyList<FsccFileStat> entries, FileInformationClass infoClass, int maxBytes, out int written)
    {
        var list = new List<byte[]>(entries.Count);
        var num = 0;
        foreach (var entry in entries)
        {
            var array = SerializeEntry(entry, infoClass);
            if ((list.Count > 0 && num + array.Length > maxBytes) || (list.Count == 0 && array.Length > maxBytes))
            {
                break;
            }

            list.Add(array);
            num += Align8(array.Length);
        }

        written = list.Count;
        if (written == 0)
        {
            return Array.Empty<byte>();
        }

        var growableWriter = new GrowableWriter(num);
        for (var i = 0; i < list.Count; i++)
        {
            var position = growableWriter.Position;
            growableWriter.WriteBytes(list[i]);
            if (i != list.Count - 1)
            {
                var num2 = Align8(growableWriter.Position - position) - (growableWriter.Position - position);
                if (num2 > 0)
                {
                    growableWriter.WriteZeros(num2);
                }

                growableWriter.PatchUInt32(position, (uint)(growableWriter.Position - position));
            }
            else
            {
                growableWriter.PatchUInt32(position, 0u);
            }
        }

        return growableWriter.ToArray();
    }

    private static byte[] SerializeEntry(FsccFileStat e, FileInformationClass infoClass)
    {
        var growableWriter = new GrowableWriter(128);
        WriteDirectoryEntry(growableWriter, e, infoClass);
        return growableWriter.ToArray();
    }

    private static void WriteDirectoryEntry(GrowableWriter w, FsccFileStat e, FileInformationClass infoClass)
    {
        var bytes = Encoding.Unicode.GetBytes(e.Name);
        w.WriteUInt32(0u);
        w.WriteUInt32(0u);
        switch (infoClass)
        {
            case FileInformationClass.FileNamesInformation:
                w.WriteUInt32((uint)bytes.Length);
                w.WriteBytes(bytes);
                return;
            case FileInformationClass.FileDirectoryInformation:
                WriteCommonTimesAndSizes(w, e);
                w.WriteUInt32((uint)bytes.Length);
                w.WriteBytes(bytes);
                return;
            case FileInformationClass.FileFullDirectoryInformation:
            case FileInformationClass.FileIdFullDirectoryInformation:
                WriteCommonTimesAndSizes(w, e);
                w.WriteUInt32((uint)bytes.Length);
                w.WriteUInt32(0u);
                if (infoClass == FileInformationClass.FileIdFullDirectoryInformation)
                {
                    w.WriteUInt32(0u);
                    w.WriteUInt64((ulong)e.IndexNumber);
                }

                w.WriteBytes(bytes);
                return;
        }

        WriteCommonTimesAndSizes(w, e);
        w.WriteUInt32((uint)bytes.Length);
        w.WriteUInt32(0u);
        w.WriteByte(0);
        w.WriteByte(0);
        w.WriteBytes(new byte[24]);
        if (infoClass == FileInformationClass.FileIdBothDirectoryInformation)
        {
            w.WriteUInt16(0);
            w.WriteUInt64((ulong)e.IndexNumber);
        }

        w.WriteBytes(bytes);
    }

    private static void WriteCommonTimesAndSizes(GrowableWriter w, FsccFileStat e)
    {
        w.WriteUInt64((ulong)e.CreationTime);
        w.WriteUInt64((ulong)e.LastAccessTime);
        w.WriteUInt64((ulong)e.LastWriteTime);
        w.WriteUInt64((ulong)e.ChangeTime);
        w.WriteUInt64((ulong)e.EndOfFile);
        w.WriteUInt64((ulong)e.AllocationSize);
        w.WriteUInt32(e.FileAttributes);
    }

    public static byte[]? BuildFileInformation(FsccFileStat e, FileInformationClass infoClass)
    {
        return infoClass switch
        {
            FileInformationClass.FileBasicInformation => FileBasic(e),
            FileInformationClass.FileStandardInformation => FileStandard(e),
            FileInformationClass.FileInternalInformation => U64((ulong)e.IndexNumber),
            FileInformationClass.FileEaInformation => U32(e.EaSize),
            FileInformationClass.FilePositionInformation => U64(0uL),
            FileInformationClass.FileNetworkOpenInformation => FileNetworkOpen(e),
            FileInformationClass.FileAttributeTagInformation => FileAttributeTag(e),
            FileInformationClass.FileAllInformation => FileAll(e),
            FileInformationClass.FileNameInformation => FileName(e),
            _ => null,
        };
    }

    private static byte[] FileBasic(FsccFileStat e)
    {
        var array = new byte[40];
        var spanWriter = new SpanWriter(array);
        spanWriter.WriteInt64(e.CreationTime);
        spanWriter.WriteInt64(e.LastAccessTime);
        spanWriter.WriteInt64(e.LastWriteTime);
        spanWriter.WriteInt64(e.ChangeTime);
        spanWriter.WriteUInt32(e.FileAttributes);
        spanWriter.WriteUInt32(0u);
        return array;
    }

    private static byte[] FileStandard(FsccFileStat e)
    {
        var array = new byte[24];
        var spanWriter = new SpanWriter(array);
        spanWriter.WriteInt64(e.AllocationSize);
        spanWriter.WriteInt64(e.EndOfFile);
        spanWriter.WriteUInt32(e.NumberOfLinks);
        spanWriter.WriteByte(e.DeletePending ? (byte)1 : (byte)0);
        spanWriter.WriteByte(e.IsDirectory ? ((byte)1) : ((byte)0));
        spanWriter.WriteUInt16(0);
        return array;
    }

    private static byte[] FileNetworkOpen(FsccFileStat e)
    {
        var array = new byte[56];
        var spanWriter = new SpanWriter(array);
        spanWriter.WriteInt64(e.CreationTime);
        spanWriter.WriteInt64(e.LastAccessTime);
        spanWriter.WriteInt64(e.LastWriteTime);
        spanWriter.WriteInt64(e.ChangeTime);
        spanWriter.WriteInt64(e.AllocationSize);
        spanWriter.WriteInt64(e.EndOfFile);
        spanWriter.WriteUInt32(e.FileAttributes);
        spanWriter.WriteUInt32(0u);
        return array;
    }

    private static byte[] FileAttributeTag(FsccFileStat e)
    {
        var array = new byte[8];
        var spanWriter = new SpanWriter(array);
        spanWriter.WriteUInt32(e.FileAttributes);
        spanWriter.WriteUInt32(0u);
        return array;
    }

    private static byte[] FileName(FsccFileStat e)
    {
        var bytes = Encoding.Unicode.GetBytes(e.Name);
        var growableWriter = new GrowableWriter(4 + bytes.Length);
        growableWriter.WriteUInt32((uint)bytes.Length);
        growableWriter.WriteBytes(bytes);
        return growableWriter.ToArray();
    }

    private static byte[] FileAll(FsccFileStat e)
    {
        var bytes = Encoding.Unicode.GetBytes(e.Name);
        var growableWriter = new GrowableWriter(96 + bytes.Length);
        growableWriter.WriteBytes(FileBasic(e));
        growableWriter.WriteBytes(FileStandard(e));
        growableWriter.WriteUInt64((ulong)e.IndexNumber);
        growableWriter.WriteUInt32(e.EaSize);
        growableWriter.WriteUInt32(2032127u);
        growableWriter.WriteUInt64(0uL);
        growableWriter.WriteUInt32(0u);
        growableWriter.WriteUInt32(0u);
        growableWriter.WriteUInt32((uint)bytes.Length);
        growableWriter.WriteBytes(bytes);
        return growableWriter.ToArray();
    }

    public static byte[]? BuildFileSystemInformation(FsInformationClass infoClass, string volumeLabel, uint serialNumber, long totalBytes = -1L, long availableBytes = -1L)
    {
        return infoClass switch
        {
            FsInformationClass.FileFsVolumeInformation => FsVolume(volumeLabel, serialNumber),
            FsInformationClass.FileFsSizeInformation => FsSize(totalBytes, availableBytes),
            FsInformationClass.FileFsFullSizeInformation => FsFullSize(totalBytes, availableBytes),
            FsInformationClass.FileFsDeviceInformation => FsDevice(),
            FsInformationClass.FileFsAttributeInformation => FsAttribute(),
            _ => null,
        };
    }

    private static byte[] FsVolume(string label, uint serial)
    {
        var bytes = Encoding.Unicode.GetBytes(label);
        var growableWriter = new GrowableWriter(18 + bytes.Length);
        growableWriter.WriteUInt64(0uL);
        growableWriter.WriteUInt32(serial);
        growableWriter.WriteUInt32((uint)bytes.Length);
        growableWriter.WriteByte(0);
        growableWriter.WriteByte(0);
        growableWriter.WriteBytes(bytes);
        return growableWriter.ToArray();
    }

    private static byte[] FsSize(long totalBytes = -1L, long availableBytes = -1L)
    {
        var value = ((totalBytes >= 0) ? (totalBytes / BytesPerUnit) : 1048576);
        var value2 = ((availableBytes >= 0) ? (availableBytes / BytesPerUnit) : 524288);
        var array = new byte[24];
        var spanWriter = new SpanWriter(array);
        spanWriter.WriteInt64(value);
        spanWriter.WriteInt64(value2);
        spanWriter.WriteUInt32((uint)SectorsPerUnit);
        spanWriter.WriteUInt32((uint)BytesPerSector);
        return array;
    }

    private static byte[] FsFullSize(long totalBytes = -1L, long availableBytes = -1L)
    {
        var value = ((totalBytes >= 0) ? (totalBytes / BytesPerUnit) : 1048576);
        var value2 = ((availableBytes >= 0) ? (availableBytes / BytesPerUnit) : 524288);
        var array = new byte[32];
        var spanWriter = new SpanWriter(array);
        spanWriter.WriteInt64(value);
        spanWriter.WriteInt64(value2);
        spanWriter.WriteInt64(value2);
        spanWriter.WriteUInt32((uint)SectorsPerUnit);
        spanWriter.WriteUInt32((uint)BytesPerSector);
        return array;
    }

    private static byte[] FsDevice()
    {
        var array = new byte[8];
        var spanWriter = new SpanWriter(array);
        spanWriter.WriteUInt32(7u);
        spanWriter.WriteUInt32(32u);
        return array;
    }

    private static byte[] FsAttribute()
    {
        var bytes = Encoding.Unicode.GetBytes("SMB");
        var growableWriter = new GrowableWriter(12 + bytes.Length);
        growableWriter.WriteUInt32(47u);
        growableWriter.WriteUInt32(255u);
        growableWriter.WriteUInt32((uint)bytes.Length);
        growableWriter.WriteBytes(bytes);
        return growableWriter.ToArray();
    }

    private static byte[] U32(uint v)
    {
        var array = new byte[4];
        new SpanWriter(array).WriteUInt32(v);
        return array;
    }

    private static byte[] U64(ulong v)
    {
        var array = new byte[8];
        new SpanWriter(array).WriteUInt64(v);
        return array;
    }

    private static int Align8(int v)
    {
        return (v + 7) & -8;
    }
}
