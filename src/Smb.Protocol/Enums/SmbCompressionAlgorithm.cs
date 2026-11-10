namespace Smb.Protocol.Enums;

public enum SmbCompressionAlgorithm : ushort
{
    None,
    Lznt1,
    Lz77,
    Lz77Huffman,
    PatternV1,
    Lz4,
}
