using System;
using System.Buffers.Binary;
using Smb.Protocol.Wire;

namespace Smb.Protocol.Compression;

public static class Lz77Huffman
{
    private ref struct BitReader(ReadOnlySpan<byte> input, int start)
    {
        private readonly ReadOnlySpan<byte> _input = input;

        private int _pos = start;

        private uint _nextBits = 0u;

        private int _extraBitCount = 0;

        public readonly int Position => _pos;

        public readonly int NextTablePosition => _pos - 2 * ((16 + _extraBitCount) / 16);

        public void StartBlock()
        {
            _nextBits = (uint)(ReadUInt16() << 16);
            _nextBits |= ReadUInt16();
            _extraBitCount = 16;
        }

        public ushort ReadUInt16()
        {
            if (_pos + 2 > _input.Length)
            {
                throw new SmbWireFormatException("Truncated LZ77+Huffman bitstream.");
            }

            var result = BinaryPrimitives.ReadUInt16LittleEndian(_input.Slice(_pos));
            _pos += 2;
            return result;
        }

        public byte ReadByte()
        {
            if (_pos >= _input.Length)
            {
                throw new SmbWireFormatException("Truncated LZ77+Huffman length byte.");
            }

            return _input[_pos++];
        }

        public int DecodeSymbol(short[] decodeTable, byte[] codeLengths)
        {
            int num = decodeTable[_nextBits >> 17];
            Consume(codeLengths[num]);
            return num;
        }

        public uint TakeBits(int bits)
        {
            var result = ((bits != 0) ? (_nextBits >> 32 - bits) : 0);
            Consume(bits);
            return result;
        }

        private void Consume(int bits)
        {
            _nextBits <<= bits;
            _extraBitCount -= bits;
            if (_extraBitCount < 0)
            {
                _nextBits |= (uint)(ReadUInt16() << -_extraBitCount);
                _extraBitCount += 16;
            }
        }
    }

    public const int MinMatch = 3;

    public const int BlockSize = 65536;

    private const int TableSize = 256;

    private const int SymbolCount = 512;

    private const int MaxCodeBits = 15;

    private const int DecodeTableSize = 32768;

    public static byte[] Decompress(ReadOnlySpan<byte> input, int originalSize)
    {
        if (originalSize < 0)
        {
            throw new SmbWireFormatException("Negative original size.");
        }

        var array = new byte[originalSize];
        var codeLengths = new byte[SymbolCount];
        var decodeTable = new short[DecodeTableSize];
        var num = 0;
        var num2 = 0;
        while (num < originalSize)
        {
            if (num2 + TableSize > input.Length)
            {
                throw new SmbWireFormatException("Truncated LZ77+Huffman Huffman table.");
            }

            BuildDecodeTable(input.Slice(num2, TableSize), codeLengths, decodeTable);
            var bitReader = new BitReader(input, num2 + TableSize);
            bitReader.StartBlock();
            var num3 = num + BlockSize;
            while (num < num3 && num < originalSize)
            {
                var num4 = bitReader.DecodeSymbol(decodeTable, codeLengths);
                if (num4 < 256)
                {
                    array[num++] = (byte)num4;
                    continue;
                }

                num4 -= 256;
                var num5 = num4 & 0xF;
                var num6 = num4 >> 4;
                if (num5 == 15)
                {
                    int num7 = bitReader.ReadByte();
                    if (num7 == 255)
                    {
                        var num8 = bitReader.ReadUInt16();
                        if (num8 < 15)
                        {
                            throw new SmbWireFormatException("Invalid LZ77+Huffman extended length.");
                        }

                        num5 = num8 - 15;
                    }
                    else
                    {
                        num5 = num7;
                    }

                    num5 += 15;
                }

                num5 += MinMatch;
                var num9 = (int)bitReader.TakeBits(num6) + (1 << num6);
                if (num9 > num)
                {
                    throw new SmbWireFormatException("LZ77+Huffman back-reference before start of output.");
                }

                if (num + num5 > originalSize)
                {
                    throw new SmbWireFormatException("LZ77+Huffman match overruns declared size.");
                }

                var num10 = num - num9;
                for (var i = 0; i < num5; i++)
                {
                    array[num + i] = array[num10 + i];
                }

                num += num5;
            }

            num2 = bitReader.NextTablePosition;
        }

        return array;
    }

    private static void BuildDecodeTable(ReadOnlySpan<byte> table, byte[] codeLengths, short[] decodeTable)
    {
        for (var i = 0; i < TableSize; i++)
        {
            codeLengths[2 * i] = (byte)(table[i] & 0xF);
            codeLengths[2 * i + 1] = (byte)(table[i] >> 4);
        }

        var num = 0;
        for (var j = 1; j <= MaxCodeBits; j++)
        {
            var num2 = 1 << MaxCodeBits - j;
            for (var k = 0; k < SymbolCount; k++)
            {
                if (codeLengths[k] == j)
                {
                    if (num + num2 > DecodeTableSize)
                    {
                        throw new SmbWireFormatException("Over-subscribed LZ77+Huffman code table.");
                    }

                    decodeTable.AsSpan(num, num2).Fill((short)k);
                    num += num2;
                }
            }
        }

        if (num != DecodeTableSize)
        {
            throw new SmbWireFormatException("Incomplete LZ77+Huffman code table.");
        }
    }
}
