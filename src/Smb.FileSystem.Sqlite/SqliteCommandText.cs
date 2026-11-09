using System.Buffers;
using System.Runtime.CompilerServices;
using static Managed.Database.Sqlite;

namespace Smb.FileSystem.Sqlite;

[InterpolatedStringHandler]
public unsafe ref struct SqliteCommandText
{
    private DefaultInterpolatedStringHandler _handler;

    private readonly SqliteCommandBinding[] _bindings;
    private int _bindingIndex;

    public SqliteCommandText(int literalLength, int formattedCount)
    {
        _handler = new DefaultInterpolatedStringHandler(literalLength, formattedCount);
        _bindings = ArrayPool<SqliteCommandBinding>.Shared.Rent(formattedCount);
    }

    public string ToStringAndClear() => _handler.ToStringAndClear();

    public void BindAndClear(SqliteConnection connection, sqlite3_stmt* statement)
    {
        var span = _bindings.AsSpan(0, _bindingIndex);
        for (var i = 0; i < span.Length; i++)
        {
            ref var item = ref span[i];
            item.Bind(connection, statement, in item);
        }

        ArrayPool<SqliteCommandBinding>.Shared.Return(_bindings);
    }

    [MethodImpl(MethodImplOptions.AggressiveInlining)]
    public void AppendLiteral(string literal)
    {
        _handler.AppendLiteral(literal);
    }

    [MethodImpl(MethodImplOptions.AggressiveInlining)]
    public void AppendFormatted(int value)
    {
        _handler.AppendLiteral("?");
        _bindings[_bindingIndex] = new SqliteCommandBinding(_bindingIndex + 1, SqliteCommandBinding.SetInt32) { Int32Value = value };
        _bindingIndex++;
    }

    [MethodImpl(MethodImplOptions.AggressiveInlining)]
    public void AppendFormatted(int? value)
    {
        _handler.AppendLiteral("?");
        _bindings[_bindingIndex] = new SqliteCommandBinding(_bindingIndex + 1, SqliteCommandBinding.SetInt32)
        {
            IsNull = value == null,
            Int32Value = value.GetValueOrDefault(),
        };
        _bindingIndex++;
    }

    [MethodImpl(MethodImplOptions.AggressiveInlining)]
    public void AppendFormatted(long value)
    {
        _handler.AppendLiteral("?");
        _bindings[_bindingIndex] = new SqliteCommandBinding(_bindingIndex + 1, SqliteCommandBinding.SetInt64) { Int64Value = value };
        _bindingIndex++;
    }

    [MethodImpl(MethodImplOptions.AggressiveInlining)]
    public void AppendFormatted(long? value)
    {
        _handler.AppendLiteral("?");
        _bindings[_bindingIndex] = new SqliteCommandBinding(_bindingIndex + 1, SqliteCommandBinding.SetInt64)
        {
            IsNull = value == null,
            Int64Value = value.GetValueOrDefault(),
        };
        _bindingIndex++;
    }

    [MethodImpl(MethodImplOptions.AggressiveInlining)]
    public void AppendFormatted(double value)
    {
        _handler.AppendLiteral("?");
        _bindings[_bindingIndex] = new SqliteCommandBinding(_bindingIndex + 1, SqliteCommandBinding.SetDouble) { DoubleValue = value };
        _bindingIndex++;
    }

    [MethodImpl(MethodImplOptions.AggressiveInlining)]
    public void AppendFormatted(double? value)
    {
        _handler.AppendLiteral("?");
        _bindings[_bindingIndex] = new SqliteCommandBinding(_bindingIndex + 1, SqliteCommandBinding.SetDouble)
        {
            IsNull = value == null,
            DoubleValue = value.GetValueOrDefault(),
        };
        _bindingIndex++;
    }

    [MethodImpl(MethodImplOptions.AggressiveInlining)]
    public void AppendFormatted(decimal value)
    {
        _handler.AppendLiteral("?");
        _bindings[_bindingIndex] = new SqliteCommandBinding(_bindingIndex + 1, SqliteCommandBinding.SetDouble) { DoubleValue = (double)value };
        _bindingIndex++;
    }

    [MethodImpl(MethodImplOptions.AggressiveInlining)]
    public void AppendFormatted(decimal? value)
    {
        _handler.AppendLiteral("?");
        _bindings[_bindingIndex] = new SqliteCommandBinding(_bindingIndex + 1, SqliteCommandBinding.SetDouble)
        {
            IsNull = value == null,
            DoubleValue = (double)value.GetValueOrDefault(),
        };
        _bindingIndex++;
    }

    [MethodImpl(MethodImplOptions.AggressiveInlining)]
    public void AppendFormatted(string? value)
    {
        _handler.AppendLiteral("?");
        _bindings[_bindingIndex] = new SqliteCommandBinding(_bindingIndex + 1, SqliteCommandBinding.SetString)
        {
            IsNull = value == null,
            StringValue = value,
        };
        _bindingIndex++;
    }

    [MethodImpl(MethodImplOptions.AggressiveInlining)]
    public void AppendFormatted(string? value, string format)
    {
        if ("Raw".Equals(format, StringComparison.OrdinalIgnoreCase) || "Sql".Equals(format, StringComparison.OrdinalIgnoreCase))
        {
            _handler.AppendLiteral(value ?? string.Empty);
            return;
        }

        _handler.AppendLiteral("?");
        _bindings[_bindingIndex] = new SqliteCommandBinding(_bindingIndex + 1, SqliteCommandBinding.SetString)
        {
            IsNull = value == null,
            StringValue = value,
        };
        _bindingIndex++;
    }

    [MethodImpl(MethodImplOptions.AggressiveInlining)]
    public void AppendFormatted(System.DateTime value)
    {
        _handler.AppendLiteral("?");
        _bindings[_bindingIndex] = new SqliteCommandBinding(_bindingIndex + 1, SqliteCommandBinding.SetDateTime)
        {
            DateTimeValue = value,
        };
        _bindingIndex++;
    }

    [MethodImpl(MethodImplOptions.AggressiveInlining)]
    public void AppendFormatted(System.DateTime? value)
    {
        _handler.AppendLiteral("?");
        _bindings[_bindingIndex] = new SqliteCommandBinding(_bindingIndex + 1, SqliteCommandBinding.SetDateTime)
        {
            IsNull = value == null,
            DateTimeValue = value.GetValueOrDefault(),
        };
        _bindingIndex++;
    }

    [MethodImpl(MethodImplOptions.AggressiveInlining)]
    public void AppendFormatted(TimeSpan value)
    {
        _handler.AppendLiteral("?");
        _bindings[_bindingIndex] = new SqliteCommandBinding(_bindingIndex + 1, SqliteCommandBinding.SetTimeSpan)
        {
            TimeSpanValue = value,
        };
        _bindingIndex++;
    }

    [MethodImpl(MethodImplOptions.AggressiveInlining)]
    public void AppendFormatted(TimeSpan? value)
    {
        _handler.AppendLiteral("?");
        _bindings[_bindingIndex] = new SqliteCommandBinding(_bindingIndex + 1, SqliteCommandBinding.SetTimeSpan)
        {
            IsNull = value == null,
            TimeSpanValue = value.GetValueOrDefault(),
        };
        _bindingIndex++;
    }

    [MethodImpl(MethodImplOptions.AggressiveInlining)]
    public void AppendFormatted(byte[]? value)
    {
        _handler.AppendLiteral("?");
        _bindings[_bindingIndex] = new SqliteCommandBinding(_bindingIndex + 1, SqliteCommandBinding.SetBlob)
        {
            IsNull = value == null,
            BlobValue = value ?? ReadOnlyMemory<byte>.Empty,
        };
        _bindingIndex++;
    }

    [MethodImpl(MethodImplOptions.AggressiveInlining)]
    public void AppendFormatted(Memory<byte>? value)
    {
        _handler.AppendLiteral("?");
        _bindings[_bindingIndex] = new SqliteCommandBinding(_bindingIndex + 1, SqliteCommandBinding.SetBlob)
        {
            IsNull = value == null,
            BlobValue = value ?? ReadOnlyMemory<byte>.Empty,
        };
        _bindingIndex++;
    }

    [MethodImpl(MethodImplOptions.AggressiveInlining)]
    public void AppendFormatted(ReadOnlyMemory<byte>? value)
    {
        _handler.AppendLiteral("?");
        _bindings[_bindingIndex] = new SqliteCommandBinding(_bindingIndex + 1, SqliteCommandBinding.SetBlob)
        {
            IsNull = value == null,
            BlobValue = value ?? ReadOnlyMemory<byte>.Empty,
        };
        _bindingIndex++;
    }

    [MethodImpl(MethodImplOptions.AggressiveInlining)]
    public void AppendFormatted(Guid value)
    {
        _handler.AppendLiteral("?");
        _bindings[_bindingIndex] = new SqliteCommandBinding(_bindingIndex + 1, SqliteCommandBinding.SetString)
        {
            StringValue = value.ToString("D"),
        };
        _bindingIndex++;
    }

    [MethodImpl(MethodImplOptions.AggressiveInlining)]
    public void AppendFormatted(Guid? value)
    {
        _handler.AppendLiteral("?");
        _bindings[_bindingIndex] = new SqliteCommandBinding(_bindingIndex + 1, SqliteCommandBinding.SetString)
        {
            IsNull = value == null,
            StringValue = value?.ToString("D"),
        };
        _bindingIndex++;
    }

    [MethodImpl(MethodImplOptions.AggressiveInlining)]
    public void AppendFormatted(RawValue value)
    {
        _handler.AppendLiteral(value.Value);
    }

    [MethodImpl(MethodImplOptions.AggressiveInlining)]
    public void AppendFormatted(bool? value)
    {
        _handler.AppendLiteral("?");
        _bindings[_bindingIndex] = new SqliteCommandBinding(_bindingIndex + 1, SqliteCommandBinding.SetInt32)
        {
            IsNull = value == null,
            Int32Value = value.GetValueOrDefault() ? 1 : 0,
        };
        _bindingIndex++;
    }

    [MethodImpl(MethodImplOptions.AggressiveInlining)]
    public void AppendFormatted(bool? value, string format)
    {
        _handler.AppendLiteral("?");
        if (format.Equals("str", StringComparison.OrdinalIgnoreCase) || format.Equals("string"))
        {
            _bindings[_bindingIndex] = new SqliteCommandBinding(_bindingIndex + 1, SqliteCommandBinding.SetString)
            {
                IsNull = value == null,
                StringValue = value.HasValue ? (value.Value ? "true" : "false") : null,
            };
        }
        else
        {
            _bindings[_bindingIndex] = new SqliteCommandBinding(_bindingIndex + 1, SqliteCommandBinding.SetInt32)
            {
                IsNull = value == null,
                Int32Value = value.GetValueOrDefault() ? 1 : 0,
            };
        }

        _bindingIndex++;
    }

    public static RawValue Raw(string value)
    {
        return new RawValue { Value = value };
    }

    public struct RawValue
    {
        public string Value;
    }
}