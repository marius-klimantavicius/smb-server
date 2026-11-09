using System.Globalization;
using System.Runtime.InteropServices;
using Sqlite3 = Managed.Database.Sqlite;

namespace Smb.FileSystem.Sqlite;

internal unsafe struct SqliteCommandBinding
{
    public static readonly SqliteBindDelegate SetInt32 = (_, statement, in binding) =>
    {
        if (binding.IsNull)
            Sqlite3.sqlite3_bind_null(statement, binding.Index);
        else
            Sqlite3.sqlite3_bind_int(statement, binding.Index, binding.Int32Value);
    };

    public static readonly SqliteBindDelegate SetInt64 = (_, statement, in binding) =>
    {
        if (binding.IsNull)
            Sqlite3.sqlite3_bind_null(statement, binding.Index);
        else
            Sqlite3.sqlite3_bind_int64(statement, binding.Index, binding.Int64Value);
    };

    public static readonly SqliteBindDelegate SetDouble = (_, statement, in binding) =>
    {
        if (binding.IsNull)
            Sqlite3.sqlite3_bind_null(statement, binding.Index);
        else
            Sqlite3.sqlite3_bind_double(statement, binding.Index, binding.DoubleValue);
    };

    public static readonly SqliteBindDelegate SetString = (_, statement, in binding) =>
    {
        if (binding.IsNull)
            Sqlite3.sqlite3_bind_null(statement, binding.Index);
        else
            Sqlite3.sqlite3_bind_text16(statement, binding.Index, binding.StringValue!);
    };

    public static readonly SqliteBindDelegate SetDateTime = (connection, statement, in binding) =>
    {
        if (binding.IsNull)
            Sqlite3.sqlite3_bind_null(statement, binding.Index);
        else if (connection.StoreDateTimeAsTicks)
            Sqlite3.sqlite3_bind_int64(statement, binding.Index, NormalizeDateTime(binding.DateTimeValue).Ticks);
        else
            Sqlite3.sqlite3_bind_text16(statement, binding.Index, NormalizeDateTime(binding.DateTimeValue).ToString(connection.DateTimeStringFormat, CultureInfo.InvariantCulture));
    };

    public static DateTime NormalizeDateTime(DateTime value)
    {
        return value.Kind == DateTimeKind.Utc ? value : value.ToUniversalTime();
    }

    public static readonly SqliteBindDelegate SetTimeSpan = (connection, statement, in binding) =>
    {
        if (binding.IsNull)
            Sqlite3.sqlite3_bind_null(statement, binding.Index);
        else if (connection.StoreTimeSpanAsTicks)
            Sqlite3.sqlite3_bind_int64(statement, binding.Index, binding.TimeSpanValue.Ticks);
        else
            Sqlite3.sqlite3_bind_text16(statement, binding.Index, binding.TimeSpanValue.ToString());
    };

    public static readonly SqliteBindDelegate SetBlob = (_, statement, in binding) =>
    {
        if (binding.IsNull)
            Sqlite3.sqlite3_bind_null(statement, binding.Index);
        else
            Sqlite3.sqlite3_bind_blob(statement, binding.Index, binding.BlobValue.Span);
    };

    private SqliteCommandValue _value;

    public readonly int Index;
    public readonly SqliteBindDelegate Bind;

    public bool IsNull;
    public string? StringValue;
    public ReadOnlyMemory<byte> BlobValue;

    public int Int32Value
    {
        get => _value.Int32Value;
        set => _value.Int32Value = value;
    }

    public long Int64Value
    {
        get => _value.Int64Value;
        set => _value.Int64Value = value;
    }

    public double DoubleValue
    {
        get => _value.DoubleValue;
        set => _value.DoubleValue = value;
    }

    public DateTime DateTimeValue
    {
        get => _value.DateTimeValue;
        set => _value.DateTimeValue = value;
    }

    public TimeSpan TimeSpanValue
    {
        get => _value.TimeSpanValue;
        set => _value.TimeSpanValue = value;
    }

    public SqliteCommandBinding(int index, SqliteBindDelegate bind)
    {
        Index = index;
        Bind = bind;
    }

    [StructLayout(LayoutKind.Explicit)]
    public struct SqliteCommandValue
    {
        [FieldOffset(0)]
        public bool IsNull;

        [FieldOffset(0)]
        public int Int32Value;

        [FieldOffset(0)]
        public long Int64Value;

        [FieldOffset(0)]
        public double DoubleValue;

        [FieldOffset(0)]
        public DateTime DateTimeValue;

        [FieldOffset(0)]
        public TimeSpan TimeSpanValue;
    }
}
