using System;
using System.Collections.Generic;

namespace Smb.FileSystem.Sqlite;

public sealed class SqliteDynamicQueryResult
{
    public string[] ColumnNames { get; }
    public List<object?[]> Rows { get; }
    public int Changes { get; }

    public SqliteDynamicQueryResult(string[] columnNames, List<object?[]> rows, int changes)
    {
        ColumnNames = columnNames;
        Rows = rows;
        Changes = changes;
    }

    public object? GetValue(object?[] row, string columnName)
    {
        var index = Array.IndexOf(ColumnNames, columnName);
        return index >= 0 ? row[index] : null;
    }
}