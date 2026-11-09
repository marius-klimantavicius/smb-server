namespace Smb.FileSystem.Sqlite;

public delegate void SqliteBindStatement<in TArguments>(in SqliteStatementBinder statement, TArguments arguments)
    where TArguments: allows ref struct;

public delegate void SqliteRefBindStatement<TArguments>(in SqliteStatementBinder statement, ref TArguments arguments)
    where TArguments: allows ref struct;
