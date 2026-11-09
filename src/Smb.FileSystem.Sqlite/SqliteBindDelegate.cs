using static Managed.Database.Sqlite;

namespace Smb.FileSystem.Sqlite;

internal unsafe delegate void SqliteBindDelegate(SqliteConnection connection, sqlite3_stmt* statement, in SqliteCommandBinding binding);