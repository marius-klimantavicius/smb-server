// Permission is hereby granted, free of charge, to any person obtaining a copy
// of this software and associated documentation files (the "Software"), to deal
// in the Software without restriction, including without limitation the rights
// to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
// copies of the Software, and to permit persons to whom the Software is
// furnished to do so, subject to the following conditions:
//
// The above copyright notice and this permission notice shall be included in
// all copies or substantial portions of the Software.
//
// THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
// IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
// FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
// AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
// LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
// OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
// THE SOFTWARE.
//

using System;

namespace Smb.FileSystem.Sqlite;

using static Managed.Database.Sqlite;

[Flags]
public enum SqliteOpenFlags
{
    ReadOnly = SQLITE_OPEN_READONLY,
    ReadWrite = SQLITE_OPEN_READWRITE,
    Create = SQLITE_OPEN_CREATE,
    DeleteOnClose = SQLITE_OPEN_DELETEONCLOSE,
    Exclusive = SQLITE_OPEN_EXCLUSIVE,
    AutoProxy = SQLITE_OPEN_AUTOPROXY,
    Uri = SQLITE_OPEN_URI,
    Memory = SQLITE_OPEN_MEMORY,
    OpenMainDb = SQLITE_OPEN_MAIN_DB,
    OpenTempDb = SQLITE_OPEN_TEMP_DB,
    OpenTransientDb = SQLITE_OPEN_TRANSIENT_DB,
    OpenMainJournal = SQLITE_OPEN_MAIN_JOURNAL,
    OpenTempJournal = SQLITE_OPEN_TEMP_JOURNAL,
    OpenSubJournal = SQLITE_OPEN_SUBJOURNAL,
    OpenMasterJournal = SQLITE_OPEN_MASTER_JOURNAL,
    NoMutex = SQLITE_OPEN_NOMUTEX,
    FullMutex = SQLITE_OPEN_FULLMUTEX,
    SharedCache = SQLITE_OPEN_SHAREDCACHE,
    PrivateCache = SQLITE_OPEN_PRIVATECACHE,
    NoFollow = SQLITE_OPEN_NOFOLLOW,
}