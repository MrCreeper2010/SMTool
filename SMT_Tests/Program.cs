using System;
using System.Collections.Generic;
using System.IO;
using System.Threading.Tasks;
using ThreeOneThree.Proxima.Agent;
using ThreeOneThree.Proxima.Core;

namespace SMT_Tests
{
    class Program
    {
        static void Main()
        {
            #region Reasons
            uint reasonMask =
            Win32Api.USN_REASON_DATA_OVERWRITE |
            Win32Api.USN_REASON_DATA_EXTEND |
            Win32Api.USN_REASON_NAMED_DATA_OVERWRITE |
            Win32Api.USN_REASON_NAMED_DATA_TRUNCATION |
            Win32Api.USN_REASON_FILE_CREATE |
            Win32Api.USN_REASON_FILE_DELETE |
            Win32Api.USN_REASON_EA_CHANGE |
            Win32Api.USN_REASON_SECURITY_CHANGE |
            Win32Api.USN_REASON_RENAME_OLD_NAME |
            Win32Api.USN_REASON_RENAME_NEW_NAME |
            Win32Api.USN_REASON_INDEXABLE_CHANGE |
            Win32Api.USN_REASON_BASIC_INFO_CHANGE |
            Win32Api.USN_REASON_HARD_LINK_CHANGE |
            Win32Api.USN_REASON_COMPRESSION_CHANGE |
            Win32Api.USN_REASON_ENCRYPTION_CHANGE |
            Win32Api.USN_REASON_OBJECT_ID_CHANGE |
            Win32Api.USN_REASON_REPARSE_POINT_CHANGE |
            Win32Api.USN_REASON_STREAM_CHANGE |
            Win32Api.USN_REASON_CLOSE;
            #endregion

            Win32Api.USN_JOURNAL_DATA data = new Win32Api.USN_JOURNAL_DATA();

            DriveConstruct construct = new DriveConstruct(Path.GetPathRoot(Environment.SystemDirectory));

            NtfsUsnJournal journal = new NtfsUsnJournal(Path.GetPathRoot(Environment.SystemDirectory));
            NtfsUsnJournal.UsnJournalReturnCode rtn = journal.GetUsnJournalEntries(construct.CurrentJournalData, reasonMask, out List<Win32Api.UsnEntry> usnEntries, out Win32Api.USN_JOURNAL_DATA newUsnState, OverrideLastUsn: data.MaxUsn);

            if (rtn == NtfsUsnJournal.UsnJournalReturnCode.USN_JOURNAL_SUCCESS)
            {
                Parallel.ForEach(usnEntries, (d) =>
                {
                    if (d.Name.Contains("KOID"))
                        Console.WriteLine(d.FileReferenceNumber);
                });
            }

            Console.WriteLine("done");
            Console.ReadLine();
        }
    }
}
