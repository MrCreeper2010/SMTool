using System;
using System.Diagnostics;
using System.IO;
using System.Runtime.InteropServices;
using System.Text.RegularExpressions;
using System.Threading.Tasks;
using Google.Apis.Services;
using Google.Apis.Urlshortener.v1;
using Google.Apis.Urlshortener.v1.Data;
using Google.Apis.Http;
using System.Text;
using System.Collections.Generic;
using System.Net;

namespace SMT_Tests
{

    [StructLayout(LayoutKind.Sequential)]
    struct IMAGE_DOS_HEADER
    {
        public ushort e_magic;    // Magic number
        public ushort e_cblp;     // Bytes on last page of file
        public ushort e_cp;       // Pages in file
        public ushort e_crlc;     // Relocations
        public ushort e_cparhdr;  // Size of header in paragraphs
        public ushort e_minalloc; // Minimum extra paragraphs needed
        public ushort e_maxalloc; // Maximum extra paragraphs needed
        public ushort e_ss;       // Initial (relative) SS value
        public ushort e_sp;       // Initial SP value
        public ushort e_csum;     // Checksum
        public ushort e_ip;       // Initial IP value
        public ushort e_cs;       // Initial (relative) CS value
        public ushort e_lfarlc;   // File address of relocation table
        public ushort e_ovno;     // Overlay number
        public uint e_res1;       // Reserved
        public uint e_res2;       // Reserved
        public ushort e_oemid;    // OEM identifier (for e_oeminfo)
        public ushort e_oeminfo;  // OEM information; e_oemid specific
        public uint e_res3;       // Reserved
        public uint e_res4;       // Reserved
        public uint e_res5;       // Reserved
        public uint e_res6;       // Reserved
        public uint e_res7;       // Reserved
        public int e_lfanew;      // File address of new exe header
    }

    [StructLayout(LayoutKind.Sequential)]
    struct IMAGE_FILE_HEADER
    {
        public ushort Machine;
        public ushort NumberOfSections;
        public uint TimeDateStamp;
        public uint PointerToSymbolTable;
        public uint NumberOfSymbols;
        public ushort SizeOfOptionalHeader;
        public ushort Characteristics;
    }

    [StructLayout(LayoutKind.Sequential)]
    struct IMAGE_NT_HEADERS_COMMON
    {
        public uint Signature;
        public IMAGE_FILE_HEADER FileHeader;
    }

    [StructLayout(LayoutKind.Sequential)]
    struct IMAGE_NT_HEADERS32
    {
        public uint Signature;
        public IMAGE_FILE_HEADER FileHeader;
        public IMAGE_OPTIONAL_HEADER32 OptionalHeader;
    }

    [StructLayout(LayoutKind.Sequential)]
    struct IMAGE_NT_HEADERS64
    {
        public uint Signature;
        public IMAGE_FILE_HEADER FileHeader;
        public IMAGE_OPTIONAL_HEADER64 OptionalHeader;
    }

    [StructLayout(LayoutKind.Sequential)]
    struct IMAGE_OPTIONAL_HEADER32
    {
        public ushort Magic;
        public byte MajorLinkerVersion;
        public byte MinorLinkerVersion;
        public uint SizeOfCode;
        public uint SizeOfInitializedData;
        public uint SizeOfUninitializedData;
        public uint AddressOfEntryPoint;
        public uint BaseOfCode;
        public uint BaseOfData;
        public uint ImageBase;
        public uint SectionAlignment;
        public uint FileAlignment;
        public ushort MajorOperatingSystemVersion;
        public ushort MinorOperatingSystemVersion;
        public ushort MajorImageVersion;
        public ushort MinorImageVersion;
        public ushort MajorSubsystemVersion;
        public ushort MinorSubsystemVersion;
        public uint Win32VersionValue;
        public uint SizeOfImage;
        public uint SizeOfHeaders;
        public uint CheckSum;
        public ushort Subsystem;
        public ushort DllCharacteristics;
        public uint SizeOfStackReserve;
        public uint SizeOfStackCommit;
        public uint SizeOfHeapReserve;
        public uint SizeOfHeapCommit;
        public uint LoaderFlags;
        public uint NumberOfRvaAndSizes;
    }

    [StructLayout(LayoutKind.Sequential)]
    struct IMAGE_OPTIONAL_HEADER64
    {
        public ushort Magic;
        public byte MajorLinkerVersion;
        public byte MinorLinkerVersion;
        public uint SizeOfCode;
        public uint SizeOfInitializedData;
        public uint SizeOfUninitializedData;
        public uint AddressOfEntryPoint;
        public uint BaseOfCode;
        public ulong ImageBase;
        public uint SectionAlignment;
        public uint FileAlignment;
        public ushort MajorOperatingSystemVersion;
        public ushort MinorOperatingSystemVersion;
        public ushort MajorImageVersion;
        public ushort MinorImageVersion;
        public ushort MajorSubsystemVersion;
        public ushort MinorSubsystemVersion;
        public uint Win32VersionValue;
        public uint SizeOfImage;
        public uint SizeOfHeaders;
        public uint CheckSum;
        public ushort Subsystem;
        public ushort DllCharacteristics;
        public ulong SizeOfStackReserve;
        public ulong SizeOfStackCommit;
        public ulong SizeOfHeapReserve;
        public ulong SizeOfHeapCommit;
        public uint LoaderFlags;
        public uint NumberOfRvaAndSizes;
    }

    static class ExeChecker
    {
        public static bool IsValidExe(string fileName)
        {
            if (!File.Exists(fileName))
                return false;

            try
            {
                using (var stream = File.OpenRead(fileName))
                {
                    IMAGE_DOS_HEADER dosHeader = GetDosHeader(stream);
                    if (dosHeader.e_magic != IMAGE_DOS_SIGNATURE)
                        return false;

                    IMAGE_NT_HEADERS_COMMON ntHeader = GetCommonNtHeader(stream, dosHeader);
                    if (ntHeader.Signature != IMAGE_NT_SIGNATURE)
                        return false;

                    if ((ntHeader.FileHeader.Characteristics & IMAGE_FILE_DLL) != 0)
                        return false;

                    switch (ntHeader.FileHeader.Machine)
                    {
                        case IMAGE_FILE_MACHINE_I386:
                            return IsValidExe32(GetNtHeader32(stream, dosHeader));

                        case IMAGE_FILE_MACHINE_IA64:
                        case IMAGE_FILE_MACHINE_AMD64:
                            return IsValidExe64(GetNtHeader64(stream, dosHeader));
                    }
                }
            }
            catch (InvalidOperationException)
            {
                return false;
            }

            return true;
        }

        public static bool isInjectableDll(string fileName)
        {
            bool value_to_return = false;
            
            try
            {
                using (var stream = File.OpenRead(fileName))
                {
                    IMAGE_DOS_HEADER dosHeader = GetDosHeader(stream);
                    if (dosHeader.e_magic != IMAGE_DOS_SIGNATURE)
                        Console.WriteLine("magic number doesn't work properly " + fileName);

                    IMAGE_NT_HEADERS_COMMON ntHeader = GetCommonNtHeader(stream, dosHeader);
                    if (ntHeader.Signature != IMAGE_NT_SIGNATURE)
                        Console.WriteLine("signature doesn't work properly");

                    if ((ntHeader.FileHeader.Characteristics & IMAGE_FILE_DLL) != 0 && Path.GetExtension(fileName).ToUpper() != ".DLL")
                        Console.WriteLine("Il File è una dll ma ha un'estensione diversa da quella DLL " + fileName);

                    switch (ntHeader.FileHeader.Machine)
                    {
                        case IMAGE_FILE_MACHINE_IA64:
                        case IMAGE_FILE_MACHINE_AMD64:
                            if (validDLL(GetNtHeader64(stream, dosHeader)) == 2)
                                value_to_return = true;
                            break;
                    }
                }
            }
            catch
            {

            }

            return value_to_return;
        }

        static bool IsValidExe32(IMAGE_NT_HEADERS32 ntHeader)
        {
            return ntHeader.OptionalHeader.Magic == IMAGE_NT_OPTIONAL_HDR32_MAGIC;
        }

        static bool IsValidExe64(IMAGE_NT_HEADERS64 ntHeader)
        {
            return ntHeader.OptionalHeader.Magic == IMAGE_NT_OPTIONAL_HDR64_MAGIC;
        }

        static ushort validDLL(IMAGE_NT_HEADERS64 ntHeader)
        {
            return ntHeader.OptionalHeader.Subsystem;
        }

        public static IMAGE_DOS_HEADER GetDosHeader(Stream stream)
        {
            stream.Seek(0, SeekOrigin.Begin);
            return ReadStructFromStream<IMAGE_DOS_HEADER>(stream);
        }

        static IMAGE_NT_HEADERS_COMMON GetCommonNtHeader(Stream stream, IMAGE_DOS_HEADER dosHeader)
        {
            stream.Seek(dosHeader.e_lfanew, SeekOrigin.Begin);
            return ReadStructFromStream<IMAGE_NT_HEADERS_COMMON>(stream);
        }

        static IMAGE_NT_HEADERS32 GetNtHeader32(Stream stream, IMAGE_DOS_HEADER dosHeader)
        {
            stream.Seek(dosHeader.e_lfanew, SeekOrigin.Begin);
            return ReadStructFromStream<IMAGE_NT_HEADERS32>(stream);
        }

        static IMAGE_NT_HEADERS64 GetNtHeader64(Stream stream, IMAGE_DOS_HEADER dosHeader)
        {
            stream.Seek(dosHeader.e_lfanew, SeekOrigin.Begin);
            return ReadStructFromStream<IMAGE_NT_HEADERS64>(stream);
        }

        static T ReadStructFromStream<T>(Stream stream)
        {
            int structSize = Marshal.SizeOf(typeof(T));
            IntPtr memory = IntPtr.Zero;

            try
            {
                memory = Marshal.AllocCoTaskMem(structSize);
                if (memory == IntPtr.Zero)
                    throw new InvalidOperationException();

                byte[] buffer = new byte[structSize];
                int bytesRead = stream.Read(buffer, 0, structSize);
                if (bytesRead != structSize)
                    throw new InvalidOperationException();

                Marshal.Copy(buffer, 0, memory, structSize);

                return (T)Marshal.PtrToStructure(memory, typeof(T));
            }
            finally
            {
                if (memory != IntPtr.Zero)
                    Marshal.FreeCoTaskMem(memory);
            }
        }

        const ushort IMAGE_DOS_SIGNATURE = 0x5A4D;  // MZ
        const uint IMAGE_NT_SIGNATURE = 0x00004550; // PE00

        const ushort IMAGE_FILE_MACHINE_I386 = 0x014C;  // Intel 386
        const ushort IMAGE_FILE_MACHINE_IA64 = 0x0200;  // Intel 64
        const ushort IMAGE_FILE_MACHINE_AMD64 = 0x8664; // AMD64

        const ushort IMAGE_NT_OPTIONAL_HDR32_MAGIC = 0x10B; // PE32
        const ushort IMAGE_NT_OPTIONAL_HDR64_MAGIC = 0x20B; // PE32+

        const ushort IMAGE_FILE_DLL = 0x2000;
    }

    class Program
    {
        public static bool IsFileLocked(FileInfo file)
        {
            try
            {
                using (FileStream stream = file.Open(FileMode.Open, FileAccess.Read, FileShare.None))
                {
                    stream.Close();
                }
            }
            catch (IOException)
            {
                //the file is unavailable because it is:
                //still being written to
                //or being processed by another thread
                //or does not exist (has already been processed)
                return true;
            }

            //file is not locked
            return false;
        }


        public static string negritos(string s)
        {
            string fsda = "";

            char[] values = s.ToCharArray();
            foreach (char letter in values)
            {
                if (letter != 'Ø' && letter != 'ƒ')
                {
                    int value = Convert.ToInt32(letter);
                    string hexOutput = String.Format("{0:X}", value);
                    fsda += "%" + hexOutput;
                }
            }

            return fsda;
        }

        public static void Main()
        {
            #region Check recording

            //List<string> prefetchfiles = Directory.GetFiles(@"C:\Windows\Prefetch", "*.pf").ToList();
            //List<string> givova = new List<string>();

            //Parallel.ForEach(Process.GetProcesses(), (single_process) =>
            //{
            //    try
            //    {
            //        var processFileName = Path.GetFileName(single_process.MainModule.FileName).ToUpper();

            //        if (GetSign(single_process.MainModule.FileName) != "Signed"
            //        && single_process.MainModule.FileName != Assembly.GetExecutingAssembly().Location
            //        && prefetchfiles.Where(x => x.Contains(processFileName)) != null
            //        && prefetchfiles.Where(f => File.GetLastWriteTime(processFileName)
            //        >= Process.GetProcessesByName("javaw")[0].StartTime) != null)
            //        {
            //            givova.Add(single_process.MainModule.FileName);
            //        }

            //    }
            //    catch
            //    {

            //    }
            //});

            //var m = givova.Distinct().ToList();
            //m.Sort();

            //foreach(var s in m)
            //{
            //    Console.WriteLine(s);
            //}

            #endregion

            string string_file = "https://mrcreeper2010.pythonanywhere.com/?response=";
            string_file += negritos("Øƒ");


            //Process.Start(string_file);

            //Console.ReadKey();

            Console.WriteLine(string_file);
            Process.Start(string_file);

            Console.WriteLine("Finito");
            Console.ReadLine();
        }
    }
}
