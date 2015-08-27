/*
 * ---------------------------------------
 * User: duketwo
 * Date: 23.03.2014
 * Time: 14:20
 * 
 * ---------------------------------------
 */
using System;
using System.Collections.Generic;
using System.Drawing;
using System.Windows.Forms;
using System.Reflection;
using System.Diagnostics;
using System.Runtime.Remoting;
using System.Runtime.InteropServices;
using System.Linq;
using System.IO;
using System.Threading;
using System.ComponentModel;
using System.Runtime.CompilerServices;
using System.Text;
using System.Threading.Tasks;


namespace WSockConnectHook
{
    /// <summary>
    /// Description of Util.
    /// </summary>
    public class Utility
    {

        [DllImport("kernel32.dll", CharSet = CharSet.Auto)]
        public static extern IntPtr GetModuleHandle(string lpModuleName);

        [DllImport("kernel32.dll", CharSet = CharSet.Ansi, ExactSpelling = true, SetLastError = true)]
        private static extern IntPtr GetProcAddress(IntPtr hModule, string procName);

        [DllImport("kernel32.dll", SetLastError = true)]
        public static extern void SetLastError(int errorCode);

        [DllImport("kernel32.dll", CharSet = CharSet.Unicode)]
        public static extern IntPtr GetModuleHandleW(IntPtr lpModuleName);

        [DllImport("kernel32.dll", EntryPoint = "RtlMoveMemory")]
        public static extern void CopyMemory(IntPtr Destination, IntPtr Source, uint Length);

        [DllImport("kernel32.dll", CharSet = CharSet.Ansi)]
        public static extern IntPtr LoadLibraryA(IntPtr lpModuleName);

        public Utility()
        {
        }


        public static IntPtr GetImportAddress(string module, string importedModule, string function)
        {
            var handle = GetModuleHandle(module);
            if (handle == IntPtr.Zero)
                return IntPtr.Zero;

            var address = GetThunk(handle, importedModule, function);
            if (address == IntPtr.Zero)
                return IntPtr.Zero;

            if (address == GetProcAddresFunc(importedModule, function))
                return IntPtr.Zero;

            return address;
        }
        private static IntPtr GetProcAddresFunc(string module, string function)
        {
            return GetProcAddress(GetModuleHandle(module), function);
        }

        #region Native structures

        [StructLayout(LayoutKind.Sequential)]
        public struct IMAGE_DOS_HEADER
        {
            [MarshalAs(UnmanagedType.ByValArray, SizeConst = 2)]
            public char[] e_magic; // Magic number
            public UInt16 e_cblp; // Bytes on last page of file
            public UInt16 e_cp; // Pages in file
            public UInt16 e_crlc; // Relocations
            public UInt16 e_cparhdr; // Size of header in paragraphs
            public UInt16 e_minalloc; // Minimum extra paragraphs needed
            public UInt16 e_maxalloc; // Maximum extra paragraphs needed
            public UInt16 e_ss; // Initial (relative) SS value
            public UInt16 e_sp; // Initial SP value
            public UInt16 e_csum; // Checksum
            public UInt16 e_ip; // Initial IP value
            public UInt16 e_cs; // Initial (relative) CS value
            public UInt16 e_lfarlc; // File address of relocation table
            public UInt16 e_ovno; // Overlay number
            [MarshalAs(UnmanagedType.ByValArray, SizeConst = 4)]
            public UInt16[] e_res1; // Reserved words
            public UInt16 e_oemid; // OEM identifier (for e_oeminfo)
            public UInt16 e_oeminfo; // OEM information; e_oemid specific
            [MarshalAs(UnmanagedType.ByValArray, SizeConst = 10)]
            public UInt16[] e_res2; // Reserved words
            public Int32 e_lfanew; // File address of new exe header

            private string _e_magic
            {
                get { return new string(e_magic); }
            }

            public bool isValid
            {
                get { return _e_magic == "MZ"; }
            }
        }

        [StructLayout(LayoutKind.Sequential)]
        public struct IMAGE_DATA_DIRECTORY
        {
            public UInt32 VirtualAddress;
            public UInt32 Size;
        }

        [StructLayout(LayoutKind.Sequential)]
        public struct IMAGE_FILE_HEADER
        {
            public UInt16 Machine;
            public UInt16 NumberOfSections;
            public UInt32 TimeDateStamp;
            public UInt32 PointerToSymbolTable;
            public UInt32 NumberOfSymbols;
            public UInt16 SizeOfOptionalHeader;
            public UInt16 Characteristics;
        }

        public enum MachineType : ushort
        {
            Native = 0,
            I386 = 0x014c,
            Itanium = 0x0200,
            x64 = 0x8664
        }

        public enum MagicType : ushort
        {
            IMAGE_NT_OPTIONAL_HDR32_MAGIC = 0x10b,
            IMAGE_NT_OPTIONAL_HDR64_MAGIC = 0x20b
        }

        public enum SubSystemType : ushort
        {
            IMAGE_SUBSYSTEM_UNKNOWN = 0,
            IMAGE_SUBSYSTEM_NATIVE = 1,
            IMAGE_SUBSYSTEM_WINDOWS_GUI = 2,
            IMAGE_SUBSYSTEM_WINDOWS_CUI = 3,
            IMAGE_SUBSYSTEM_POSIX_CUI = 7,
            IMAGE_SUBSYSTEM_WINDOWS_CE_GUI = 9,
            IMAGE_SUBSYSTEM_EFI_APPLICATION = 10,
            IMAGE_SUBSYSTEM_EFI_BOOT_SERVICE_DRIVER = 11,
            IMAGE_SUBSYSTEM_EFI_RUNTIME_DRIVER = 12,
            IMAGE_SUBSYSTEM_EFI_ROM = 13,
            IMAGE_SUBSYSTEM_XBOX = 14
        }

        public enum DllCharacteristicsType : ushort
        {
            RES_0 = 0x0001,
            RES_1 = 0x0002,
            RES_2 = 0x0004,
            RES_3 = 0x0008,
            IMAGE_DLL_CHARACTERISTICS_DYNAMIC_BASE = 0x0040,
            IMAGE_DLL_CHARACTERISTICS_FORCE_INTEGRITY = 0x0080,
            IMAGE_DLL_CHARACTERISTICS_NX_COMPAT = 0x0100,
            IMAGE_DLLCHARACTERISTICS_NO_ISOLATION = 0x0200,
            IMAGE_DLLCHARACTERISTICS_NO_SEH = 0x0400,
            IMAGE_DLLCHARACTERISTICS_NO_BIND = 0x0800,
            RES_4 = 0x1000,
            IMAGE_DLLCHARACTERISTICS_WDM_DRIVER = 0x2000,
            IMAGE_DLLCHARACTERISTICS_TERMINAL_SERVER_AWARE = 0x8000
        }

        [StructLayout(LayoutKind.Explicit)]
        public struct IMAGE_OPTIONAL_HEADER32
        {
            [FieldOffset(0)]
            public MagicType Magic;

            [FieldOffset(2)]
            public byte MajorLinkerVersion;

            [FieldOffset(3)]
            public byte MinorLinkerVersion;

            [FieldOffset(4)]
            public uint SizeOfCode;

            [FieldOffset(8)]
            public uint SizeOfInitializedData;

            [FieldOffset(12)]
            public uint SizeOfUninitializedData;

            [FieldOffset(16)]
            public uint AddressOfEntryPoint;

            [FieldOffset(20)]
            public uint BaseOfCode;

            // PE32 contains this additional field
            [FieldOffset(24)]
            public uint BaseOfData;

            [FieldOffset(28)]
            public uint ImageBase;

            [FieldOffset(32)]
            public uint SectionAlignment;

            [FieldOffset(36)]
            public uint FileAlignment;

            [FieldOffset(40)]
            public ushort MajorOperatingSystemVersion;

            [FieldOffset(42)]
            public ushort MinorOperatingSystemVersion;

            [FieldOffset(44)]
            public ushort MajorImageVersion;

            [FieldOffset(46)]
            public ushort MinorImageVersion;

            [FieldOffset(48)]
            public ushort MajorSubsystemVersion;

            [FieldOffset(50)]
            public ushort MinorSubsystemVersion;

            [FieldOffset(52)]
            public uint Win32VersionValue;

            [FieldOffset(56)]
            public uint SizeOfImage;

            [FieldOffset(60)]
            public uint SizeOfHeaders;

            [FieldOffset(64)]
            public uint CheckSum;

            [FieldOffset(68)]
            public SubSystemType Subsystem;

            [FieldOffset(70)]
            public DllCharacteristicsType DllCharacteristics;

            [FieldOffset(72)]
            public uint SizeOfStackReserve;

            [FieldOffset(76)]
            public uint SizeOfStackCommit;

            [FieldOffset(80)]
            public uint SizeOfHeapReserve;

            [FieldOffset(84)]
            public uint SizeOfHeapCommit;

            [FieldOffset(88)]
            public uint LoaderFlags;

            [FieldOffset(92)]
            public uint NumberOfRvaAndSizes;

            [FieldOffset(96)]
            public IMAGE_DATA_DIRECTORY ExportTable;

            [FieldOffset(104)]
            public IMAGE_DATA_DIRECTORY ImportTable;

            [FieldOffset(112)]
            public IMAGE_DATA_DIRECTORY ResourceTable;

            [FieldOffset(120)]
            public IMAGE_DATA_DIRECTORY ExceptionTable;

            [FieldOffset(128)]
            public IMAGE_DATA_DIRECTORY CertificateTable;

            [FieldOffset(136)]
            public IMAGE_DATA_DIRECTORY BaseRelocationTable;

            [FieldOffset(144)]
            public IMAGE_DATA_DIRECTORY Debug;

            [FieldOffset(152)]
            public IMAGE_DATA_DIRECTORY Architecture;

            [FieldOffset(160)]
            public IMAGE_DATA_DIRECTORY GlobalPtr;

            [FieldOffset(168)]
            public IMAGE_DATA_DIRECTORY TLSTable;

            [FieldOffset(176)]
            public IMAGE_DATA_DIRECTORY LoadConfigTable;

            [FieldOffset(184)]
            public IMAGE_DATA_DIRECTORY BoundImport;

            [FieldOffset(192)]
            public IMAGE_DATA_DIRECTORY IAT;

            [FieldOffset(200)]
            public IMAGE_DATA_DIRECTORY DelayImportDescriptor;

            [FieldOffset(208)]
            public IMAGE_DATA_DIRECTORY CLRRuntimeHeader;

            [FieldOffset(216)]
            public IMAGE_DATA_DIRECTORY Reserved;
        }

        [StructLayout(LayoutKind.Explicit)]
        public struct IMAGE_NT_HEADERS32
        {
            [FieldOffset(0)]
            [MarshalAs(UnmanagedType.ByValArray, SizeConst = 4)]
            public char[] Signature;

            [FieldOffset(4)]
            public IMAGE_FILE_HEADER FileHeader;

            [FieldOffset(24)]
            public IMAGE_OPTIONAL_HEADER32 OptionalHeader;

            private string _Signature
            {
                get { return new string(Signature); }
            }

            public bool isValid
            {
                get { return _Signature == "PE\0\0" && OptionalHeader.Magic == MagicType.IMAGE_NT_OPTIONAL_HDR32_MAGIC; }
            }
        }

        [StructLayout(LayoutKind.Sequential)]
        public struct IMAGE_IMPORT_BY_NAME
        {
            public short Hint;
            public byte Name;
        }

        [StructLayout(LayoutKind.Explicit)]
        public struct IMAGE_IMPORT_DESCRIPTOR
        {
            #region union

            /// <summary>
            ///     C# doesn't really support unions, but they can be emulated by a field offset 0
            /// </summary>
            [FieldOffset(0)]
            public uint Characteristics; // 0 for terminating null import descriptor

            [FieldOffset(0)]
            public uint OriginalFirstThunk; // RVA to original unbound IAT (PIMAGE_THUNK_DATA)

            #endregion

            [FieldOffset(4)]
            public uint TimeDateStamp;
            [FieldOffset(8)]
            public uint ForwarderChain;
            [FieldOffset(12)]
            public uint Name;
            [FieldOffset(16)]
            public uint FirstThunk;
        }

        [StructLayout(LayoutKind.Explicit)]
        public struct IMAGE_THUNK_DATA
        {
            [FieldOffset(0)]
            public uint ForwarderString; // PBYTE
            [FieldOffset(0)]
            public uint Function; // PDWORD
            [FieldOffset(0)]
            public uint Ordinal;
            [FieldOffset(0)]
            public uint AddressOfData; // PIMAGE_IMPORT_BY_NAME
        }

        #endregion



        public static IntPtr GetThunk(IntPtr moduleHandle, string intermodName, string funcName)
        {
            var idh = (IMAGE_DOS_HEADER)Marshal.PtrToStructure(moduleHandle, typeof(IMAGE_DOS_HEADER));
            if (!idh.isValid)
                return IntPtr.Zero;

            var inh32 = (IMAGE_NT_HEADERS32)Marshal.PtrToStructure(IntPtr.Add(moduleHandle, idh.e_lfanew), typeof(IMAGE_NT_HEADERS32));
            if (!inh32.isValid || inh32.OptionalHeader.ImportTable.VirtualAddress == 0)
                return IntPtr.Zero;

            var iidPtr = IntPtr.Add(moduleHandle, (int)inh32.OptionalHeader.ImportTable.VirtualAddress);
            if (iidPtr == IntPtr.Zero)
                return IntPtr.Zero;

            var iid = (IMAGE_IMPORT_DESCRIPTOR)Marshal.PtrToStructure(iidPtr, typeof(IMAGE_IMPORT_DESCRIPTOR));
            while (iid.Name != 0)
            {
                var iidName = Marshal.PtrToStringAnsi(IntPtr.Add(moduleHandle, (int)iid.Name));
                if (string.Compare(iidName, intermodName, System.StringComparison.OrdinalIgnoreCase) != 0)
                {
                    iidPtr = IntPtr.Add(iidPtr, Marshal.SizeOf(typeof(IMAGE_IMPORT_DESCRIPTOR)));
                    iid = (IMAGE_IMPORT_DESCRIPTOR)Marshal.PtrToStructure(iidPtr, typeof(IMAGE_IMPORT_DESCRIPTOR));

                    continue;
                }

                // this probably won't work for 64-bit processes as the thunk data structure is different
                var itdPtr = IntPtr.Add(moduleHandle, (int)iid.FirstThunk);
                var oitdPtr = IntPtr.Add(moduleHandle, (int)iid.OriginalFirstThunk);
                while (itdPtr != IntPtr.Zero && oitdPtr != IntPtr.Zero)
                {
                    var itd = (IMAGE_THUNK_DATA)Marshal.PtrToStructure(itdPtr, typeof(IMAGE_THUNK_DATA));
                    var oitd = (IMAGE_THUNK_DATA)Marshal.PtrToStructure(oitdPtr, typeof(IMAGE_THUNK_DATA));

                    var iibnPtr = IntPtr.Add(moduleHandle, (int)oitd.AddressOfData);
                    var iibnName = Marshal.PtrToStringAnsi(IntPtr.Add(iibnPtr, Marshal.OffsetOf(typeof(IMAGE_IMPORT_BY_NAME), "Name").ToInt32()));
                    if (itd.Function == 0)
                        return IntPtr.Zero;

                    if (string.Compare(iibnName, funcName, System.StringComparison.OrdinalIgnoreCase) == 0)
                    {
                        return new IntPtr(itd.Function);
                    }

                    itdPtr = IntPtr.Add(itdPtr, Marshal.SizeOf(typeof(IMAGE_THUNK_DATA)));
                    oitdPtr = IntPtr.Add(oitdPtr, Marshal.SizeOf(typeof(IMAGE_THUNK_DATA)));
                }

                return IntPtr.Zero;
            }

            return IntPtr.Zero;
        }

        public static void LoadLibrary(string libraryName)
        {
            if (GetModuleHandle(libraryName) == IntPtr.Zero)
            {
                var lib = Marshal.StringToHGlobalAnsi(libraryName);
                try
                {
                    LoadLibraryA(lib);
                }
                finally
                {
                    Marshal.FreeHGlobal(lib);
                }
            }
        }

        public static void DirectoryCopy(string sourceDirName, string destDirName, bool copySubDirs)
        {

            DirectoryInfo dir = new DirectoryInfo(sourceDirName);
            DirectoryInfo[] dirs = dir.GetDirectories();

            if (!dir.Exists)
            {
                throw new DirectoryNotFoundException(
                    "Source directory does not exist or could not be found: "
                    + sourceDirName);
            }
            if (!Directory.Exists(destDirName))
            {
                Directory.CreateDirectory(destDirName);
            }
            FileInfo[] files = dir.GetFiles();
            foreach (FileInfo file in files)
            {
                string temppath = Path.Combine(destDirName, file.Name);
                file.CopyTo(temppath, false);
            }

            if (copySubDirs)
            {
                foreach (DirectoryInfo subdir in dirs)
                {
                    string temppath = Path.Combine(destDirName, subdir.Name);
                    DirectoryCopy(subdir.FullName, temppath, copySubDirs);
                }
            }
        }
    }
}
