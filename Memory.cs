using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Linq;
using System.Net;
using System.Numerics;
using System.Runtime.InteropServices;
using System.Text;
using System.Threading.Tasks;

internal class Memory
{
    public static Process AttachProcess = default;
    public static IntPtr Handle = IntPtr.Zero, BaseAddress = IntPtr.Zero;
    public static string ProcessName = string.Empty;
    public static int ProcessId = 0;

    public static bool Initalize(int procId)
    {
        try
        {
            Process process = Process.GetProcessById((int)procId);
            if (!process.HasExited)
            {
                AttachProcess = process;
                ProcessName = process.ProcessName;
                ProcessId = process.Id;
                BaseAddress = process.MainModule.BaseAddress;
                Handle = Native.OpenProcess(Native.ProcessAccessFlags.VirtualMemoryRead | Native.ProcessAccessFlags.VirtualMemoryWrite | Native.ProcessAccessFlags.VirtualMemoryOperation, false, ProcessId);
                return true;
            }
            return false;
        }
        catch { return false; }
    }

    public static bool Initalize(string processName)
    {
        Process[] processes = Process.GetProcessesByName(processName);
        if (processes.Length > 0)
            return Initalize(processes.FirstOrDefault().Id);
        else
            return false;
    }

    private static IntPtr BytesRead = IntPtr.Zero;
    private static IntPtr BytesWritten = IntPtr.Zero;

    public static byte[] ReadMemory(nint address, int size)
    {
        byte[] buffer = new byte[size];
        Native.ReadProcessMemory(Handle, address, buffer, buffer.Length, out BytesRead);
        return buffer;
    }

    public static bool ReadBytes(nint address, ref byte[] buffer)
    {
        return Native.ReadProcessMemory(Handle, address, buffer, buffer.Length, out BytesRead) ? true : false;
    }

    public static byte[] ReadBytes(nint address, int size)
    {
        byte[] buffer = new byte[size];
        Native.ReadProcessMemory(Handle, address, buffer, buffer.Length, out BytesRead);
        return buffer;
    }

    public static T Read<T>(nint address) where T : struct
    {
        byte[] buffer = new byte[Marshal.SizeOf(typeof(T))];
        Native.ReadProcessMemory(Handle, address, buffer, buffer.Length, out BytesRead);
        return ByteArrayToStructure<T>(buffer);
    }

    public static unsafe T[] ReadStructArray<T>(nint address, int length) where T : struct
    {
        T[] array = new T[length];
        for (int i = 0; i < length; i++)
        {
            unsafe
            {
                array[i] = Memory.Read<T>(address + sizeof(T) * i);
            }
        }
        return array;
    }

    public static void Write<T>(nint address, object value) where T : struct
    {
        byte[] buffer = StructureToByteArray(value);
        Native.WriteProcessMemory(Handle, address, buffer, buffer.Length, out BytesWritten);
    }

    public static float[] ReadMatrix<T>(nint address, int matrixSize) where T : struct
    {
        byte[] buffer = new byte[Marshal.SizeOf(typeof(T)) * matrixSize];
        Native.ReadProcessMemory(Handle, address, buffer, buffer.Length, out BytesRead);
        return ConvertToFloatArray(buffer);
    }

    public static string ReadString(nint address, int size, Encoding encoding = default)
    {
        return CutString(encoding.GetString(ReadMemory(address, size)));
    }

    //public static bool WorldToScreen(Vector3 target, out Vector2 pos, float[] viewmatrix)
    //{
    //    //Matrix-vector Product, multiplying world(eye) coordinates by projection matrix = clipCoords
    //    pos = new Vector2(0, 0);
    //    Vector4 clipCoords = new Vector4()
    //    {
    //        X = target.X * viewmatrix[0] + target.Y * viewmatrix[1] + target.Z * viewmatrix[2] + viewmatrix[3],
    //       Y = target.X * viewmatrix[4] + target.Y * viewmatrix[5] + target.Z * viewmatrix[6] + viewmatrix[7],
    //       Z = target.X * viewmatrix[8] + target.Y * viewmatrix[9] + target.Z * viewmatrix[10] + viewmatrix[11],
    //        W = target.X * viewmatrix[12] + target.Y * viewmatrix[13] + target.Z * viewmatrix[14] + viewmatrix[15]
    //    };

    //    if (clipCoords.W < 0.1f)
    //         return false;

    //    //perspective division, dividing by clip.W = Normalized Device Coordinates
    //    Vector3 NDC;
    //    NDC.X = clipCoords.X / clipCoords.W;
    //    NDC.Y = clipCoords.Y / clipCoords.W;
    //    NDC.Z = clipCoords.Z / clipCoords.W;
    //   var display = ImGuiNET.ImGui.GetIO().DisplaySize;
    //    pos.X = (display.X / 2 * NDC.X) + (NDC.X + display.X / 2);
    //    pos.Y = -(display.Y / 2 * NDC.Y) + (NDC.Y + display.Y / 2);
    //    return true;
    //}

    // public static bool WorldToScreen(Vector3 target, out Vector2 pos)
    //{
    //    return WorldToScreen(target, out pos, EngineClient.Viewmatrix);
    //}

    public static (nint, int) GetModuleAddress(string module)
    {
        foreach (ProcessModule process_module in AttachProcess.Modules)
        {
            if (process_module.ModuleName == module)
                return (process_module.BaseAddress, process_module.ModuleMemorySize);
        }
        return (nint.Zero, 0);
    }

    public static nint GetAbsoluteAddress(nint address, int offset, int size)
    {
        offset = Read<int>(address + offset);
        return address + offset + size;
    }

    public static nint FindPattern(String pattern)
    {
        return FindPattern(pattern, AttachProcess.MainModule.BaseAddress, AttachProcess.MainModule.ModuleMemorySize);
    }

    public static nint FindPattern(String pattern, nint start, Int32 length)
    {
        //var skip = pattern.ToLower().Contains("cc") ? 0xcc : pattern.ToLower().Contains("aa") ? 0xaa : 0;
        var sigScan = new SigScan(AttachProcess, start, length);
        var arrayOfBytes = pattern.Split(' ').Select(b => b.Contains("?") ? (Byte)0 : (Byte)Convert.ToInt32(b, 16)).ToArray();
        var strMask = String.Join("", pattern.Split(' ').Select(b => b.Contains("?") ? '?' : 'x'));
        return sigScan.FindPattern(arrayOfBytes, strMask, 0);
    }
    public static List<nint> FindPatterns(String pattern)
    {
        //var skip = pattern.ToLower().Contains("cc") ? 0xcc : pattern.ToLower().Contains("aa") ? 0xaa : 0;
        var sigScan = new SigScan(AttachProcess, AttachProcess.MainModule.BaseAddress, AttachProcess.MainModule.ModuleMemorySize);
        var arrayOfBytes = pattern.Split(' ').Select(b => b.Contains("?") ? (Byte)0 : (Byte)Convert.ToInt32(b, 16)).ToArray();
        var strMask = String.Join("", pattern.Split(' ').Select(b => b.Contains("?") ? '?' : 'x'));
        return sigScan.FindPatterns(arrayOfBytes, strMask, 0);
    }

    public static nint FindStringRef(String str)
    {
        var stringAddr = FindPattern(BitConverter.ToString(Encoding.Unicode.GetBytes(str)).Replace("-", " "));
        var sigScan = new SigScan(AttachProcess, AttachProcess.MainModule.BaseAddress, AttachProcess.MainModule.ModuleMemorySize);
        sigScan.DumpMemory();
        for (var i = 0; i < sigScan.Size; i++)
        {
            if ((sigScan.m_vDumpedRegion[i] == 0x48 || sigScan.m_vDumpedRegion[i] == 0x4c) && sigScan.m_vDumpedRegion[i + 1] == 0x8d)
            {
                var jmpTo = BitConverter.ToInt32(sigScan.m_vDumpedRegion, i + 3);
                var addr = sigScan.Address + i + jmpTo + 7;
                if (addr == stringAddr)
                {
                    return AttachProcess.MainModule.BaseAddress + i;
                }
            }
        }
        return 0;
    }

    #region Transformations
    private static float[] ConvertToFloatArray(byte[] bytes)
    {
        if (bytes.Length % 4 != 0) throw new ArgumentException();

        float[] floats = new float[bytes.Length / 4];

        for (int i = 0; i < floats.Length; i++) floats[i] = BitConverter.ToSingle(bytes, i * 4);

        return floats;
    }

    private static T ByteArrayToStructure<T>(byte[] bytes) where T : struct
    {
        GCHandle handle = GCHandle.Alloc(bytes, GCHandleType.Pinned);

        try
        {
            return (T)Marshal.PtrToStructure(handle.AddrOfPinnedObject(), typeof(T));
        }
        finally
        {
            handle.Free();
        }
    }

    private static byte[] StructureToByteArray(object obj)
    {
        int length = Marshal.SizeOf(obj);

        byte[] array = new byte[length];

        IntPtr pointer = Marshal.AllocHGlobal(length);

        Marshal.StructureToPtr(obj, pointer, true);
        Marshal.Copy(pointer, array, 0, length);
        Marshal.FreeHGlobal(pointer);

        return array;
    }

    private static string CutString(string mystring)
    {
        //char[] chArray = mystring.ToCharArray();
        //string str = "";
        //for (int i = 0; i < mystring.Length; i++)
        //{
        //    if ((chArray[i] == ' ') && (chArray[i + 1] == ' '))
        //    {
        //        return str;
        //    }
        //    if (chArray[i] == '\0')
        //    {
        //        return str;
        //    }
        //    str = str + chArray[i].ToString();
        //}
        //return mystring.TrimEnd(new char[] { '0' });
        return mystring;
    }
    #endregion

    internal class Native
    {
        [DllImport("kernel32.dll", SetLastError = true)]
        public static extern nint OpenProcess(ProcessAccessFlags processAccess, bool bInheritHandle, int processId);

        [DllImport("kernel32.dll", SetLastError = true)]
        public static extern bool WriteProcessMemory(nint hProcess, nint lpBaseAddress, byte[] lpBuffer, Int32 nSize, out nint lpNumberOfBytesWritten);

        [DllImport("kernel32.dll", SetLastError = true)]
        public static extern bool ReadProcessMemory(nint hProcess, nint lpBaseAddress, [Out] byte[] lpBuffer, int dwSize, out nint lpNumberOfBytesRead);

        [Flags]
        public enum ProcessAccessFlags : uint
        {
            All = 0x001F0FFF,
            Terminate = 0x00000001,
            CreateThread = 0x00000002,
            VirtualMemoryOperation = 0x00000008,
            VirtualMemoryRead = 0x00000010,
            VirtualMemoryWrite = 0x00000020,
            DuplicateHandle = 0x00000040,
            CreateProcess = 0x000000080,
            SetQuota = 0x00000100,
            SetInformation = 0x00000200,
            QueryInformation = 0x00000400,
            QueryLimitedInformation = 0x00001000,
            Synchronize = 0x00100000
        }
    }

    public class SignatureEntity
    {
        public int StartAddress { get; set; }
        public int SearchRange { get; set; }
        public byte[] WantedBytes { get; set; }
        public String Mask { get; set; }
        public int AddressOffset { get; set; }

        public SignatureEntity(int startSAddress, int searchRange, byte[] wantedBytes, String mask, int addressOffset)
        {
            StartAddress = startSAddress;
            SearchRange = searchRange;
            WantedBytes = wantedBytes;
            Mask = mask;
            AddressOffset = addressOffset;
        }

        public IntPtr ScanSignature(Process process)
        {
            SigScan sigScan = new SigScan(process, new IntPtr(StartAddress), SearchRange);
            return sigScan.FindPattern(WantedBytes, Mask, AddressOffset);
        }
    }


    public class SigScan
    {
        /// <summary>
        /// ReadProcessMemory
        /// 
        ///     API import definition for ReadProcessMemory.
        /// </summary>
        /// <param name="hProcess">Handle to the process we want to read from.</param>
        /// <param name="lpBaseAddress">The base address to start reading from.</param>
        /// <param name="lpBuffer">The return buffer to write the read data to.</param>
        /// <param name="dwSize">The size of data we wish to read.</param>
        /// <param name="lpNumberOfBytesRead">The number of bytes successfully read.</param>
        /// <returns></returns>
        [DllImport("kernel32.dll", SetLastError = true)]
        private static extern bool ReadProcessMemory(
            IntPtr hProcess,
            IntPtr lpBaseAddress,
            [Out()] byte[] lpBuffer,
            int dwSize,
            out int lpNumberOfBytesRead
            );

        /// <summary>
        /// m_vDumpedRegion
        /// 
        ///     The memory dumped from the external process.
        /// </summary>
        public byte[] m_vDumpedRegion;

        /// <summary>
        /// m_vProcess
        /// 
        ///     The process we want to read the memory of.
        /// </summary>
        private Process m_vProcess;

        /// <summary>
        /// m_vAddress
        /// 
        ///     The starting address we want to begin reading at.
        /// </summary>
        private IntPtr m_vAddress;

        /// <summary>
        /// m_vSize
        /// 
        ///     The number of bytes we wish to read from the process.
        /// </summary>
        private Int32 m_vSize;


        #region "sigScan Class Construction"
        /// <summary>
        /// SigScan
        /// 
        ///     Main class constructor that uses no params. 
        ///     Simply initializes the class properties and 
        ///     expects the user to set them later.
        /// </summary>
        public SigScan()
        {
            this.m_vProcess = null;
            this.m_vAddress = IntPtr.Zero;
            this.m_vSize = 0;
            this.m_vDumpedRegion = null;
        }
        /// <summary>
        /// SigScan
        /// 
        ///     Overloaded class constructor that sets the class
        ///     properties during construction.
        /// </summary>
        /// <param name="proc">The process to dump the memory from.</param>
        /// <param name="addr">The started address to begin the dump.</param>
        /// <param name="size">The size of the dump.</param>
        public SigScan(Process proc, IntPtr addr, int size)
        {
            this.m_vProcess = proc;
            this.m_vAddress = addr;
            this.m_vSize = size;
        }
        #endregion

        #region "sigScan Class Private Methods"
        /// <summary>
        /// DumpMemory
        /// 
        ///     Internal memory dump function that uses the set class
        ///     properties to dump a memory region.
        /// </summary>
        /// <returns>Boolean based on RPM results and valid properties.</returns>
        public bool DumpMemory()
        {
            try
            {
                // Checks to ensure we have valid data.
                if (this.m_vProcess == null)
                    return false;
                if (this.m_vProcess.HasExited == true)
                    return false;
                if (this.m_vAddress == IntPtr.Zero)
                    return false;
                if (this.m_vSize == 0)
                    return false;

                // Create the region space to dump into.
                this.m_vDumpedRegion = new byte[this.m_vSize];

                bool bReturn = false;
                int nBytesRead = 0;

                // Dump the memory.
                bReturn = ReadProcessMemory(
                    this.m_vProcess.Handle, this.m_vAddress, this.m_vDumpedRegion, this.m_vSize, out nBytesRead
                    );

                // Validation checks.
                if (bReturn == false || nBytesRead != this.m_vSize)
                    return false;
                return true;
            }
            catch (Exception)
            {
                return false;
            }
        }

        /// <summary>
        /// MaskCheck
        /// 
        ///     Compares the current pattern byte to the current memory dump
        ///     byte to check for a match. Uses wildcards to skip bytes that
        ///     are deemed unneeded in the compares.
        /// </summary>
        /// <param name="nOffset">Offset in the dump to start at.</param>
        /// <param name="btPattern">Pattern to scan for.</param>
        /// <param name="strMask">Mask to compare against.</param>
        /// <returns>Boolean depending on if the pattern was found.</returns>
        private bool MaskCheck(int nOffset, byte[] btPattern, string strMask)
        {
            // Loop the pattern and compare to the mask and dump.
            for (int x = 0; x < btPattern.Length; x++)
            {
                // If the mask char is a wildcard, just continue.
                if (strMask[x] == '?')
                    continue;

                // If the mask char is not a wildcard, ensure a match is made in the pattern.
                if ((strMask[x] == 'x') && (btPattern[x] != this.m_vDumpedRegion[nOffset + x]))
                    return false;
            }

            // The loop was successful so we found the pattern.
            return true;
        }
        #endregion

        #region "sigScan Class Public Methods"
        /// <summary>
        /// FindPattern
        /// 
        ///     Attempts to locate the given pattern inside the dumped memory region
        ///     compared against the given mask. If the pattern is found, the offset
        ///     is added to the located address and returned to the user.
        /// </summary>
        /// <param name="btPattern">Byte pattern to look for in the dumped region.</param>
        /// <param name="strMask">The mask string to compare against.</param>
        /// <param name="nOffset">The offset added to the result address.</param>
        /// <returns>IntPtr - zero if not found, address if found.</returns>
        public IntPtr FindPattern(byte[] btPattern, string strMask, int nOffset)
        {
            try
            {
                // Dump the memory region if we have not dumped it yet.
                if (this.m_vDumpedRegion == null || this.m_vDumpedRegion.Length == 0)
                {
                    if (!this.DumpMemory())
                        return IntPtr.Zero;
                }

                // Ensure the mask and pattern lengths match.
                if (strMask.Length != btPattern.Length)
                    return IntPtr.Zero;

                // Loop the region and look for the pattern.
                for (int x = 0; x < this.m_vDumpedRegion.Length - strMask.Length; x++)
                {
                    if (this.MaskCheck(x, btPattern, strMask))
                    {
                        // The pattern was found, return it.
                        return IntPtr.Add(this.m_vAddress, x + nOffset);
                    }
                }

                // Pattern was not found.
                return IntPtr.Zero;
            }
            catch (Exception)
            {
                return IntPtr.Zero;
            }
        }
        public List<IntPtr> FindPatterns(byte[] btPattern, string strMask, int nOffset)
        {
            var ptrs = new List<IntPtr>();
            try
            {
                // Dump the memory region if we have not dumped it yet.
                if (this.m_vDumpedRegion == null || this.m_vDumpedRegion.Length == 0)
                {
                    if (!this.DumpMemory())
                        return null;
                }

                // Ensure the mask and pattern lengths match.
                if (strMask.Length != btPattern.Length)
                    return null;

                // Loop the region and look for the pattern.
                for (int x = 0; x < this.m_vDumpedRegion.Length; x++)
                {
                    if (this.MaskCheck(x, btPattern, strMask))
                    {
                        // The pattern was found, return it.
                        ptrs.Add(IntPtr.Add(this.m_vAddress, x + nOffset));
                    }
                }

                // Pattern was not found.
                return ptrs;
            }
            catch (Exception)
            {
                return null;
            }
        }

        /// <summary>
        /// ResetRegion
        /// 
        ///     Resets the memory dump array to nothing to allow
        ///     the class to redump the memory.
        /// </summary>
        public void ResetRegion()
        {
            this.m_vDumpedRegion = null;
        }
        #endregion

        #region "sigScan Class Properties"
        public Process Process
        {
            get { return this.m_vProcess; }
            set { this.m_vProcess = value; }
        }
        public IntPtr Address
        {
            get { return this.m_vAddress; }
            set { this.m_vAddress = value; }
        }
        public Int32 Size
        {
            get { return this.m_vSize; }
            set { this.m_vSize = value; }
        }
        #endregion

    }
}
