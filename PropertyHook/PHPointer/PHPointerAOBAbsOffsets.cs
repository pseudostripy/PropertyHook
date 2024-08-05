using System;

namespace PropertyHook
{
    /// <summary>
    /// A dynamic pointer starting from the base address of an array of bytes scanned for in the target process.
    /// </summary>
    public class PHPointerAOBAbsOffsets : PHPointerAOB
    {
        /// <summary>
        /// The offset of the relative address from the beginning of the AOB.
        /// </summary>
        public int AddressOffset { get; set; }

        /// <summary>
        /// Creates a new absolute AOB pointer.
        /// </summary>
        public PHPointerAOBAbsOffsets(PHook parent, byte?[] aob, int addressOffset, params int[] offsets) : base(parent, aob, offsets)
        {
            AddressOffset = addressOffset;
        }

        internal override bool ScanAOB(AOBScanner scanner)
        {
            IntPtr result = scanner.Scan(AOB);
            if (result == IntPtr.Zero)
            {
                AOBResult = result;
                return false;
            }

            uint address = Kernel32.ReadUInt32(Hook.Handle, result + AddressOffset);
            //AOBResult = (IntPtr)((ulong)Hook.Process.MainModule.BaseAddress + address);
            AOBResult = Kernel32.ReadIntPtr(Hook.Handle, (IntPtr)address, Hook.Is64Bit);
            return true;
        }
    }
}
