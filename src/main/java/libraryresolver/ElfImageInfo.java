package libraryresolver;

import java.io.IOException;
import java.io.RandomAccessFile;

/**
 * Minimal, dependency-free reader for the few ELF facts the resolver needs:
 * the DT_SONAME, the machine type, the ELF class (32/64-bit), and endianness.
 *
 * Deliberately does NOT use any Ghidra classes. That is what lets the resolver
 * be unit-tested against ordinary .so files on disk with no Ghidra project,
 * no ExternalManager, and no running tool. It reads only program headers
 * (PT_DYNAMIC / PT_LOAD), so it still works on libraries whose section
 * headers have been stripped.
 *
 * This reads just enough to support:
 *   - Step 1 (gather by soname): {@link #soname}
 *   - Step 2 (arch/endianness filter): {@link #machine}, {@link #is64Bit}, {@link #bigEndian}
 *
 * It does NOT parse version tables (.gnu.version_d etc.) -- that is Step 3/4,
 * added later.
 */
public final class ElfImageInfo {

    // ELF constants we care about.
    private static final int  EI_NIDENT   = 16;
    private static final int  ELFCLASS32  = 1;
    private static final int  ELFCLASS64  = 2;
    private static final int  ELFDATA2LSB = 1; // little-endian
    private static final int  ELFDATA2MSB = 2; // big-endian
    private static final int  PT_LOAD     = 1;
    private static final int  PT_DYNAMIC  = 2;
    private static final long DT_NULL     = 0;
    private static final long DT_STRTAB   = 5;  // vaddr of the dynamic string table
    private static final long DT_SONAME   = 14; // offset into that string table
    private static final long DT_VERDEF    = 0x6ffffffc; // NEW
    private static final long DT_VERDEFNUM = 0x6ffffffd; // NEW

    private final String  soname;     // DT_SONAME, or null if the file has none
    private final int     machine;    // e_machine (e.g. 0x08 = MIPS, 0x28 = ARM, 0x3E = x86-64)
    private final boolean is64Bit;
    private final boolean bigEndian;

    private ElfImageInfo(String soname, int machine, boolean is64Bit, boolean bigEndian) {
        this.soname    = soname;
        this.machine   = machine;
        this.is64Bit   = is64Bit;
        this.bigEndian = bigEndian;
    }

    public String  soname()    { return soname; }
    public int     machine()   { return machine; }
    public boolean is64Bit()   { return is64Bit; }
    public boolean bigEndian() { return bigEndian; }

    /**
     * Read ELF facts from {@code path}. Returns null if the file is not a valid
     * ELF (bad magic, truncated, unreadable) -- callers treat null as "not a
     * candidate" and move on, which is exactly the skip-and-report behavior we
     * want for non-ELF files mixed into an extracted image tree.
     */
    public static ElfImageInfo read(String path) {
        try (RandomAccessFile f = new RandomAccessFile(path, "r")) {
            byte[] ident = new byte[EI_NIDENT];
            if (f.length() < EI_NIDENT) return null;
            f.readFully(ident);

            // ELF magic: 0x7F 'E' 'L' 'F'
            if (ident[0] != 0x7F || ident[1] != 'E' || ident[2] != 'L' || ident[3] != 'F') {
                return null;
            }

            boolean is64 = (ident[4] == ELFCLASS64);
            boolean be   = (ident[5] == ELFDATA2MSB);
            if (ident[4] != ELFCLASS32 && ident[4] != ELFCLASS64) return null;
            if (ident[5] != ELFDATA2LSB && ident[5] != ELFDATA2MSB) return null;

            Reader r = new Reader(f, be, is64);

            // ----- ELF header: we need e_machine, e_phoff, e_phentsize, e_phnum -----
            f.seek(18);                       // e_machine is at offset 18 for both classes
            int machine = r.u16();

            long phoff;
            int  phentsize, phnum;
            if (is64) {
                f.seek(32); phoff = r.u64();   // e_phoff
                f.seek(54); phentsize = r.u16(); // e_phentsize
                phnum = r.u16();               // e_phnum (immediately follows)
            } else {
                f.seek(28); phoff = r.u32l();  // e_phoff is 4 bytes in a 32-bit ELF
                f.seek(42); phentsize = r.u16(); // e_phentsize
                phnum = r.u16();               // e_phnum
            }

            // ----- walk program headers to find PT_DYNAMIC and the PT_LOAD map -----
            long   dynOffset = -1, dynFilesz = 0;
            long[] loadVaddr  = new long[phnum];
            long[] loadOffset = new long[phnum];
            long[] loadFilesz = new long[phnum];
            int    loadCount  = 0;

            for (int i = 0; i < phnum; i++) {
                long ph = phoff + (long) i * phentsize;
                f.seek(ph);
                int pType = r.u32();
                long pOffset, pVaddr, pFilesz;
                if (is64) {
                    // 64-bit Phdr: p_type(4) p_flags(4) p_offset(8) p_vaddr(8) p_paddr(8) p_filesz(8)...
                    r.u32();                  // p_flags
                    pOffset = r.u64();
                    pVaddr  = r.u64();
                    r.u64();                  // p_paddr
                    pFilesz = r.u64();
                } else {
                    // 32-bit Phdr: p_type(4) p_offset(4) p_vaddr(4) p_paddr(4) p_filesz(4)...
                    pOffset = r.u32();
                    pVaddr  = r.u32();
                    r.u32();                  // p_paddr
                    pFilesz = r.u32();
                }

                if (pType == PT_DYNAMIC) {
                    dynOffset = pOffset;
                    dynFilesz = pFilesz;
                } else if (pType == PT_LOAD) {
                    loadVaddr[loadCount]  = pVaddr;
                    loadOffset[loadCount] = pOffset;
                    loadFilesz[loadCount] = pFilesz;
                    loadCount++;
                }
            }

            // No dynamic segment -> not a dynamically-linked object we can read a soname from.
            if (dynOffset < 0) {
                return new ElfImageInfo(null, machine, is64, be);
            }

            // ----- walk the dynamic entries for DT_STRTAB (vaddr) and DT_SONAME (offset) -----
            long strtabVaddr  = -1;
            long sonameOffset = -1;
            long verdefVaddr  = -1;   // NEW: DT_VERDEF
            long verdefNum    =  0;   // NEW: DT_VERDEFNUM
            int  entSize = is64 ? 16 : 8;     // Elf64_Dyn = 16, Elf32_Dyn = 8
            long entries = dynFilesz / entSize;

            for (long i = 0; i < entries; i++) {
                f.seek(dynOffset + i * entSize);
                long tag = is64 ? r.s64() : r.s32();
                long val = is64 ? r.u64() : r.u32();
                if (tag == DT_NULL)   break;
                if (tag == DT_STRTAB) strtabVaddr  = val;
                if (tag == DT_SONAME) sonameOffset = val;
                if (tag == DT_VERDEF)     verdefVaddr  = val;   // NEW
                if (tag == DT_VERDEFNUM)  verdefNum    = val;
            }

            
            if (sonameOffset < 0 || strtabVaddr < 0) {
                // Dynamic object but no soname recorded (common for executables and
                // for libraries built without -soname). Still a valid ELF; soname null.
                return new ElfImageInfo(null, machine, is64, be);
            }

            // ----- translate the string-table vaddr to a file offset via PT_LOAD -----
            long strtabFileOff = vaddrToOffset(strtabVaddr, loadVaddr, loadOffset, loadFilesz, loadCount);
            if (strtabFileOff < 0) {
                return new ElfImageInfo(null, machine, is64, be);
            }

            String soname = readCString(f, strtabFileOff + sonameOffset);
            return new ElfImageInfo(soname, machine, is64, be);

        } catch (IOException e) {
            return null; // unreadable / truncated -> not a candidate
        }
    }

    /** Map a virtual address into a file offset using the PT_LOAD segments. */
    private static long vaddrToOffset(long vaddr, long[] vad, long[] off, long[] sz, int n) {
        for (int i = 0; i < n; i++) {
            if (vaddr >= vad[i] && vaddr < vad[i] + sz[i]) {
                return vaddr - vad[i] + off[i];
            }
        }
        return -1;
    }

    /** Read a NUL-terminated ASCII string at a file offset. */
    private static String readCString(RandomAccessFile f, long offset) throws IOException {
        f.seek(offset);
        StringBuilder sb = new StringBuilder();
        int b;
        while ((b = f.read()) > 0) {        // stops at NUL (0) and at EOF (-1)
            sb.append((char) b);
        }
        return sb.toString();
    }

    /** Endianness- and width-aware little reader over the open file. */
    private static final class Reader {
        private final RandomAccessFile f;
        private final boolean be;
        Reader(RandomAccessFile f, boolean be, boolean is64) { this.f = f; this.be = be; }

        int u16() throws IOException {
            int a = f.read(), b = f.read();
            return be ? ((a << 8) | b) : ((b << 8) | a);
        }
        int u32() throws IOException {
            long v = u32l();
            return (int) v;
        }
        long u32l() throws IOException {
            int a = f.read(), b = f.read(), c = f.read(), d = f.read();
            return be ? ((long)a << 24) | ((long)b << 16) | ((long)c << 8) | d
                      : ((long)d << 24) | ((long)c << 16) | ((long)b << 8) | a;
        }
        long s32() throws IOException { return (int) u32l(); } // sign-extend
        long u64() throws IOException {
            long lo, hi;
            if (be) { hi = u32l(); lo = u32l(); }
            else    { lo = u32l(); hi = u32l(); }
            return (hi << 32) | (lo & 0xFFFFFFFFL);
        }
        long s64() throws IOException { return u64(); } // tags fit in signed range
    }
}