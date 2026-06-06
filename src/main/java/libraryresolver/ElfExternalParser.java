package libraryresolver;

import ghidra.program.model.listing.Program;
import ghidra.program.model.mem.Memory;
import ghidra.program.model.mem.MemoryBlock;
import ghidra.program.model.address.Address;
import ghidra.program.model.symbol.*;
import ghidra.app.util.importer.MessageLog;
import ghidra.util.exception.CancelledException;
import ghidra.util.task.TaskMonitor;

import java.util.*;

public class ElfExternalParser {
	
	private final Program program;
	private final MessageLog log;
	
	public ElfExternalParser(Program program, MessageLog log) {
		this.program = program;
		this.log = log;
	}
	
	/**
	 * Main entry point. Returns all external (undefined) symbols with version /
	 * library attribution where available.
	 *
	 * Everything is keyed off the true .dynsym index, so the symbol name (.dynstr),
	 * the version index (.gnu.version), and the library (.gnu.version_r) are all
	 * read for the SAME index i -- aligned by construction, no running counter.
	 */
	
	public List<ExternalSymbol> parse(TaskMonitor monitor) throws CancelledException {
	   // List<ExternalSymbol> results = new ArrayList<>();

	    // Step 1: version index -> [libName, versionString], from .gnu.version_r
	 	monitor.setMessage("LibraryResolver: parsing version requirements...");
	 	Map<Integer, String[]> versionMap = parseGnuVersionRequirements();

		// Step 2: dynsym index -> version index, from .gnu.version
		monitor.setMessage("LibraryResolver: parsing version table...");
		Map<Integer, Integer> symVersionIndex = parseGnuVersionTable();

		// Step 3: walk .dynsym directly and join the two maps by index.
		monitor.setMessage("LibraryResolver: walking .dynsym...");
		List<ExternalSymbol> results =
			parseDynamicSymbols(versionMap, symVersionIndex, monitor);
		
		
		log.appendMsg("LibraryResolver",
				String.format("Found %d external symbols", results.size()));
	 
			return results;
	}
	
	
	/**
	 * Walks the .dynsym table entry by entry. For each UNDEFINED symbol (an import),
	 * reads its name from .dynstr and looks up its version/library using the SAME
	 * index, guaranteeing alignment with the .gnu.version array.
	 */
	private List<ExternalSymbol> parseDynamicSymbols(
			Map<Integer, String[]> versionMap,
			Map<Integer, Integer> symVersionIndex,
			TaskMonitor monitor) throws CancelledException {
 
		List<ExternalSymbol> results = new ArrayList<>();
 
		Memory mem = program.getMemory();
		MemoryBlock dynsymBlock = mem.getBlock(".dynsym");
		MemoryBlock dynstrBlock = mem.getBlock(".dynstr");
		if (dynsymBlock == null || dynstrBlock == null) {
			log.appendMsg("LibraryResolver",
				"No .dynsym/.dynstr block - cannot walk dynamic symbols");
			return results;
		}
 
		boolean le   = !program.getLanguage().isBigEndian();
		boolean is64 = program.getDefaultPointerSize() == 8;
		int entSize  = is64 ? 24 : 16;   // sizeof(Elf64_Sym) / sizeof(Elf32_Sym)
 
		// Start address of .dynsym section
		Address symBase = dynsymBlock.getStart();
		
		// Start address of .dynstr section
		Address strBase = dynstrBlock.getStart();
		long count = dynsymBlock.getSize() / entSize;
 
		try {
			// Index 0 is the reserved null entry -- skip it.
			for (int i = 1; i < count; i++) {
				monitor.checkCancelled();
				Address symAddr = symBase.add((long) i * entSize);
 
				// Field order differs between 32- and 64-bit ELF symbols:
				//   Elf64_Sym: name(4) info(1) other(1) shndx(2) value(8) size(8)
				//   Elf32_Sym: name(4) value(4) size(4) info(1) other(1) shndx(2)
				int stName = readU32(mem, symAddr, le);
				int stShndx = is64
					? readU16(mem, symAddr.add(6), le)
					: readU16(mem, symAddr.add(14), le);
 
				// Only undefined symbols (st_shndx == SHN_UNDEF == 0) are imports.
				if (stShndx != 0) continue;
				if (stName == 0) continue;           // unnamed
 
				String name = readCString(mem, strBase.add(stName));
				if (name.isEmpty()) continue;
 
				// Same index i drives the version + library lookup.
				String library = null;
				String version = null;
				int verIdx = -1;
 
				Integer vi = symVersionIndex.get(i);
				if (vi != null) {
					verIdx = vi;
					String[] libVer = versionMap.get(vi);
					if (libVer != null) {
						library = libVer[0];   // e.g. "libm.so.6"
						version = libVer[1];   // e.g. "GLIBC_2.29"
					}
				}
 
				results.add(new ExternalSymbol(name, library, version, verIdx));
			}
		}
		catch (Exception e) {
			log.appendMsg("LibraryResolver", "Error walking .dynsym: " + e.getMessage());
		}
 
		return results;
	}
	
	

	
	/**
	 * Parses .gnu.version_r to build a map of version index -> [libName, versionString].
	 * This is the section that tells you "symbol version index 3 means GLIBC_2.17 from libc.so.6".
	 */
	
	private Map<Integer, String[]> parseGnuVersionRequirements() {
		Map<Integer, String[]> result = new HashMap<>();
		
		Memory mem = program.getMemory();
		MemoryBlock verneedBlock = mem.getBlock(".gnu.version_r");
		MemoryBlock dynstrBlock = mem.getBlock(".dynstr");
		
		if (verneedBlock == null || dynstrBlock == null) {
			log.appendMsg("LibraryResolver", "No .gnu.version_r found - skipping version parsing");
			return result;
		}
		
		try {
			Address base = verneedBlock.getStart();
			Address strBase = dynstrBlock.getStart();
			boolean littleEndian = !program.getLanguage().isBigEndian();
			
			int offset = 0;
			int safetyLimit = 1000; // max verneed entries
			int loopCount = 0;
			
			// The loopCount variable is intended for preventing against infinite loops
			
			while (offset < verneedBlock.getSize() && loopCount++ < safetyLimit) {
				// Elf*_Verneed: vn_version(2) vn_cnt(2) vn_file(4) vn_aux(4) vn_next(4)
				int vn_cnt  = readU16(mem, base.add(offset + 2), littleEndian);
				int vn_file = readU32(mem, base.add(offset + 4), littleEndian);
				int vn_aux  = readU32(mem, base.add(offset + 8), littleEndian);
				int vn_next = readU32(mem, base.add(offset + 12), littleEndian);
				
				// Use the value from vn_file as the offset into the .gnu.version_r section to retrieve the library name
				String libFileName = readCString(mem, strBase.add(vn_file));
				
				// Walk vernaux entries for this verneed
				int auxOffset = offset + vn_aux;
				for (int i = 0; i < vn_cnt && i < 64; i++) { // cap at 64 aux entries
					// Elf64_Vernaux: vna_hash (4), vna_flags (2), vna_other (2), vna_name (4), vna_next (4)
					int vna_other = readU16(mem, base.add(auxOffset + 6), littleEndian);
					int vna_name  = readU32(mem, base.add(auxOffset + 8), littleEndian);
					int vna_next  = readU32(mem, base.add(auxOffset + 12), littleEndian);
					
					String versionStr = readCString(mem, strBase.add(vna_name));
					result.put(vna_other, new String[] { libFileName, versionStr });
					
					if (vna_next == 0) break;
					auxOffset += vna_next;
					
				}
				
				if (vn_next == 0) break;
				offset += vn_next;
				
			}
			
		} catch (Exception e) {
			log.appendMsg("LibraryResolver", "Error parsing .gnu.version_r: " + e.getMessage());
		}
		
		return result;
	}
	
	/**
     * Parses .gnu.version — an array of 2-byte version indices, one per dynsym entry.
     * Index 0 = undefined symbol, 1 = local, 2+ = into verneed table.
     */
	
	private Map<Integer, Integer> parseGnuVersionTable() {
		
		Map<Integer, Integer> result = new HashMap<>();
		
		Memory mem = program.getMemory();
		MemoryBlock verBlock = mem.getBlock(".gnu.version");
		if (verBlock == null) return result;
		
		try {
			Address base = verBlock.getStart();
			boolean littleEndian = !program.getLanguage().isBigEndian();
			int count = (int)(verBlock.getSize() / 2);
			
			for (int i = 0; i < count; i++) {
				int verIdx = readU16(mem, base.add(i * 2L), littleEndian) & 0x7fff;
				if (verIdx > 1) { // 0=local/undef, 1=global unversioned
					result.put(i, verIdx);
				}
			}
			
		} catch (Exception e) {
			log.appendMsg("LibraryResolver", "Error parsing .gnu.version: " + e.getMessage());
		}
		
		return result;
	}
	
	
	// --- Raw memory read helpers ---
	
	private int readU16(Memory mem, Address addr, boolean le) throws Exception{
		byte b0 = mem.getByte(addr);
		byte b1 = mem.getByte(addr.add(1));
		if (le) return (b0 & 0xFF) | ((b1 & 0xFF) << 8);
		else	return ((b0 & 0xFF) << 8) | (b1 & 0xFF);
	}
	
	private int readU32(Memory mem, Address addr, boolean le) throws Exception {
		byte[] b = new byte[4];
		mem.getBytes(addr, b);
		if (le) return (b[0] & 0xFF) | ((b[1] & 0xFF) << 8) | ((b[2] & 0xFF) << 16) | ((b[3] & 0xFF) << 24);
		else    return ((b[0] & 0xFF) << 24) | ((b[1] & 0xFF) << 16) | ((b[2] & 0xFF) << 8) | (b[3] & 0xFF);
	}
	
	private String readCString(Memory mem, Address addr) throws Exception {
		StringBuilder sb = new StringBuilder();
		for (int i = 0; i< 256; i++) {
			byte b = mem.getByte(addr.add(i));
			if (b == 0) break;
			sb.append((char) b);
		}
		
		return sb.toString();
	}
	
	
	
	
}