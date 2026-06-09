package libraryresolver; // <-- change to match your existing package

import java.util.Arrays;
import java.util.List;

import ghidra.framework.model.DomainFile;
import ghidra.framework.model.DomainFolder;
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.CodeUnit;
import ghidra.program.model.listing.Program;
import ghidra.program.model.symbol.ExternalLocation;
import ghidra.program.model.symbol.ExternalManager;
import ghidra.program.model.listing.Library;
import ghidra.program.model.symbol.SourceType;
import ghidra.program.model.symbol.Symbol;
import ghidra.program.model.symbol.SymbolTable;
import ghidra.util.Msg;
import ghidra.util.exception.DuplicateNameException;
import ghidra.util.exception.InvalidInputException;
import ghidra.util.task.TaskMonitor;
import ghidra.util.exception.CancelledException;
import java.util.Set;
import java.util.HashSet;
import java.util.Arrays;


/**
 * Writes resolved library + version attribution back into the program database.
 *
 * For each {@link ExternalSymbol} produced by the parser, this:
 *   1. finds the external symbol the ELF importer already created (by bare name),
 *   2. ensures the resolved library namespace exists,
 *   3. re-parents the symbol under that library, and
 *   4. records the symbol version as an EOL comment (Ghidra has no native
 *      version field on external symbols).
 *
 * Intended to be called from an Analyzer's added() method, which already runs
 * inside Ghidra's analysis transaction -- no manual startTransaction() needed.
 */
public class LibraryResultApplicator {

    private final Program program;
    private final ExternalManager extMgr;
    private final SymbolTable symbolTable;

    public LibraryResultApplicator(Program program) {
        this.program = program;
        this.extMgr = program.getExternalManager();
        this.symbolTable = program.getSymbolTable();
    }

    /**
     * Apply every resolved symbol. Returns the number successfully written.
     */
    public int apply(List<ExternalSymbol> symbols, TaskMonitor monitor) throws CancelledException {
       
    	// Bind library paths first - one pass per library, before per-symbol work
    	Set<String> libraryNames = new HashSet<>(Arrays.asList(program.getExternalManager().getExternalLibraryNames()));
    	bindLibraryPaths(program, libraryNames, monitor);
    	
    	int applied = 0;
        for (ExternalSymbol sym : symbols) {
            monitor.checkCancelled();
            if (applySymbol(sym)) {
                applied++;
            }
        }
        return applied;
    }

    private boolean applySymbol(ExternalSymbol sym) {
    	
    	// NOTE: getName() must return the BARE name (e.g. "__cxa_atexit"),
        // NOT "__cxa_atexit@GLIBC_2.2.5" -- Ghidra stored the import under the
        // bare name, so the version suffix here would cause the lookup to miss.
        String name    = sym.name;           // bare name, e.g. "__cxa_atexit"
        String libName = sym.library;        // e.g. "libc.so.6"
        String version = sym.version;        // e.g. "GLIBC_2.2.5" (may be null)


        // 1. Find the external symbol the importer already created.
        Symbol symbol = symbolTable.getExternalSymbol(name);
        if (symbol == null) {
            Msg.warn(this, "No external symbol found for: " + name);
            return false;
        }

        ExternalLocation extLoc = extMgr.getExternalLocation(symbol);
        if (extLoc == null) {
            Msg.warn(this, "No external location for symbol: " + name);
            return false;
        }

        // Only re-home when we actually resolved a library. Unversioned imports
        // (e.g. __gmon_start__, _ITM_*) arrive with library == null and stay put.
        // "<EXTERNAL>" is Ghidra's catch-all and counts as "unresolved" here.
        boolean hasLibrary = libName != null
                && !libName.isEmpty()
                && !libName.equals("<EXTERNAL>");
        
    
        try {
            if (hasLibrary) {
                // 2. Get-or-create the resolved library namespace.
                Library lib = extMgr.getExternalLibrary(libName);
                if (lib == null) {
                    lib = extMgr.addExternalLibraryName(libName, SourceType.ANALYSIS);
                }
 
                // 3. Move the symbol under the resolved library (re-parent + relabel).
                extLoc.setName(lib, name, SourceType.ANALYSIS);
            }
 
            // 4. Stamp the version as a comment (no native version field exists).
            if (version != null && !version.isEmpty()) {
                Address addr = extLoc.getExternalSpaceAddress();
                program.getListing().setComment(addr, CodeUnit.EOL_COMMENT,
                        "Symbol version: " + version);
            }
 
            // "Applied" means we actually attributed something.
            return hasLibrary || (version != null && !version.isEmpty());
        }
        catch (DuplicateNameException | InvalidInputException e) {
            Msg.error(this, "Failed to apply " + name + " -> " + libName, e);
            return false;
        }
    }
    
    private void bindLibraryPaths(Program program, Set<String> libraryNames, TaskMonitor monitor) {
    	ExternalManager extMgr = program.getExternalManager();
    	DomainFolder folder = program.getDomainFile().getParent();
    	
    	for (String libName : libraryNames) {
    			DomainFile libFile = folder.getFile(libName);
    			if (libFile == null) {
    				Msg.warn(this, "No imported program found for " + libName + "; skipping path bind");
    				continue;
    			}
    			try {
    				extMgr.setExternalPath(libName, libFile.getPathname(), true);
    			} catch (InvalidInputException e) {
    				Msg.warn(this, "Failed to bind path for " + libName + ": "  + e.getMessage());
    			}
    	}
    	
    	
    }
    
    
    
}