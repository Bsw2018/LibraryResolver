package libraryresolver;

import java.io.File;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.List;
import java.util.stream.Stream;

/**
 * Stage 3 of the pipeline: given what the target needs (soname + required
 * versions, derived from the parser's {@link ExternalSymbol} list), find the
 * library file on disk that satisfies it.
 *
 * This class is intentionally free of any Ghidra dependency. It takes a search
 * root (e.g. the directory you extracted the customer's disk image into) and
 * plain data, and returns plain {@link File}s. That is what makes it unit-
 * testable on an ordinary machine: point it at a temp directory of .so files
 * and assert what it picks, with no Ghidra project in the loop.
 *
 * Current scope is STEP 1 of the resolution funnel only:
 *     gather candidate files by soname (arch-aware match on DT_SONAME).
 * Steps 2-4 (arch/endianness filter, version-defined filter, symbol-at-version
 * confirmation, tie-break) are layered on later and consume this output.
 */
public class LibraryResolver {

    /**
     * One candidate library file found during the gather, paired with the ELF
     * facts read from it. Keeping the {@link ElfImageInfo} alongside the file
     * means later steps (arch filter, version match) don't have to re-read it.
     */
    public static final class Candidate {
        public final File         file;
        public final ElfImageInfo info;
        public Candidate(File file, ElfImageInfo info) {
            this.file = file;
            this.info = info;
        }
        @Override public String toString() {
            return file.getPath() + "  [soname=" + info.soname()
                 + ", machine=0x" + Integer.toHexString(info.machine())
                 + ", " + (info.is64Bit() ? "64" : "32") + "-bit"
                 + ", " + (info.bigEndian() ? "BE" : "LE") + "]";
        }
    }

    /**
     * STEP 1: walk {@code searchRoot} recursively and return every ELF file
     * whose DT_SONAME equals {@code wantedSoname}.
     *
     * Matching is on the file's *recorded* soname (DT_SONAME), not its filename.
     * That is deliberate: in an extracted image a file named "libversioned.so.1"
     * can carry a different real soname (renamed/vendored libraries), and a
     * filename-only match would wrongly grab it. We also fall back to a filename
     * match ONLY for files that record no soname at all, since some libraries
     * are built without -soname yet are still the right target.
     *
     * Non-ELF files and unreadable files are silently skipped (they return null
     * from {@link ElfImageInfo#read}), which is the correct behavior for a tree
     * that contains READMEs, configs, data blobs, etc.
     *
     * @param wantedSoname e.g. "libc.so.6" -- the namespace name your tool created
     * @param searchRoot   directory to walk (the extracted image root)
     * @return all matching candidates; empty list if none found
     */
    public List<Candidate> gatherBySoname(String wantedSoname, File searchRoot) {
        List<Candidate> matches = new ArrayList<>();
        if (wantedSoname == null || searchRoot == null || !searchRoot.isDirectory()) {
            return matches;
        }

        Path root = searchRoot.toPath();
        try (Stream<Path> walk = Files.walk(root)) {
            walk.filter(Files::isRegularFile).forEach(p -> {
                File file = p.toFile();
                ElfImageInfo info = ElfImageInfo.read(file.getPath());
                if (info == null) {
                    return; // not an ELF / unreadable -> skip
                }
                if (sonameMatches(wantedSoname, info, file)) {
                    matches.add(new Candidate(file, info));
                }
            });
        } catch (IOException e) {
            // A walk failure (e.g. a directory we can't traverse) is non-fatal:
            // return whatever we gathered so far rather than aborting the resolve.
        }
        return matches;
    }

    /**
     * A candidate matches if its recorded DT_SONAME equals the wanted soname.
     * If the file records no soname, fall back to comparing the wanted soname
     * against the filename (handles libraries built without -soname).
     */
    private boolean sonameMatches(String wanted, ElfImageInfo info, File file) {
        String recorded = info.soname();
        if (recorded != null && !recorded.isEmpty()) {
            return recorded.equals(wanted);
        }
        // No DT_SONAME -> filename fallback only.
        return file.getName().equals(wanted);
    }


    public List<Candidate> filterByArch(List<Candidate> candidates, ElfImageInfo target) {
    	List<Candidate> kept = new ArrayList<>();
    	for (Candidate c : candidates) {
    		if (c.info.machine()   == target.machine()
    				&& c.info.is64Bit()   == target.is64Bit()
    				&& c.info.bigEndian() == target.bigEndian()) {
    			kept.add(c);
    		}
    	}
    	return kept;
    }

    public Candidate pickOne(List<Candidate> candidates) {
        if (candidates == null || candidates.isEmpty()) {
            return null;
        }
        // Collapse symlink-equals-realfile duplicates: canonical path is the identity.
        java.util.LinkedHashMap<String, Candidate> byRealPath = new java.util.LinkedHashMap<>();
        for (Candidate c : candidates) {
            String key;
            try {
                key = c.file.getCanonicalPath();   // follows symlinks to the real file
            } catch (java.io.IOException e) {
                key = c.file.getAbsolutePath();    // fall back; treat as its own identity
            }
            byRealPath.putIfAbsent(key, c);        // first one wins for a given real file
        }
        java.util.List<Candidate> distinct = new java.util.ArrayList<>(byRealPath.values());
        if (distinct.size() == 1) {
            return distinct.get(0);
        }
        // Still more than one genuinely different file: deterministic tiebreak.
        // Prefer the shortest path (usually the canonical install location),
        // then alphabetical so the result is stable across runs.
        distinct.sort((a, b) -> {
            int byLen = Integer.compare(a.file.getPath().length(), b.file.getPath().length());
            return byLen != 0 ? byLen : a.file.getPath().compareTo(b.file.getPath());
        });
        return distinct.get(0);
    }
    
    
    
    
}


