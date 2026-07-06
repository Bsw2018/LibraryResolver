/* ###
 * IP: GHIDRA
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package libraryresolver;

import ghidra.app.services.AbstractAnalyzer;
import ghidra.app.services.AnalysisPriority;
import ghidra.app.services.AnalyzerType;
import ghidra.app.util.importer.MessageLog;
import ghidra.framework.options.Options;
import ghidra.program.model.address.AddressSetView;
import ghidra.program.model.lang.Language;
import ghidra.program.model.listing.Program;
import ghidra.util.exception.CancelledException;
import ghidra.util.task.TaskMonitor;

import java.util.List;
import java.util.Set;
import java.util.HashSet;


/**
 * Provide class-level documentation that describes what this analyzer does.
 */
public class LibraryResolverAnalyzer extends AbstractAnalyzer {

	public LibraryResolverAnalyzer() {

		// Name the analyzer and give it a description.

		super("Library Resolver",										// display name
			  "Resolves and annotates external library references",		// description
			  AnalyzerType.BYTE_ANALYZER);								// runs early in pipeline
		setPriority(AnalysisPriority.FORMAT_ANALYSIS.after());			// after ELF parsing
		setDefaultEnablement(true);
	}

	@Override
	public boolean getDefaultEnablement(Program program) {

		// Return true if analyzer should be enabled by default

		return true;
	}

	@Override
	public boolean canAnalyze(Program program) {

		// Examine 'program' to determine of this analyzer should analyze it.  Return true
		// if it can.
		String format = program.getExecutableFormat();
		return format.contains("ELF"); // || format.contains("PE");
	}

	@Override
	public void registerOptions(Options options, Program program) {

		// If this analyzer has custom options, register them here

		options.registerOption("Option name goes here", false, null,
			"Option description goes here");
	}

	@Override
	public boolean added(Program program, AddressSetView set, TaskMonitor monitor, MessageLog log)
			throws CancelledException {

		// Perform analysis when things get added to the 'program'.  Return true if the
		// analysis succeeded.
		log.appendMsg("LibraryResolver", "Starting analysis on: " + program.getName());
		
		String format = program.getExecutableFormat(); // This returns a string containing the type of executable
		
		if (format.contains("ELF")) {
			ElfExternalParser parser = new ElfExternalParser(program, log);
			List<ExternalSymbol> symbols = parser.parse(monitor); 
			
			// For now, just log everything we found
			for (ExternalSymbol sym : symbols) {
				log.appendMsg("LibraryResolver", "Found: " + sym.toString());
			}
			
			Set<String> sonames = new HashSet<>();
			for (ExternalSymbol sym : symbols) {
				if (sym.library != null
						&& !sym.library.isEmpty()
						&& !sym.library.equals("<EXTERNAL")) {
					sonames.add(sym.library);
				}
			}
			
			// For now, point at a fixed directory so we can watch it work.
			// TODO: make this an analyzer option (the extracted image root).
			java.io.File searchRoot = new java.io.File("/usr/lib/x86_64-linux-gnu");
			
			// Build the target arch spec ONCE, before the soname loop. Ghidra's
			// Language gives us endianness + size but NOT the raw ELF e_machine,
			// which filterByArch compares on. So read the target's own file with
			// the same reader we use on candidates: we get the real machine number
			// for free and reuse code that's already proven, with no Ghidra deps.
			ElfImageInfo target = ElfImageInfo.read(program.getExecutablePath());
			if (target == null) {
				log.appendMsg("LibraryResolver",
						"Could not read target ELF for arch filter; arch filter skipped");
			}
			
			LibraryResolver resolver = new LibraryResolver();
			
			java.util.Map<String, java.io.File> resolved = new java.util.HashMap<>();
			
			for (String soname : sonames) {
				List<LibraryResolver.Candidate> candidates =
						resolver.gatherBySoname(soname, searchRoot);
				
				// Arch/endianness filter: hard-disqualify candidates that can't
				// possibly link against this target. Skipped only if we couldn't
				// read the target's own ELF facts above.
				if (target != null) {
					candidates = resolver.filterByArch(candidates, target);
				}
				LibraryResolver.Candidate winner = resolver.pickOne(candidates);
				if (winner != null) {
			        resolved.put(soname, winner.file);
			        log.appendMsg("LibraryResolver", soname + " -> resolved to " + winner.file.getPath());
			    } else {
			        log.appendMsg("LibraryResolver", soname + " -> no candidate");
			    }
				
				
			}
			
			java.util.Map<String, String> projectPaths =
                    importResolvedLibraries(resolved, log, monitor);
			
			LibraryResultApplicator applicator = new LibraryResultApplicator(program);
            int applied = applicator.apply(symbols, projectPaths, monitor);
			log.appendMsg("LibraryResolver",
				    "Applied " + applied + " of " + symbols.size() + " symbols");
			
		}
		
		// PE support comes later
		
		
		return true; // return false if nothing was applied
	}
	
	private java.util.Map<String, String> importResolvedLibraries(
	        java.util.Map<String, java.io.File> resolved,
	        MessageLog log, TaskMonitor monitor) {

	    java.util.Map<String, String> projectPaths = new java.util.HashMap<>();

	    // VERIFY: AppInfo.getActiveProject() is the usual way to reach the Project
	    // from inside an analyzer. Confirm the import resolves on 12.1.
	    ghidra.framework.model.Project project = ghidra.framework.main.AppInfo.getActiveProject();
	    if (project == null) {
	        log.appendMsg("LibraryResolver", "No active project; cannot import libraries");
	        return projectPaths;
	    }

	    final String folderPath = "/resolved_libs";
	    ghidra.framework.model.DomainFolder root = project.getProjectData().getRootFolder();
	    ghidra.framework.model.DomainFolder libFolder = root.getFolder("resolved_libs");
	    if (libFolder == null) {
	        try {
	            libFolder = root.createFolder("resolved_libs");
	        } catch (Exception e) {
	            log.appendMsg("LibraryResolver", "Could not create resolved_libs: " + e.getMessage());
	            return projectPaths;
	        }
	    }

	    for (java.util.Map.Entry<String, java.io.File> e : resolved.entrySet()) {
	        String soname = e.getKey();
	        java.io.File file = e.getValue();
	        String programName = file.getName();              // e.g. "libc-2.31.so"
	        String projectPath = folderPath + "/" + programName;

	        // Skip-if-exists: don't re-import on a re-run.
	        if (libFolder.getFile(programName) != null) {
	            log.appendMsg("LibraryResolver", soname + " already imported; skipping");
	            projectPaths.put(soname, projectPath);
	            continue;
	        }

	        try {
	            // VERIFY: 12.1 signature is importByUsingBestGuess(File, Project,
	            // String projectFolderPath, Object consumer, MessageLog, TaskMonitor)
	            // returning LoadResults<Program>. It is DEPRECATED (use ProgramLoader)
	            // but still functional. Confirm the return type and package.
	            ghidra.app.util.opinion.LoadResults<Program> results =
	                ghidra.app.util.importer.AutoImporter.importByUsingBestGuess(
	                    file, project, folderPath, this, log, monitor);

	            results.save(monitor);   // REQUIRED: import alone does not persist to project
	            results.close();         // REQUIRED: release the loaded programs

	            projectPaths.put(soname, projectPath);
	            log.appendMsg("LibraryResolver", "Imported " + soname + " -> " + projectPath);
	        } catch (Exception ex) {
	            log.appendMsg("LibraryResolver", "Import failed for " + soname + ": " + ex);
	        }
	    }
	    return projectPaths;
	}
	
	
	
	
}
