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
import ghidra.program.model.listing.Program;
import ghidra.util.exception.CancelledException;
import ghidra.util.task.TaskMonitor;

import java.util.List;


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
		
		// TODO: your logic goes here
		
		String format = program.getExecutableFormat(); // This returns a string containing the type of executable
		
		if (format.contains("ELF")) {
			ElfExternalParser parser = new ElfExternalParser(program, log);
			List<ExternalSymbol> symbols = parser.parse(monitor); 
			
			// For now, just log everything we found
			for (ExternalSymbol sym : symbols) {
				log.appendMsg("LibraryResolver", "Found: " + sym.toString());
			}
			
			LibraryResultApplicator applicator = new LibraryResultApplicator(program);
			int applied = applicator.apply(symbols, monitor);
			log.appendMsg("LibraryResolver",
				    "Applied " + applied + " of " + symbols.size() + " symbols");
			
		}
		
		// PE support comes later
		
		
		return true; // return false if nothing was applied
	}
}
