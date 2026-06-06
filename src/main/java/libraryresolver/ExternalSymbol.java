package libraryresolver;

public class ExternalSymbol {
	public final String name;		// e.g. "printf"
	public final String library;	// e.g. "libc.so.6"
	public final String version;	// e.g. "GLIBC_2.17" (may be null)
	public final int versionIndex;	// raw GNU version index (may be -1)
	
	
	public ExternalSymbol(String name, String library, String version, int versionIndex) {
		this.name = name;
		this.library = library;
		this.version = version;
		this.versionIndex = versionIndex;
		
	}
	
	@Override
	public String toString() {
		return String.format("%s@%s [%s]", name, version != null ? version : "?", library);
	}
	
	
	
}