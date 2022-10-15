//Google the current selection
//@author @larsborn
//@category malRE
//@keybinding F2
//@menupath 
//@toolbar 

import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStreamReader;
import java.net.HttpURLConnection;
import java.net.URL;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

import ghidra.app.script.GhidraScript;
import ghidra.program.model.address.Address;
import ghidra.program.model.data.Pointer;
import ghidra.program.model.listing.Data;
import ghidra.program.model.symbol.ExternalReference;
import ghidra.program.model.symbol.RefType;
import ghidra.program.model.symbol.Reference;

public class GoogleSelection extends GhidraScript {
	private static final Pattern p = Pattern.compile("^(\\w+)_[a-f0-9]{8}$");

	private static final String[] urls = new String[] {"docs.microsoft.com", "learn.microsoft.com"};
	
	public void run() throws Exception {
		String query = getReferenceName(currentAddress);
		Matcher m = p.matcher(query);
        if(m.find()) {
        	query = m.group(1);
        }
		println(query);
		String content = google(query);
		println(String.format("%d", content.indexOf("/url")));
		for (String url : urls) {
			int start = content.indexOf(String.format("/url?q=https://%s/", url));
			if (start != -1) {
				int end = content.indexOf("&", start + 1);
				openDefaultBrowser(content.substring(start + 7, end));			
				return;
			}
		}
		println(String.format("No results found for: %s", query));
	}

	private String google(String query) throws Exception {
		URL url = new URL(String.format("https://www.google.com/search?q=%s", query));
		HttpURLConnection con = (HttpURLConnection) url.openConnection();
		con.setRequestMethod("GET");
		con.setRequestProperty("User-Agent", "Ghidra Google Search (by mal.re)");
		con.setConnectTimeout(1000);
		con.setReadTimeout(1000);

		BufferedReader in = new BufferedReader(
				new InputStreamReader(con.getResponseCode() > 299 ? con.getErrorStream() : con.getInputStream()));
		String line;
		StringBuffer ret = new StringBuffer();
		while ((line = in.readLine()) != null) {
			ret.append(line);
		}
		in.close();

		return ret.toString();
	}

	private String getReferenceName(Address address) {
		return getReferenceName(address, 0);
	}

	private String getReferenceName(Address address, int recursionDepth) {
		Data d = getDataAfter(address);
		if (d.getDataType() instanceof Pointer) {
			for (Reference reference : getReferencesFrom(address)) {
				if (reference.isExternalReference()) {
					return ((ExternalReference) reference).getLabel();
				}
				if (reference.getReferenceType() == RefType.UNCONDITIONAL_CALL) {
					return getFunctionAt(reference.getToAddress()).getName();
				}
				if (reference.getReferenceType() == RefType.INDIRECTION) {
					return getReferenceName(reference.getToAddress(), recursionDepth + 1);
				}
				if (reference.getReferenceType() == RefType.DATA || reference.getReferenceType() == RefType.READ) {
					try {
						return cleanSymbolNameAt(reference.getToAddress());
					} catch (NullPointerException e) {
						return "TODO2";
					}
				}
				// println(reference.getReferenceType().toString());
			}
		}
		// println(d.getDataType().toString());
		return d.getValue().toString();
	}

	private String cleanSymbolNameAt(Address address) {
		return getSymbolAt(address).getName().replaceAll("^PTR_", "").replaceAll("^s_", "");
	}

	private void openDefaultBrowser(String url) throws IOException {
		// https://stackoverflow.com/questions/5226212/how-to-open-the-default-webbrowser-using-java
		String os = System.getProperty("os.name").toLowerCase();
		Runtime rt = Runtime.getRuntime();
		if (os.indexOf("win") >= 0) {
			rt.exec("rundll32 url.dll,FileProtocolHandler " + url);
		} else if (os.indexOf("mac") >= 0) {
			rt.exec("open " + url);
		} else if (os.indexOf("nix") >= 0 || os.indexOf("nux") >= 0) {
			String[] browsers = { "google-chrome", "firefox", "mozilla", "epiphany", "konqueror", "netscape", "opera",
					"links", "lynx" };
			StringBuffer cmd = new StringBuffer();
			boolean firstRun = true;
			for (String browser : browsers) {
				if (firstRun) {
					firstRun = false;
					cmd.append(String.format("%s \"%s\"", browser, url));
				} else {
					cmd.append(String.format(" || %s \"%s\"", browser, url));
				}
			}

			rt.exec(new String[] { "sh", "-c", cmd.toString() });
		}
	}
}
