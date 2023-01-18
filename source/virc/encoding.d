/++
+ Module for handling low-level message encoding.
+/
module virc.encoding;

import std.encoding;
import std.string;

/++
+ Decodes a byte array to a UTF-8 string. Old IRC clients don't use UTF-8,
+ but it is a simple matter to detect and convert those strings. Lines truncated
+ mid-codepoint by the protocol's line length will be treated as invalid UTF-8.
+/

auto toUTF8String(Encoding = Latin1String)(const immutable(ubyte)[] raw) {
	auto utf = cast(string)raw;
	static if (!is(Encoding == string)) {
		if (!utf.isValid()) {
			char[] fallback;
			transcode(cast(Encoding)raw, fallback);
			return fallback.idup;
		}
	}
	return utf;
}
//@system due to transcode()
///
@system pure unittest {
	import std.string : representation;
	//Basic case
	assert("test".representation.toUTF8String == "test");
	//ISO-8859-1
	assert([cast(ubyte)0xA9].toUTF8String == "©");
	//Truncated utf-8 will be treated as fallback encoding
	assert("©".representation[0..1].toUTF8String == "Â");
}
