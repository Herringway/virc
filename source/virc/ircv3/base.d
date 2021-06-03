/++
+ Module for IRCv3 core features.
+/
module virc.ircv3.base;

/++
+
+/
enum IRCV3Commands {
	cap = "CAP",
	metadata = "METADATA",
	authenticate = "AUTHENTICATE",
	account = "ACCOUNT",
	starttls = "STARTTLS",
	monitor = "MONITOR",
	batch = "BATCH",
	chghost = "CHGHOST"
}

/++
+
+/
enum CapabilityServerSubcommands {
	ls = "LS",
	acknowledge = "ACK",
	notAcknowledge = "NAK",
	list = "LIST",
	new_ = "NEW",
	delete_ = "DEL"
}

/++
+
+/
enum CapabilityClientSubcommands {
	ls = "LS",
	list = "LIST",
	request = "REQ",
	end = "END"
}

/++
+
+/
struct Capability {
	///
	string name;
	///DEPRECATED - indicates that the capability cannot be disabled
	bool isSticky;
	///Indicates that the capability is being disabled
	bool isDisabled;
	///DEPRECATED - indicates that the client must acknowledge this cap via CAP ACK
	bool mustAck;
	///
	string value;

	alias name this;

	@disable this();

	///
	this(string str) @safe pure @nogc in {
		import std.range : empty;
		assert(!str.empty);
	} do {
		import std.algorithm.comparison : among;
		import std.algorithm.searching : findSplit;
		import std.range : front, popFront;
		import std.utf : byCodeUnit;
		auto prefix = str.byCodeUnit.front;
		setFlagsByPrefix(prefix);
		if (prefix.among('~', '=', '-')) {
			str.popFront();
		}
		auto split = str.findSplit("=");
		this(split[0], split[2]);
	}
	///
	this(string key, string val) @safe pure @nogc nothrow {
		name = key;
		value = val;
	}
	/++
	+ Indicates whether or not this is a vendor-specific capability.
	+
	+ Often these are draft implementations of not-yet-accepted capabilities.
	+/
	bool isVendorSpecific() @safe pure @nogc nothrow {
		import std.algorithm.searching : canFind;
		import std.utf : byCodeUnit;
		return name.byCodeUnit.canFind('/');
	}
	///
	string toString() const pure @safe {
		import std.range : empty;
		return name~(value.empty ? "" : "=")~value;
	}
	private void setFlagsByPrefix(char chr) @safe pure @nogc nothrow {
		switch (chr) {
			case '~':
				mustAck = true;
				break;
			case '=':
				isSticky = true;
				break;
			case '-':
				isDisabled = true;
				break;
			default:
				break;
		}
	}
}
///
@safe pure @nogc unittest {
	{
		auto cap = Capability("~account-notify");
		assert(cap.name == "account-notify");
		assert(cap.mustAck);
	}
	{
		auto cap = Capability("=account-notify");
		assert(cap.name == "account-notify");
		assert(cap.isSticky);
	}
	{
		auto cap = Capability("-account-notify");
		assert(cap.name == "account-notify");
		assert(cap.isDisabled);
	}
	{
		auto cap = Capability("example.com/cap");
		assert(cap.name == "example.com/cap");
		assert(cap.isVendorSpecific);
	}
	{
		auto cap = Capability("cap=value");
		assert(cap.name == "cap");
		assert(cap.value == "value");
	}
	{
		auto cap = Capability("cap=value/notvendor");
		assert(cap.name == "cap");
		assert(cap.value == "value/notvendor");
		assert(!cap.isVendorSpecific);
	}
}
@system pure unittest {
	import core.exception : AssertError;
	import std.exception : assertThrown;
	{
		assertThrown!AssertError(Capability(""));
	}
}
