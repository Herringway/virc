///SASL support module
module virc.ircv3.sasl;

/++
+ Interface for SASL authentication mechanisms.
+/
interface SASLMechanism {
	///
	string name() @safe pure @nogc nothrow;
	///
	bool empty() @safe nothrow;
	///
	string front() @safe nothrow;
	///
	void popFront() @safe nothrow;
	///
	void put(string) @safe nothrow;
}

/++
+ EXTERNAL SASL mechanism support. For authentication based on other network
+ layers, such as TLS or IPSec.
+/
class SASLExternal : SASLMechanism {
	private bool popped;
	override string name() @safe pure @nogc nothrow { return "EXTERNAL"; }
	override bool empty() @safe pure @nogc nothrow { return popped; }
	override string front() @safe pure @nogc nothrow { assert(!popped); return ""; }
	override void popFront() @safe pure @nogc nothrow { assert(!popped); popped = true; }
	override void put(string) @safe pure @nogc nothrow {}
}
/++
+ PLAIN SASL mechanism support. For authentication with plaintext username(s)
+ and password combination.
+/
class SASLPlain : SASLMechanism {
	private bool popped;
	override string name() @safe pure @nogc nothrow { return "PLAIN"; }
	override bool empty() @safe pure @nogc nothrow { return popped; }
	override string front() @safe pure @nogc nothrow { assert(!popped); return authStr; }
	override void popFront() @safe pure @nogc nothrow { popped = true; }
	override void put(string) @safe pure @nogc nothrow {}
	private string authStr;
	/++
	+
	+/
	this(const string authorizationIdentity, const string authenticationIdentity, const string password) @safe in {
		import std.algorithm : filter;
		import std.array : empty;
		assert(authenticationIdentity != "");
		assert(authenticationIdentity.filter!(x => x == '\0').empty);
		assert(authorizationIdentity != "");
		assert(authorizationIdentity.filter!(x => x == '\0').empty);
		assert(password.filter!(x => x == '\0').empty);
	} do {
		authStr = authorizationIdentity~"\0"~authenticationIdentity~"\0"~password;
	}
}