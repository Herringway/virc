/++
+
+/
module virc.numerics.monitor;

import std.algorithm : among;

import virc.numerics.definitions;
/++
+
+/
//730 <nick> :target[!user@host][,target[!user@host]]*
auto parseNumeric(Numeric numeric : Numeric.RPL_MONONLINE, T)(T input) {
	import std.algorithm : map, splitter;
	import virc.common : User;
	import virc.usermask : UserMask;
	input.popFront();
	auto split = input.front.splitter(",");
	return split.map!((x) { User user; user.mask = UserMask(x); return user; });
}
///
@safe pure nothrow @nogc unittest { //Numeric.RPL_MONONLINE
	import std.range : only;
	{
		auto logon = parseNumeric!(Numeric.RPL_MONONLINE)(only("test", "someone!someIdent@example.net"));
		assert(logon.front.mask.nickname == "someone");
		assert(logon.front.mask.ident == "someIdent");
		assert(logon.front.mask.host == "example.net");
	}
	{
		auto logon = parseNumeric!(Numeric.RPL_MONONLINE)(only("test", "someone!someIdent@example.net,someone2!someOther@example.com"));
		assert(logon.front.mask.nickname == "someone");
		assert(logon.front.mask.ident == "someIdent");
		assert(logon.front.mask.host == "example.net");
		logon.popFront();
		assert(logon.front.mask.nickname == "someone2");
		assert(logon.front.mask.ident == "someOther");
		assert(logon.front.mask.host == "example.com");
	}
}

/++
+
+/
//731 <nick> :target[,target2]*
//732 <nick> :target[,target2]*
auto parseNumeric(Numeric numeric, T)(T input) if (numeric.among(Numeric.RPL_MONOFFLINE,Numeric.RPL_MONLIST)) {
	import std.algorithm.iteration : map, splitter;
	import virc.common : User;
	input.popFront();
	auto split = input.front.splitter(",");
	return split.map!((x) { User user; user.mask.nickname = x; return user; });
}
///
@safe pure nothrow @nogc unittest { //Numeric.RPL_MONOFFLINE
	import std.range : only;
	{
		auto logoff = parseNumeric!(Numeric.RPL_MONONLINE)(only("test", "someone"));
		assert(logoff.front.mask.nickname == "someone");
		assert(logoff.front.mask.ident.isNull);
		assert(logoff.front.mask.host.isNull);
	}
	{
		auto logoff = parseNumeric!(Numeric.RPL_MONONLINE)(only("test", "someone,someone2"));
		assert(logoff.front.mask.nickname == "someone");
		assert(logoff.front.mask.ident.isNull);
		assert(logoff.front.mask.host.isNull);
		logoff.popFront();
		assert(logoff.front.mask.nickname == "someone2");
		assert(logoff.front.mask.ident.isNull);
		assert(logoff.front.mask.host.isNull);
	}
}

/++
+
+/
//734 <nick> <limit> <targets> :Monitor list is full.
auto parseNumeric(Numeric numeric : Numeric.ERR_MONLISTFULL, T)(T input) {
	import std.conv : to;
	import std.range : front, popFront;
	import std.typecons : Tuple;
	import virc.common : User;
	input.popFront();
	auto limit = input.front.to!ulong;
	input.popFront();
	User user;
	user.mask.nickname = input.front;
	return Tuple!(ulong, "limit", User, "userAdded")(limit, user);
}
///
@safe pure /+nothrow @nogc+/ unittest { //Numeric.ERR_MONLISTFULL
	import std.range : only;
	auto test = parseNumeric!(Numeric.ERR_MONLISTFULL)(only("someone", "5", "someone2", "Monitor list is full."));
	assert(test.limit == 5);
	assert(test.userAdded.nickname == "someone2");
}
