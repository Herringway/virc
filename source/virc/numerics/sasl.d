/++
+
+/
module virc.numerics.sasl;

import std.algorithm : among;

import virc.numerics.definitions;

/++
+
+ Format is `900 <nick> <nick>!<ident>@<host> <account> :You are now logged in as <user>`
+/
//900 <nick> <nick>!<ident>@<host> <account> :You are now logged in as <user>
auto parseNumeric(Numeric numeric : Numeric.RPL_LOGGEDIN, T)(T input) {
	import std.typecons : Nullable;
	import virc.common : User;
	import virc.usermask : UserMask;
	Nullable!User user;
	if (input.empty) {
		return user;
	}
	input.popFront();
	if (input.empty) {
		return user.init;
	}
	user = User(input.front);
	input.popFront();
	if (input.empty) {
		return user.init;
	}
	user.get.account = input.front;
	return user;
}
///
@safe pure nothrow @nogc unittest { //Numeric.RPL_LOGGEDIN
	import std.range : only, takeNone;
	{
		immutable logon = parseNumeric!(Numeric.RPL_LOGGEDIN)(only("test", "someone!someIdent@example.net", "some_account", "Well hello there"));
		assert(logon.get.mask.nickname == "someone");
		assert(logon.get.mask.ident == "someIdent");
		assert(logon.get.mask.host == "example.net");
		assert(logon.get.account == "some_account");
	}
	{
		immutable logon = parseNumeric!(Numeric.RPL_LOGGEDIN)(takeNone(only("")));
		assert(logon.isNull);
	}
	{
		immutable logon = parseNumeric!(Numeric.RPL_LOGGEDIN)(only("test"));
		assert(logon.isNull);
	}
	{
		immutable logon = parseNumeric!(Numeric.RPL_LOGGEDIN)(only("test", "someone!someIdent@example.net"));
		assert(logon.isNull);
	}
}
/++
+
+ Format is `901 <nick> <nick>!<ident>@<host> :You are now logged out`
+/
auto parseNumeric(Numeric numeric : Numeric.RPL_LOGGEDOUT, T)(T input) {
	import std.typecons : Nullable;
	import virc.common : User;
	import virc.usermask : UserMask;
	Nullable!User user;
	if (input.empty) {
		return user;
	}
	input.popFront();
	if (input.empty) {
		return user.init;
	}
	user = User(input.front);
	return user;
}
///
@safe pure nothrow @nogc unittest { //Numeric.RPL_LOGGEDOUT
	import std.range : only, takeNone;
	{
		immutable logon = parseNumeric!(Numeric.RPL_LOGGEDOUT)(only("test", "someone!someIdent@example.net", "Well hello there"));
		assert(logon.get.mask.nickname == "someone");
		assert(logon.get.mask.ident == "someIdent");
		assert(logon.get.mask.host == "example.net");
		assert(logon.get.account.isNull);
	}
	{
		immutable logon = parseNumeric!(Numeric.RPL_LOGGEDOUT)(takeNone(only("")));
		assert(logon.isNull);
	}
	{
		immutable logon = parseNumeric!(Numeric.RPL_LOGGEDOUT)(only("test"));
		assert(logon.isNull);
	}
}
/++
+ SASL numerics that don't have any parsable information.
+
+ This includes 902, 903, 904, 905, 906 and 907.
+/
void parseNumeric(Numeric numeric, T)(T) if (numeric.among(Numeric.ERR_NICKLOCKED, Numeric.RPL_SASLSUCCESS, Numeric.ERR_SASLFAIL, Numeric.ERR_SASLTOOLONG, Numeric.ERR_SASLABORTED, Numeric.ERR_SASLALREADY)) {
}
///
@safe pure nothrow @nogc unittest { //Numeric.RPL_LOGGEDOUT
	import std.range : only;
	{
		parseNumeric!(Numeric.ERR_NICKLOCKED)(only("test", "You must use a nick assigned to you"));
	}
	{
		parseNumeric!(Numeric.RPL_SASLSUCCESS)(only("test", "SASL authentication successful"));
	}
	{
		parseNumeric!(Numeric.ERR_SASLFAIL)(only("test", "SASL authentication failed"));
	}
	{
		parseNumeric!(Numeric.ERR_SASLTOOLONG)(only("test", "SASL message too long"));
	}
	{
		parseNumeric!(Numeric.ERR_SASLABORTED)(only("test", "SASL authentication aborted"));
	}
	{
		parseNumeric!(Numeric.ERR_SASLALREADY)(only("test", "You have already authenticated using SASL"));
	}
}

/++
+ RPL_SASLMECHS. This is sent in response to a request for a mechanism the
+ server does not support, and will list any mechanisms that are available.
+
+ Format is `908 <nick> <mechanisms> :are available SASL mechanisms`
+/
auto parseNumeric(Numeric numeric : Numeric.RPL_SASLMECHS, T)(T input) {
	import std.algorithm : splitter;
	import std.typecons : nullable;
	if (!input.empty) {
		input.popFront();
	}
	if (!input.empty) {
		return nullable(input.front.splitter(","));
	} else {
		return typeof(return).init;
	}
}
///
@safe pure nothrow @nogc unittest { //Numeric.RPL_SASLMECHS
	import std.algorithm.searching : canFind;
	import std.range : only, takeNone;
	{
		auto logon = parseNumeric!(Numeric.RPL_SASLMECHS)(only("test", "EXTERNAL,PLAIN", "Well hello there"));
		assert(logon.get.canFind("EXTERNAL"));
		assert(logon.get.canFind("PLAIN"));
	}
	{
		immutable logon = parseNumeric!(Numeric.RPL_SASLMECHS)(takeNone(only("")));
		assert(logon.isNull);
	}
	{
		immutable logon = parseNumeric!(Numeric.RPL_SASLMECHS)(only("test"));
		assert(logon.isNull);
	}
}