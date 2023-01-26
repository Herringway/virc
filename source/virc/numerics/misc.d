/++
+
+/
module virc.numerics.misc;

import virc.numerics.definitions;

import std.typecons : Nullable;
/++
+
+/
auto parseNumeric(Numeric numeric)() if (numeric.among(noInformationNumerics)) {
	static assert(0, "Cannot parse "~numeric~": No information to parse.");
}
/++
+
+/
struct TopicWhoTime {
	import std.datetime : SysTime;
	import virc.common : User;
	User me;
	///Channel that the topic was set on.
	string channel;
	///The nickname or full mask of the user who set the topic.
	User setter;
	///The time the topic was set. Will always be UTC.
	SysTime timestamp;
}
/++
+ Parse RPL_TOPICWHOTIME (aka RPL_TOPICTIME) numeric replies.
+
+ Format is `333 <user> <channel> <setter> <timestamp>`
+/
auto parseNumeric(Numeric numeric : Numeric.RPL_TOPICWHOTIME, T)(T input) {
	import virc.numerics.magicparser : autoParse;
	return autoParse!TopicWhoTime(input);
}
///
@safe pure nothrow unittest {
	import std.datetime : DateTime, SysTime, UTC;
	import std.range : only, takeNone;
	{
		immutable result = parseNumeric!(Numeric.RPL_TOPICWHOTIME)(only("Someone", "#test", "Another!id@hostmask", "1496101944"));
		assert(result.get.channel == "#test");
		assert(result.get.setter.nickname == "Another");
		assert(result.get.setter.ident == "id");
		assert(result.get.setter.host == "hostmask");
		static immutable time = SysTime(DateTime(2017, 05, 29, 23, 52, 24), UTC());
		assert(result.get.timestamp == time);
	}
	{
		immutable badResult = parseNumeric!(Numeric.RPL_TOPICWHOTIME)(takeNone(only("")));
		assert(badResult.isNull);
	}
	{
		immutable badResult = parseNumeric!(Numeric.RPL_TOPICWHOTIME)(only("Someone"));
		assert(badResult.isNull);
	}
	{
		immutable badResult = parseNumeric!(Numeric.RPL_TOPICWHOTIME)(only("Someone", "#test"));
		assert(badResult.isNull);
	}
	{
		immutable badResult = parseNumeric!(Numeric.RPL_TOPICWHOTIME)(only("Someone", "#test", "Another!id@hostmask"));
		assert(badResult.isNull);
	}
	{
		immutable badResult = parseNumeric!(Numeric.RPL_TOPICWHOTIME)(only("Someone", "#test", "Another!id@hostmask", "invalidTimestamp"));
		assert(badResult.isNull);
	}
}

struct NoPrivsError {
	import virc.common : User;
	User me;
	///The missing privilege that prompted this error reply.
	string priv;
	///Human-readable error message.
	string message;
}
/++
+ Parse ERR_NOPRIVS numeric replies.
+
+ Format is `723 <user> <priv> :Insufficient oper privileges.`
+/
auto parseNumeric(Numeric numeric : Numeric.ERR_NOPRIVS, T)(T input) {
	import virc.numerics.magicparser : autoParse;
	return autoParse!NoPrivsError(input);
}
///
@safe pure nothrow unittest {
	import std.range : only, takeNone;
	{
		immutable result = parseNumeric!(Numeric.ERR_NOPRIVS)(only("Someone", "rehash", "Insufficient oper privileges."));
		assert(result.get.priv == "rehash");
		assert(result.get.message == "Insufficient oper privileges.");
	}
	{
		immutable badResult = parseNumeric!(Numeric.ERR_NOPRIVS)(takeNone(only("")));
		assert(badResult.isNull);
	}
	{
		immutable badResult = parseNumeric!(Numeric.ERR_NOPRIVS)(only("Someone"));
		assert(badResult.isNull);
	}
}
/++
+ Parser for RPL_WHOISSECURE
+
+ Format is `671 <client> <nick> :is using a secure connection`
+/
auto parseNumeric(Numeric numeric : Numeric.RPL_WHOISSECURE, T)(T input) {
	import virc.numerics.magicparser : autoParse;
	import virc.numerics.rfc1459 : InfolessWhoisReply;
	return autoParse!InfolessWhoisReply(input);
}
///
@safe pure nothrow unittest {
	import virc.common : User;
	import std.range : only, takeNone;
	{
		auto reply = parseNumeric!(Numeric.RPL_WHOISSECURE)(only("someone", "whoisuser", "is using a secure connection"));
		assert(reply.get.user == User("whoisuser"));
	}
	{
		immutable reply = parseNumeric!(Numeric.RPL_WHOISSECURE)(only("someone", "whoisuser"));
		assert(reply.isNull);
	}
	{
		immutable reply = parseNumeric!(Numeric.RPL_WHOISSECURE)(only("someone"));
		assert(reply.isNull);
	}
	{
		immutable reply = parseNumeric!(Numeric.RPL_WHOISSECURE)(takeNone(only("")));
		assert(reply.isNull);
	}
}
/++
+ Parser for RPL_WHOISREGNICK
+
+ Format is `307 <client> <nick> :is a registered nick`
+/
auto parseNumeric(Numeric numeric : Numeric.RPL_WHOISREGNICK, T)(T input) {
	import virc.numerics.magicparser : autoParse;
	import virc.numerics.rfc1459 : InfolessWhoisReply;
	return autoParse!InfolessWhoisReply(input);
}
///
@safe pure nothrow unittest {
	import virc.common : User;
	import std.range : only, takeNone;
	{
		auto reply = parseNumeric!(Numeric.RPL_WHOISREGNICK)(only("someone", "whoisuser", "is a registered nick"));
		assert(reply.get.user == User("whoisuser"));
	}
	{
		immutable reply = parseNumeric!(Numeric.RPL_WHOISREGNICK)(only("someone", "whoisuser"));
		assert(reply.isNull);
	}
	{
		immutable reply = parseNumeric!(Numeric.RPL_WHOISREGNICK)(only("someone"));
		assert(reply.isNull);
	}
	{
		immutable reply = parseNumeric!(Numeric.RPL_WHOISREGNICK)(takeNone(only("")));
		assert(reply.isNull);
	}
}
struct WhoisAccountReply {
	import virc.common : User;
	User me;
	///User who is being queried.
	User user;
	///Account name for this user.
	string account;
	///Human-readable numeric message.
	string message;
}
/++
+ Parser for RPL_WHOISACCOUNT
+
+ Format is `330 <client> <nick> <account> :is logged in as`
+/
auto parseNumeric(Numeric numeric : Numeric.RPL_WHOISACCOUNT, T)(T input) {
	import virc.numerics.magicparser : autoParse;
	return autoParse!WhoisAccountReply(input);
}
///
@safe pure nothrow unittest {
	import virc.common : User;
	import std.range : only, takeNone;
	{
		auto reply = parseNumeric!(Numeric.RPL_WHOISACCOUNT)(only("someone", "whoisuser", "accountname", "is logged in as"));
		assert(reply.get.user == User("whoisuser"));
		assert(reply.get.account == "accountname");
	}
	{
		immutable reply = parseNumeric!(Numeric.RPL_WHOISACCOUNT)(only("someone", "whoisuser", "accountname"));
		assert(reply.isNull);
	}
	{
		immutable reply = parseNumeric!(Numeric.RPL_WHOISACCOUNT)(only("someone", "whoisuser"));
		assert(reply.isNull);
	}
	{
		immutable reply = parseNumeric!(Numeric.RPL_WHOISACCOUNT)(only("someone"));
		assert(reply.isNull);
	}
	{
		immutable reply = parseNumeric!(Numeric.RPL_WHOISACCOUNT)(takeNone(only("")));
		assert(reply.isNull);
	}
}
struct WHOXReply {
	Nullable!string token;
	Nullable!string channel;
	Nullable!string ident;
	Nullable!string ip;
	Nullable!string host;
	Nullable!string server;
	Nullable!string nick;
	Nullable!string flags;
	Nullable!string hopcount;
	Nullable!string idle;
	Nullable!string account;
	Nullable!string oplevel;
	Nullable!string realname;
}
/++
+ Parser for RPL_WHOSPCRPL
+
+ Format is `354 <client> [token] [channel] [user] [ip] [host] [server] [nick] [flags] [hopcount] [idle] [account] [oplevel] [:realname]`
+/
auto parseNumeric(Numeric numeric : Numeric.RPL_WHOSPCRPL, T)(T input, string flags) {
	WHOXReply reply;
	enum map = [
		't': 0,
		'c': 1,
		'u': 2,
		'i': 3,
		'h': 4,
		's': 5,
		'n': 6,
		'f': 7,
		'd': 8,
		'l': 9,
		'a': 10,
		'o': 11,
		'r': 12,
	];
	if (input.empty) {
		return Nullable!WHOXReply.init;
	}
	input.popFront();
	bool[13] expectedFields;
	foreach (flag; flags) {
		expectedFields[map.get(flag, throw new Exception("Flag not supported"))] = true;
	}
	size_t currentField;
	static foreach (idx; 0 .. WHOXReply.tupleof.length) {
		if (expectedFields[idx]) {
			if (input.empty) {
				return Nullable!WHOXReply.init;
			}
			static if (idx == map['a']) {
				if (input.front != "0") {
					reply.tupleof[idx] = input.front;
				}
			} else static if (idx == map['c']) {
				if (input.front != "*") {
					reply.tupleof[idx] = input.front;
				}
			} else static if (idx == map['i']) {
				if (input.front != "255.255.255.255") {
					reply.tupleof[idx] = input.front;
				}
			} else {
				reply.tupleof[idx] = input.front;
			}
			input.popFront();
		}
	}
	return Nullable!WHOXReply(reply);
}
///
@safe pure unittest {
	import virc.common : User;
	import std.range : only, takeNone;
	{
		immutable reply = parseNumeric!(Numeric.RPL_WHOSPCRPL)(only("mynick", "#ircv3", "~cooluser", "coolhost", "cooluser", "coolaccount", "Cool User"), "cuhnar");
		assert(reply.get.channel.get == "#ircv3");
		assert(reply.get.ident.get == "~cooluser");
		assert(reply.get.host.get == "coolhost");
		assert(reply.get.nick.get == "cooluser");
		assert(reply.get.account.get == "coolaccount");
		assert(reply.get.realname.get == "Cool User");
	}
	{
		immutable reply = parseNumeric!(Numeric.RPL_WHOSPCRPL)(only("mynick", "#ircv3", "~cooluser", "coolhost", "cooluser", "0", "Cool User"), "cuhnar");
		assert(reply.get.channel.get == "#ircv3");
		assert(reply.get.ident.get == "~cooluser");
		assert(reply.get.host.get == "coolhost");
		assert(reply.get.nick.get == "cooluser");
		assert(reply.get.account.isNull);
		assert(reply.get.realname.get == "Cool User");
	}
	{
		immutable reply = parseNumeric!(Numeric.RPL_WHOSPCRPL)(only("mynick", "#ircv3", "~cooluser", "coolhost", "cooluser", "coolaccount"), "cuhnar");
		assert(reply.isNull);
	}
	{
		immutable reply = parseNumeric!(Numeric.RPL_WHOSPCRPL)(only("mynick", "#ircv3", "~cooluser", "coolhost", "cooluser"), "cuhnar");
		assert(reply.isNull);
	}
	{
		immutable reply = parseNumeric!(Numeric.RPL_WHOSPCRPL)(only("mynick", "#ircv3", "~cooluser", "coolhost"), "cuhnar");
		assert(reply.isNull);
	}
	{
		immutable reply = parseNumeric!(Numeric.RPL_WHOSPCRPL)(only("mynick", "#ircv3", "~cooluser"), "cuhnar");
		assert(reply.isNull);
	}
	{
		immutable reply = parseNumeric!(Numeric.RPL_WHOSPCRPL)(only("mynick", "#ircv3"), "cuhnar");
		assert(reply.isNull);
	}
	{
		immutable reply = parseNumeric!(Numeric.RPL_WHOSPCRPL)(only("mynick"), "cuhnar");
		assert(reply.isNull);
	}
	{
		immutable reply = parseNumeric!(Numeric.RPL_WHOSPCRPL)(takeNone(only("")), "cuhnar");
		assert(reply.isNull);
	}
}