/++
+
+/
module virc.numerics.rfc1459;

import virc.modes : ModeType;
import virc.numerics.definitions;

/++
+
+/
struct LUserClient {
	///
	string message;
	///
	this(string msg) pure @safe {
		message = msg;
	}
}
/++
+
+/
struct LUserMe {
	///
	string message;
	///
	this(string msg) pure @safe {
		message = msg;
	}
}
/++
+
+/
struct LUserChannels {
	///
	ulong numChannels;
	///
	string message;
	///
	this(string chans, string msg) pure @safe {
		import std.conv : to;
		numChannels = chans.to!ulong;
		message = msg;
	}
}
/++
+
+/
struct LUserOp {
	///
	ulong numOperators;
	///
	string message;
	///
	this(string ops, string msg) pure @safe {
		import std.conv : to;
		numOperators = ops.to!ulong;
		message = msg;
	}
}
/++
+ RPL_VERSION reply contents.
+/
struct VersionReply {
	import virc.common : User;
	User me;
	///The responding server's version string.
	string version_;
	///The server hostmask responding to the version query
	string server;
	///Contents depend on server, but are usually related to version
	string comments;
}

/++
+ RPL_REHASHING reply contents.
+/
struct RehashingReply {
	import virc.common : User;
	User me;
	///The config file being rehashed.
	string configFile;
	///Message displayed to user.
	string message;
}

/++
+
+/
//251 :There are <users> users and <services> services on <servers> servers
//TODO: Find out if this is safe to parse
auto parseNumeric(Numeric numeric : Numeric.RPL_LUSERCLIENT, T)(T input) {
	input.popFront();
	return LUserClient(input.front);
}
///
@safe pure /+nothrow @nogc+/ unittest { //Numeric.RPL_LUSERCLIENT
	import std.range : only;
	{
		immutable luser = parseNumeric!(Numeric.RPL_LUSERCLIENT)(only("someone", "There are 42 users and 43 services on 44 servers"));
		assert(luser.message == "There are 42 users and 43 services on 44 servers");
	}
}
/++
+
+/
//252 <opers> :operator(s) online
auto parseNumeric(Numeric numeric : Numeric.RPL_LUSEROP, T)(T input) {
	input.popFront();
	auto ops = input.front;
	input.popFront();
	auto msg = input.front;
	auto output = LUserOp(ops, msg);
	return output;
}
///
@safe pure /+nothrow @nogc+/ unittest { //Numeric.RPL_LUSEROP
	import std.range : only;
	{
		immutable luser = parseNumeric!(Numeric.RPL_LUSEROP)(only("someone", "45", "operator(s) online"));
		assert(luser.numOperators == 45);
		assert(luser.message == "operator(s) online");
	}
}

/++
+
+/
//254 <channels> :channels formed
auto parseNumeric(Numeric numeric : Numeric.RPL_LUSERCHANNELS, T)(T input) {
	input.popFront();
	auto chans = input.front;
	input.popFront();
	auto msg = input.front;
	auto output = LUserChannels(chans, msg);
	return output;
}
///
@safe pure /+nothrow @nogc+/ unittest { //Numeric.RPL_LUSERCHANNELS
	import std.range : only;
	{
		immutable luser = parseNumeric!(Numeric.RPL_LUSERCHANNELS)(only("someone", "46", "channels formed"));
		assert(luser.numChannels == 46);
		assert(luser.message == "channels formed");
	}
}
/++
+
+/
//255 :I have <clients> clients and <servers> servers
//TODO: Find out if this is safe to parse
auto parseNumeric(Numeric numeric : Numeric.RPL_LUSERME, T)(T input) {
	input.popFront();
	return LUserMe(input.front);
}
///
@safe pure /+nothrow @nogc+/ unittest { //Numeric.RPL_LUSERME
	import std.range : only;
	{
		immutable luser = parseNumeric!(Numeric.RPL_LUSERME)(only("someone", "I have 47 clients and 48 servers"));
		assert(luser.message == "I have 47 clients and 48 servers");
	}
}

struct ChannelListResult {
	import virc.common : Topic;
	import virc.modes : Mode;
	string name;
	uint userCount;
	Topic topic;
	Mode[] modes;
}

/++
+
+/
//322 <username> <channel> <count> :[\[<modes\] ]<topic>
auto parseNumeric(Numeric numeric : Numeric.RPL_LIST, T)(T input, ModeType[char] channelModeTypes) {
	import std.algorithm.iteration : filter, map;
	import std.algorithm.searching : findSplitAfter, startsWith;
	import std.array : array;
	import std.conv : parse;
	import virc.common : Channel, Topic;
	import virc.modes : Change, parseModeString;
	//Note: RFC2812 makes no mention of the modes being included.
	//Seems to be a de-facto standard, supported by several softwares.
	ChannelListResult channel;
	//username doesn't really help us here. skip it
	input.popFront();
	channel.name = input.front;
	input.popFront();
	auto str = input.front;
	channel.userCount = parse!uint(str);
	input.popFront();
	if (input.front.startsWith("[+")) {
		auto splitTopicStr = input.front.findSplitAfter("] ");
		channel.topic = Topic(splitTopicStr[1]);
		channel.modes = parseModeString(splitTopicStr[0][1..$], channelModeTypes).filter!(x => x.change == Change.set).map!(x => x.mode).array;
	} else {
		channel.topic = Topic(input.front);
	}
	return channel;
}
///
@safe pure /+nothrow @nogc+/ unittest { //Numeric.RPL_LIST
	import std.algorithm.searching : canFind;
	import std.range : only;
	import std.typecons : Nullable;
	import virc.common : Topic;
	import virc.modes : Mode;
	{
		immutable listEntry = parseNumeric!(Numeric.RPL_LIST)(only("someone", "#test", "4", "[+fnt 200:2] some words"), ['n': ModeType.d, 't': ModeType.d, 'f': ModeType.c]);
		assert(listEntry.name == "#test");
		assert(listEntry.userCount == 4);
		assert(listEntry.topic == Topic("some words"));
		assert(listEntry.modes.canFind(Mode(ModeType.d, 'n')));
		assert(listEntry.modes.canFind(Mode(ModeType.d, 't')));
		assert(listEntry.modes.canFind(Mode(ModeType.c, 'f', Nullable!string("100:2"))));
	}
	{
		immutable listEntry = parseNumeric!(Numeric.RPL_LIST)(only("someone", "#test2", "6", "[+fnst 100:2] some more words"), ['n': ModeType.d, 't': ModeType.d, 'f': ModeType.c]);
		assert(listEntry.name == "#test2");
		assert(listEntry.userCount == 6);
		assert(listEntry.topic == Topic("some more words"));
		assert(listEntry.modes.canFind(Mode(ModeType.d, 'n')));
		assert(listEntry.modes.canFind(Mode(ModeType.d, 't')));
		assert(listEntry.modes.canFind(Mode(ModeType.d, 's')));
		assert(listEntry.modes.canFind(Mode(ModeType.c, 'f', Nullable!string("100:2"))));
	}
	{
		immutable listEntry = parseNumeric!(Numeric.RPL_LIST)(only("someone", "#test3", "1", "no modes?"), ['n': ModeType.d, 't': ModeType.d, 'f': ModeType.c]);
		assert(listEntry.name == "#test3");
		assert(listEntry.userCount == 1);
		assert(listEntry.topic == Topic("no modes?"));
		assert(listEntry.modes.length == 0);
	}
}
struct TopicReply {
	string channel;
	string topic;
}
/++
+ Parser for RPL_TOPIC.
+
+ Format is `332 <client><channel> :<topic>`
+/
auto parseNumeric(Numeric numeric : Numeric.RPL_TOPIC, T)(T input) {
	import std.typecons : Nullable;
	Nullable!TopicReply output = TopicReply();
	if (input.empty) {
		output.nullify;
		return output;
	}
	input.popFront();
	if (input.empty) {
		output.nullify;
		return output;
	}
	output.get.channel = input.front;
	input.popFront();
	if (input.empty) {
		output.nullify;
		return output;
	}
	output.get.topic = input.front;
	return output;
}
///
@safe pure nothrow @nogc unittest {
	import std.range : only, takeNone;
	{
		immutable topic = parseNumeric!(Numeric.RPL_TOPIC)(only("someone", "#channel", "This is the topic!"));
		assert(topic.get.channel == "#channel");
		assert(topic.get.topic == "This is the topic!");
	}
	{
		immutable topic = parseNumeric!(Numeric.RPL_TOPIC)(takeNone(only("")));
		assert(topic.isNull);
	}
	{
		immutable topic = parseNumeric!(Numeric.RPL_TOPIC)(only("someone"));
		assert(topic.isNull);
	}
	{
		immutable topic = parseNumeric!(Numeric.RPL_TOPIC)(only("someone", "#channel"));
		assert(topic.isNull);
	}
}
struct NamesReply {
	import std.algorithm : splitter;
	import std.traits : ReturnType;
	import std.typecons : No;
	NamReplyFlag chanFlag;
	string channel;
	string _users;
	static struct User {
		string modes;
		string name;
		this(string str, char[char] prefixes) @safe pure nothrow {
			size_t nameStart;
			foreach (idx, char chr; str) {
				bool found;
				foreach (mode; prefixes.keys) {
					const prefix = prefixes[mode];
					if (chr == prefix) {
						found = true;
						modes ~= mode;
						break;
					}
				}
				if (!found) {
					nameStart = idx;
					break;
				}
			}
			name = str[nameStart .. $];
		}
	}
	auto users(char[char] prefixes) inout nothrow {
		import std.algorithm.iteration : map;
		return _users.splitter(" ").map!(x => User(x, prefixes));
	}
}
/++
+
+/
enum NamReplyFlag : string {
	///Channel will never be shown to users that aren't in it
	secret = "@",
	///Channel will have its name replaced for users that aren't in it
	private_ = "*",
	///Non-private and non-secret channel.
	public_ = "=",
	///ditto
	other = public_
}
/++
+ Parser for RPL_VERSION
+
+ Format is `351 <client> <version> <server> :<comments>`
+/
auto parseNumeric(Numeric numeric : Numeric.RPL_VERSION, T)(T input) {
	import virc.numerics.magicparser : autoParse;
	return autoParse!VersionReply(input);
}
///
@safe pure nothrow @nogc unittest {
	import std.algorithm.searching : canFind;
	import std.array : array;
	import std.range : only, takeNone;
	import virc.ircsplitter : IRCSplitter;
	{
		auto versionReply = parseNumeric!(Numeric.RPL_VERSION)(only("Someone", "ircd-seven-1.1.4(20170104-717fbca8dbac,charybdis-3.4-dev)", "localhost", "eHIKMpSZ6 TS6ow 7IZ"));
		assert(versionReply.get.version_ == "ircd-seven-1.1.4(20170104-717fbca8dbac,charybdis-3.4-dev)");
		assert(versionReply.get.server == "localhost");
		assert(versionReply.get.comments == "eHIKMpSZ6 TS6ow 7IZ");
	}
	{
		immutable versionReply = parseNumeric!(Numeric.RPL_VERSION)(takeNone(only("")));
		assert(versionReply.isNull);
	}
	{
		immutable versionReply = parseNumeric!(Numeric.RPL_VERSION)(only("Someone"));
		assert(versionReply.isNull);
	}
	{
		immutable versionReply = parseNumeric!(Numeric.RPL_VERSION)(only("Someone", "ircd-seven-1.1.4(20170104-717fbca8dbac,charybdis-3.4-dev)"));
		assert(versionReply.isNull);
	}
	{
		immutable versionReply = parseNumeric!(Numeric.RPL_VERSION)(only("Someone", "", "localhost"));
		assert(versionReply.isNull);
	}
}

/++
+ Parser for RPL_NAMREPLY
+
+ Format is `353 <client> =/*/@ <channel> :<prefix[es]><usermask>[ <prefix[es]><usermask>...]`
+/
auto parseNumeric(Numeric numeric : Numeric.RPL_NAMREPLY, T)(T input) {
	import std.algorithm : splitter;
	import std.typecons : Nullable;
	Nullable!NamesReply output = NamesReply();
	if (input.empty) {
		output.nullify();
		return output;
	}
	input.popFront();
	if (input.empty) {
		output.nullify();
		return output;
	}
	output.get.chanFlag = cast(NamReplyFlag)input.front;
	input.popFront();
	if (input.empty) {
		output.nullify();
		return output;
	}
	output.get.channel = input.front;
	input.popFront();
	if (input.empty) {
		output.nullify();
		return output;
	}
	output.get._users = input.front;
	return output;
}
///
@safe pure nothrow unittest {
	import std.algorithm.searching : canFind;
	import std.algorithm.comparison : equal;
	import std.array : array;
	import std.range : only, takeNone;
	import virc.ircsplitter : IRCSplitter;
	{
		auto namReply = parseNumeric!(Numeric.RPL_NAMREPLY)(IRCSplitter("someone = #channel :User1 User2 @User3 +User4"));
		assert(namReply.get.chanFlag == NamReplyFlag.public_);
		assert(namReply.get.channel == "#channel");
		auto users = namReply.get.users(['o': '@', 'v': '+']);
		with(users.front) {
			assert(modes.equal(""));
			assert(name == "User1");
		}
		users.popFront();
		with(users.front) {
			assert(modes.equal(""));
			assert(name == "User2");
		}
		users.popFront();
		with(users.front) {
			assert(modes.equal("o"));
			assert(name == "User3");
		}
		users.popFront();
		with(users.front) {
			assert(modes.equal("v"));
			assert(name == "User4");
		}
	}
	{
		immutable namReply = parseNumeric!(Numeric.RPL_NAMREPLY)(IRCSplitter("someone = #channel"));
		assert(namReply.isNull);
	}
	{
		immutable namReply = parseNumeric!(Numeric.RPL_NAMREPLY)(IRCSplitter("someone ="));
		assert(namReply.isNull);
	}
	{
		immutable namReply = parseNumeric!(Numeric.RPL_NAMREPLY)(IRCSplitter("someone"));
		assert(namReply.isNull);
	}
	{
		immutable namReply = parseNumeric!(Numeric.RPL_NAMREPLY)(takeNone(only("")));
		assert(namReply.isNull);
	}
}
/++
+ Parser for RPL_REHASHING
+
+ Format is `382 <client> <config file> :Rehashing]`
+/
auto parseNumeric(Numeric numeric : Numeric.RPL_REHASHING, T)(T input) {
	import virc.numerics.magicparser : autoParse;
	return autoParse!RehashingReply(input);
}
///
@safe pure nothrow unittest {
	import std.range : only, takeNone;
	{
		auto reply = parseNumeric!(Numeric.RPL_REHASHING)(only("someone", "ircd.conf", "Rehashing"));
		assert(reply.get.configFile == "ircd.conf");
		assert(reply.get.message == "Rehashing");
	}
	{
		immutable reply = parseNumeric!(Numeric.RPL_REHASHING)(only("someone", "ircd.conf"));
		assert(reply.isNull);
	}
	{
		immutable reply = parseNumeric!(Numeric.RPL_REHASHING)(only("someone"));
		assert(reply.isNull);
	}
	{
		immutable reply = parseNumeric!(Numeric.RPL_REHASHING)(takeNone(only("")));
		assert(reply.isNull);
	}
}

struct NoSuchServerError {
	import virc.common : User;
	User me;
	///Server mask that failed to match any servers.
	string serverMask;
	///User-readable error message
	string message;
}
/++
+ Parser for ERR_NOSUCHSERVER
+
+ Format is `402 <client> <server> :No such server`
+/
auto parseNumeric(Numeric numeric : Numeric.ERR_NOSUCHSERVER, T)(T input) {
	import virc.numerics.magicparser : autoParse;
	return autoParse!NoSuchServerError(input);
}
///
@safe pure nothrow unittest {
	import std.range : only, takeNone;
	{
		auto reply = parseNumeric!(Numeric.ERR_NOSUCHSERVER)(only("someone", "badserver.example.net", "No such server"));
		assert(reply.get.serverMask == "badserver.example.net");
		assert(reply.get.message == "No such server");
	}
	{
		immutable reply = parseNumeric!(Numeric.ERR_NOSUCHSERVER)(only("someone", "badserver.example.net"));
		assert(reply.isNull);
	}
	{
		immutable reply = parseNumeric!(Numeric.ERR_NOSUCHSERVER)(only("someone"));
		assert(reply.isNull);
	}
	{
		immutable reply = parseNumeric!(Numeric.ERR_NOSUCHSERVER)(takeNone(only("")));
		assert(reply.isNull);
	}
}
struct AwayReply {
	import virc.common : User;
	User me;
	///User that's away.
	User user;
	///User's away message.
	string message;
}
/++
+ Parser for RPL_AWAY
+
+ Format is `301 <client> <nick> <message>`
+/
auto parseNumeric(Numeric numeric : Numeric.RPL_AWAY, T)(T input) {
	import virc.numerics.magicparser : autoParse;
	return autoParse!AwayReply(input);
}
///
@safe pure nothrow unittest {
	import virc.common : User;
	import std.range : only, takeNone;
	{
		auto reply = parseNumeric!(Numeric.RPL_AWAY)(only("someone", "awayuser", "On fire"));
		assert(reply.get.user == User("awayuser"));
		assert(reply.get.message == "On fire");
	}
	{
		immutable reply = parseNumeric!(Numeric.RPL_AWAY)(only("someone", "awayuser"));
		assert(reply.isNull);
	}
	{
		immutable reply = parseNumeric!(Numeric.RPL_AWAY)(only("someone"));
		assert(reply.isNull);
	}
	{
		immutable reply = parseNumeric!(Numeric.RPL_AWAY)(takeNone(only("")));
		assert(reply.isNull);
	}
}
/++
+ WHOIS reply containing only a nickname and human-readable message.
+/
struct InfolessWhoisReply {
	import virc.common : User;
	User me;
	///User whose query is complete.
	User user;
	///Human-readable numeric message.
	string message;
}
/++
+ Parser for RPL_ENDOFWHOIS
+
+ Format is `318 <client> <nick> :End of /WHOIS list`
+/
auto parseNumeric(Numeric numeric : Numeric.RPL_ENDOFWHOIS, T)(T input) {
	import virc.numerics.magicparser : autoParse;
	return autoParse!InfolessWhoisReply(input);
}
///
@safe pure nothrow unittest {
	import virc.common : User;
	import std.range : only, takeNone;
	{
		auto reply = parseNumeric!(Numeric.RPL_ENDOFWHOIS)(only("someone", "whoisuser", "End of /WHOIS list"));
		assert(reply.get.user == User("whoisuser"));
	}
	{
		immutable reply = parseNumeric!(Numeric.RPL_ENDOFWHOIS)(only("someone", "whoisuser"));
		assert(reply.isNull);
	}
	{
		immutable reply = parseNumeric!(Numeric.RPL_ENDOFWHOIS)(only("someone"));
		assert(reply.isNull);
	}
	{
		immutable reply = parseNumeric!(Numeric.RPL_ENDOFWHOIS)(takeNone(only("")));
		assert(reply.isNull);
	}
}
/++
+ Parser for RPL_WHOISOPERATOR
+
+ Format is `313 <client> <nick> :is an IRC operator`
+/
auto parseNumeric(Numeric numeric : Numeric.RPL_WHOISOPERATOR, T)(T input) {
	import virc.numerics.magicparser : autoParse;
	return autoParse!InfolessWhoisReply(input);
}
///
@safe pure nothrow unittest {
	import virc.common : User;
	import std.range : only, takeNone;
	{
		auto reply = parseNumeric!(Numeric.RPL_WHOISOPERATOR)(only("someone", "whoisuser", "is an IRC operator"));
		assert(reply.get.user == User("whoisuser"));
	}
	{
		immutable reply = parseNumeric!(Numeric.RPL_WHOISOPERATOR)(only("someone", "whoisuser"));
		assert(reply.isNull);
	}
	{
		immutable reply = parseNumeric!(Numeric.RPL_WHOISOPERATOR)(only("someone"));
		assert(reply.isNull);
	}
	{
		immutable reply = parseNumeric!(Numeric.RPL_WHOISOPERATOR)(takeNone(only("")));
		assert(reply.isNull);
	}
}
/++
+
+/
struct WhoisUserReply {
	import virc.common : User;
	User me;
	///User whose query is complete.
	User user;
	///User's username.
	string username;
	///User's hostname.
	string hostname;
	//Reserved. Just a *.
	string reserved;
	///User's realname.
	string realname;
}
/++
+ Parser for RPL_WHOISUSER
+
+ Format is `311 <client> <nick> <user> <host> * :<real name>`
+/
auto parseNumeric(Numeric numeric : Numeric.RPL_WHOISUSER, T)(T input) {
	import virc.numerics.magicparser : autoParse;
	return autoParse!WhoisUserReply(input);
}
///
@safe pure nothrow unittest {
	import virc.common : User;
	import std.range : only, takeNone;
	{
		immutable reply = parseNumeric!(Numeric.RPL_WHOISUSER)(only("someone", "whoisuser", "someUsername", "someHostname", "*", "a real name"));
		assert(reply.get.user == User("whoisuser"));
		assert(reply.get.username == "someUsername");
		assert(reply.get.hostname == "someHostname");
		assert(reply.get.realname == "a real name");
	}
	{
		immutable reply = parseNumeric!(Numeric.RPL_WHOISUSER)(only("someone", "whoisuser", "someUsername", "someHostname", "*"));
		assert(reply.isNull);
	}
	{
		immutable reply = parseNumeric!(Numeric.RPL_WHOISUSER)(only("someone", "whoisuser", "someUsername", "someHostname"));
		assert(reply.isNull);
	}
	{
		immutable reply = parseNumeric!(Numeric.RPL_WHOISUSER)(only("someone", "whoisuser", "someUsername"));
		assert(reply.isNull);
	}
	{
		immutable reply = parseNumeric!(Numeric.RPL_WHOISUSER)(only("someone", "whoisuser"));
		assert(reply.isNull);
	}
	{
		immutable reply = parseNumeric!(Numeric.RPL_WHOISUSER)(only("someone"));
		assert(reply.isNull);
	}
	{
		immutable reply = parseNumeric!(Numeric.RPL_WHOISUSER)(takeNone(only("")));
		assert(reply.isNull);
	}
}
/++
+ Newer form of RPL_WHOISIDLE. Also provides the time at which the user
+ connected.
+/
struct WhoisIdleReplyNew {
	import core.time : Duration;
	import std.datetime.systime : SysTime;
	import virc.common : User;
	User me;
	///User whose query is complete.
	User user;
	///How long the user has been idle.
	Duration idleTime;
	///Time at which the user connected.
	SysTime connectedTime;
	///Human-readable numeric message.
	string message;
}
/++
+ Older form of RPL_WHOISIDLE. Does not have user connection time.
+/
struct WhoisIdleReplyOld {
	import core.time : Duration;
	import virc.common : User;
	User me;
	///User whose query is complete.
	User user;
	///How long the user has been idle.
	Duration idleTime;
	///Human-readable numeric message.
	string message;
}
/++
+ Parser for RPL_WHOISIDLE
+
+ Format is `317 <client> <nick> <idle time in seconds> :seconds idle` or
+ `317 <client> <nick> <idle time in seconds> <time connected> :seconds idle, signon time`
+/
auto parseNumeric(Numeric numeric : Numeric.RPL_WHOISIDLE, T)(T input) {
	import virc.numerics.magicparser : autoParse;
	return autoParse!(WhoisIdleReplyNew, WhoisIdleReplyOld)(input);
}
///
@safe pure nothrow unittest {
	import core.time : seconds;
	import std.datetime : DateTime, SysTime, UTC;
	import std.range : only, takeNone;
	import virc.common : User;
	static immutable testTime = SysTime(DateTime(2017, 07, 14, 02, 40, 00), UTC());
	{
		immutable reply = parseNumeric!(Numeric.RPL_WHOISIDLE)(only("someone", "whoisuser", "1500", "1500000000", "seconds idle, signon time"));
		assert(reply.user == User("whoisuser"));
		assert(reply.idleTime == 1500.seconds);
		assert(reply.connectedTime.get == testTime);
	}
	{
		immutable reply = parseNumeric!(Numeric.RPL_WHOISIDLE)(only("someone", "whoisuser", "1500", "seconds idle"));
		assert(reply.user == User("whoisuser"));
		assert(reply.idleTime == 1500.seconds);
		assert(reply.connectedTime.isNull);
	}
	{
		immutable reply = parseNumeric!(Numeric.RPL_WHOISIDLE)(only("someone", "whoisuser", "1500"));
		assert(reply.isNull);
	}
	{
		immutable reply = parseNumeric!(Numeric.RPL_WHOISIDLE)(only("someone", "whoisuser"));
		assert(reply.isNull);
	}
	{
		immutable reply = parseNumeric!(Numeric.RPL_WHOISIDLE)(only("someone"));
		assert(reply.isNull);
	}
	{
		immutable reply = parseNumeric!(Numeric.RPL_WHOISIDLE)(takeNone(only("")));
		assert(reply.isNull);
	}
}
/++
+
+/
struct WhoisServerReply {
	import virc.common : User;
	User me;
	///User whose query is complete.
	User user;
	///Hostmask of server the user is connected to.
	string server;
	///Server description.
	string serverDescription;
}
/++
+ Parser for RPL_WHOISSERVER
+
+ Format is `312 <client> <nick> <server mask> :<server description>`
+/
auto parseNumeric(Numeric numeric : Numeric.RPL_WHOISSERVER, T)(T input) {
	import virc.numerics.magicparser : autoParse;
	return autoParse!WhoisServerReply(input);
}
///
@safe pure nothrow unittest {
	import std.range : only, takeNone;
	import virc.common : User;
	{
		immutable reply = parseNumeric!(Numeric.RPL_WHOISSERVER)(only("someone", "whoisuser", "example.net", "Mysterious example server"));
		assert(reply.get.user == User("whoisuser"));
		assert(reply.get.server == "example.net");
		assert(reply.get.serverDescription == "Mysterious example server");
	}
	{
		immutable reply = parseNumeric!(Numeric.RPL_WHOISSERVER)(only("someone", "whoisuser", "example.net"));
		assert(reply.isNull);
	}
	{
		immutable reply = parseNumeric!(Numeric.RPL_WHOISSERVER)(only("someone", "whoisuser"));
		assert(reply.isNull);
	}
	{
		immutable reply = parseNumeric!(Numeric.RPL_WHOISSERVER)(only("someone"));
		assert(reply.isNull);
	}
	{
		immutable reply = parseNumeric!(Numeric.RPL_WHOISSERVER)(takeNone(only("")));
		assert(reply.isNull);
	}
}
/++
+
+/
struct WhoisChannelReply {
	import virc.common : User;
	User me;
	///User whose query is complete.
	User user;
	///Channel details of this user, including name and prefix.
	WhoisChannelReplyChannel[] channels;
}
/++
+
+/
struct WhoisChannelReplyChannel {
	import std.typecons : Nullable;
	import virc.common : Channel;
	///Mode prefix applied to this user on this channel.
	Nullable!string prefix;
	///Name of the channel.
	Channel channel;
}
/++
+ Parser for RPL_WHOISCHANNELS
+
+ Format is `319 <client> <nick> <server mask> :<server description>`
+/
auto parseNumeric(Numeric numeric : Numeric.RPL_WHOISCHANNELS, T)(T input, string prefixes, string channelTypes) {
	import std.algorithm.iteration : splitter;
	import std.typecons : Nullable;
	import virc.target : Target;
	import virc.numerics.magicparser : autoParse;
	struct Reduced {
		import virc.common : User;
		User me;
		User user;
		string channels;
	}
	Nullable!WhoisChannelReply output;
	auto parsed = autoParse!Reduced(input);
	if (!parsed.isNull) {
		output = WhoisChannelReply();
		output.get.me = parsed.get.me;
		output.get.user = parsed.get.user;
		auto split = parsed.get.channels.splitter(" ");
		foreach (rawChan; split) {
			auto parsedChannel = Target(rawChan, prefixes, channelTypes);
			if (parsedChannel.isChannel) {
				auto channel = WhoisChannelReplyChannel();
				channel.prefix = parsedChannel.prefixes;
				channel.channel = parsedChannel.channel.get;
				output.get.channels ~= channel;
			}
		}
	}
	return output;
}
///
/+@safe pure nothrow +/unittest {
	import std.range : only, takeNone;
	import virc.common : User;
	import virc.numerics.isupport : defaultModePrefixes;
	{
		auto reply = parseNumeric!(Numeric.RPL_WHOISCHANNELS)(only("someone", "whoisuser", "#test3 +#test"), defaultModePrefixes, "#");
		assert(reply.get.user == User("whoisuser"));
		assert(reply.get.channels.length == 2);
		with(reply.get.channels[0]) {
			assert(channel == Channel("#test3"));
			assert(prefix.isNull);
		}
		with(reply.get.channels[1]) {
			assert(channel == Channel("#test"));
			assert(prefix.get == "+");
		}
	}
	{
		auto reply = parseNumeric!(Numeric.RPL_WHOISCHANNELS)(only("someone", "whoisuser"), defaultModePrefixes, "#");
		assert(reply.isNull);
	}
	{
		auto reply = parseNumeric!(Numeric.RPL_WHOISCHANNELS)(only("someone"), defaultModePrefixes, "#");
		assert(reply.isNull);
	}
	{
		auto reply = parseNumeric!(Numeric.RPL_WHOISCHANNELS)(takeNone(only("")), defaultModePrefixes, "#");
		assert(reply.isNull);
	}
}

auto parseNumeric(Numeric numeric : Numeric.RPL_ISON, T)(T input) {
	import std.algorithm.iteration : splitter;
	import std.typecons : Nullable, Tuple;
	import virc.common : User;
	Nullable!(Tuple!(User, "user", typeof("".splitter(" ")), "online")) output = Tuple!(User, "user", typeof("".splitter(" ")), "online")();
	if (input.empty) {
		return output.init;
	}
	output.get.user = User(input.front);
	input.popFront();
	if (input.empty) {
		return output.init;
	}
	output.get.online = input.front.splitter(" ");
	return output;
}
unittest {
	import std.array : array;
	import std.range : only, takeNone;
	import virc.common : User;
	assert(parseNumeric!(Numeric.RPL_ISON)(takeNone(only(""))).isNull);
	assert(parseNumeric!(Numeric.RPL_ISON)(only("someone")).isNull);
	{
		auto reply = parseNumeric!(Numeric.RPL_ISON)(only("someone", "user1 user2 user3"));
		assert(reply.get.user == User("someone"));
		assert(reply.get.online.array == ["user1", "user2", "user3"]);
	}
}