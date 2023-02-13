module virc.message;


/++
+
+/
struct MessageMetadata {
	import std.datetime.systime : SysTime;
	import std.typecons : Nullable;
	import virc.ircv3.batch : BatchInformation;
	import virc.numerics.definitions : Numeric;
	///
	SysTime time;
	///
	string[string] tags;
	///
	Nullable!Numeric messageNumeric;
	///
	string original;
	///
	BatchInformation batch;
}
/++
+
+/
enum MessageType {
	notice,
	privmsg
}
/++
+ An IRC message, passed between clients.
+/
struct Message {
	import std.algorithm.iteration : splitter;
	import std.algorithm.searching : endsWith, findSplit, startsWith;
	///This message's payload. Will include \x01 characters if the message is CTCP.
	string msg;

	/++
	+ Type of message.
	+
	+ NOTICE and PRIVMSG are identical, but replying to a NOTICE
	+ is discouraged.
	+/
	MessageType type;

	///Whether or not the message was the result of the server echoing back our messages.
	bool isEcho;

	/++
	+ Whether or not the message was a CTCP message.
	+
	+ Note that some clients may mangle long CTCP messages by truncation. Those
	+ messages will not be detected as CTCP messages.
	+/
	auto isCTCP() const {
		return (msg.startsWith("\x01")) && (msg.endsWith("\x01"));
	}
	///Whether or not the message is safe to reply to.
	auto isReplyable() const {
		return type != MessageType.notice;
	}
	///The CTCP command, if this is a CTCP message.
	auto ctcpCommand() const
		in(isCTCP, "This is not a CTCP message!")
	{
		auto split = msg[1..$-1].splitter(" ");
		return split.front;
	}
	///The arguments after the CTCP command, if this is a CTCP message.
	auto ctcpArgs() const
		in(isCTCP, "This is not a CTCP message!")
	{
		auto split = msg[1..$-1].findSplit(" ");
		return split[2];
	}
	bool opEquals(string str) @safe pure nothrow @nogc const {
		return str == msg;
	}
	auto toHash() const {
		return hashOf(msg);
	}
	string toString() @safe pure nothrow @nogc const {
		return msg;
	}
}
///
@safe pure nothrow @nogc unittest {
	{
		auto msg = Message("Hello!", MessageType.notice);
		assert(!msg.isCTCP);
		assert(!msg.isReplyable);
	}
	{
		auto msg = Message("Hello!", MessageType.privmsg);
		assert(msg.isReplyable);
	}
	{
		auto msg = Message("\x01ACTION does a thing\x01", MessageType.privmsg);
		assert(msg.isCTCP);
		assert(msg.ctcpCommand == "ACTION");
		assert(msg.ctcpArgs == "does a thing");
	}
	{
		auto msg = Message("\x01VERSION\x01", MessageType.privmsg);
		assert(msg.isCTCP);
		assert(msg.ctcpCommand == "VERSION");
		assert(msg.ctcpArgs == "");
	}
}
@safe pure nothrow @nogc unittest {
	assert(Message("Hello!", MessageType.notice).toHash == Message("Hello!", MessageType.privmsg).toHash);
}
