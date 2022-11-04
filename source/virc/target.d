module virc.target;
/++
+
+/
struct Target {
	import std.range : isOutputRange;
	import std.typecons : Nullable;
	import virc.common : Channel, User;
	///
	Nullable!Channel channel;
	///
	Nullable!User user;
	///
	bool isChannel() @safe pure nothrow @nogc const {
		return !channel.isNull;
	}
	///
	bool isUser() @safe pure nothrow @nogc const {
		return !user.isNull;
	}
	/++
	+ Mode prefixes present in target. May be present on both channels and users.
	+
	+ Channel mode prefixes are used when targetting a subset of users on that
	+ channel (all voiced users, for example), while user mode prefixes are found
	+ mainly in responses from the server.
	+/
	Nullable!string prefixes;
	///
	bool isNickname() @safe pure nothrow @nogc const {
		return !user.isNull;
	}
	bool opEquals(string target) @safe pure nothrow @nogc const {
		if (!channel.isNull) {
			return channel.get == Channel(target);
		} else if (!user.isNull) {
			return user.get == User(target);
		}
		return false;
	}
	bool opEquals(const User target) @safe pure nothrow @nogc const {
		if (!user.isNull) {
			return user.get == target;
		}
		return false;
	}
	bool opEquals(const Channel target) @safe pure nothrow @nogc const {
		if (!channel.isNull) {
			return channel.get == target;
		}
		return false;
	}
	void toString(T)(T sink) const if (isOutputRange!(T, const(char))) {
		if (!channel.isNull) {
			channel.get.toString(sink);
		} else if (!user.isNull) {
			user.get.toString(sink);
		}
	}
	/++
	+
	+/
	this(Channel chan) @safe pure nothrow @nogc {
		channel = chan;
	}
	/++
	+
	+/
	this(User user_) @safe pure nothrow @nogc {
		user = user_;
	}
	this(string str, string modePrefixes, string channelPrefixes) @safe pure nothrow {
		import std.array : empty, front, popFront;
		import std.algorithm : canFind;
		import std.utf : byDchar;
		if (str.empty) {
			return;
		}
		auto tmpStr = str;
		while (modePrefixes.byDchar.canFind(tmpStr.byDchar.front)) {
			if (prefixes.isNull) {
				prefixes = "";
			}
			prefixes.get ~= tmpStr.byDchar.front;
			tmpStr.popFront();
		}
		if (!tmpStr.empty && channelPrefixes.byDchar.canFind(tmpStr.byDchar.front)) {
			channel = Channel(tmpStr);
		} else {
			user = User(tmpStr);
		}
	}
	/++
	+
	+/
	auto targetText() const {
		if (!channel.isNull) {
			return channel.get.name;
		} else if (!user.isNull) {
			return user.get.nickname;
		}
		assert(0, "No target specified");
	}
}
///
@safe pure nothrow unittest {
	import virc.common : Channel, User;
	{
		Target target;
		target.channel = Channel("#hello");
		assert(target == Channel("#hello"));
		assert(target != User("test"));
		assert(target == "#hello");
		assert(target.isChannel && !target.isUser);
	}
	{
		Target target;
		target.user = User("test");
		assert(target != Channel("#hello"));
		assert(target == User("test"));
		assert(target == "test");
		assert(!target.isChannel && target.isUser);
	}
	{
		Target target;
		assert(target != Channel("#hello"));
		assert(target != User("test"));
		assert(target != "test");
		assert(target != "#hello");
	}
	assert(Target("Hello", "+@%", "#&")  == User("Hello"));
	assert(Target(Channel("#test")) == Channel("#test"));
	assert(Target(User("Test")) == User("Test"));
	{
		auto target = Target("+Hello", "+@%", "#&");
		assert(target == User("Hello"));
		assert(target.prefixes == "+");
	}
	assert(Target("#Hello", "+@%", "#&")  == Channel("#Hello"));
	{
		auto target = Target("+#Hello", "+@%", "#&");
		assert(target == Channel("#Hello"));
		assert(target.prefixes == "+");
	}
	{
		auto target = Target("+@#Hello", "+@%", "#&");
		assert(target == Channel("#Hello"));
		assert(target.prefixes == "+@");
	}
	{
		auto target = Target("", "", "");
		assert(target.channel.isNull);
		assert(target.user.isNull);
	}
}
