/++
+ Various bits common to different parts of IRC, such as channel and user
+ metadata.
+/
module virc.common;

import std.datetime : SysTime;
import std.range : isOutputRange, put;
import std.typecons : Flag, Nullable;

import virc.modes;
import virc.usermask;

alias RFC2812Compliance = Flag!"RFC2812Compliance";
/++
+ Metadata for an IRC channel.
+/
struct Channel {
	///
	string name;
	void toString(T)(T sink) const if (isOutputRange!(T, const(char))) {
		put(sink, name);
	}
	this(string str) @safe pure nothrow @nogc {
		name = str;
	}
	this(string str, string modePrefixes, string chanPrefixes) @safe pure in {
		import std.algorithm : canFind;
		import std.array : front;
		assert(str.length > 0);
		assert(modePrefixes.canFind(str.front) || chanPrefixes.canFind(str.front));
	} do {
		import std.algorithm : canFind;
		import std.array : empty, front, popFront;
		if (modePrefixes.canFind(str.front)) {
			auto tmpCopy = str;
			tmpCopy.popFront();
			if (!tmpCopy.empty && chanPrefixes.canFind(tmpCopy.front)) {
				name = tmpCopy;
			} else {
				name = str;
			}
		} else {
			name = str;
		}
	}
}
///
@safe pure unittest {
	assert(Channel("#test").name == "#test");
	assert(Channel("#test", "@%+", "#").name == "#test");
	assert(Channel("+test", "@%+", "+").name == "+test");
	assert(Channel("++test", "@%+", "+").name == "+test");
	assert(Channel("@+test", "@%+", "#+").name == "+test");
	assert(Channel("@+", "@%+", "#+").name == "+");
	assert(Channel("+", "@%+", "#+").name == "+");
}
/++
+ Channel topic metadata. A message is guaranteed, but the time and user
+ associated with setting it may not be present.
+/
struct Topic {
	///
	string message;
	///
	Nullable!SysTime time;
	///
	Nullable!User setBy;
	auto opEquals(const Topic b) const {
		return message == b.message;
	}
	///
	auto toHash() const {
		return message.hashOf;
	}
}
@safe pure nothrow @nogc unittest {
	assert(Topic("Hello!").toHash == Topic("Hello!").toHash);
}
/++
+ User metadata. User's mask will always be present, but real name's presence
+ depends on the context. Account's presence depends on the server's
+ capabilities.
+/
struct User {
	///
	UserMask mask;
	///
	Nullable!string realName;
	///
	Nullable!string account;
	///
	this(string str) @safe pure nothrow @nogc {
		mask = UserMask(str);
	}
	///
	this(UserMask mask_) @safe pure nothrow @nogc {
		mask = mask_;
	}
	///
	this(string nick, string ident, string host) @safe pure nothrow @nogc {
		mask.nickname = nick;
		mask.ident = ident;
		mask.host = host;
	}
	///
	auto nickname() const {
		return mask.nickname;
	}
	///
	auto ident() const {
		return mask.ident;
	}
	///
	auto host() const {
		return mask.host;
	}
	///
	auto server() const {
		assert(mask.ident.isNull);
		assert(mask.host.isNull);
		return mask.nickname;
	}
	void toString(T)(T sink) const if (isOutputRange!(T, const(char))) {
		mask.toString(sink);
		if (!account.isNull) {
			put(sink, " (");
			put(sink, account.get);
			put(sink, ")");
		}
	}
	auto opEquals(const User b) const {
		if (!this.realName.isNull && !b.realName.isNull && (this.realName != b.realName)) {
			return false;
		}
		if (!this.account.isNull && !b.account.isNull && (this.account != b.account)) {
			return false;
		}
		return this.mask == b.mask;
	}
	///
	auto toHash() const {
		return mask.hashOf;
	}
}
@safe pure nothrow @nogc unittest {
	auto user = User("Test!Testo@Testy");
	auto compUser = User("Test!Testo@Testy");
	assert(user.mask.nickname == "Test");
	assert(user.mask.ident == "Testo");
	assert(user.mask.host == "Testy");
	assert(user == compUser);
	user.realName = "TestseT";
	compUser.realName = "whoever";
	assert(user != compUser);
	compUser.realName = user.realName;
	user.account = "Testeridoo";
	compUser.account = "Tototo";
	assert(user != compUser);
	assert(User("Test!Testo@Testy") == User("Test", "Testo", "Testy"));
}
@safe pure unittest {
	import std.conv : text;
	auto user = User("Test!Testo@Testy");
	user.account = "Tester";
	assert(user.text == "Test!Testo@Testy (Tester)");
}
@safe pure nothrow /+@nogc+/ unittest {
	immutable user = User("Test!Testo@Testy");
	immutable compUser = User("Test!Testo@Testy");
	assert(user.toHash == compUser.toHash);
}