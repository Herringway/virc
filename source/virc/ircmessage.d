module virc.ircmessage;

import virc.common : User;
import virc.ircv3.batch;
import virc.ircv3.tags;

import std.typecons : Nullable;

struct IRCMessage {
	string raw;
	IRCTags tags;
	private string nonTaggedString;
	Nullable!User sourceUser;
	string verb;
	private string argString;
	BatchInformation batch;

	invariant() {
		import std.algorithm.searching : canFind;
		assert(!verb.canFind(" "), "Verb cannot contain spaces");
	}

	this(string msg) @safe pure {
		import std.algorithm.iteration : splitter;
		import std.algorithm.searching : findSplit;
		import std.string : join;
		raw = msg;
		if (raw[0] == '@') {
			auto split = msg.findSplit(" ");
			assert(split, "Found nothing following tags");
			tags = IRCTags(split[0][1..$]);
			nonTaggedString = split[2];
		} else {
			nonTaggedString = msg;
		}
		auto split = nonTaggedString.splitter(" ");
		if (split.front[0] == ':') {
			sourceUser = User(split.front[1..$]);
			do {
				split.popFront();
			} while((split.front == "") && !split.empty);
		}
		verb = split.front;
		do {
			split.popFront();
		} while(!split.empty && (split.front == ""));
		argString = split.join(" ");
	}
	static IRCMessage fromClient(string str) @safe {
		return IRCMessage(str);
	}
	static IRCMessage fromServer(string str) @safe {
		return IRCMessage(str);
	}

	auto args() const @safe {
		import virc.ircsplitter : IRCSplitter;
		return IRCSplitter(argString);
	}

	void args(string input) @safe {
		argString = ":"~input;
	}

	void args(string[] input) @safe {
		import std.algorithm.searching : canFind;
		import std.format : format;

		if (input.length == 0) {
			argString = "";
			return;
		}

		foreach (earlyArg; input[0..$-1]) {
			assert(!earlyArg.canFind(" "));
		}
		argString = format!"%-(%s %|%):%s"(input[0..$-1], input[$-1]);
	}
	void toString(S)(ref S sink) const @safe {
		import std.conv : text;
		import std.format : formattedWrite;
		import std.range : put;
		auto tagString = tags.toString();
		if (tagString != "") {
			put(sink, "@");
			put(sink, tagString);
			put(sink, " ");
		}
		if (!sourceUser.isNull) {
			put(sink, ":");
			sink.formattedWrite!"%s"(sourceUser.get);
			put(sink, " ");
		}
		put(sink, verb);
		if (argString != "") {
			put(sink, " ");
			put(sink, argString);
		}
	}
	bool opEquals(const IRCMessage other) const @safe pure {
		import std.algorithm.comparison : equal;
		return ((this.tags == other.tags) && (this.sourceUser == other.sourceUser) && (this.verb == other.verb) && (this.args.equal(other.args)));
	}
}

@safe unittest {
	import std.algorithm.comparison : equal;
	import std.conv : text;
	import std.range : only;
	{
		auto msg1 = IRCMessage("foo bar baz asdf");
		assert(msg1 == IRCMessage("foo bar baz :asdf"));
		with(msg1) {
			assert(verb == "foo");
			assert(args.equal(only("bar", "baz", "asdf")));
		}
	}
	with(IRCMessage(":src AWAY")) {
		assert(verb == "AWAY");
		assert(sourceUser.get == User("src"));
		assert(args.empty);
	}
	with(IRCMessage(":src AWAY :")) {
		assert(verb == "AWAY");
		assert(sourceUser.get == User("src"));
		assert(args.equal(only("")));
	}
	{
		auto msg1 = IRCMessage(":coolguy foo bar baz asdf");
		assert(msg1 == IRCMessage(":coolguy foo bar baz :asdf"));
		with(msg1) {
			assert(sourceUser.get == User("coolguy"));
			assert(verb == "foo");
			assert(args.equal(only("bar", "baz", "asdf")));
		}
	}
	with(IRCMessage("foo bar baz :asdf quux")) {
		assert(verb == "foo");
		assert(args.equal(only("bar", "baz", "asdf quux")));
	}
	with(IRCMessage("foo bar baz :")) {
		assert(verb == "foo");
		assert(args.equal(only("bar", "baz", "")));
	}
	with(IRCMessage("foo bar baz ::asdf")) {
		assert(verb == "foo");
		assert(args.equal(only("bar", "baz", ":asdf")));
	}
	with(IRCMessage(":coolguy foo bar baz :asdf quux")) {
		assert(sourceUser.get == User("coolguy"));
		assert(verb == "foo");
		assert(args.equal(only("bar", "baz", "asdf quux")));
	}
	with(IRCMessage(":coolguy foo bar baz :  asdf quux ")) {
		assert(sourceUser.get == User("coolguy"));
		assert(verb == "foo");
		assert(args.equal(only("bar", "baz", "  asdf quux ")));
	}
	with(IRCMessage(":coolguy PRIVMSG bar :lol :) ")) {
		assert(sourceUser.get == User("coolguy"));
		assert(verb == "PRIVMSG");
		assert(args.equal(only("bar", "lol :) ")));
	}
	with(IRCMessage(":coolguy foo bar baz :")) {
		assert(sourceUser.get == User("coolguy"));
		assert(verb == "foo");
		assert(args.equal(only("bar", "baz", "")));
	}
	with(IRCMessage(":coolguy foo bar baz :  ")) {
		assert(sourceUser.get == User("coolguy"));
		assert(verb == "foo");
		assert(args.equal(only("bar", "baz", "  ")));
	}
	{
		auto msg1 = IRCMessage(":coolguy foo b\tar baz");
		assert(msg1 == IRCMessage(":coolguy foo b\tar :baz"));
		with(msg1) {
			assert(sourceUser.get == User("coolguy"));
			assert(verb == "foo");
			assert(args.equal(only("b\tar", "baz")));
		}
	}
	with(IRCMessage("@asd :coolguy foo bar baz :  ")) {
		assert(sourceUser.get == User("coolguy"));
		assert(verb == "foo");
		assert(args.equal(["bar", "baz", "  "]));
		assert(tags == ["asd": ""]);
	}
	{
		auto msg1 = IRCMessage("@a=b\\\\and\\nk;d=gh\\:764 foo");
		assert(msg1 == IRCMessage("@d=gh\\:764;a=b\\\\and\\nk foo"));
		with(msg1) {
			assert(tags["a"] == "b\\and\nk");
			assert(tags["d"] == "gh;764");
			assert(verb == "foo");
		}
	}
	{
		auto msg1 = IRCMessage("@a=b\\\\and\\nk;d=gh\\:764 foo par1 par2");
		assert(msg1 == IRCMessage("@a=b\\\\and\\nk;d=gh\\:764 foo par1 :par2"));
		assert(msg1 == IRCMessage("@d=gh\\:764;a=b\\\\and\\nk foo par1 par2"));
		assert(msg1 == IRCMessage("@d=gh\\:764;a=b\\\\and\\nk foo par1 :par2"));
		with(msg1) {
			assert(tags["a"] == "b\\and\nk");
			assert(tags["d"] == "gh;764");
			assert(verb == "foo");
			assert(args.equal(only("par1", "par2")));
		}
	}
	with(IRCMessage("@c;h=;a=b :quux ab cd")) {
		assert(sourceUser.get == User("quux"));
		assert(verb == "ab");
		assert(args.equal(["cd"]));
		assert(tags["c"] == "");
		assert(tags["h"] == "");
		assert(tags["a"] == "b");
	}
	with(IRCMessage(":src JOIN #chan")) {
		assert(sourceUser.get == User("src"));
		assert(verb == "JOIN");
		assert(args.equal(["#chan"]));
	}
	with(IRCMessage(":src JOIN :#chan")) {
		assert(sourceUser.get == User("src"));
		assert(verb == "JOIN");
		assert(args.equal(["#chan"]));
	}
	with(IRCMessage(":src AWAY")) {
		assert(sourceUser.get == User("src"));
		assert(verb == "AWAY");
		assert(args.empty);
	}
	with(IRCMessage(":src AWAY ")) {
		assert(sourceUser.get == User("src"));
		assert(verb == "AWAY");
		assert(args.empty);
	}
	with(IRCMessage(":cool\tguy foo bar baz")) {
		assert(sourceUser.get == User("cool\tguy"));
		assert(verb == "foo");
		assert(args.equal(only("bar", "baz")));
	}
	with(IRCMessage(":coolguy!ag@net\x035w\x03ork.admin PRIVMSG foo :bar baz")) {
		assert(sourceUser.get == User("coolguy!ag@net\x035w\x03ork.admin"));
		assert(verb == "PRIVMSG");
		assert(args.equal(only("foo", "bar baz")));
	}
	with(IRCMessage(":coolguy!~ag@n\x02et\x0305w\x0fork.admin PRIVMSG foo :bar baz")) {
		assert(sourceUser.get == User("coolguy!~ag@n\x02et\x0305w\x0fork.admin"));
		assert(verb == "PRIVMSG");
		assert(args.equal(only("foo", "bar baz")));
	}
	with(IRCMessage("@tag1=value1;tag2;vendor1/tag3=value2;vendor2/tag4 :irc.example.com COMMAND param1 param2 :param3 param3")) {
		assert(sourceUser.get == User("irc.example.com"));
		assert(verb == "COMMAND");
		assert(args.equal(only("param1", "param2", "param3 param3")));
		assert(tags["tag1"] == "value1");
		assert(tags["tag2"] == "");
		assert(tags["vendor1/tag3"] == "value2");
		assert(tags["vendor2/tag4"] == "");
	}
	with(IRCMessage(":irc.example.com COMMAND param1 param2 :param3 param3")) {
		assert(sourceUser.get == User("irc.example.com"));
		assert(verb == "COMMAND");
		assert(args.equal(only("param1", "param2", "param3 param3")));
	}
	with(IRCMessage("@tag1=value1;tag2;vendor1/tag3=value2;vendor2/tag4 COMMAND param1 param2 :param3 param3")) {
		assert(verb == "COMMAND");
		assert(args.equal(only("param1", "param2", "param3 param3")));
		assert(tags["tag1"] == "value1");
		assert(tags["tag2"] == "");
		assert(tags["vendor1/tag3"] == "value2");
		assert(tags["vendor2/tag4"] == "");
	}
	with(IRCMessage("@foo=\\\\\\\\\\:\\\\s\\s\\r\\n COMMAND")) {
		assert(verb == "COMMAND");
		assert(args.empty);
		assert(tags["foo"] == "\\\\;\\s \r\n");
	}
	with(IRCMessage(":gravel.mozilla.org 432  #momo :Erroneous Nickname: Illegal characters")) {
		assert(sourceUser.get == User("gravel.mozilla.org"));
		assert(verb == "432");
		assert(args.equal(only("#momo", "Erroneous Nickname: Illegal characters")));
	}
	with(IRCMessage(":gravel.mozilla.org MODE #tckk +n ")) {
		assert(sourceUser.get == User("gravel.mozilla.org"));
		assert(verb == "MODE");
		assert(args.equal(only("#tckk", "+n")));
	}
	with(IRCMessage(":services.esper.net MODE #foo-bar +o foobar  ")) {
		assert(sourceUser.get == User("services.esper.net"));
		assert(verb == "MODE");
		assert(args.equal(only("#foo-bar", "+o", "foobar")));
	}
	with(IRCMessage("@tag1=value\\\\ntest COMMAND")) {
		assert(verb == "COMMAND");
		assert(args.empty);
		assert(tags["tag1"] == "value\\ntest");
	}
	with(IRCMessage("@tag1=value\\1 COMMAND")) {
		assert(verb == "COMMAND");
		assert(args.empty);
		assert(tags["tag1"] == "value1");
	}
	with(IRCMessage("@tag1=value1\\ COMMAND")) {
		assert(verb == "COMMAND");
		assert(args.empty);
		assert(tags["tag1"] == "value1");
	}
	with(IRCMessage("@tag1=value1\\\\ COMMAND")) {
		assert(verb == "COMMAND");
		assert(args.empty);
		assert(tags["tag1"] == "value1\\");
	}
	with(IRCMessage(":remote!foo@example.com PRIVMSG local :I like turtles.")) {
		assert(sourceUser.get == User("remote!foo@example.com"));
		assert(verb == "PRIVMSG");
		assert(args.equal(["local", "I like turtles."]));
		assert(tags.length == 0);
	}
	assert(IRCMessage(IRCMessage(":remote!foo@example.com PRIVMSG local :I like turtles.").text) == IRCMessage(":remote!foo@example.com PRIVMSG local :I like turtles."));
	with(IRCMessage("@aaa=bbb;ccc;example.com/ddd=eee :nick!ident@host.com PRIVMSG me :Hello")) {
		assert(sourceUser.get == User("nick!ident@host.com"));
		assert(verb == "PRIVMSG");
		assert(args.equal(["me", "Hello"]));
		assert(tags["aaa"] == "bbb");
		assert(tags["ccc"] == "");
		assert(tags["example.com/ddd"] == "eee");
	}
	assert(IRCMessage(IRCMessage("@aaa=bbb;ccc;example.com/ddd=eee :nick!ident@host.com PRIVMSG me :Hello").text) == IRCMessage("@aaa=bbb;ccc;example.com/ddd=eee :nick!ident@host.com PRIVMSG me :Hello"));
	{
		auto msg = IRCMessage();
		msg.sourceUser = User("server");
		msg.verb = "HELLO";
		msg.args = "WORLD";
		assert(msg.text == ":server HELLO :WORLD");
	}
	with(IRCMessage(":example.com                   PRIVMSG              local           :I like turtles.")) {
		assert(sourceUser.get == User("example.com"));
		assert(verb == "PRIVMSG");
		assert(args.equal(["local", "I like turtles."]));
		assert(tags.length == 0);
	}
	{
		auto msg = IRCMessage();
		msg.sourceUser = User("server");
		msg.verb = "HELLO";
		msg.args = string[].init;
		assert(msg.text == ":server HELLO");
	}
	{
		auto msg = IRCMessage();
		msg.sourceUser = User("server");
		msg.verb = "HELLO";
		msg.args = ["WORLD"];
		assert(msg.text == ":server HELLO :WORLD");
	}
	{
		auto msg = IRCMessage();
		msg.sourceUser = User("server");
		msg.verb = "HELLO";
		msg.args = ["WORLD", "!!!"];
		assert(msg.text == ":server HELLO WORLD :!!!");
	}
}
