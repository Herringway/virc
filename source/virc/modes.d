/++
+ Module for parsing IRC mode strings.
+/
module virc.modes;

import std.algorithm : among, splitter;
import std.range.primitives : isInputRange, isOutputRange;
import std.range : put;
import std.typecons : Nullable, Tuple;


/++
 + IRC modes. These are settings for channels and users on an IRC network,
 + responsible for things ranging from user bans, flood control and colour
 + stripping to registration status.
 + Consists of a single character and (often) an argument string to go along
 + with it.
 +/
struct Mode {
	///
	ModeType type = ModeType.d;
	///
	char mode;
	///
	Nullable!string arg;
	invariant() {
		assert((type != ModeType.d) || arg.isNull);
	}
	///
	auto opEquals(Mode b) const {
		return (mode == b.mode);
	}
	///
	auto toHash() const {
		return mode.hashOf;
	}
}
@safe pure nothrow /+@nogc+/ unittest {
	assert(Mode(ModeType.d, 'a').toHash == Mode(ModeType.d, 'a').toHash);
}
/++
+ Mode classification.
+/
enum ModeType {
	///Adds/removes nick/address to a list. always has a parameter.
	a,
	///Mode that changes a setting and always has a parameter.
	b,
	///Mode that changes a setting and only has a parameter when set.
	c ,
	///Mode that changes a setting and never has a parameter.
	d
}
/++
+ Whether a mode was set or unset.
+/
enum Change {
	///Mode was set.
	set,
	///Mode was unset.
	unset
}

/++
+ Full metadata associated with a mode change.
+/
struct ModeChange {
	///
	Mode mode;
	///
	Change change;
	void toString(T)(T sink) const if (isOutputRange!(T, const(char))) {
		final switch(change) {
			case Change.set:
				put(sink, '+');
				break;
			case Change.unset:
				put(sink, '-');
				break;
		}
		put(sink, mode.mode);
	}
}

/++
+ Parse a mode string into individual mode changes.
+/
auto parseModeString(T)(T input, ModeType[char] channelModeTypes) if (isInputRange!T) {
	ModeChange[] changes;
	bool unsetMode = false;
	auto modeList = input.front;
	input.popFront();
	foreach (mode; modeList) {
		if (mode == '+') {
			unsetMode = false;
		} else if (mode == '-') {
			unsetMode = true;
		} else {
			if (unsetMode) {
				auto modeType = mode in channelModeTypes ? channelModeTypes[mode] : ModeType.d;
				if (modeType.among(ModeType.a, ModeType.b)) {
					if (input.empty) {
						changes = [];
						break;
					}
					auto arg = input.front;
					input.popFront();
					changes ~= ModeChange(Mode(modeType, mode, Nullable!string(arg)), Change.unset);
				} else {
					changes ~= ModeChange(Mode(modeType, mode), Change.unset);
				}
			} else {
				auto modeType = mode in channelModeTypes ? channelModeTypes[mode] : ModeType.d;
				if (modeType.among(ModeType.a, ModeType.b, ModeType.c)) {
					if (input.empty) {
						changes = [];
						break;
					}
					auto arg = input.front;
					input.popFront();
					changes ~= ModeChange(Mode(modeType, mode, Nullable!string(arg)), Change.set);
				} else {
					changes ~= ModeChange(Mode(modeType, mode), Change.set);
				}
			}
		}
	}
	return changes;
}
///ditto
auto parseModeString(string input, ModeType[char] channelModeTypes) {
	return parseModeString(input.splitter(" "), channelModeTypes);
}
///
@safe pure nothrow unittest {
	import std.algorithm : canFind, filter, map;
	import std.range : empty;
	{
		const testParsed = parseModeString("+s", null);
		assert(testParsed.filter!(x => x.change == Change.set).map!(x => x.mode).canFind(Mode(ModeType.d, 's')));
		assert(testParsed.filter!(x => x.change == Change.unset).empty);
	}
	{
		const testParsed = parseModeString("-s", null);
		assert(testParsed.filter!(x => x.change == Change.set).empty);
		assert(testParsed.filter!(x => x.change == Change.unset).map!(x => x.mode).canFind(Mode(ModeType.d, 's')));
	}
	{
		const testParsed = parseModeString("+s-n", null);
		assert(testParsed.filter!(x => x.change == Change.set).map!(x => x.mode).canFind(Mode(ModeType.d, 's')));
		assert(testParsed.filter!(x => x.change == Change.unset).map!(x => x.mode).canFind(Mode(ModeType.d, 'n')));
	}
	{
		const testParsed = parseModeString("-s+n", null);
		assert(testParsed.filter!(x => x.change == Change.set).map!(x => x.mode).canFind(Mode(ModeType.d, 'n')));
		assert(testParsed.filter!(x => x.change == Change.unset).map!(x => x.mode).canFind(Mode(ModeType.d, 's')));
	}
	{
		const testParsed = parseModeString("+kp secret", ['k': ModeType.b]);
		assert(testParsed.filter!(x => x.change == Change.set).map!(x => x.mode).canFind(Mode(ModeType.d, 'p')));
		assert(testParsed.filter!(x => x.change == Change.set).map!(x => x.mode).canFind(Mode(ModeType.b, 'k', Nullable!string("secret"))));
	}
	{
		const testParsed = parseModeString("+kp secret", null);
		assert(testParsed.filter!(x => x.change == Change.set).map!(x => x.mode).canFind(Mode(ModeType.d, 'p')));
		assert(testParsed.filter!(x => x.change == Change.set).map!(x => x.mode).canFind(Mode(ModeType.d, 'k')));
	}
	{
		const testParsed = parseModeString("-s+nk secret", ['k': ModeType.b]);
		assert(testParsed.filter!(x => x.change == Change.set).map!(x => x.mode).canFind(Mode(ModeType.d, 'n')));
		assert(testParsed.filter!(x => x.change == Change.set).map!(x => x.mode).canFind(Mode(ModeType.b, 'k', Nullable!string("secret"))));
		assert(testParsed.filter!(x => x.change == Change.unset).map!(x => x.mode).canFind(Mode(ModeType.d, 's')));
	}
	{
		const testParsed = parseModeString("-sk+nl secret 4", ['k': ModeType.b, 'l': ModeType.c]);
		assert(testParsed.filter!(x => x.change == Change.set).map!(x => x.mode).canFind(Mode(ModeType.d, 'n')));
		assert(testParsed.filter!(x => x.change == Change.set).map!(x => x.mode).canFind(Mode(ModeType.b, 'l', Nullable!string("4"))));
		assert(testParsed.filter!(x => x.change == Change.unset).map!(x => x.mode).canFind(Mode(ModeType.b, 'k', Nullable!string("secret"))));
		assert(testParsed.filter!(x => x.change == Change.unset).map!(x => x.mode).canFind(Mode(ModeType.d, 's')));
	}
	{
		const testParsed = parseModeString("-s+nl 3333", ['l': ModeType.c]);
		assert(testParsed.filter!(x => x.change == Change.set).map!(x => x.mode).canFind(Mode(ModeType.d, 'n')));
		assert(testParsed.filter!(x => x.change == Change.set).map!(x => x.mode).canFind(Mode(ModeType.c, 'l', Nullable!string("3333"))));
		assert(testParsed.filter!(x => x.change == Change.unset).map!(x => x.mode).canFind(Mode(ModeType.d, 's')));
	}
	{
		const testParsed = parseModeString("+s-nl", ['l': ModeType.c]);
		assert(testParsed.filter!(x => x.change == Change.unset).map!(x => x.mode).canFind(Mode(ModeType.d, 'n')));
		assert(testParsed.filter!(x => x.change == Change.unset).map!(x => x.mode).canFind(Mode(ModeType.c, 'l')));
		assert(testParsed.filter!(x => x.change == Change.set).map!(x => x.mode).canFind(Mode(ModeType.d, 's')));
	}
	{
		const testParsed = parseModeString("+kp", ['k': ModeType.b]);
		assert(testParsed.empty);
	}
	{
		const testParsed = parseModeString("-kp", ['k': ModeType.b]);
		assert(testParsed.empty);
	}
}

auto toModeStringLazy(ModeChange[] changes) {
	static struct Result {
		ModeChange[] changes;
		void toString(S)(ref S sink) {
			import std.algorithm : joiner, map;
			import std.format : formattedWrite;
			import std.range : put;
			Nullable!Change last;
			foreach(change; changes) {
				if (last.isNull || (change.change != last)) {
					put(sink, change.change == Change.set ? '+' : '-');
					last = change.change;
				}
				put(sink, change.mode.mode);
			}
			sink.formattedWrite!"%-( %s%)"(changes.map!(x => x.mode.arg).joiner);
		}
	}
	return Result(changes);
}

@safe pure unittest {
	import std.conv : text;
	assert(toModeStringLazy([ModeChange(Mode(ModeType.d, 's'), Change.set)]).text == "+s");
	assert(toModeStringLazy([ModeChange(Mode(ModeType.d, 's'), Change.unset)]).text == "-s");
	assert(toModeStringLazy([ModeChange(Mode(ModeType.d, 's'), Change.set), ModeChange(Mode(ModeType.d, 's'), Change.unset)]).text == "+s-s");
	assert(toModeStringLazy([ModeChange(Mode(ModeType.d, 's'), Change.set), ModeChange(Mode(ModeType.b, 'k', Nullable!string("pass")), Change.set)]).text == "+sk pass");
	assert(toModeStringLazy([ModeChange(Mode(ModeType.d, 's'), Change.set), ModeChange(Mode(ModeType.b, 'k', Nullable!string("pass")), Change.set), ModeChange(Mode(ModeType.c, 'l', Nullable!string("3")), Change.set)]).text == "+skl pass 3");
}

string toModeString(ModeChange[] changes) @safe pure {
	import std.conv : text;
	return changes.toModeStringLazy().text;
}
