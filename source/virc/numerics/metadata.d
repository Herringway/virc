/++
+ Numerics for METADATA specification (post-3.2 WIP)
+/
module virc.numerics.metadata;
import virc.numerics.definitions;

struct RPL_WhoisKeyValue {
	import virc.target : Target;
	Target target;
	string key;
	string visibility;
	string value;
}
/++
+
+ Format is `760 <Target> <Key> <Visibility> :<Value>`
+/
auto parseNumeric(Numeric numeric : Numeric.RPL_WHOISKEYVALUE, T)(T input, string prefixes, string channelTypes) {
	import std.typecons : Nullable;
	import virc.numerics.magicparser : autoParse;
	import virc.target : Target;
	struct Reduced {
		string target;
		string key;
		string visibility;
		string value;
	}
	Nullable!RPL_WhoisKeyValue output;
	auto reply = autoParse!Reduced(input);
	if (!reply.isNull) {
		output = RPL_WhoisKeyValue(Target(reply.get.target, prefixes, channelTypes), reply.get.key, reply.get.visibility, reply.get.value);
	}
	return output;
}
///
@safe pure nothrow unittest { //Numeric.RPL_WHOISKEYVALUE
	import virc.common : User;
	import std.range : only, takeNone;
	{
		with(parseNumeric!(Numeric.RPL_WHOISKEYVALUE)(only("someone!test@example.com", "url", "*", "http://www.example.com"), "@", "#").get) {
			assert(target.user == User("someone!test@example.com"));
			assert(key == "url");
			assert(visibility == "*");
			assert(value == "http://www.example.com");
		}
	}
	{
		immutable logon = parseNumeric!(Numeric.RPL_WHOISKEYVALUE)(takeNone(only("")), "@", "#");
		assert(logon.isNull);
	}
	{
		immutable logon = parseNumeric!(Numeric.RPL_WHOISKEYVALUE)(only("*"), "@", "#");
		assert(logon.isNull);
	}
	{
		immutable logon = parseNumeric!(Numeric.RPL_WHOISKEYVALUE)(only("*", "url"), "@", "#");
		assert(logon.isNull);
	}
	{
		immutable logon = parseNumeric!(Numeric.RPL_WHOISKEYVALUE)(only("*", "url", "*"), "@", "#");
		assert(logon.isNull);
	}
}

struct RPL_KeyValue {
	import virc.numerics.magicparser : Optional;
	import virc.target : Target;
	import std.typecons : Nullable;
	Target target;
	string key;
	string visibility;
	@Optional Nullable!string value;
}
/++
+
+ Format is `761 <Target> <Key> <Visibility>[ :<Value>]`
+/
auto parseNumeric(Numeric numeric : Numeric.RPL_KEYVALUE, T)(T input, string prefixes, string channelTypes) {
	import std.typecons : Nullable;
	import virc.numerics.magicparser : autoParse, Optional;
	import virc.target : Target;
	struct Reduced {
		string target;
		string key;
		string visibility;
		@Optional Nullable!string value;
	}
	Nullable!RPL_KeyValue output;
	auto reply = autoParse!Reduced(input);
	if (!reply.isNull) {
		output = RPL_KeyValue(Target(reply.get.target, prefixes, channelTypes), reply.get.key, reply.get.visibility, reply.get.value);
	}
	return output;
}
///
@safe pure nothrow unittest { //Numeric.RPL_KEYVALUE
	import std.range : only, takeNone;
	import virc.common : User;

	with(parseNumeric!(Numeric.RPL_KEYVALUE)(only("someone!test@example.com", "url", "*", "http://www.example.com"), "@", "#").get) {
		assert(target== User("someone!test@example.com"));
		assert(key == "url");
		assert(visibility == "*");
		assert(value == "http://www.example.com");
	}

	assert(parseNumeric!(Numeric.RPL_KEYVALUE)(takeNone(only("")), "@", "#").isNull);
	assert(parseNumeric!(Numeric.RPL_KEYVALUE)(only("*"), "@", "#").isNull);
	assert(parseNumeric!(Numeric.RPL_KEYVALUE)(only("*", "url"), "@", "#").isNull);

	with(parseNumeric!(Numeric.RPL_KEYVALUE)(only("*", "url", "*"), "@", "#").get) {
		assert(target == "*");
		assert(key == "url");
		assert(visibility == "*");
		assert(value.isNull);
	}
}


struct ERR_MetadataLimit {
	import virc.target : Target;
	Target target;
	string humanReadable;
}
/++
+
+ Format is `764 <Target> :metadata limit reached`
+/
auto parseNumeric(Numeric numeric : Numeric.ERR_METADATALIMIT, T)(T input, string prefixes, string channelTypes) {
	import std.typecons : Nullable;
	import virc.numerics.magicparser : autoParse;
	import virc.target : Target;
	struct Reduced {
		string target;
		string errorMessage;
	}
	Nullable!ERR_MetadataLimit output;
	auto reply = autoParse!Reduced(input);
	if (!reply.isNull) {
		output = ERR_MetadataLimit(Target(reply.get.target, prefixes, channelTypes), reply.get.errorMessage);
	}
	return output;
}
struct ERR_NoMatchingKey {
	import virc.target : Target;
	Target target;
	string key;
	string humanReadable;
}
/++
+
+ Format is `766 <Target> <Key> :no matching key`
+/
auto parseNumeric(Numeric numeric : Numeric.ERR_NOMATCHINGKEY, T)(T input, string prefixes, string channelTypes) {
	import std.typecons : Nullable;
	import virc.numerics.magicparser : autoParse;
	import virc.target : Target;
	struct Reduced {
		string target;
		string key;
		string errorMessage;
	}
	Nullable!ERR_NoMatchingKey output;
	auto reply = autoParse!Reduced(input);
	if (!reply.isNull) {
		output = ERR_NoMatchingKey(Target(reply.get.target, prefixes, channelTypes), reply.get.key, reply.get.errorMessage);
	}
	return output;
}
struct ERR_KeyInvalid {
	string key;
	string humanReadable;
}
/++
+
+ Format is `767 <Key> :invalid metadata key`
+/
auto parseNumeric(Numeric numeric : Numeric.ERR_KEYINVALID, T)(T input, string prefixes, string channelTypes) {
	import virc.numerics.magicparser : autoParse;
	return autoParse!ERR_KeyInvalid(input);
}
struct ERR_KeyNoPermission {
	import virc.target : Target;
	Target target;
	string key;
	string humanReadable;
}
/++
+
+ Format is `769 <Target> <Key> :permission denied`
+/
auto parseNumeric(Numeric numeric : Numeric.ERR_KEYNOPERMISSION, T)(T input, string prefixes, string channelTypes) {
	import std.typecons : Nullable;
	import virc.numerics.magicparser : autoParse;
	import virc.target : Target;
	struct Reduced {
		string target;
		string key;
		string errorMessage;
	}
	Nullable!ERR_KeyNoPermission output;
	auto reply = autoParse!Reduced(input);
	if (!reply.isNull) {
		output = ERR_KeyNoPermission(Target(reply.get.target, prefixes, channelTypes), reply.get.key, reply.get.errorMessage);
	}
	return output;
}
struct ERR_MetadataSyncLater {
	import core.time : Duration;
	import std.typecons : Nullable;
	import virc.target : Target;
	Target target;
	Nullable!Duration time;
}
/++
+
+ Format is `771 <Target>[ time]`
+/
auto parseNumeric(Numeric numeric : Numeric.ERR_METADATASYNCLATER, T)(T input, string prefixes, string channelTypes) {
	import core.time : Duration;
	import std.typecons : Nullable;
	import virc.numerics.magicparser : autoParse, Optional;
	import virc.target : Target;
	struct Reduced {
		string target;
		@Optional Duration time;
	}
	Nullable!ERR_MetadataSyncLater output;
	auto reply = autoParse!Reduced(input);
	if (!reply.isNull) {
		output = ERR_MetadataSyncLater(Target(reply.get.target, prefixes, channelTypes), Nullable!Duration(reply.get.time));
	}
	return output;
}

/++
+
+ Format is `777 :<Key1> [<Key2> ...]`
+/
auto parseNumeric(Numeric numeric : Numeric.RPL_METADATASUBS, T)(T input) {
	import std.algorithm.iteration : splitter;
	import core.time : Duration;
	import std.typecons : Nullable, Tuple, tuple;
	import virc.common : User;
	import virc.numerics.magicparser : autoParse, Optional;
	import virc.target : Target;
	struct Reduced {
		User me;
		string subs;
	}
	Nullable!(Tuple!(User, "user", typeof("".splitter(" ")), "subs")) output = Tuple!(User, "user", typeof("".splitter(" ")), "subs")();
	auto reply = autoParse!Reduced(input);
	if (!reply.isNull) {
		output = typeof(output.get).init;
		output.get.user = reply.get.me;
		output.get.subs = reply.get.subs.splitter(" ");
		return output;
	} else {
		return output.init;
	}
}
///
@safe pure nothrow unittest { //Numeric.RPL_METADATASUBS
	import std.array : array;
	import std.range : only, takeNone;
	import virc.common : User;

	with(parseNumeric!(Numeric.RPL_METADATASUBS)(only("someone!test@example.com", "url example")).get) {
		assert(user == User("someone!test@example.com"));
		assert(subs.array == ["url", "example"]);
	}

	assert(parseNumeric!(Numeric.RPL_METADATASUBS)(takeNone(only(""))).isNull);
	assert(parseNumeric!(Numeric.RPL_METADATASUBS)(only("someone!test@example.com")).isNull);

	with(parseNumeric!(Numeric.RPL_METADATASUBS)(only("someone!test@example.com", "")).get) {
		assert(user == User("someone!test@example.com"));
		assert(subs.empty);
	}
}