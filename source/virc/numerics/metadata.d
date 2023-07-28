/++
+ Numerics for METADATA specification (post-3.2 WIP)
+/
module virc.numerics.metadata;
import virc.common : User;
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
+ Format is `760 <Client> <Target> <Key> <Visibility> :<Value>`
+/
auto parseNumeric(Numeric numeric : Numeric.RPL_WHOISKEYVALUE, T)(T input, string prefixes, string channelTypes) {
	import std.typecons : Nullable;
	import virc.numerics.magicparser : autoParse;
	import virc.target : Target;
	struct Reduced {
		User me;
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
		with(parseNumeric!(Numeric.RPL_WHOISKEYVALUE)(only("client", "someone!test@example.com", "url", "*", "http://www.example.com"), "@", "#").get) {
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
+ Format is `761 <Client> <Target> <Key> <Visibility>[ :<Value>]`
+/
auto parseNumeric(Numeric numeric : Numeric.RPL_KEYVALUE, T)(T input, string prefixes, string channelTypes) {
	import std.typecons : Nullable;
	import virc.numerics.magicparser : autoParse, Optional;
	import virc.target : Target;
	struct Reduced {
		User me;
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

	with(parseNumeric!(Numeric.RPL_KEYVALUE)(only("client", "someone!test@example.com", "url", "*", "http://www.example.com"), "@", "#").get) {
		assert(target== User("someone!test@example.com"));
		assert(key == "url");
		assert(visibility == "*");
		assert(value == "http://www.example.com");
	}

	assert(parseNumeric!(Numeric.RPL_KEYVALUE)(takeNone(only("")), "@", "#").isNull);
	assert(parseNumeric!(Numeric.RPL_KEYVALUE)(only("*"), "@", "#").isNull);
	assert(parseNumeric!(Numeric.RPL_KEYVALUE)(only("*", "url"), "@", "#").isNull);

	with(parseNumeric!(Numeric.RPL_KEYVALUE)(only("client", "*", "url", "*"), "@", "#").get) {
		assert(target == "*");
		assert(key == "url");
		assert(visibility == "*");
		assert(value.isNull);
	}
}

struct RPL_KeyNotSet {
	import virc.target : Target;
	Target target;
	string key;
	string humanReadable;
}
/++
+
+ Format is `766 <Client> <Target> <Key> :no matching key`
+/
auto parseNumeric(Numeric numeric : Numeric.RPL_KEYNOTSET, T)(T input, string prefixes, string channelTypes) {
	import std.typecons : Nullable;
	import virc.numerics.magicparser : autoParse;
	import virc.target : Target;
	struct Reduced {
		User me;
		string target;
		string key;
		string errorMessage;
	}
	Nullable!RPL_KeyNotSet output;
	auto reply = autoParse!Reduced(input);
	if (!reply.isNull) {
		output = RPL_KeyNotSet(Target(reply.get.target, prefixes, channelTypes), reply.get.key, reply.get.errorMessage);
	}
	return output;
}
///
@safe pure nothrow unittest { //Numeric.RPL_KEYNOTSET
	import std.range : only, takeNone;
	import virc.common : User;

	with(parseNumeric!(Numeric.RPL_KEYNOTSET)(only("client", "someone!test@example.com", "examplekey", "no matching key"), "@", "#").get) {
		assert(target== User("someone!test@example.com"));
		assert(key== "examplekey");
		assert(humanReadable == "no matching key");
	}

	assert(parseNumeric!(Numeric.RPL_KEYNOTSET)(takeNone(only("")), "@", "#").isNull);
	assert(parseNumeric!(Numeric.RPL_KEYNOTSET)(only("client"), "@", "#").isNull);
	assert(parseNumeric!(Numeric.RPL_KEYNOTSET)(only("client", "someone!test@example.com"), "@", "#").isNull);
	assert(parseNumeric!(Numeric.RPL_KEYNOTSET)(only("client", "someone!test@example.com", "examplekey"), "@", "#").isNull);
}

/++
+
+ Format is `770 <Client> <Key1> [<Key2> ...]` OR
+ `771 <Client> <Key1> [<Key2> ...]`
+ `772 <Client> <Key1> [<Key2> ...]`
+/
auto parseNumeric(Numeric numeric, T)(T input) if ((numeric == Numeric.RPL_METADATASUBOK) || (numeric == Numeric.RPL_METADATAUNSUBOK) || (numeric == Numeric.RPL_METADATASUBS)) {
	import std.typecons : Nullable;
	Nullable!(typeof(input)) output;
	if (input.empty) {
		return output;
	}
	input.popFront();
	output = input;
	return output;
}
///
@safe pure unittest { //Numeric.RPL_METADATASUBOK, Numeric.RPL_METADATAUNSUBOK, Numeric.RPL_METADATASUBS
	import std.array : array;
	import std.range : only, takeNone;
	import virc.common : User;

	assert(parseNumeric!(Numeric.RPL_METADATASUBOK)(only("client", "url", "example")).get.array == ["url", "example"]);
	assert(parseNumeric!(Numeric.RPL_METADATAUNSUBOK)(only("client", "url", "example")).get.array == ["url", "example"]);
	assert(parseNumeric!(Numeric.RPL_METADATASUBS)(only("client", "url", "example")).get.array == ["url", "example"]);

	assert(parseNumeric!(Numeric.RPL_METADATASUBOK)(takeNone(only(""))).isNull);
	assert(parseNumeric!(Numeric.RPL_METADATAUNSUBOK)(takeNone(only(""))).isNull);
	assert(parseNumeric!(Numeric.RPL_METADATASUBS)(takeNone(only(""))).isNull);
}

struct ERR_MetadataSyncLater {
	import core.time : Duration;
	import std.typecons : Nullable;
	import virc.target : Target;
	Target target;
	Nullable!Duration retryAfter;
}
/++
+
+ Format is `774 <Client> <Target>[ <RetryAfter>]`
+/
auto parseNumeric(Numeric numeric : Numeric.ERR_METADATASYNCLATER, T)(T input, string prefixes, string channelTypes) {
	import core.time : Duration;
	import std.typecons : Nullable;
	import virc.numerics.magicparser : autoParse, Optional;
	import virc.target : Target;
	struct Reduced {
		User me;
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
///
@safe pure nothrow unittest { //Numeric.ERR_METADATASYNCLATER
	import core.time : seconds;
	import std.array : array;
	import std.range : only, takeNone;
	import virc.common : Channel;

	with(parseNumeric!(Numeric.ERR_METADATASYNCLATER)(only("modernclient", "#bigchan", "4"), "@", "#").get) {
		assert(target.channel == Channel("#bigchan"));
		assert(retryAfter == 4.seconds);
	}

	assert(parseNumeric!(Numeric.ERR_METADATASYNCLATER)(takeNone(only("")), "@", "#").isNull);
}
