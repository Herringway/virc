module virc.irckeyvaluesplitter;

import std.typecons : Nullable;

auto splitKeyValues(string input) {
	import std.algorithm.iteration : map, splitter;
	return input.splitter(",").map!keyValuePair();
}

private struct TokenPair {
	string key;
	Nullable!string value;
}

private auto keyValuePair(string token) pure @safe {
	import std.algorithm : findSplit;
	TokenPair result;
	auto splitParams = token.findSplit("=");
	result.key = splitParams[0];
	if (splitParams) {
		result.value = splitParams[2];
	}
	return result;
}

@safe pure unittest {
	import std.algorithm.comparison : equal;
	import std.algorithm.iteration : map;
	import std.range : only;
	{
		auto split = splitKeyValues("foo,max-subs=50,bar");
		assert(split.map!(x => x.key).equal(only("foo", "max-subs", "bar")));
		assert(split.map!(x => x.value).equal(only(Nullable!string.init, Nullable!string("50"), Nullable!string.init)));
	}
}
