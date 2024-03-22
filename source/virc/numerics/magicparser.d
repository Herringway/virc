module virc.numerics.magicparser;

import std.datetime : UTC;
import std.range : isInputRange, ElementType;
import std.traits : hasUDA;
import std.typecons : Nullable;

enum Optional;

enum isOptional(T, string member) = hasUDA!(__traits(getMember, T, member), Optional);

template autoParse(T...) {
	MostCommon!T autoParse(Range)(Range input) if (isInputRange!Range && is(ElementType!Range == string)){
		import core.time : Duration, seconds;
		import std.array : empty, front, popFront;
		import std.conv : to;
		import std.datetime : SysTime;
		import std.traits : FieldNameTuple, hasIndirections, hasUDA;
		MostCommon!T output;
		static foreach (Type; T) {{
			auto attempt = tryParse!Type(input);
			if (!attempt.isNull) {
				output = MostCommon!T(attempt.get);
				return output;
			}
		}}
		return output;
	}
}
private immutable utc = UTC();
Nullable!T tryParse(T, Range)(Range input) if (isInputRange!Range && is(ElementType!Range == string)){
	import core.time : Duration, seconds;
	import std.array : empty, front, popFront;
	import std.conv : to;
	import std.datetime : SysTime;
	import std.traits : FieldNameTuple, hasIndirections, hasUDA;
	Nullable!T output = T.init;
	foreach (member; FieldNameTuple!T) {
		alias MemberType = typeof(__traits(getMember, T, member));
		if (input.empty) {
			static if (isOptional!(T, member)) {
				continue;
			} else {
				return Nullable!T.init;
			}
		}
		static if (is(MemberType == SysTime)) {
			try {
				__traits(getMember, output.get, member) = SysTime.fromUnixTime(input.front.to!ulong, utc);
			} catch (Exception) {
				static if (isOptional!(T, member)) {
					continue;
				} else {
					return Nullable!T.init;
				}
			}
		} else static if (is(MemberType == Duration)) {
			try {
				__traits(getMember, output.get, member) = input.front.to!ulong.seconds;
			} catch (Exception) {
				static if (isOptional!(T, member)) {
					continue;
				} else {
					return Nullable!T.init;
				}
			}
		} else {
			__traits(getMember, output.get, member) = input.front.to!MemberType;
		}
		input.popFront();
	}
	return output;
}
template MostCommon(Types...) {
	static if (Types.length == 1) {
		alias MostCommon = Nullable!(Types[0]);
	} else {
		struct MostCommon {
			import std.conv : text;
			import std.meta : ApplyRight, Filter, NoDuplicates, staticMap;
			import std.string : toLower;
			import std.traits : hasMember;
			import std.typecons : Nullable;
			static foreach (i, Type; Types) {
				mixin("Nullable!(Types["~i.text~"]) " ~ Type.stringof.toLower()~";");
				void opAssign(Type input) {
					mixin(Type.stringof.toLower()~" = input;");
				}
				this(Type input) {
					mixin(Type.stringof.toLower()~" = input;");
				}
			}
			auto opDispatch(string member)() const {
				alias HasMemberTypes = Filter!(ApplyRight!(hasMember, member), Types);
				alias subMemberType(T) = typeof(__traits(getMember, T, member));
				static assert(HasMemberTypes.length > 0, member~" not found in any of the provided types!");
				static assert(NoDuplicates!(staticMap!(subMemberType, HasMemberTypes)).length == 1, member~" does not have a common type in all provided types!");
				alias FinalType = typeof(__traits(getMember, HasMemberTypes[0], member));

				Nullable!FinalType output;
				static foreach(SubType; HasMemberTypes) {
					if (!__traits(getMember, this, SubType.stringof.toLower()).isNull) {
						output = __traits(getMember, __traits(getMember, this, SubType.stringof.toLower()).get, member);
					}
				}
				return output;
			}
			bool isNull() const {
				static foreach(SubType; Types) {
					if (!__traits(getMember, this, SubType.stringof.toLower()).isNull) {
						return false;
					}
				}
				return true;
			}
		}
	}
}
///
unittest {
	struct A {
		uint c;
		uint x;
		string y;
	}
	struct B {
		string c;
		uint x;
		uint z;
	}
	MostCommon!(A, B) test;
	test.a = A(0, 1, "b");
	assert(test.x == 1);
	assert(test.z.isNull);
}