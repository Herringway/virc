/++
+ Module for dealing with IRC formatting.
+/
module virc.style;

import std.range : isOutputRange;

///Names for the default colours in mIRC-style control codes.
enum MIRCColours {
	///RGB(255,255,255)
	white = 0,
	///RGB(0,0,0)
	black = 1,
	///RGB(0,0,127)
	blue = 2,
	///RGB(0,147,0)
	green = 3,
	///RGB(255,0,0)
	lightRed = 4,
	///RGB(127,0,0)
	brown = 5,
	///RGB(156,0,156)
	purple = 6,
	///RGB(252,127,0)
	orange = 7,
	///RGB(255,255,0)
	yellow = 8,
	///RGB(0,252,0)
	lightGreen = 9,
	///RGB(0,147,147)
	cyan = 10,
	///RGB(0,255,255)
	lightCyan = 11,
	///RGB(0,0,252)
	lightBlue = 12,
	///RGB(255,0,255)
	pink = 13,
	///RGB(127,127,127)
	grey = 14,
	///RGB(210,210,210)
	lightGrey = 15,
	///"Default" colour
	transparent = 99
}

///Characters that indicate text style changes.
enum ControlCharacters {
	///Bold text
	bold = '\x02',
	///Underlined text
	underline = '\x1F',
	///Italicized text
	italic = '\x1D',
	///Resets all following text to default style
	plain = '\x0F',
	///Coloured text and/or background.
	color = '\x03',
	///As colour, but extended to 24 bit colour.
	extendedColor = '\x04',
	///Text where the background and foreground colours are reversed.
	reverse = '\x16',
	///Text where every character has the same width
	monospace = '\x11',
	///Text with a line through the middle
	strikethrough = '\x1E'
}


auto colouredText(string fmt = "%s", T)(ulong f, ulong b, T val) {
	return ColouredText!(fmt, T)(f, b, val);
}
auto colouredText(string fmt = "%s", T)(ulong f, T val) {
	return ColouredText!(fmt, T)(f, val);
}
auto colouredText(string fmt = "%s", T)(RGBA32 f, RGBA32 b, T val) {
	return ColouredText!(fmt, T)(f.closestMIRCColour, b.closestMIRCColour, val);
}
auto colouredText(string fmt = "%s", T)(RGBA32 f, T val) {
	return ColouredText!(fmt, T)(f.closestMIRCColour, val);
}
struct ColouredText(string fmt, T) {
	ulong fg;
	ulong bg;
	bool hasBG;
	T thing;

	void toString(T)(T sink) const if (isOutputRange!(T, const(char))) {
		import std.format : formattedWrite;
		if (fg == ulong.max) {
			sink.formattedWrite!fmt(thing);
		} else if (hasBG) {
			sink.formattedWrite!(ControlCharacters.color~"%02d,%02d"~fmt~ControlCharacters.color)(fg, bg, thing);
		} else {
			sink.formattedWrite!(ControlCharacters.color~"%02d"~fmt~ControlCharacters.color)(fg, thing);
		}
	}
	this(ulong f, ulong b, T str) @safe pure nothrow @nogc {
		fg = f;
		bg = b;
		thing = str;
		hasBG = true;
	}
	this(ulong f, T str) @safe pure nothrow @nogc {
		fg = f;
		thing = str;
	}
}
///
@safe unittest {
	import std.conv : text;
	import std.outbuffer;
	ColouredText!("%s", ulong)().toString(new OutBuffer);
	assert(colouredText!"Test %s"(1,2,3).text == "\x0301,02Test 3\x03");
	assert(colouredText!"Test %s"(1,3).text == "\x0301Test 3\x03");
}

private struct StyledText(string fmt, char controlCode, T) {
	T thing;

	void toString(T)(T sink) const if (isOutputRange!(T, const(char))) {
		import std.format : formattedWrite;
		sink.formattedWrite(controlCode~fmt~controlCode, thing);
	}
}
///
@safe unittest {
	import std.outbuffer;
	StyledText!("%s", ControlCharacters.bold, ulong)().toString(new OutBuffer);
}
auto underlinedText(string fmt = "%s", T)(T val) {
	return StyledText!(fmt, ControlCharacters.underline, T)(val);
}
///
@safe unittest {
	import std.conv : text;
	assert(underlinedText!"Test %s"(3).text == "\x1FTest 3\x1F");
}

auto boldText(string fmt = "%s", T)(T val) {
	return StyledText!(fmt, ControlCharacters.bold, T)(val);
}
///
@safe unittest {
	import std.conv : text;
	assert(boldText!"Test %s"(3).text == "\x02Test 3\x02");
}

auto italicText(string fmt = "%s", T)(T val) {
	return StyledText!(fmt, ControlCharacters.italic, T)(val);
}
///
@safe unittest {
	import std.conv : text;
	assert(italicText!"Test %s"(3).text == "\x1DTest 3\x1D");
}


auto reverseText(string fmt = "%s", T)(T val) {
	return StyledText!(fmt, ControlCharacters.reverse, T)(val);
}
///
@safe unittest {
	import std.conv : text;
	assert(reverseText!"Test %s"(3).text == "\x16Test 3\x16");
}

auto monospaceText(string fmt = "%s", T)(T val) {
	return StyledText!(fmt, ControlCharacters.monospace, T)(val);
}
///
@safe unittest {
	import std.conv : text;
	assert(monospaceText!"Test %s"(3).text == "\x11Test 3\x11");
}

auto strikethroughText(string fmt = "%s", T)(T val) {
	return StyledText!(fmt, ControlCharacters.strikethrough, T)(val);
}
///
@safe unittest {
	import std.conv : text;
	assert(strikethroughText!"Test %s"(3).text == "\x1ETest 3\x1E");
}

struct RGBA32 {
	ubyte red;
	ubyte green;
	ubyte blue;
	ubyte alpha;
	float distance(const RGBA32 other) const @safe pure nothrow {
		import std.math : sqrt;
		return sqrt(cast(float)((red-other.red)^^2 + (blue-other.blue)^^2 + (green-other.green)^^2));
	}
	auto closestMIRCColour() const @safe pure nothrow {
		import std.algorithm : minIndex;
		return mIRCColourDefs[].minIndex!((x,y) => x.distance(this) < y.distance(this));
	}
	auto closestANSIColour() const @safe pure nothrow {
		return ANSIColours[closestMIRCColour];
	}
	static auto randomColour() @safe {
		import std.random : uniform;
		return RGBA32(uniform!(typeof(red))(),uniform!(typeof(green))(),uniform!(typeof(blue))(),0);
	}
	auto randomComplementaryColour() const @safe {
		import std.random : uniform;
		static immutable gamma = 2.2;
		const L = 0.2126 * (cast(float)red / ubyte.max) +
			0.7152 * (cast(float)green / ubyte.max) +
			0.0722 * (cast(float)blue / ubyte.max);
		return (L > 0.5) ?
			RGBA32(cast(ubyte)uniform(0,127),cast(ubyte)uniform(0,127),cast(ubyte)uniform(0,127),0) :
			RGBA32(cast(ubyte)uniform(127, 255),cast(ubyte)uniform(127, 255),cast(ubyte)uniform(127, 255),0);
	}
}

///
unittest {
	assert(RGBA32(0,0,0,0).closestMIRCColour == 1);
	assert(RGBA32(0,0,1,0).closestMIRCColour == 1);
	assert(RGBA32(0,0,255,0).closestMIRCColour == 60);
}

immutable RGBA32[100] mIRCColourDefs = [
	RGBA32(255,255,255,0),
	RGBA32(0,0,0,0),
	RGBA32(0,0,127,0),
	RGBA32(0,147,0,0),
	RGBA32(255,0,0,0),
	RGBA32(127,0,0,0),
	RGBA32(156,0,156,0),
	RGBA32(252,127,0,0),
	RGBA32(255,255,0,0),
	RGBA32(0,252,0,0),
	RGBA32(0,147,147,0),
	RGBA32(0,255,255,0),
	RGBA32(0,0,252,0),
	RGBA32(255,0,255,0),
	RGBA32(127,127,127,0),
	RGBA32(210,210,210,0),
	RGBA32(71,0,0,0),
	RGBA32(71,33,0,0),
	RGBA32(71,71,0,0),
	RGBA32(50,71,0,0),
	RGBA32(0,71,0,0),
	RGBA32(0,71,44,0),
	RGBA32(0,71,71,0),
	RGBA32(0,39,71,0),
	RGBA32(0,0,71,0),
	RGBA32(46,0,71,0),
	RGBA32(71,0,71,0),
	RGBA32(71,0,42,0),
	RGBA32(116,0,0,0),
	RGBA32(116,58,0,0),
	RGBA32(116,116,0,0),
	RGBA32(81,116,0,0),
	RGBA32(0,116,0,0),
	RGBA32(0,116,73,0),
	RGBA32(0,116,116,0),
	RGBA32(0,64,116,0),
	RGBA32(0,0,116,0),
	RGBA32(75,0,116,0),
	RGBA32(116,0,116,0),
	RGBA32(116,0,69,0),
	RGBA32(181,0,0,0),
	RGBA32(181,99,0,0),
	RGBA32(181,181,0,0),
	RGBA32(125,181,0,0),
	RGBA32(0,181,0,0),
	RGBA32(0,181,113,0),
	RGBA32(0,181,181,0),
	RGBA32(0,99,181,0),
	RGBA32(0,0,181,0),
	RGBA32(117,0,181,0),
	RGBA32(181,0,181,0),
	RGBA32(181,0,107,0),
	RGBA32(255,0,0,0),
	RGBA32(255,140,0,0),
	RGBA32(255,255,0,0),
	RGBA32(178,255,0,0),
	RGBA32(0,255,0,0),
	RGBA32(0,255,160,0),
	RGBA32(0,255,255,0),
	RGBA32(0,140,255,0),
	RGBA32(0,0,255,0),
	RGBA32(165,0,255,0),
	RGBA32(255,0,255,0),
	RGBA32(255,0,152,0),
	RGBA32(255,89,89,0),
	RGBA32(255,180,89,0),
	RGBA32(255,255,113,0),
	RGBA32(207,255,96,0),
	RGBA32(111,255,111,0),
	RGBA32(101,255,201,0),
	RGBA32(109,255,255,0),
	RGBA32(89,180,255,0),
	RGBA32(89,89,255,0),
	RGBA32(196,89,255,0),
	RGBA32(255,102,255,0),
	RGBA32(255,89,188,0),
	RGBA32(255,156,156,0),
	RGBA32(255,211,156,0),
	RGBA32(255,255,156,0),
	RGBA32(226,255,156,0),
	RGBA32(156,255,156,0),
	RGBA32(156,255,219,0),
	RGBA32(156,255,255,0),
	RGBA32(156,211,255,0),
	RGBA32(156,156,255,0),
	RGBA32(220,156,255,0),
	RGBA32(255,156,255,0),
	RGBA32(255,148,211,0),
	RGBA32(0,0,0,0),
	RGBA32(19,19,19,0),
	RGBA32(40,40,40,0),
	RGBA32(54,54,54,0),
	RGBA32(77,77,77,0),
	RGBA32(101,101,101,0),
	RGBA32(129,129,129,0),
	RGBA32(159,159,159,0),
	RGBA32(188,188,188,0),
	RGBA32(226,226,226,0),
	RGBA32(255,255,255,0),
	RGBA32(0,0,0,255)
];

immutable ubyte[100] ANSIColours = [
	15,
	0,
	4,
	2,
	9,
	1,
	5,
	202,
	11,
	10,
	6,
	14,
	12,
	13,
	8,
	7,
	52,
	94,
	100,
	58,
	22,
	29,
	23,
	24,
	17,
	54,
	53,
	89,
	88,
	130,
	142,
	64,
	28,
	35,
	30,
	25,
	18,
	91,
	90,
	125,
	124,
	166,
	184,
	106,
	34,
	49,
	37,
	33,
	19,
	129,
	127,
	161,
	196,
	208,
	226,
	154,
	46,
	86,
	51,
	75,
	21,
	171,
	201,
	198,
	203,
	215,
	227,
	191,
	83,
	122,
	87,
	111,
	63,
	177,
	207,
	205,
	217,
	223,
	229,
	193,
	157,
	158,
	159,
	153,
	147,
	183,
	219,
	212,
	16,
	233,
	235,
	237,
	239,
	241,
	244,
	247,
	250,
	254,
	231,
	0
];

struct ActiveFormatting {
	bool bold;
	bool underline;
	bool strikethrough;
	bool italic;
	bool reverse;
	bool monospace;
	string colour;
}

ActiveFormatting checkFormatting(string input) @safe pure {
	ActiveFormatting result;
	for (size_t offset; offset < input.length; offset++) {
		switch (input[offset]) {
			case ControlCharacters.bold:
				result.bold ^= true;
				break;
			case ControlCharacters.underline:
				result.underline ^= true;
				break;
			case ControlCharacters.italic:
				result.italic ^= true;
				break;
			case ControlCharacters.plain:
				result.bold = false;
				result.underline = false;
				result.strikethrough = false;
				result.reverse = false;
				result.monospace = false;
				result.italic = false;
				result.colour = "";
				break;
			case ControlCharacters.color:
				bool sawComma;
				size_t o = offset + 1;
				size_t seenDigits = 0;
				for (; o < input.length; o++) {
					if ((input[o] == ',')) {
						if ((seenDigits == 0) || sawComma) {
							break;
						}
						sawComma = true;
						seenDigits = 0;
						continue;
					}
					if ((input[o] < '0') || (input[o] > '9')) {
						break;
					}
					if (++seenDigits > 2) {
						break;
					}
				}
				if ((o - offset) > 1) {
					result.colour = input[offset .. o];
				} else {
					result.colour = "";
				}
				offset = o - 1; //account for loop's offset++
				break;
			case ControlCharacters.extendedColor:
				bool sawComma;
				size_t o = offset + 1;
				size_t seenDigits = 0;
				for (; o < input.length; o++) {
					if ((input[o] == ',')) {
						if ((seenDigits == 0) || sawComma) {
							break;
						}
						sawComma = true;
						seenDigits = 0;
						continue;
					}
					if (!(((input[o] >= '0') && (input[o] <= '9')) ||
							((input[o] >= 'A') && (input[o] <= 'F')) ||
							((input[o] >= 'a') && (input[o] <= 'f')))) {
						break;
					}
					if (++seenDigits > 6) {
						break;
					}
				}
				if ((o - offset) > 1) {
					result.colour = input[offset .. o];
				} else {
					result.colour = "";
				}
				offset = o - 1; //account for loop's offset++
				break;
			case ControlCharacters.reverse:
				result.reverse ^= true;
				break;
			case ControlCharacters.monospace:
				result.monospace ^= true;
				break;
			case ControlCharacters.strikethrough:
				result.strikethrough ^= true;
				break;
			default: break;
		}
	}
	return result;
}

@safe pure unittest {
	with(checkFormatting("")) {
		assert(bold == false);
		assert(underline == false);
		assert(strikethrough == false);
		assert(italic == false);
		assert(reverse == false);
		assert(monospace == false);
		assert(colour == "");
	}
	with(checkFormatting("\x1F")) {
		assert(bold == false);
		assert(underline == true);
		assert(strikethrough == false);
		assert(italic == false);
		assert(reverse == false);
		assert(monospace == false);
		assert(colour == "");
	}
	with(checkFormatting("\x1F\x1F")) {
		assert(bold == false);
		assert(underline == false);
		assert(strikethrough == false);
		assert(italic == false);
		assert(reverse == false);
		assert(monospace == false);
		assert(colour == "");
	}
	with(checkFormatting("\x0310")) {
		assert(bold == false);
		assert(underline == false);
		assert(strikethrough == false);
		assert(italic == false);
		assert(reverse == false);
		assert(monospace == false);
		assert(colour == "\x0310");
	}
	with(checkFormatting("\x0310,12")) {
		assert(bold == false);
		assert(underline == false);
		assert(strikethrough == false);
		assert(italic == false);
		assert(reverse == false);
		assert(monospace == false);
		assert(colour == "\x0310,12");
	}
	with(checkFormatting("\x0310\x03")) {
		assert(bold == false);
		assert(underline == false);
		assert(strikethrough == false);
		assert(italic == false);
		assert(reverse == false);
		assert(monospace == false);
		assert(colour == "");
	}
	with(checkFormatting("\x04FFFFFF")) {
		assert(bold == false);
		assert(underline == false);
		assert(strikethrough == false);
		assert(italic == false);
		assert(reverse == false);
		assert(monospace == false);
		assert(colour == "\x04FFFFFF");
	}
	with(checkFormatting("\x04FFFFFF,000000")) {
		assert(bold == false);
		assert(underline == false);
		assert(strikethrough == false);
		assert(italic == false);
		assert(reverse == false);
		assert(monospace == false);
		assert(colour == "\x04FFFFFF,000000");
	}
}
