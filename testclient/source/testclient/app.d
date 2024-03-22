module testclient.app;

import std.algorithm;
import std.json;
import std.range;
import std.stdio;
import vibe.core.core;
import vibe.core.net;
import vibe.stream.operations;
import vibe.stream.stdio;
import vibe.stream.tls;
import vibe.stream.wrapper;
import virc;
import virc.client;

interface IStream : Output {
	ubyte[] readLine();
	bool empty();
}

class WrapStream : IStream {
	Stream stream;
	this(Stream stream) nothrow {
		this.stream = stream;
	}
	override void put(char c) {
		stream.write([c]);
	}
	override ubyte[] readLine() {
		return stream.readLine();
	}
	override bool empty() {
		return stream.empty;
	}
}
class WrapConnection : IStream {
	TCPConnection connection;
	this(TCPConnection conn) nothrow {
		connection = conn;
	}
	override void put(char c) {
		connection.write([c]);
	}
	override ubyte[] readLine() {
		return connection.readLine();
	}
	override bool empty() {
		return connection.empty;
	}
}

string currentChannel;
string[] channelsToJoin;
void autoJoinChannel(string chan) @safe {
	channelsToJoin ~= chan;
}

auto runClient(JSONValue settings, IStream stream) {
	import std.typecons;
	auto client = ircClient(stream, NickInfo(settings["nickname"].str, settings["identd"].str, settings["real name"].str));
	void writeLine(string line) {
		import std.string : toLower;
		if (line.startsWith("/")) {
			auto split = line[1..$].splitter(" ");
			switch(split.front.toLower()) {
				default:
					write(line[1..$]);
					break;
			}
		} else {
			client.msg(currentChannel, line);
		}
	}
	client.onMessage = (const User user, const Target target, const Message msg, const MessageMetadata metadata) @safe {
		if (msg.isCTCP) {
			if (msg.ctcpCommand == "ACTION") {
				writefln("<%s> * %s %s", metadata.time, user, msg.ctcpArgs);
			} else if (msg.ctcpCommand == "VERSION") {
				client.ctcpReply(Target(user), "VERSION", "virc-testclient");
			} else {
				writefln("<%s> [%s:%s] %s", metadata.time, user, msg.ctcpCommand, msg.ctcpArgs);
			}
		} else if (!msg.isReplyable) {
			writefln("<%s> -%s- %s", metadata.time, user.nickname, msg.msg);
		} else if (msg.isReplyable) {
			writefln("<%s> <%s:%s> %s", metadata.time, user.nickname, target, msg.msg);
		}
	};

	client.onJoin = (const User user, const Channel channel, const MessageMetadata metadata) @safe {
		writefln("<%s> *** %s joined %s", metadata.time, user, channel);
		currentChannel = channel.name;
	};

	client.onPart = (const User user, const Channel channel, const string message, const MessageMetadata metadata) @safe {
		writefln("<%s> *** %s parted %s: %s", metadata.time, user, channel, message);
	};

	client.onQuit = (const User user, const string message, const MessageMetadata metadata) @safe {
		writefln("<%s> *** %s quit IRC: %s", metadata.time, user, message);
	};

	client.onNick = (const User user, const User newname, const MessageMetadata metadata) @safe {
		writefln("<%s> *** %s changed name to %s", metadata.time, user, newname);
	};

	client.onKick = (const User user, const Channel channel, const User initiator, const string message, const MessageMetadata metadata) @safe {
		writefln("<%s> *** %s was kicked from %s by %s: %s", metadata.time, user, channel, initiator, message);
	};

	client.onLogin = (const User user, const MessageMetadata metadata) @safe {
		writefln("<%s> *** %s logged in", metadata.time, user);
	};

	client.onLogout = (const User user, const MessageMetadata metadata) @safe {
		writefln("<%s> *** %s logged out", metadata.time, user);
	};

	client.onOtherUserAwayReply = (const User user, const string message, const MessageMetadata metadata) @safe {
		writefln("<%s> *** %s is away: %s", metadata.time, user, message);
	};

	client.onBack = (const User user, const MessageMetadata metadata) @safe {
		writefln("<%s> *** %s is no longer away", metadata.time, user);
	};

	client.onTopicChange = (const User user, const Channel channel, const string topic, const MessageMetadata metadata) @safe {
		writefln("<%s> *** %s changed topic on %s to %s", metadata.time, user, channel, topic);
	};

	client.onMode = (const User user, const Target target, const ModeChange mode, const MessageMetadata metadata) @safe {
		writefln("<%s> *** %s changed modes on %s: %s", metadata.time, user, target, mode);
	};
	client.onWhois = (const User user, const WhoisResponse whoisResponse) @safe {
		writefln("%s is %s@%s (%s)", user, whoisResponse.username, whoisResponse.hostname, whoisResponse.realname);
		if (whoisResponse.isOper) {
			writefln("%s is an IRC operator", user);
		}
		if (whoisResponse.isSecure) {
			writefln("%s is on a secure connection", user);
		}
		if (whoisResponse.isRegistered && whoisResponse.account.isNull) {
			writefln("%s is a registered nick", user);
		}
		if (!whoisResponse.account.isNull) {
			writefln("%s is logged in as %s", user, whoisResponse.account);
		}
		if (!whoisResponse.idleTime.isNull) {
			writefln("%s has been idle for %s", user, whoisResponse.idleTime.get);
		}
		if (!whoisResponse.connectedTime.isNull) {
			writefln("%s connected on %s", user, whoisResponse.connectedTime.get);
		}
		if (!whoisResponse.connectedTo.isNull) {
			writefln("%s is connected to %s", user, whoisResponse.connectedTo);
		}
	};
	client.onConnect = () @safe {
		foreach (channel; channelsToJoin) {
			client.join(channel);
		}
	};
	foreach (channel; settings["channels to join"].arrayNoRef) {
		autoJoinChannel(channel.str);
	}

	void readIRC() nothrow {
		try {
			while(!stream.empty) {
				put(client, stream.readLine().idup);
			}
		} catch (Exception e) {
			assert(0, e.msg);
		}
	}
	void readCLI() nothrow {
		try {
			auto standardInput = new StdinStream;
			while (true) {
				auto str = cast(string)readLine(standardInput);
				writeLine(str);
			}
		} catch (Exception e) {
			assert(0, e.msg);
		}
	}
	runTask(&readIRC);
	runTask(&readCLI);
	return runApplication();
}

int main() {
	import std.file : exists, readText;
	import std.json : JSONType, parseJSON;
	if (exists("settings.json")) {
		auto settings = readText("settings.json").parseJSON();
		auto conn = connectTCP(settings["address"].str, cast(ushort)settings["port"].integer);
		Stream stream;
		if (settings["ssl"].type == JSONType.true_) {
			auto sslctx = createTLSContext(TLSContextKind.client);
			sslctx.peerValidationMode = TLSPeerValidationMode.none;
			try {
				stream = createTLSStream(conn, sslctx);
			} catch (Exception) {
				writeln("SSL connection failed!");
				return 1;
			}
			return runClient(settings, new WrapStream(stream));
		} else {
			return runClient(settings, new WrapConnection(conn));
		}
	} else {
		writeln("No settings file found");
		return 1;
	}
}
