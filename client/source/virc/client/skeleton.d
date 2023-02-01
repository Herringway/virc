/++
+ Module containing IRC client guts. Parses and dispatches to appropriate
+ handlers/
+/
module virc.client.skeleton;
import std.algorithm.comparison : among;
import std.algorithm.iteration : chunkBy, cumulativeFold, filter, map, splitter;
import std.algorithm.searching : canFind, endsWith, find, findSplit, findSplitAfter, findSplitBefore, skipOver, startsWith;
import std.array : array;
import std.ascii : isDigit;
import std.conv : parse, text;
import std.datetime;
import std.exception : enforce;
import std.format : format, formattedWrite;
import std.meta : AliasSeq;
import std.range.primitives : ElementType, isInputRange, isOutputRange;
import std.range : chain, empty, front, put, walkLength;
import std.traits : isCopyable, Parameters, Unqual;
import std.typecons : Nullable, RefCounted, refCounted;
import std.utf : byCodeUnit;

import virc.common;
import virc.encoding;
import virc.client.internaladdresslist;
import virc.ircsplitter;
import virc.ircv3.batch;
import virc.ircv3.sasl;
import virc.ircv3.tags;
import virc.ircmessage;
import virc.message;
import virc.modes;
import virc.numerics;
import virc.target;
import virc.usermask;

/++
+
+/
struct NickInfo {
	///
	string nickname;
	///
	string username;
	///
	string realname;
}

/++
+
+/
enum supportedCaps = AliasSeq!(
	"account-notify", // http://ircv3.net/specs/extensions/account-notify-3.1.html
	"account-tag", // http://ircv3.net/specs/extensions/account-tag-3.2.html
	"away-notify", // http://ircv3.net/specs/extensions/away-notify-3.1.html
	"batch", // http://ircv3.net/specs/extensions/batch-3.2.html
	"cap-notify", // http://ircv3.net/specs/extensions/cap-notify-3.2.html
	"chghost", // http://ircv3.net/specs/extensions/chghost-3.2.html
	"echo-message", // http://ircv3.net/specs/extensions/echo-message-3.2.html
	"extended-join", // http://ircv3.net/specs/extensions/extended-join-3.1.html
	"invite-notify", // http://ircv3.net/specs/extensions/invite-notify-3.2.html
	"draft/metadata-2", //
	"message-tags", //https://ircv3.net/specs/extensions/message-tags
	"draft/metadata-notify-2", //
	"draft/multiline", // https://ircv3.net/specs/extensions/multiline
	//"monitor", // http://ircv3.net/specs/core/monitor-3.2.html
	"multi-prefix", // http://ircv3.net/specs/extensions/multi-prefix-3.1.html
	"sasl", // http://ircv3.net/specs/extensions/sasl-3.1.html and http://ircv3.net/specs/extensions/sasl-3.2.html
	"server-time", // http://ircv3.net/specs/extensions/server-time-3.2.html
	"userhost-in-names", // http://ircv3.net/specs/extensions/userhost-in-names-3.2.html
);

/++
+
+/
auto ircClient(Output output, NickInfo info, SASLMechanism[] saslMechs = [], string password = string.init) {
	auto client = IRCClient(output);
	client.nickinfo.username = info.username;
	client.nickinfo.realname = info.realname;
	client.nickinfo.nickname = info.nickname;
	if (password != string.init) {
		client.password = password;
	}
	client.saslMechs = saslMechs;
	client.initialize();
	return client;
}

/++
+
+/
struct Server {
	///
	MyInfo myInfo;
	///
	ISupport iSupport;
}
/++
+
+/
enum RFC1459Commands {
	privmsg = "PRIVMSG",
	notice = "NOTICE",
	info = "INFO",
	admin = "ADMIN",
	trace = "TRACE",
	connect = "CONNECT",
	time = "TIME",
	links = "LINKS",
	stats = "STATS",
	version_ = "VERSION",
	kick = "KICK",
	invite = "INVITE",
	list = "LIST",
	names = "NAMES",
	topic = "TOPIC",
	mode = "MODE",
	part = "PART",
	join = "JOIN",
	squit = "SQUIT",
	quit = "QUIT",
	oper = "OPER",
	server = "SERVER",
	user = "USER",
	nick = "NICK",
	pass = "PASS",
	who = "WHO",
	whois = "WHOIS",
	whowas = "WHOWAS",
	kill = "KILL",
	ping = "PING",
	pong = "PONG",
	error = "ERROR",
	away = "AWAY",
	rehash = "REHASH",
	restart = "RESTART",
	summon = "SUMMON",
	users = "USERS",
	wallops = "WALLOPS",
	userhost = "USERHOST",
	ison = "ISON",
}
/++
+
+/
enum RFC2812Commands {
	service = "SERVICE"
}

import virc.ircv3 : IRCV3Commands;
alias ClientNoOpCommands = AliasSeq!(
	RFC1459Commands.server,
	RFC1459Commands.user,
	RFC1459Commands.pass,
	RFC1459Commands.whois,
	RFC1459Commands.whowas,
	RFC1459Commands.kill,
	RFC1459Commands.who,
	RFC1459Commands.oper,
	RFC1459Commands.squit,
	RFC1459Commands.summon,
	RFC1459Commands.pong, //UNIMPLEMENTED
	RFC1459Commands.error, //UNIMPLEMENTED
	RFC1459Commands.userhost,
	RFC1459Commands.version_,
	RFC1459Commands.names,
	RFC1459Commands.away,
	RFC1459Commands.connect,
	RFC1459Commands.trace,
	RFC1459Commands.links,
	RFC1459Commands.stats,
	RFC1459Commands.ison,
	RFC1459Commands.restart,
	RFC1459Commands.users,
	RFC1459Commands.list,
	RFC1459Commands.admin,
	RFC1459Commands.rehash,
	RFC1459Commands.time,
	RFC1459Commands.info,
	RFC2812Commands.service,
	IRCV3Commands.starttls, //DO NOT IMPLEMENT
	IRCV3Commands.batch, //SPECIAL CASE
	IRCV3Commands.monitor,
	Numeric.RPL_HOSTHIDDEN,
	Numeric.RPL_ENDOFNAMES,
	Numeric.RPL_ENDOFMONLIST,
	Numeric.RPL_ENDOFWHO,
	Numeric.RPL_LOCALUSERS,
	Numeric.RPL_GLOBALUSERS,
	Numeric.RPL_YOURHOST,
	Numeric.RPL_YOURID,
	Numeric.RPL_CREATED,
	Numeric.RPL_LISTSTART,
	Numeric.RPL_LISTEND,
	Numeric.RPL_TEXT,
	Numeric.RPL_ADMINME,
	Numeric.RPL_ADMINLOC1,
	Numeric.RPL_ADMINLOC2,
	Numeric.RPL_ADMINEMAIL,
	Numeric.RPL_WHOISCERTFP,
	Numeric.RPL_WHOISHOST,
	Numeric.RPL_WHOISMODE
);

/++
+
+/
struct ChannelState {
	Channel channel;
	string topic;
	InternalAddressList users;
	Mode[] modes;
	void toString(T)(T sink) const if (isOutputRange!(T, const(char))) {
		formattedWrite!"Channel: %s\n"(sink, channel);
		formattedWrite!"\tTopic: %s\n"(sink, topic);
		formattedWrite!"\tUsers:\n"(sink);
		foreach (user; users.list) {
			formattedWrite!"\t\t%s\n"(sink, user);
		}
	}
}
unittest {
	import std.outbuffer;
	ChannelState(Channel("#test"), "Words").toString(new OutBuffer);
}
/++
+ Types of errors.
+/
enum ErrorType {
	///Insufficient privileges for command. See message for missing privilege.
	noPrivs,
	///Monitor list is full.
	monListFull,
	///Server has no MOTD.
	noMOTD,
	///No server matches client-provided server mask.
	noSuchServer,
	///User is not an IRC operator.
	noPrivileges,
	///Malformed message received from server.
	malformed,
	///Message received unexpectedly.
	unexpected,
	///Unhandled command or numeric.
	unrecognized,
	///Bad input from client.
	badUserInput,
	///No key matched
	keyNotSet,
	///Action could not be performed now, try again later
	waitAndRetry,
	///Too many metadata subscriptions
	tooManySubs,
	///Standard replies: FAIL
	standardFail
}
/++
+ Struct holding data about non-fatal errors.
+/
struct IRCError {
	ErrorType type;
	string message;
}
/++
+ Channels in a WHOIS response.
+/
struct WhoisChannel {
	Channel name;
	string prefix;
}

/++
+ Full response to a WHOIS.
+/
struct WhoisResponse {
	bool isOper;
	bool isSecure;
	bool isRegistered;
	Nullable!string username;
	Nullable!string hostname;
	Nullable!string realname;
	Nullable!SysTime connectedTime;
	Nullable!Duration idleTime;
	Nullable!string connectedTo;
	Nullable!string account;
	WhoisChannel[string] channels;
}

/++
+ Metadata update.
+/
struct MetadataValue {
	///Visibility of this value. Exact meaning is defined by the server implementation.
	string visibility;
	///Main payload
	string value;

	alias value this;
}

interface Output {
	void put(char) @safe;
}

enum ChannelListUpdateType {
	added,
	removed,
	updated
}

/++
+ IRC client implementation.
+/
struct IRCClient {
	import virc.ircv3 : Capability, CapabilityServerSubcommands, IRCV3Commands;
	Output output;
	///
	Server server;
	///
	Capability[] capsEnabled;
	///User metadata received so far
	MetadataValue[string][User] userMetadata;
	///Channel metadata received so far
	MetadataValue[string][Channel] channelMetadata;

	NickInfo nickinfo;
	Nullable!string password;
	///
	ChannelState[string] channels;

	///SASL mechanisms available for usage
	SASLMechanism[] saslMechs;
	///
	InternalAddressList internalAddressList;

	///
	void delegate(const Capability, const MessageMetadata) @safe onReceiveCapList;
	///
	void delegate(const Capability, const MessageMetadata) @safe onReceiveCapLS;
	///
	void delegate(const Capability, const MessageMetadata) @safe onReceiveCapAck;
	///
	void delegate(const Capability, const MessageMetadata) @safe onReceiveCapNak;
	///
	void delegate(const Capability, const MessageMetadata) @safe onReceiveCapDel;
	///
	void delegate(const Capability, const MessageMetadata) @safe onReceiveCapNew;
	///
	void delegate(const User, const SysTime, const MessageMetadata) @safe onUserOnline;
	///
	void delegate(const User, const MessageMetadata) @safe onUserOffline;
	///
	void delegate(const User, const MessageMetadata) @safe onLogin;
	///
	void delegate(const User, const MessageMetadata) @safe onLogout;
	///
	void delegate(const User, const string, const MessageMetadata) @safe onOtherUserAwayReply;
	///
	void delegate(const User, const MessageMetadata) @safe onBack;
	///
	void delegate(const User, const MessageMetadata) @safe onMonitorList;
	///
	void delegate(const User, const User, const MessageMetadata) @safe onNick;
	///
	void delegate(const User, const User, const Channel, const MessageMetadata) @safe onInvite;
	///
	void delegate(const User, const Channel, const MessageMetadata) @safe onJoin;
	///
	void delegate(const User, const Channel, const string, const MessageMetadata) @safe onPart;
	///
	void delegate(const User, const Channel, const User, const string, const MessageMetadata) @safe onKick;
	///
	void delegate(const User, const string, const MessageMetadata) @safe onQuit;
	///
	void delegate(const User, const Target, const ModeChange, const MessageMetadata) @safe onMode;
	///
	void delegate(const User, const Target, const Message, const MessageMetadata) @safe onMessage;
	///
	void delegate(const User, const WhoisResponse) @safe onWhois;
	///
	void delegate(const User, const string, const MessageMetadata) @safe onWallops;
	///
	void delegate(const ChannelListResult, const MessageMetadata) @safe onList;
	///
	void delegate(const User, const User, const MessageMetadata) @safe onChgHost;
	///
	void delegate(const LUserClient, const MessageMetadata) @safe onLUserClient;
	///
	void delegate(const LUserOp, const MessageMetadata) @safe onLUserOp;
	///
	void delegate(const LUserChannels, const MessageMetadata) @safe onLUserChannels;
	///
	void delegate(const LUserMe, const MessageMetadata) @safe onLUserMe;
	///
	void delegate(const NamesReply, const MessageMetadata) @safe onNamesReply;
	///
	void delegate(const WHOXReply, const MessageMetadata) @safe onWHOXReply;
	///
	void delegate(const TopicReply, const MessageMetadata) @safe onTopicReply;
	///
	void delegate(const User, const Channel, const string, const MessageMetadata) @safe onTopicChange;
	///
	void delegate(const User, const MessageMetadata) @safe onUnAwayReply;
	///
	void delegate(const User, const MessageMetadata) @safe onAwayReply;
	///
	void delegate(const TopicWhoTime, const MessageMetadata) @safe onTopicWhoTimeReply;
	///
	void delegate(const VersionReply, const MessageMetadata) @safe onVersionReply;
	///
	void delegate(const RehashingReply, const MessageMetadata) @safe onServerRehashing;
	///
	void delegate(const MessageMetadata) @safe onYoureOper;
	///Called when an RPL_ISON message is received
	void delegate(const User, const MessageMetadata) @safe onIsOn;
	///Called when a metadata subscription list is received
	void delegate(const string, const MessageMetadata) @safe onMetadataSubList;
	///
	void delegate(const IRCError, const MessageMetadata) @safe onError;
	///
	void delegate(const MessageMetadata) @safe onRaw;
	///
	void delegate() @safe onConnect;
	/// Called whenever a channel user list is updated
	void delegate(const User, const User, const Channel, ChannelListUpdateType) @safe onChannelListUpdate;
	///
	debug void delegate(const string) @safe onSend;

	static struct ClientState {
		bool invalid = true;
		bool isRegistered;
		ulong capReqCount = 0;
		BatchProcessor batchProcessor;
		bool isAuthenticating;
		bool authenticationSucceeded;
		string[] supportedSASLMechs;
		SASLMechanism selectedSASLMech;
		bool autoSelectSASLMech;
		string receivedSASLAuthenticationText;
		bool _isAway;
		ulong maxMetadataSubscriptions;
		ulong maxMetadataSelfKeys;
		const(string)[] metadataSubscribedKeys;
		Capability[string] availableCapabilities;
		WhoisResponse[string] whoisCache;
	}
	private ClientState state;

	bool isAuthenticated() @safe {
		return state.authenticationSucceeded;
	}

	void initialize(NickInfo info) @safe {
		nickinfo = info;
		initialize();
	}
	void initialize() @safe {
		state = state.init;
		state.invalid = false;
		write("CAP LS 302");
		register();
	}
	public void ping() @safe {

	}
	public void names() @safe {
		write("NAMES");
	}
	public void ping(const string nonce) @safe {
		write!"PING :%s"(nonce);
	}
	public void lUsers() @safe {
		write!"LUSERS";
	}
	private void pong(const string nonce) @safe {
		write!"PONG :%s"(nonce);
	}
	public void put(string line) @safe {
		import std.conv : asOriginalType;
		import std.meta : NoDuplicates;
		import std.string : representation;
		import std.traits : EnumMembers;
		debug(verboseirc) import std.experimental.logger : trace;
		//Chops off terminating \r\n. Everything after is ignored, according to spec.
		line = findSplitBefore(line, "\r\n")[0];
		debug(verboseirc) trace("←: ", line);
		assert(isValid, "Received data after invalidation");
		if (line.empty) {
			return;
		}
		state.batchProcessor.put(line);
		foreach (batch; state.batchProcessor) {
			state.batchProcessor.popFront();
			foreach (parsed; batch.lines) {
				auto metadata = MessageMetadata();
				metadata.batch = parsed.batch;
				metadata.tags = parsed.tags;
				if("time" in parsed.tags) {
					metadata.time = parseTime(parsed.tags);
				} else {
					metadata.time = Clock.currTime(UTC());
				}
				if ("account" in parsed.tags) {
					if (!parsed.sourceUser.isNull) {
						parsed.sourceUser.get.account = parsed.tags["account"];
					}
				}
				if (!parsed.sourceUser.isNull) {
					internalAddressList.update(parsed.sourceUser.get);
					if (parsed.sourceUser.get.nickname in internalAddressList) {
						parsed.sourceUser = internalAddressList[parsed.sourceUser.get.nickname];
					}
				}

				if (parsed.verb.filter!(x => !isDigit(x)).empty) {
					metadata.messageNumeric = cast(Numeric)parsed.verb;
				}
				metadata.original = parsed.raw;
				tryCall!"onRaw"(metadata);

				switchy: switch (parsed.verb) {
					//TOO MANY TEMPLATE INSTANTIATIONS! uncomment when compiler fixes this!
					//alias Numerics = NoDuplicates!(EnumMembers!Numeric);
					alias Numerics = AliasSeq!(Numeric.RPL_WELCOME, Numeric.RPL_ISUPPORT, Numeric.RPL_LIST, Numeric.RPL_YOURHOST, Numeric.RPL_CREATED, Numeric.RPL_LISTSTART, Numeric.RPL_LISTEND, Numeric.RPL_ENDOFMONLIST, Numeric.RPL_ENDOFNAMES, Numeric.RPL_YOURID, Numeric.RPL_LOCALUSERS, Numeric.RPL_GLOBALUSERS, Numeric.RPL_HOSTHIDDEN, Numeric.RPL_TEXT, Numeric.RPL_MYINFO, Numeric.RPL_LOGON, Numeric.RPL_MONONLINE, Numeric.RPL_MONOFFLINE, Numeric.RPL_MONLIST, Numeric.RPL_LUSERCLIENT, Numeric.RPL_LUSEROP, Numeric.RPL_LUSERCHANNELS, Numeric.RPL_LUSERME, Numeric.RPL_TOPIC, Numeric.RPL_NAMREPLY, Numeric.RPL_TOPICWHOTIME, Numeric.RPL_SASLSUCCESS, Numeric.RPL_LOGGEDIN, Numeric.RPL_VERSION, Numeric.ERR_MONLISTFULL, Numeric.ERR_NOMOTD, Numeric.ERR_NICKLOCKED, Numeric.ERR_SASLFAIL, Numeric.ERR_SASLTOOLONG, Numeric.ERR_SASLABORTED, Numeric.RPL_REHASHING, Numeric.ERR_NOPRIVS, Numeric.RPL_YOUREOPER, Numeric.ERR_NOSUCHSERVER, Numeric.ERR_NOPRIVILEGES, Numeric.RPL_AWAY, Numeric.RPL_UNAWAY, Numeric.RPL_NOWAWAY, Numeric.RPL_ENDOFWHOIS, Numeric.RPL_WHOISUSER, Numeric.RPL_WHOISSECURE, Numeric.RPL_WHOISOPERATOR, Numeric.RPL_WHOISREGNICK, Numeric.RPL_WHOISIDLE, Numeric.RPL_WHOISSERVER, Numeric.RPL_WHOISACCOUNT, Numeric.RPL_ADMINEMAIL, Numeric.RPL_ADMINLOC1, Numeric.RPL_ADMINLOC2, Numeric.RPL_ADMINME, Numeric.RPL_WHOISHOST, Numeric.RPL_WHOISMODE, Numeric.RPL_WHOISCERTFP, Numeric.RPL_WHOISCHANNELS, Numeric.RPL_ISON, Numeric.RPL_WHOISKEYVALUE, Numeric.RPL_KEYVALUE, Numeric.RPL_KEYNOTSET, Numeric.ERR_METADATASYNCLATER, Numeric.RPL_METADATASUBOK, Numeric.RPL_METADATAUNSUBOK, Numeric.RPL_METADATASUBS, Numeric.RPL_WHOSPCRPL, Numeric.RPL_ENDOFWHO);

					static foreach (cmd; AliasSeq!(NoDuplicates!(EnumMembers!IRCV3Commands), NoDuplicates!(EnumMembers!RFC1459Commands), NoDuplicates!(EnumMembers!RFC2812Commands), Numerics)) {
						case cmd:
							static if (!cmd.asOriginalType.among(ClientNoOpCommands)) {
								rec!cmd(parsed, metadata);
							}
							break switchy;
					}
					default: recUnknownCommand(parsed.verb, metadata); break;
				}
			}
		}
	}
	void put(const immutable(ubyte)[] rawString) @safe {
		put(rawString.toUTF8String);
	}
	private void tryEndRegistration() @safe {
		if (state.capReqCount == 0 && !state.isAuthenticating && !state.isRegistered) {
			endRegistration();
		}
	}
	private void endAuthentication() @safe {
		state.isAuthenticating = false;
		tryEndRegistration();
	}
	private void endRegistration() @safe {
		write("CAP END");
	}
	public void capList() @safe {
		write("CAP LIST");
	}
	public void list() @safe {
		write("LIST");
	}
	public void away(const string message) @safe {
		write!"AWAY :%s"(message);
	}
	public void away() @safe {
		write("AWAY");
	}
	public void whois(const string nick) @safe {
		write!"WHOIS %s"(nick);
	}
	public void monitorClear() @safe {
		assert(monitorIsEnabled);
		write("MONITOR C");
	}
	public void monitorList() @safe {
		assert(monitorIsEnabled);
		write("MONITOR L");
	}
	public void monitorStatus() @safe {
		assert(monitorIsEnabled);
		write("MONITOR S");
	}
	public void monitorAdd(T)(T users) if (isInputRange!T && is(ElementType!T == User)) {
		assert(monitorIsEnabled);
		writeList!("MONITOR + ", ",")(users.map!(x => x.nickname));
	}
	public void monitorRemove(T)(T users) if (isInputRange!T && is(ElementType!T == User)) {
		assert(monitorIsEnabled);
		writeList!("MONITOR - ", ",")(users.map!(x => x.nickname));
	}
	public bool isAway() const @safe {
		return state._isAway;
	}
	public bool monitorIsEnabled() @safe {
		return capsEnabled.canFind("MONITOR");
	}
	public void quit(const string msg) @safe {
		write!"QUIT :%s"(msg);
		state = state.init;
		state.invalid = false;
	}
	public void changeNickname(const string nick) @safe {
		write!"NICK %s"(nick);
	}
	public void join(T,U)(T chans, U keys) if (isInputRange!T && isInputRange!U) {
		auto filteredKeys = keys.filter!(x => !x.empty);
		if (!filteredKeys.empty) {
			write!"JOIN %-(%s,%) %-(%s,%)"(chans, filteredKeys);
		} else {
			write!"JOIN %-(%s,%)"(chans);
		}
	}
	public void join(const string chan, const string key = "") @safe {
		import std.range : only;
		join(only(chan), only(key));
	}
	public void join(const Channel chan, const string key = "") @safe {
		import std.range : only;
		join(only(chan.text), only(key));
	}
	public void msg(const string target, const string message, IRCTags tags = IRCTags.init) @safe {
		writeTags!"PRIVMSG %s :%s"(tags, target, message);
	}
	public void tagMsg(const string target, IRCTags tags = IRCTags.init) @safe {
		writeTags!"TAGMSG %s"(tags, target);
	}
	public void wallops(const string message) @safe {
		write!"WALLOPS :%s"(message);
	}
	public void msg(const Target target, const Message message, IRCTags tags = IRCTags.init) @safe {
		msg(target.targetText, message.text, tags);
	}
	public void tagMsg(const Target target, IRCTags tags = IRCTags.init) @safe {
		tagMsg(target.targetText, tags);
	}
	public void ctcp(const Target target, const string command, const string args) @safe {
		msg(target, Message("\x01"~command~" "~args~"\x01"));
	}
	public void ctcp(const Target target, const string command) @safe {
		msg(target, Message("\x01"~command~"\x01"));
	}
	public void ctcpReply(const Target target, const string command, const string args) @safe {
		notice(target, Message("\x01"~command~" "~args~"\x01"));
	}
	public void notice(const string target, const string message) @safe {
		write!"NOTICE %s :%s"(target, message);
	}
	public void notice(const Target target, const Message message) @safe {
		notice(target.targetText, message.text);
	}
	public void changeTopic(const Target target, const string topic) @safe {
		write!"TOPIC %s :%s"(target, topic);
	}
	public void oper(const string name, const string pass) @safe {
		assert(!name.canFind(" ") && !pass.canFind(" "));
		write!"OPER %s %s"(name, pass);
	}
	public void rehash() @safe {
		write!"REHASH";
	}
	public void restart() @safe {
		write!"RESTART";
	}
	public void squit(const string server, const string reason) @safe {
		assert(!server.canFind(" "));
		write!"SQUIT %s :%s"(server, reason);
	}
	public void version_() @safe {
		write!"VERSION"();
	}
	public void version_(const string serverMask) @safe {
		write!"VERSION %s"(serverMask);
	}
	public void kick(const Channel chan, const User nick, const string message = "") @safe {
		assert(message.length < server.iSupport.kickLength, "Kick message length exceeded");
		write!"KICK %s %s :%s"(chan, nick, message);
	}
	public void isOn(const string[] nicknames...) @safe {
		write!"ISON %-(%s %)"(nicknames);
	}
	public void isOn(const User[] users...) @safe {
		write!"ISON %-(%s %)"(users.map!(x => x.nickname));
	}
	public void admin(const string server = "") @safe {
		if (server == "") {
			write!"ADMIN"();
		} else {
			write!"ADMIN %s"(server);
		}
	}
	public auto ownMetadata() const @safe {
		if (me !in userMetadata) {
			return null;
		}
		return userMetadata[me];
	}
	public void setMetadata(const User user, const string key, const string data) @safe {
		write!"METADATA %s SET %s :%s"(user, key, data);
	}
	public void setMetadata(const Channel channel, const string key, const string data) @safe {
		write!"METADATA %s SET %s :%s"(channel, key, data);
	}
	public void setMetadata(const string key, const string data) @safe {
		write!"METADATA * SET %s :%s"(key, data);
	}
	public void getMetadata(const Channel channel, const string[] keys...) @safe {
		write!"METADATA %s GET %-(%s %)"(channel, keys);
	}
	public void getMetadata(const User user, const string[] keys...) @safe {
		write!"METADATA %s GET %-(%s %)"(user, keys);
	}
	public void listMetadata(const Channel channel) @safe {
		write!"METADATA %s LIST"(channel);
	}
	public void listMetadata(const User user) @safe {
		write!"METADATA %s LIST"(user);
	}
	public void subscribeMetadata(const string[] keys...) @safe {
		write!"METADATA * SUB %-(%s %)"(keys);
	}
	public void unsubscribeMetadata(const string[] keys...) @safe {
		write!"METADATA * UNSUB %-(%s %)"(keys);
	}
	public void listSubscribedMetadata() @safe {
		write!"METADATA * SUBS"();
	}
	public void syncMetadata(const User user) @safe {
		write!"METADATA %s SYNC"(user);
	}
	public void syncMetadata(const Channel channel) @safe {
		write!"METADATA %s SYNC"(channel);
	}
	public void syncMetadata() @safe {
		write!"METADATA * SYNC"();
	}
	public void clearMetadata(const User user) @safe {
		write!"METADATA %s CLEAR"(user);
	}
	public void clearMetadata(const Channel channel) @safe {
		write!"METADATA %s CLEAR"(channel);
	}
	public void clearMetadata() @safe {
		write!"METADATA * CLEAR"();
	}
	public bool isSubscribed(const string key) @safe {
		return state.metadataSubscribedKeys.canFind(key);
	}
	private void sendAuthenticatePayload(const string payload) @safe {
		import std.base64 : Base64;
		import std.range : chunks;
		import std.string : representation;
		if (payload == "") {
			write!"AUTHENTICATE +"();
		} else {
			auto str = Base64.encode(payload.representation);
			size_t lastChunkSize = 0;
			foreach (chunk; str.byCodeUnit.chunks(400)) {
				write!"AUTHENTICATE %s"(chunk);
				lastChunkSize = chunk.length;
			}
			if (lastChunkSize == 400) {
				write!"AUTHENTICATE +"();
			}
		}
	}
	private void user(const string username_, const string realname_) @safe {
		write!"USER %s 0 * :%s"(username_, realname_);
	}
	private void pass(const string pass) @safe {
		write!"PASS :%s"(pass);
	}
	private void register() @safe {
		assert(!state.isRegistered);
		if (!password.isNull) {
			pass(password.get);
		}
		changeNickname(nickinfo.nickname);
		user(nickinfo.username, nickinfo.realname);
	}
	private void write(string fmt, T...)(scope T args) {
		writeTags!(fmt, T)(IRCTags.init, args);
	}
	private void writeTags(string fmt, T...)(IRCTags tags, scope T args) {
		import std.range : put;
		debug(verboseirc) import std.experimental.logger : tracef;
		const sendTags = !tags.empty && isEnabled(Capability("message-tags"));
		debug(verboseirc) tracef("→: %s"~fmt, sendTags ? format!"@%s "(tags) : "", args);
		if (sendTags) {
			formattedWrite!"@%s "(output, tags);
		}
		formattedWrite!fmt(output, args);
		put(output, "\r\n");
		debug {
			tryCall!"onSend"(format!fmt(args));
		}
		static if (is(typeof(output.flush()))) {
			output.flush();
		}
	}
	private void write(const scope string text) @safe {
		write!"%s"(text);
	}
	private void writeList(string prefix, string separator, T)(T range) if (isInputRange!T && is(Unqual!(ElementType!T) == string)) {
		write!(prefix~"%-(%s"~separator~"%)")(range);
	}
	private bool isEnabled(const Capability cap) @safe {
		return capsEnabled.canFind(cap);
	}
	private void tryCall(string func, T...)(const T params) {
		if (__traits(getMember, this, func) !is null) {
			__traits(getMember, this, func)(params);
		}
	}
	auto me() const @safe {
		assert(nickinfo.nickname in internalAddressList);
		return internalAddressList[nickinfo.nickname];
	}
	//Message parsing functions follow
	private void rec(string cmd : IRCV3Commands.cap)(IRCMessage message, const MessageMetadata metadata) {
		auto tokens = message.args;
		immutable username = tokens.front; //Unused?
		tokens.popFront();
		immutable subCommand = tokens.front;
		tokens.popFront();
		immutable terminator = !tokens.skipOver("*");
		auto args = tokens
			.front
			.splitter(" ")
			.filter!(x => x != "")
			.map!(x => Capability(x));
		final switch (cast(CapabilityServerSubcommands) subCommand) {
			case CapabilityServerSubcommands.ls:
				recCapLS(args, metadata);
				break;
			case CapabilityServerSubcommands.list:
				recCapList(args, metadata);
				break;
			case CapabilityServerSubcommands.acknowledge:
				recCapAck(args, metadata);
				break;
			case CapabilityServerSubcommands.notAcknowledge:
				recCapNak(args, metadata);
				break;
			case CapabilityServerSubcommands.new_:
				recCapNew(args, metadata);
				break;
			case CapabilityServerSubcommands.delete_:
				recCapDel(args, metadata);
				break;
		}
	}
	private void recCapLS(T)(T caps, const MessageMetadata metadata) if (is(ElementType!T == Capability)) {
		auto requestCaps = caps.filter!(among!supportedCaps);
		state.capReqCount += requestCaps.save().walkLength;
		if (!requestCaps.empty) {
			write!"CAP REQ :%-(%s %)"(requestCaps);
		}
		foreach (ref cap; caps) {
			state.availableCapabilities[cap.name] = cap;
			tryCall!"onReceiveCapLS"(cap, metadata);
		}
	}
	private void recCapList(T)(T caps, const MessageMetadata metadata) if (is(ElementType!T == Capability)) {
		foreach (ref cap; caps) {
			state.availableCapabilities[cap.name] = cap;
			tryCall!"onReceiveCapList"(cap, metadata);
		}
	}
	private void recCapAck(T)(T caps, const MessageMetadata metadata) if (is(ElementType!T == Capability)) {
		import std.range : hasLength;
		capsEnabled ~= caps.save().array;
		foreach (ref cap; caps) {
			enableCapability(cap);
			tryCall!"onReceiveCapAck"(state.availableCapabilities[cap.name], metadata);
			static if (!hasLength!T) {
				capAcknowledgementCommon(1);
			}
		}
		static if (hasLength!T) {
			capAcknowledgementCommon(caps.length);
		}
	}
	private void recCapNak(T)(T caps, const MessageMetadata metadata) if (is(ElementType!T == Capability)) {
		import std.range : hasLength;
		foreach (ref cap; caps) {
			tryCall!"onReceiveCapNak"(state.availableCapabilities[cap.name], metadata);
			static if (!hasLength!T) {
				capAcknowledgementCommon(1);
			}
		}
		static if (hasLength!T) {
			capAcknowledgementCommon(caps.length);
		}
	}
	private void capAcknowledgementCommon(const size_t count) @safe {
		state.capReqCount -= count;
		tryEndRegistration();
	}
	private void recCapNew(T)(T caps, const MessageMetadata metadata) if (is(ElementType!T == Capability)) {
		auto requestCaps = caps.filter!(among!supportedCaps);
		state.capReqCount += requestCaps.save().walkLength;
		if (!requestCaps.empty) {
			write!"CAP REQ :%-(%s %)"(requestCaps);
		}
		foreach (ref cap; caps) {
			state.availableCapabilities[cap.name] = cap;
			tryCall!"onReceiveCapNew"(cap, metadata);
		}
	}
	private void recCapDel(T)(T caps, const MessageMetadata metadata) if (is(ElementType!T == Capability)) {
		import std.algorithm.mutation : remove;
		import std.algorithm.searching : countUntil;
		foreach (ref cap; caps) {
			state.availableCapabilities.remove(cap.name);
			auto findCap = countUntil(capsEnabled, cap);
			if (findCap > -1) {
				capsEnabled = capsEnabled.remove(findCap);
			}
			tryCall!"onReceiveCapDel"(cap, metadata);
		}
	}
	private void enableCapability(const Capability cap) @safe {
		import virc.keyvaluesplitter : splitKeyValues;
		import std.conv : to;
		const capDetails = state.availableCapabilities[cap.name];
		switch (cap.name) {
			case "sasl":
				state.supportedSASLMechs = capDetails.value.splitter(",").array;
				startSASL();
				break;
			case "draft/metadata-2":
				state.maxMetadataSubscriptions = ulong.max;
				state.maxMetadataSelfKeys = ulong.max;
				foreach (kv; capDetails.value.splitKeyValues) {
					switch (kv.key) {
						case "maxsub":
							if (!kv.value.isNull) {
								state.maxMetadataSubscriptions = kv.value.get.to!ulong;
							}
							break;
						case "maxkey":
							if (!kv.value.isNull) {
								state.maxMetadataSelfKeys = kv.value.get.to!ulong;
							}
							break;
						default: break;
					}
				}
				break;
			default: break;
		}
	}
	private void startSASL() @safe {
		if (state.supportedSASLMechs.empty && !saslMechs.empty) {
			state.autoSelectSASLMech = true;
			saslAuth(saslMechs.front);
		} else if (!state.supportedSASLMechs.empty && !saslMechs.empty) {
			foreach (id, mech; saslMechs) {
				if (state.supportedSASLMechs.canFind(mech.name)) {
					saslAuth(mech);
				}
			}
		}
	}
	private void saslAuth(SASLMechanism mech) @safe {
		state.selectedSASLMech = mech;
		write!"AUTHENTICATE %s"(mech.name);
		state.isAuthenticating = true;
	}
	private void rec(string cmd : RFC1459Commands.kick)(IRCMessage message, const MessageMetadata metadata) {
		auto split = message.args;
		auto source = message.sourceUser.get;
		if (split.empty) {
			return;
		}
		Channel channel = Channel(split.front);
		split.popFront();
		if (split.empty) {
			return;
		}
		User victim = User(split.front);
		split.popFront();
		string msg;

		if (!split.empty) {
			msg = split.front;
		}

		tryCall!"onChannelListUpdate"(victim, victim, channel, ChannelListUpdateType.removed);
		tryCall!"onKick"(source, channel, victim, msg, metadata);
	}
	private void rec(string cmd : RFC1459Commands.wallops)(IRCMessage message, const MessageMetadata metadata) {
		tryCall!"onWallops"(message.sourceUser.get, message.args.front, metadata);
	}
	private void rec(string cmd : RFC1459Commands.mode)(IRCMessage message, const MessageMetadata metadata) {
		auto split = message.args;
		auto source = message.sourceUser.get;
		auto target = Target(split.front, server.iSupport.statusMessage, server.iSupport.channelTypes);
		split.popFront();
		ModeType[char] modeTypes;
		if (target.isChannel) {
			modeTypes = server.iSupport.channelModeTypes;
		} else {
			//there are no user mode types.
		}
		auto modes = parseModeString(split, modeTypes);
		foreach (mode; modes) {
			tryCall!"onMode"(source, target, mode, metadata);
		}
	}
	private void rec(string cmd : RFC1459Commands.join)(IRCMessage message, const MessageMetadata metadata) {
		auto split = message.args;
		auto channel = Channel(split.front);
		auto source = message.sourceUser.get;
		split.popFront();
		if (isEnabled(Capability("extended-join"))) {
			if (split.front != "*") {
				source.account = split.front;
			}
			split.popFront();
			source.realName = split.front;
			split.popFront();
		}
		if (server.iSupport.whoX) {
			write!"WHO %s %%uihsnflar"(channel);
		}
		if (channel.name !in channels) {
			channels[channel.name] = ChannelState(Channel(channel.name));
		}
		internalAddressList.update(source);
		if (source.nickname in internalAddressList) {
			channels[channel.name].users.update(internalAddressList[source.nickname]);
		}
		tryCall!"onChannelListUpdate"(source, source, channel, ChannelListUpdateType.added);
		tryCall!"onJoin"(source, channel, metadata);
	}
	private void rec(string cmd : RFC1459Commands.part)(IRCMessage message, const MessageMetadata metadata) {
		import std.algorithm.mutation : remove;
		import std.algorithm.searching : countUntil;
		auto split = message.args;
		auto user = message.sourceUser.get;
		auto channel = Channel(split.front);
		split.popFront();
		string msg;
		if (!split.empty) {
			msg = split.front;
		}
		if ((channel.name in channels) && (user.nickname in channels[channel.name].users)) {
			channels[channel.name].users.invalidate(user.nickname);
		}
		if ((user == me) && (channel.name in channels)) {
			channels.remove(channel.name);
		}
		tryCall!"onChannelListUpdate"(user, user, channel, ChannelListUpdateType.removed);
		tryCall!"onPart"(user, channel, msg, metadata);
	}
	private void rec(string cmd : RFC1459Commands.notice)(IRCMessage message, const MessageMetadata metadata) {
		auto split = message.args;
		auto user = message.sourceUser.get;
		auto target = Target(split.front, server.iSupport.statusMessage, server.iSupport.channelTypes);
		split.popFront();
		auto msg = Message(split.front, MessageType.notice);
		recMessageCommon(user, target, msg, metadata);
	}
	private void rec(string cmd : RFC1459Commands.privmsg)(IRCMessage message, const MessageMetadata metadata) {
		auto split = message.args;
		auto user = message.sourceUser.get;
		auto target = Target(split.front, server.iSupport.statusMessage, server.iSupport.channelTypes);
		split.popFront();
		if (split.empty) {
			return;
		}
		auto msg = Message(split.front, MessageType.privmsg);
		recMessageCommon(user, target, msg, metadata);
	}
	private void recMessageCommon(const User user, const Target target, Message msg, const MessageMetadata metadata) @safe {
		if (user.nickname == nickinfo.nickname) {
			msg.isEcho = true;
		}
		tryCall!"onMessage"(user, target, msg, metadata);
	}
	private void rec(string cmd : Numeric.RPL_ISUPPORT)(IRCMessage message, const MessageMetadata metadata) {
		auto split = message.args;
		switch (split.save().canFind("UHNAMES", "NAMESX")) {
			case 1:
				if (!isEnabled(Capability("userhost-in-names"))) {
					write("PROTOCTL UHNAMES");
				}
				break;
			case 2:
				if (!isEnabled(Capability("multi-prefix"))) {
					write("PROTOCTL NAMESX");
				}
				break;
			default: break;
		}
		parseNumeric!(Numeric.RPL_ISUPPORT)(split, server.iSupport);
	}
	private void rec(string cmd : Numeric.RPL_WELCOME)(IRCMessage message, const MessageMetadata metadata) {
		state.isRegistered = true;
		if (!message.args.empty && (message.args.front != "*") && (User(message.args.front).nickname != nickinfo.nickname)) {
			nickinfo.nickname = User(message.args.front).nickname;
		}
		auto meUser = User();
		meUser.mask.nickname = nickinfo.nickname;
		meUser.mask.ident = nickinfo.username;
		meUser.mask.host = "127.0.0.1";
		internalAddressList.update(meUser);
		tryCall!"onConnect"();
	}
	private void rec(string cmd : Numeric.RPL_LOGGEDIN)(IRCMessage message, const MessageMetadata metadata) {
		import virc.numerics.sasl : parseNumeric;
		if (state.isAuthenticating || isAuthenticated) {
			auto parsed = parseNumeric!(Numeric.RPL_LOGGEDIN)(message.args);
			auto user = User(parsed.get.mask);
			user.account = parsed.get.account;
			internalAddressList.update(user);
		}
	}
	private void rec(string cmd)(IRCMessage message, const MessageMetadata metadata) if (cmd.among(Numeric.ERR_NICKLOCKED, Numeric.ERR_SASLFAIL, Numeric.ERR_SASLTOOLONG, Numeric.ERR_SASLABORTED)) {
		endAuthentication();
	}
	private void rec(string cmd : Numeric.RPL_MYINFO)(IRCMessage message, const MessageMetadata metadata) {
		server.myInfo = parseNumeric!(Numeric.RPL_MYINFO)(message.args).get;
	}
	private void rec(string cmd : Numeric.RPL_LUSERCLIENT)(IRCMessage message, const MessageMetadata metadata) {
		tryCall!"onLUserClient"(parseNumeric!(Numeric.RPL_LUSERCLIENT)(message.args), metadata);
	}
	private void rec(string cmd : Numeric.RPL_LUSEROP)(IRCMessage message, const MessageMetadata metadata) {
		tryCall!"onLUserOp"(parseNumeric!(Numeric.RPL_LUSEROP)(message.args), metadata);
	}
	private void rec(string cmd : Numeric.RPL_LUSERCHANNELS)(IRCMessage message, const MessageMetadata metadata) {
		tryCall!"onLUserChannels"(parseNumeric!(Numeric.RPL_LUSERCHANNELS)(message.args), metadata);
	}
	private void rec(string cmd : Numeric.RPL_LUSERME)(IRCMessage message, const MessageMetadata metadata) {
		tryCall!"onLUserMe"(parseNumeric!(Numeric.RPL_LUSERME)(message.args), metadata);
	}
	private void rec(string cmd : Numeric.RPL_YOUREOPER)(IRCMessage message, const MessageMetadata metadata) {
		tryCall!"onYoureOper"(metadata);
	}
	private void rec(string cmd : Numeric.ERR_NOMOTD)(IRCMessage message, const MessageMetadata metadata) {
		tryCall!"onError"(IRCError(ErrorType.noMOTD), metadata);
	}
	private void rec(string cmd : Numeric.RPL_SASLSUCCESS)(IRCMessage message, const MessageMetadata metadata) {
		if (state.selectedSASLMech) {
			state.authenticationSucceeded = true;
		}
		endAuthentication();
	}
	private void rec(string cmd : Numeric.RPL_LIST)(IRCMessage message, const MessageMetadata metadata) {
		auto channel = parseNumeric!(Numeric.RPL_LIST)(message.args, server.iSupport.channelModeTypes);
		tryCall!"onList"(channel, metadata);
	}
	private void rec(string cmd : RFC1459Commands.ping)(IRCMessage message, const MessageMetadata) {
		pong(message.args.front);
	}
	private void rec(string cmd : Numeric.RPL_ISON)(IRCMessage message, const MessageMetadata metadata) {
		auto reply = parseNumeric!(Numeric.RPL_ISON)(message.args);
		if (!reply.isNull) {
			foreach (online; reply.get.online) {
				internalAddressList.update(User(online));
				tryCall!"onIsOn"(internalAddressList[online], metadata);
			}
		} else {
			tryCall!"onError"(IRCError(ErrorType.malformed), metadata);
		}
	}
	private void rec(string cmd : Numeric.RPL_MONONLINE)(IRCMessage message, const MessageMetadata metadata) {
		auto users = parseNumeric!(Numeric.RPL_MONONLINE)(message.args);
		foreach (user; users) {
			tryCall!"onUserOnline"(user, SysTime.init, metadata);
		}
	}
	private void rec(string cmd : Numeric.RPL_MONOFFLINE)(IRCMessage message, const MessageMetadata metadata) {
		auto users = parseNumeric!(Numeric.RPL_MONOFFLINE)(message.args);
		foreach (user; users) {
			tryCall!"onUserOffline"(user, metadata);
		}
	}
	private void rec(string cmd : Numeric.RPL_MONLIST)(IRCMessage message, const MessageMetadata metadata) {
		auto users = parseNumeric!(Numeric.RPL_MONLIST)(message.args);
		foreach (user; users) {
			tryCall!"onMonitorList"(user, metadata);
		}
	}
	private void rec(string cmd : Numeric.ERR_MONLISTFULL)(IRCMessage message, const MessageMetadata metadata) {
		auto err = parseNumeric!(Numeric.ERR_MONLISTFULL)(message.args);
		tryCall!"onError"(IRCError(ErrorType.monListFull), metadata);
	}
	private void rec(string cmd : Numeric.RPL_VERSION)(IRCMessage message, const MessageMetadata metadata) {
		auto versionReply = parseNumeric!(Numeric.RPL_VERSION)(message.args);
		tryCall!"onVersionReply"(versionReply.get, metadata);
	}
	private void rec(string cmd : Numeric.RPL_LOGON)(IRCMessage message, const MessageMetadata metadata) {
		auto reply = parseNumeric!(Numeric.RPL_LOGON)(message.args);
		tryCall!"onUserOnline"(reply.user, reply.timeOccurred, metadata);
	}
	private void rec(string cmd : IRCV3Commands.chghost)(IRCMessage message, const MessageMetadata metadata) {
		User target;
		auto split = message.args;
		auto user = message.sourceUser.get;
		target.mask.nickname = user.nickname;
		target.mask.ident = split.front;
		split.popFront();
		target.mask.host = split.front;
		internalAddressList.update(target);
		tryCall!"onChgHost"(user, target, metadata);
	}
	private void rec(string cmd : Numeric.RPL_TOPICWHOTIME)(IRCMessage message, const MessageMetadata metadata) {
		auto reply = parseNumeric!(Numeric.RPL_TOPICWHOTIME)(message.args);
		if (!reply.isNull) {
			tryCall!"onTopicWhoTimeReply"(reply.get, metadata);
		}
	}
	private void rec(string cmd : Numeric.RPL_AWAY)(IRCMessage message, const MessageMetadata metadata) {
		auto reply = parseNumeric!(Numeric.RPL_AWAY)(message.args);
		if (!reply.isNull) {
			tryCall!"onOtherUserAwayReply"(reply.get.user, reply.get.message, metadata);
		}
	}
	private void rec(string cmd : Numeric.RPL_UNAWAY)(IRCMessage message, const MessageMetadata metadata) {
		tryCall!"onUnAwayReply"(message.sourceUser.get, metadata);
		state._isAway = false;
	}
	private void rec(string cmd : Numeric.RPL_NOWAWAY)(IRCMessage message, const MessageMetadata metadata) {
		tryCall!"onAwayReply"(message.sourceUser.get, metadata);
		state._isAway = true;
	}
	private void rec(string cmd : Numeric.RPL_TOPIC)(IRCMessage message, const MessageMetadata metadata) {
		auto reply = parseNumeric!(Numeric.RPL_TOPIC)(message.args);
		if (!reply.isNull) {
			tryCall!"onTopicReply"(reply.get, metadata);
		}
	}
	private void rec(string cmd : RFC1459Commands.topic)(IRCMessage message, const MessageMetadata metadata) {
		auto split = message.args;
		auto user = message.sourceUser.get;
		if (split.empty) {
			tryCall!"onError"(IRCError(ErrorType.malformed), metadata);
			return;
		}
		auto target = Channel(split.front);
		split.popFront();
		if (split.empty) {
			tryCall!"onError"(IRCError(ErrorType.malformed), metadata);
			return;
		}
		auto msg = split.front;
		tryCall!"onTopicChange"(user, target, msg, metadata);
	}
	private void rec(string cmd : RFC1459Commands.nick)(IRCMessage message, const MessageMetadata metadata) {
		auto split = message.args;
		if (!split.empty) {
			auto old = message.sourceUser.get;
			auto newNick = split.front;
			internalAddressList.renameTo(old, newNick);
			foreach (ref channel; channels) {
				if (old.nickname in channel.users) {
					channel.users.renameTo(old, newNick);
				}
			}
			auto new_ = internalAddressList[newNick];
			if (old.nickname == nickinfo.nickname) {
				nickinfo.nickname = new_.nickname;
			}
			tryCall!"onNick"(old, new_, metadata);
		}
	}
	private void rec(string cmd : RFC1459Commands.invite)(IRCMessage message, const MessageMetadata metadata) {
		auto split = message.args;
		auto inviter = message.sourceUser.get;
		if (!split.empty) {
			User invited;
			if (split.front in internalAddressList) {
				invited = internalAddressList[split.front];
			} else {
				invited = User(split.front);
			}
			split.popFront();
			if (!split.empty) {
				auto channel = Channel(split.front);
				tryCall!"onInvite"(inviter, invited, channel, metadata);
			}
		}
	}
	private void rec(string cmd : RFC1459Commands.quit)(IRCMessage message, const MessageMetadata metadata) {
		auto split = message.args;
		auto user = message.sourceUser.get;
		string msg;
		if (!split.empty) {
			msg = split.front;
		}
		foreach (ref channel; channels) {
			if (user.nickname in channel.users) {
				tryCall!"onChannelListUpdate"(user, user, channel.channel, ChannelListUpdateType.added);
			}
		}
		if (isMe(user)) {
			state.invalid = true;
		}
		tryCall!"onQuit"(user, msg, metadata);
		internalAddressList.invalidate(user.nickname);
	}
	private void recUnknownCommand(const string cmd, const MessageMetadata metadata) @safe {
		if (cmd.filter!(x => !x.isDigit).empty) {
			recUnknownNumeric(cmd, metadata);
		} else {
			tryCall!"onError"(IRCError(ErrorType.unrecognized, cmd), metadata);
			debug(verboseirc) import std.experimental.logger : trace;
			debug(verboseirc) trace(" Unknown command: ", metadata.original);
		}
	}
	private void rec(string cmd : Numeric.RPL_NAMREPLY)(IRCMessage message, const MessageMetadata metadata) {
		auto reply = parseNumeric!(Numeric.RPL_NAMREPLY)(message.args);
		foreach (user; reply.get.users(server.iSupport.prefixes)) {
			internalAddressList.update(User(user.name));
		}
		if (reply.get.channel in channels) {
			foreach (user; reply.get.users(server.iSupport.prefixes)) {
				const newUser = User(user.name);
				channels[reply.get.channel].users.update(newUser);
				if (newUser != me) {
					tryCall!"onChannelListUpdate"(newUser, newUser, Channel(reply.get.channel), ChannelListUpdateType.added);
				}
			}
		}
		if (!reply.isNull) {
			tryCall!"onNamesReply"(reply.get, metadata);
		}
	}
	private void rec(string cmd : Numeric.RPL_WHOSPCRPL)(IRCMessage message, const MessageMetadata metadata) {
		auto reply = parseNumeric!(Numeric.RPL_WHOSPCRPL)(message.args, "uihsnflar");
		if (!reply.isNull) {
			User user;
			user.account = reply.get.account;
			user.realName = reply.get.realname;
			user.mask.ident = reply.get.ident;
			user.mask.host = reply.get.host;
			user.mask.nickname = reply.get.nick.get;
			auto oldUser = internalAddressList[user.mask.nickname];
			internalAddressList.update(user);
			foreach (ref channel; channels) {
				if (user.nickname in channel.users) {
					tryCall!"onChannelListUpdate"(user, oldUser, channel.channel, ChannelListUpdateType.updated);
				}
			}
			tryCall!"onWHOXReply"(reply.get, metadata);
		}
	}
	private void rec(string cmd : Numeric.RPL_REHASHING)(IRCMessage message, const MessageMetadata metadata) {
		auto reply = parseNumeric!(Numeric.RPL_REHASHING)(message.args);
		if (!reply.isNull) {
			tryCall!"onServerRehashing"(reply.get, metadata);
		}
	}
	private void rec(string cmd : Numeric.ERR_NOPRIVS)(IRCMessage message, const MessageMetadata metadata) {
		auto reply = parseNumeric!(Numeric.ERR_NOPRIVS)(message.args);
		if (!reply.isNull) {
			tryCall!"onError"(IRCError(ErrorType.noPrivs, reply.get.priv), metadata);
		} else {
			tryCall!"onError"(IRCError(ErrorType.malformed), metadata);
		}
	}
	private void rec(string cmd : Numeric.ERR_NOPRIVILEGES)(IRCMessage message, const MessageMetadata metadata) {
		tryCall!"onError"(IRCError(ErrorType.noPrivileges), metadata);
	}
	private void rec(string cmd : Numeric.ERR_NOSUCHSERVER)(IRCMessage message, const MessageMetadata metadata) {
		auto reply = parseNumeric!(Numeric.ERR_NOSUCHSERVER)(message.args);
		if (!reply.isNull) {
			tryCall!"onError"(IRCError(ErrorType.noSuchServer, reply.get.serverMask), metadata);
		} else {
			tryCall!"onError"(IRCError(ErrorType.malformed), metadata);
		}
	}
	private void rec(string cmd : Numeric.RPL_ENDOFWHOIS)(IRCMessage message, const MessageMetadata metadata) {
		auto reply = parseNumeric!(Numeric.RPL_ENDOFWHOIS)(message.args);
		if (!reply.isNull) {
			if (reply.get.user.nickname in state.whoisCache) {
				tryCall!"onWhois"(reply.get.user, state.whoisCache[reply.get.user.nickname]);
				state.whoisCache.remove(reply.get.user.nickname);
			} else {
				tryCall!"onError"(IRCError(ErrorType.unexpected, "empty WHOIS data returned"), metadata);
			}
		} else {
			tryCall!"onError"(IRCError(ErrorType.malformed), metadata);
		}
	}
	private void rec(string cmd : Numeric.RPL_WHOISUSER)(IRCMessage message, const MessageMetadata metadata) {
		auto reply = parseNumeric!(Numeric.RPL_WHOISUSER)(message.args);
		if (!reply.isNull) {
			if (reply.get.user.nickname !in state.whoisCache) {
				state.whoisCache[reply.get.user.nickname] = WhoisResponse();
			}
			state.whoisCache[reply.get.user.nickname].username = reply.get.username;
			state.whoisCache[reply.get.user.nickname].hostname = reply.get.hostname;
			state.whoisCache[reply.get.user.nickname].realname = reply.get.realname;
		} else {
			tryCall!"onError"(IRCError(ErrorType.malformed), metadata);
		}
	}
	private void rec(string cmd : Numeric.RPL_WHOISSECURE)(IRCMessage message, const MessageMetadata metadata) {
		auto reply = parseNumeric!(Numeric.RPL_WHOISSECURE)(message.args);
		if (!reply.isNull) {
			if (reply.get.user.nickname !in state.whoisCache) {
				state.whoisCache[reply.get.user.nickname] = WhoisResponse();
			}
			state.whoisCache[reply.get.user.nickname].isSecure = true;
		} else {
			tryCall!"onError"(IRCError(ErrorType.malformed), metadata);
		}
	}
	private void rec(string cmd : Numeric.RPL_WHOISOPERATOR)(IRCMessage message, const MessageMetadata metadata) {
		auto reply = parseNumeric!(Numeric.RPL_WHOISOPERATOR)(message.args);
		if (!reply.isNull) {
			if (reply.get.user.nickname !in state.whoisCache) {
				state.whoisCache[reply.get.user.nickname] = WhoisResponse();
			}
			state.whoisCache[reply.get.user.nickname].isOper = true;
		} else {
			tryCall!"onError"(IRCError(ErrorType.malformed), metadata);
		}
	}
	private void rec(string cmd : Numeric.RPL_WHOISREGNICK)(IRCMessage message, const MessageMetadata metadata) {
		auto reply = parseNumeric!(Numeric.RPL_WHOISREGNICK)(message.args);
		if (!reply.isNull) {
			if (reply.get.user.nickname !in state.whoisCache) {
				state.whoisCache[reply.get.user.nickname] = WhoisResponse();
			}
			state.whoisCache[reply.get.user.nickname].isRegistered = true;
		} else {
			tryCall!"onError"(IRCError(ErrorType.malformed), metadata);
		}
	}
	private void rec(string cmd : Numeric.RPL_WHOISIDLE)(IRCMessage message, const MessageMetadata metadata) {
		auto reply = parseNumeric!(Numeric.RPL_WHOISIDLE)(message.args);
		if (!reply.isNull) {
			if (reply.user.get.nickname !in state.whoisCache) {
				state.whoisCache[reply.user.get.nickname] = WhoisResponse();
			}
			state.whoisCache[reply.user.get.nickname].idleTime = reply.idleTime;
			state.whoisCache[reply.user.get.nickname].connectedTime = reply.connectedTime;
		} else {
			tryCall!"onError"(IRCError(ErrorType.malformed), metadata);
		}
	}
	private void rec(string cmd : Numeric.RPL_WHOISSERVER)(IRCMessage message, const MessageMetadata metadata) {
		auto reply = parseNumeric!(Numeric.RPL_WHOISSERVER)(message.args);
		if (!reply.isNull) {
			if (reply.get.user.nickname !in state.whoisCache) {
				state.whoisCache[reply.get.user.nickname] = WhoisResponse();
			}
			state.whoisCache[reply.get.user.nickname].connectedTo = reply.get.server;
		} else {
			tryCall!"onError"(IRCError(ErrorType.malformed), metadata);
		}
	}
	private void rec(string cmd : Numeric.RPL_WHOISACCOUNT)(IRCMessage message, const MessageMetadata metadata) {
		auto reply = parseNumeric!(Numeric.RPL_WHOISACCOUNT)(message.args);
		if (!reply.isNull) {
			if (reply.get.user.nickname !in state.whoisCache) {
				state.whoisCache[reply.get.user.nickname] = WhoisResponse();
			}
			state.whoisCache[reply.get.user.nickname].account = reply.get.account;
		} else {
			tryCall!"onError"(IRCError(ErrorType.malformed), metadata);
		}
	}
	private void rec(string cmd : IRCV3Commands.metadata)(IRCMessage message, const MessageMetadata metadata) {
		auto split = message.args;
		auto target = Target(split.front, server.iSupport.statusMessage, server.iSupport.channelTypes);
		split.popFront();
		auto key = split.front;
		split.popFront();
		auto visibility = split.front;
		split.popFront();
		if (split.empty) {
			deleteMetadataCommon(target, key);
		} else {
			setMetadataCommon(target, visibility, key, split.front);
		}
	}
	private void rec(string cmd : Numeric.RPL_WHOISKEYVALUE)(IRCMessage message, const MessageMetadata metadata) {
		auto split = message.args;
		string prefixes;
		foreach (k,v; server.iSupport.prefixes) {
			prefixes ~= v;
		}
		auto reply = parseNumeric!(Numeric.RPL_WHOISKEYVALUE)(split, prefixes, server.iSupport.channelTypes);
		if (!reply.isNull) {
			setMetadataCommon(reply.get.target, reply.get.visibility, reply.get.key, reply.get.value);
		} else {
			tryCall!"onError"(IRCError(ErrorType.malformed), metadata);
		}
	}
	private void rec(string cmd : Numeric.RPL_KEYVALUE)(IRCMessage message, const MessageMetadata metadata) {
		auto split = message.args;
		string prefixes;
		foreach (k,v; server.iSupport.prefixes) {
			prefixes ~= v;
		}
		auto reply = parseNumeric!(Numeric.RPL_KEYVALUE)(split, prefixes, server.iSupport.channelTypes);
		if (!reply.isNull) {
			if (reply.get.value.isNull) {
				deleteMetadataCommon(reply.get.target, reply.get.key);
			} else {
				setMetadataCommon(reply.get.target, reply.get.visibility, reply.get.key, reply.get.value.get);
			}
		} else {
			tryCall!"onError"(IRCError(ErrorType.malformed), metadata);
		}
	}
	private void setMetadataCommon(Target target, string visibility, string key, string value) @safe pure {
		if (target.isUser && target.user == User("*")) {
			userMetadata[me][key] = MetadataValue(visibility, value);
		} else if (target.isChannel) {
			channelMetadata[target.channel.get][key] = MetadataValue(visibility, value);
		} else if (target.isUser) {
			userMetadata[target.user.get][key] = MetadataValue(visibility, value);
		}
	}
	private void deleteMetadataCommon(Target target, string key) @safe pure {
		if (target.isUser && target.user == User("*")) {
			userMetadata[me].remove(key);
		} else if (target.isChannel) {
			channelMetadata[target.channel.get].remove(key);
		} else if (target.isUser) {
			userMetadata[target.user.get].remove(key);
		}
	}
	private void rec(string cmd : Numeric.RPL_METADATASUBOK)(IRCMessage message, const MessageMetadata metadata) {
		auto parsed = parseNumeric!(Numeric.RPL_METADATASUBOK)(message.args);
		if (!parsed.isNull) {
			foreach (sub; parsed.get.subs) {
				if (!state.metadataSubscribedKeys.canFind(sub)) {
					state.metadataSubscribedKeys ~= sub;
				}
			}
		} else {
			tryCall!"onError"(IRCError(ErrorType.malformed), metadata);
		}
	}
	private void rec(string cmd : Numeric.RPL_METADATAUNSUBOK)(IRCMessage message, const MessageMetadata metadata) {
		auto parsed = parseNumeric!(Numeric.RPL_METADATAUNSUBOK)(message.args);
		if (!parsed.isNull) {
			state.metadataSubscribedKeys = state.metadataSubscribedKeys.filter!(x => !parsed.get.subs.canFind(x)).array;
		} else {
			tryCall!"onError"(IRCError(ErrorType.malformed), metadata);
		}
	}
	private void rec(string cmd : Numeric.RPL_METADATASUBS)(IRCMessage message, const MessageMetadata metadata) {
		auto reply = parseNumeric!(Numeric.RPL_METADATASUBS)(message.args);
		if (!reply.isNull) {
			foreach (sub; reply.get.subs) {
				tryCall!"onMetadataSubList"(sub, metadata);
			}
		} else {
			tryCall!"onError"(IRCError(ErrorType.malformed), metadata);
		}
	}
	private void rec(string cmd : Numeric.RPL_KEYNOTSET)(IRCMessage message, const MessageMetadata metadata) {
		auto split = message.args;
		string prefixes;
		foreach (k,v; server.iSupport.prefixes) {
			prefixes ~= v;
		}
		auto err = parseNumeric!(Numeric.RPL_KEYNOTSET)(split, prefixes, server.iSupport.channelTypes);
		tryCall!"onError"(IRCError(ErrorType.keyNotSet, err.get.humanReadable), metadata);
	}
	private void rec(string cmd : Numeric.ERR_METADATASYNCLATER)(IRCMessage message, const MessageMetadata metadata) {
		auto split = message.args;
		string prefixes;
		foreach (k,v; server.iSupport.prefixes) {
			prefixes ~= v;
		}
		auto err = parseNumeric!(Numeric.ERR_METADATASYNCLATER)(split, prefixes, server.iSupport.channelTypes);
		tryCall!"onError"(IRCError(ErrorType.waitAndRetry), metadata);
	}
	private void rec(string cmd : Numeric.RPL_WHOISCHANNELS)(IRCMessage message, const MessageMetadata metadata) {
		string prefixes;
		foreach (k,v; server.iSupport.prefixes) {
			prefixes ~= v;
		}
		auto reply = parseNumeric!(Numeric.RPL_WHOISCHANNELS)(message.args, prefixes, server.iSupport.channelTypes);
		if (!reply.isNull) {
			if (reply.get.user.nickname !in state.whoisCache) {
				state.whoisCache[reply.get.user.nickname] = WhoisResponse();
			}
			foreach (channel; reply.get.channels) {
				auto whoisChannel = WhoisChannel();
				whoisChannel.name = channel.channel;
				if (!channel.prefix.isNull) {
					whoisChannel.prefix = channel.prefix.get;
				}
				state.whoisCache[reply.get.user.nickname].channels[channel.channel.name] = whoisChannel;
			}
		} else {
			tryCall!"onError"(IRCError(ErrorType.malformed), metadata);
		}
	}
	private void recUnknownNumeric(const string cmd, const MessageMetadata metadata) @safe {
		tryCall!"onError"(IRCError(ErrorType.unrecognized, cmd), metadata);
		debug(verboseirc) import std.experimental.logger : trace;
		debug(verboseirc) trace("Unhandled numeric: ", cast(Numeric)cmd, " ", metadata.original);
	}
	private void rec(string cmd : IRCV3Commands.account)(IRCMessage message, const MessageMetadata metadata) {
		auto split = message.args;
		if (!split.empty) {
			auto user = message.sourceUser.get;
			auto newAccount = split.front;
			internalAddressList.update(user);
			auto newUser = internalAddressList[user.nickname];
			if (newAccount == "*") {
				newUser.account.nullify();
			} else {
				newUser.account = newAccount;
			}
			internalAddressList.updateExact(newUser);
		}
	}
	private void rec(string cmd : IRCV3Commands.authenticate)(IRCMessage message, const MessageMetadata metadata) {
		import std.base64 : Base64;
		auto split = message.args;
		if (split.front != "+") {
			state.receivedSASLAuthenticationText ~= Base64.decode(split.front);
		}
		if ((state.selectedSASLMech) && (split.front == "+" || (split.front.length < 400))) {
			state.selectedSASLMech.put(state.receivedSASLAuthenticationText);
			if (state.selectedSASLMech.empty) {
				sendAuthenticatePayload("");
			} else {
				sendAuthenticatePayload(state.selectedSASLMech.front);
				state.selectedSASLMech.popFront();
			}
			state.receivedSASLAuthenticationText = [];
		}
	}
	private void rec(string cmd : IRCV3Commands.note)(IRCMessage message, const MessageMetadata metadata) {
	}
	private void rec(string cmd : IRCV3Commands.warn)(IRCMessage message, const MessageMetadata metadata) {
	}
	private void rec(string cmd : IRCV3Commands.fail)(IRCMessage message, const MessageMetadata metadata) {
		tryCall!"onError"(IRCError(ErrorType.standardFail, cmd), metadata);
	}
	bool isMe(const User user) const pure @safe nothrow {
		return user == me;
	}
	bool isValid() const pure @safe nothrow {
		return !state.invalid;
	}
	bool isRegistered() const pure @safe nothrow {
		return state.isRegistered;
	}
}
version(unittest) {
	import std.algorithm : equal, sort, until;
	import std.array : appender, array;
	import std.range: drop, empty, tail;
	import std.stdio : writeln;
	import std.string : lineSplitter, representation;
	import std.typecons : Tuple, tuple;
	import virc.ircv3 : Capability;
	static immutable testClientInfo = NickInfo("someone", "ident", "real name!");
	static immutable testUser = User(testClientInfo.nickname, testClientInfo.username, "example.org");
	mixin template Test() {
		bool lineReceived;
		void onRaw(const MessageMetadata) @safe pure {
			lineReceived = true;
		}
	}
	void setupFakeConnection(T)(ref T client) {
		if (!client.onError) {
			client.onError = (const IRCError error, const MessageMetadata metadata) {
				writeln(metadata.time, " - ", error.type, " - ", metadata.original);
			};
		}
		client.put(":localhost 001 someone :Welcome to the TestNet IRC Network "~testUser.text);
		client.put(":localhost 002 someone :Your host is localhost, running version IRCd-2.0");
		client.put(":localhost 003 someone :This server was created 20:21:33 Oct  21 2016");
		client.put(":localhost 004 someone localhost IRCd-2.0 BGHIRSWcdgikorswx ABCDFGIJKLMNOPQRSTYabcefghijklmnopqrstuvz FIJLYabefghjkloqv");
		client.put(":localhost 005 someone AWAYLEN=200 CALLERID=g CASEMAPPING=rfc1459 CHANMODES=IYbeg,k,FJLfjl,ABCDGKMNOPQRSTcimnprstuz CHANNELLEN=31 CHANTYPES=# CHARSET=ascii ELIST=MU ESILENCE EXCEPTS=e EXTBAN=,ABCNOQRSTUcjmprsz FNC INVEX=I :are supported by this server");
		client.put(":localhost 005 someone KICKLEN=255 MAP MAXBANS=60 MAXCHANNELS=25 MAXPARA=32 MAXTARGETS=20 MODES=10 NAMESX NETWORK=TestNet NICKLEN=31 OPERLOG OVERRIDE PREFIX=(qaohv)~&@%+ :are supported by this server");
		client.put(":localhost 005 someone REMOVE SECURELIST SILENCE=32 SSL=[::]:6697 STARTTLS STATUSMSG=~&@%+ TOPICLEN=307 UHNAMES USERIP VBANLIST WALLCHOPS WALLVOICES WATCH=1000 WHOX :are supported by this server");
		assert(client.isRegistered);
		assert(client.server.iSupport.userhostsInNames == true);
	}
	void initializeCaps(T)(ref T client) {
		initializeWithCaps(client, [Capability("multi-prefix"), Capability("server-time"), Capability("sasl", "EXTERNAL")]);
	}
	void initializeWithCaps(T)(ref T client, Capability[] caps) {
		foreach (i, cap; caps) {
			client.put(":localhost CAP * LS " ~ ((i+1 == caps.length) ? "" : "* ")~ ":" ~ cap.toString);
			client.put(":localhost CAP * ACK :" ~ cap.name);
		}
		setupFakeConnection(client);
	}
	class Wrapper : Output {
		import std.array : Appender;
		Appender!string buffer;
		override void put(char c) @safe {
			buffer.put(c);
		}
		this(Appender!string buf) @safe {
			buffer = buf;
		}
	}
	auto data(Output o) @safe {
		return (cast(Wrapper)o).buffer.data;
	}
	auto spawnNoBufferClient(string password = string.init) {
		auto buffer = appender!(string);
		return ircClient(new Wrapper(buffer), testClientInfo, [], password);
	}
}
//Test the basics
@safe unittest {
	auto client = spawnNoBufferClient();
	bool lineReceived;
	client.onRaw = (_) {
		lineReceived = true;
	};
	client.put("");
	assert(lineReceived == false);
	client.put("\r\n");
	assert(lineReceived == false);
	client.put("hello");
	assert(lineReceived == true);
	assert(!client.isRegistered);
	client.put(":localhost 001 someone :words");
	assert(client.isRegistered);
	client.put(":localhost 001 someone :words");
	assert(client.isRegistered);
}
//Auto-decoding test
@safe unittest {
	auto client = spawnNoBufferClient();
	bool lineReceived;
	client.onRaw = (_) {
		lineReceived = true;
	};
	client.put("\r\n".representation);
	assert(lineReceived == false);
}
@safe unittest {
	import virc.ircv3 : Capability;
	{ //password test
		auto client = spawnNoBufferClient("Example");

		assert(client.output.data.lineSplitter.until!(x => x.startsWith("USER")).canFind("PASS :Example"));
	}
	//Request capabilities (IRC v3.2)
	{
		auto client = spawnNoBufferClient();
		client.put(":localhost CAP * LS :multi-prefix sasl");
		client.put(":localhost CAP * ACK :multi-prefix sasl");

		auto lineByLine = client.output.data.lineSplitter;

		assert(lineByLine.front == "CAP LS 302");
		lineByLine.popFront();
		lineByLine.popFront();
		lineByLine.popFront();
		//sasl not yet supported
		assert(lineByLine.front == "CAP REQ :multi-prefix sasl");
		lineByLine.popFront();
		assert(!lineByLine.empty);
		assert(lineByLine.front == "CAP END");
	}
	//Request capabilities NAK (IRC v3.2)
	{
		auto client = spawnNoBufferClient();
		Capability[] capabilities;
		client.onReceiveCapNak = (const Capability cap, const MessageMetadata) {
			capabilities ~= cap;
		};
		client.put(":localhost CAP * LS :multi-prefix");
		client.put(":localhost CAP * NAK :multi-prefix");


		auto lineByLine = client.output.data.lineSplitter;

		assert(lineByLine.front == "CAP LS 302");
		lineByLine.popFront();
		lineByLine.popFront();
		lineByLine.popFront();
		//sasl not yet supported
		assert(lineByLine.front == "CAP REQ :multi-prefix");
		lineByLine.popFront();
		assert(!lineByLine.empty);
		assert(lineByLine.front == "CAP END");

		assert(!client.capsEnabled.canFind("multi-prefix"));
		assert(capabilities.length == 1);
		assert(capabilities[0] == Capability("multi-prefix"));
	}
	//Request capabilities, multiline (IRC v3.2)
	{
		auto client = spawnNoBufferClient();
		auto lineByLine = client.output.data.lineSplitter();

		Capability[] capabilities;
		client.onReceiveCapLS = (const Capability cap, const MessageMetadata) {
			capabilities ~= cap;
		};

		assert(lineByLine.front == "CAP LS 302");

		put(client, ":localhost CAP * LS * :multi-prefix extended-join account-notify batch invite-notify tls");
		put(client, ":localhost CAP * LS * :cap-notify server-time example.org/dummy-cap=dummyvalue example.org/second-dummy-cap");
		put(client, ":localhost CAP * LS :userhost-in-names sasl=EXTERNAL,DH-AES,DH-BLOWFISH,ECDSA-NIST256P-CHALLENGE,PLAIN");
		assert(capabilities.length == 12);
		setupFakeConnection(client);
	}
	//CAP LIST multiline (IRC v3.2)
	{
		auto client = spawnNoBufferClient();
		Capability[] capabilities;
		client.onReceiveCapList = (const Capability cap, const MessageMetadata) {
			capabilities ~= cap;
		};
		setupFakeConnection(client);
		client.capList();
		client.put(":localhost CAP modernclient LIST * :example.org/example-cap example.org/second-example-cap account-notify");
		client.put(":localhost CAP modernclient LIST :invite-notify batch example.org/third-example-cap");
		assert(
			capabilities.array.sort().equal(
				[
					Capability("account-notify"),
					Capability("batch"),
					Capability("example.org/example-cap"),
					Capability("example.org/second-example-cap"),
					Capability("example.org/third-example-cap"),
					Capability("invite-notify")
				]
		));
	}
	//CAP NEW, DEL (IRCv3.2 - cap-notify)
	{
		auto client = spawnNoBufferClient();
		Capability[] capabilitiesNew;
		Capability[] capabilitiesDeleted;
		client.onReceiveCapNew = (const Capability cap, const MessageMetadata) {
			capabilitiesNew ~= cap;
		};
		client.onReceiveCapDel = (const Capability cap, const MessageMetadata) {
			capabilitiesDeleted ~= cap;
		};
		initializeWithCaps(client, [Capability("cap-notify"), Capability("userhost-in-names"), Capability("multi-prefix"), Capability("away-notify")]);

		assert(client.capsEnabled.length == 4);

		client.put(":irc.example.com CAP modernclient NEW :batch");
		assert(capabilitiesNew == [Capability("batch")]);
		client.put(":irc.example.com CAP modernclient ACK :batch");
		assert(
			client.capsEnabled.sort().equal(
				[
					Capability("away-notify"),
					Capability("batch"),
					Capability("cap-notify"),
					Capability("multi-prefix"),
					Capability("userhost-in-names")
				]
		));

		client.put(":irc.example.com CAP modernclient DEL :userhost-in-names multi-prefix away-notify");
		assert(
			capabilitiesDeleted.array.sort().equal(
				[
					Capability("away-notify"),
					Capability("multi-prefix"),
					Capability("userhost-in-names")
				]
		));
		assert(
			client.capsEnabled.sort().equal(
				[
					Capability("batch"),
					Capability("cap-notify")
				]
		));
		client.put(":irc.example.com CAP modernclient NEW :account-notify");
		auto lineByLine = client.output.data.lineSplitter();
		assert(lineByLine.array[$-1] == "CAP REQ :account-notify");
	}
	{ //JOIN
		auto client = spawnNoBufferClient();
		Tuple!(const User, "user", const Channel, "channel")[] joins;
		client.onJoin = (const User user, const Channel chan, const MessageMetadata) {
			joins ~= tuple!("user", "channel")(user, chan);
		};
		TopicWhoTime topicWhoTime;
		bool topicWhoTimeReceived;
		client.onTopicWhoTimeReply = (const TopicWhoTime twt, const MessageMetadata) {
			assert(!topicWhoTimeReceived);
			topicWhoTimeReceived = true;
			topicWhoTime = twt;
		};
		Tuple!(const User, "user", const Channel, "channel", ChannelListUpdateType, "type")[] updates;
		client.onChannelListUpdate = (const User user, const User old, const Channel chan, ChannelListUpdateType type) {
			updates ~= tuple!("user", "channel", "type")(user, chan, type);
		};
		NamesReply[] namesReplies;
		client.onNamesReply = (const NamesReply reply, const MessageMetadata) {
			namesReplies ~= reply;
		};
		TopicReply topicReply;
		bool topicReplyReceived;
		client.onTopicReply = (const TopicReply tr, const MessageMetadata) {
			assert(!topicReplyReceived);
			topicReplyReceived = true;
			topicReply = tr;
		};
		setupFakeConnection(client);
		client.join("#test");
		client.put(":someone!ident@hostmask JOIN :#test");
		client.put(":localhost 332 someone #test :a topic");
		client.put(":localhost 333 someone #test someoneElse :1496821983");
		client.put(":localhost 353 someone = #test :someone!ident@hostmask +@another!user@somewhere");
		client.put(":localhost 366 someone #test :End of /NAMES list.");
		client.put(":localhost 324 someone #test :+nt");
		client.put(":localhost 329 someone #test :1496821983");
		assert("someone" in client.internalAddressList);
		assert(client.internalAddressList["someone"] == User("someone!ident@hostmask"));
		assert(client.internalAddressList["someone"].account.isNull);
		client.put(":localhost 354 someone ident 127.0.0.1 hostmask localhost someone H@r 0 SomeoneAccount * :a real name");
		client.put(":localhost 354 someone ident 127.0.0.2 somewhere localhost another H@r 66 SomeoneElseAccount * :a different real name");
		client.put(":localhost 315 someone #test :End of WHO list");

		assert(joins.length == 1);
		with(joins[0]) {
			assert(user.nickname == "someone");
			assert(channel.name == "#test");
		}
		assert("someone" in client.channels["#test"].users);
		assert(client.channels["#test"].channel.name == "#test");
		assert(client.channels["#test"].users["someone"] == User("someone!ident@hostmask"));
		assert("someone" in client.internalAddressList);
		assert(client.internalAddressList["someone"] == User("someone!ident@hostmask"));
		assert(client.internalAddressList["someone"].account.get == "SomeoneAccount");

		assert(topicWhoTimeReceived);
		assert(topicReplyReceived);

		with(topicReply) {
			assert(channel == "#test");
			assert(topic == "a topic");
		}

		with (topicWhoTime) {
			//TODO: remove when lack of these imports no longer produces warnings
			import std.datetime : SysTime;
			import virc.common : User;
			assert(channel == "#test");
			assert(setter == User("someoneElse"));
			assert(timestamp == SysTime(DateTime(2017, 6, 7, 7, 53, 3), UTC()));
		}
		//TODO: Add 366, 324, 329 tests
		auto lineByLine = client.output.data.lineSplitter();
		assert(lineByLine.array[$-2] == "JOIN #test");
		assert(namesReplies.length == 1);
		assert(namesReplies[0].users(['o': '@', 'v': '+']).array.length == 2);
		assert(updates.length == 4);
		with(updates[0]) {
			assert(user.nickname == "someone");
			assert(user.account.isNull);
			assert(channel.name == "#test");
		}
		with(updates[1]) {
			assert(user.nickname == "another");
			assert(user.account.isNull);
			assert(channel.name == "#test");
		}
		with(updates[2]) {
			assert(user.nickname == "someone");
			assert(!user.account.isNull);
			assert(user.account.get == "SomeoneAccount");
			assert(channel.name == "#test");
		}
		with(updates[3]) {
			assert(user.nickname == "another");
			assert(!user.account.isNull);
			assert(user.account.get == "SomeoneElseAccount");
			assert(channel.name == "#test");
		}
	}
	{ //Channel list example
		auto client = spawnNoBufferClient();
		const(ChannelListResult)[] channels;
		client.onList = (const ChannelListResult chan, const MessageMetadata) {
			channels ~= chan;
		};
		setupFakeConnection(client);
		client.list();
		client.put("321 someone Channel :Users Name");
		client.put("322 someone #test 4 :[+fnt 200:2] some words");
		client.put("322 someone #test2 6 :[+fnst 100:2] some more words");
		client.put("322 someone #test3 1 :no modes?");
		client.put("323 someone :End of channel list.");
		assert(channels.length == 3);
		with(channels[0]) {
			//TODO: remove when lack of import no longer produces a warning
			import virc.common : Topic;
			assert(name == "#test");
			assert(userCount == 4);
			assert(topic == Topic("some words"));
		}
		with(channels[1]) {
			//TODO: remove when lack of import no longer produces a warning
			import virc.common : Topic;
			assert(name == "#test2");
			assert(userCount == 6);
			assert(topic == Topic("some more words"));
		}
		with(channels[2]) {
			//TODO: remove when lack of import no longer produces a warning
			import virc.common : Topic;
			assert(name == "#test3");
			assert(userCount == 1);
			assert(topic == Topic("no modes?"));
		}
	}
	{ //server-time http://ircv3.net/specs/extensions/server-time-3.2.html
		auto client = spawnNoBufferClient();
		User[] users;
		const(Channel)[] channels;
		client.onJoin = (const User user, const Channel chan, const MessageMetadata metadata) {
			users ~= user;
			channels ~= chan;
			assert(metadata.time == SysTime(DateTime(2012, 6, 30, 23, 59, 59), 419.msecs, UTC()));
		};
		setupFakeConnection(client);
		client.put("@time=2012-06-30T23:59:59.419Z :John!~john@1.2.3.4 JOIN #chan");
		assert(users.length == 1);
		assert(users[0].nickname == "John");
		assert(channels.length == 1);
		assert(channels[0].name == "#chan");
	}
	{ //monitor
		auto client = spawnNoBufferClient();
		User[] users;
		const(MessageMetadata)[] metadata;
		client.onUserOnline = (const User user, const SysTime, const MessageMetadata) {
			users ~= user;
		};
		client.onUserOffline = (const User user, const MessageMetadata) {
			users ~= user;
		};
		client.onMonitorList = (const User user, const MessageMetadata) {
			users ~= user;
		};
		client.onError = (const IRCError error, const MessageMetadata received) {
			assert(error.type == ErrorType.monListFull);
			metadata ~= received;
		};
		setupFakeConnection(client);
		client.put(":localhost 730 someone :John!test@example.net,Bob!test2@example.com");
		assert(users.length == 2);
		with (users[0]) {
			assert(nickname == "John");
			assert(ident == "test");
			assert(host == "example.net");
		}
		with (users[1]) {
			assert(nickname == "Bob");
			assert(ident == "test2");
			assert(host == "example.com");
		}

		users.length = 0;

		client.put(":localhost 731 someone :John");
		assert(users.length == 1);
		assert(users[0].nickname == "John");

		users.length = 0;

		client.put(":localhost 732 someone :John,Bob");
		client.put(":localhost 733 someone :End of MONITOR list");
		assert(users.length == 2);
		assert(users[0].nickname == "John");
		assert(users[1].nickname == "Bob");

		client.put(":localhost 734 someone 5 Earl :Monitor list is full.");
		assert(metadata.length == 1);
		assert(metadata[0].messageNumeric.get == Numeric.ERR_MONLISTFULL);
	}
	{ //extended-join http://ircv3.net/specs/extensions/extended-join-3.1.html
		auto client = spawnNoBufferClient();

		User[] users;
		client.onJoin = (const User user, const Channel, const MessageMetadata) {
			users ~= user;
		};

		initializeWithCaps(client, [Capability("extended-join")]);

		client.put(":nick!user@host JOIN #channelname accountname :Real Name");
		auto user = User("nick!user@host");
		user.account = "accountname";
		user.realName = "Real Name";
		assert(users.front == user);

		user.account.nullify();
		users = [];
		client.put(":nick!user@host JOIN #channelname * :Real Name");
		assert(users.front == user);
	}
	{ //test for blank caps
		auto client = spawnNoBufferClient();
		put(client, ":localhost CAP * LS * : ");
		setupFakeConnection(client);
		assert(client.isRegistered);
	}
	{ //example taken from RFC2812, section 3.2.2
		auto client = spawnNoBufferClient();

		User[] users;
		const(Channel)[] channels;
		string lastMsg;
		client.onPart = (const User user, const Channel chan, const string msg, const MessageMetadata) {
			users ~= user;
			channels ~= chan;
			lastMsg = msg;
		};

		setupFakeConnection(client);

		client.put(":WiZ!jto@tolsun.oulu.fi PART #playzone :I lost");
		immutable user = User("WiZ!jto@tolsun.oulu.fi");
		assert(users.front == user);
		assert(channels.front == Channel("#playzone"));
		assert(lastMsg == "I lost");
	}
	{ //PART tests
		auto client = spawnNoBufferClient();

		Tuple!(const User, "user", const Channel, "channel", string, "message")[] parts;
		client.onPart = (const User user, const Channel chan, const string msg, const MessageMetadata) {
			parts ~= tuple!("user", "channel", "message")(user, chan, msg);
		};

		setupFakeConnection(client);

		client.put(":"~testUser.text~" JOIN #example");
		client.put(":SomeoneElse JOIN #example");
		assert("#example" in client.channels);
		assert("SomeoneElse" in client.channels["#example"].users);
		client.put(":SomeoneElse PART #example :bye forever");
		assert("SomeoneElse" !in client.channels["#example"].users);
		client.put(":"~testUser.text~" PART #example :see ya");
		assert("#example" !in client.channels);

		client.put(":"~testUser.text~" JOIN #example");
		client.put(":SomeoneElse JOIN #example");
		assert("#example" in client.channels);
		assert("SomeoneElse" in client.channels["#example"].users);
		client.put(":SomeoneElse PART #example");
		assert("SomeoneElse" !in client.channels["#example"].users);
		client.put(":"~testUser.text~" PART #example");
		assert("#example" !in client.channels);

		assert(parts.length == 4);
		with (parts[0]) {
			assert(user == User("SomeoneElse"));
			assert(channel == Channel("#example"));
			assert(message == "bye forever");
		}
		with (parts[1]) {
			assert(user == client.me);
			assert(channel == Channel("#example"));
			assert(message == "see ya");
		}
		with (parts[2]) {
			assert(user == User("SomeoneElse"));
			assert(channel == Channel("#example"));
		}
		with (parts[3]) {
			assert(user == client.me);
			assert(channel == Channel("#example"));
		}
	}
	{ //http://ircv3.net/specs/extensions/chghost-3.2.html
		auto client = spawnNoBufferClient();

		User[] users;
		client.onChgHost = (const User user, const User newUser, const MessageMetadata) {
			users ~= user;
			users ~= newUser;
		};

		setupFakeConnection(client);
		client.put(":nick!user@host JOIN #test");
		assert("nick" in client.internalAddressList);
		assert(client.internalAddressList["nick"] == User("nick!user@host"));
		client.put(":nick!user@host CHGHOST user new.host.goes.here");
		assert(users[0] == User("nick!user@host"));
		assert(users[1] == User("nick!user@new.host.goes.here"));
		assert(client.internalAddressList["nick"] == User("nick!user@new.host.goes.here"));
		client.put(":nick!user@host CHGHOST newuser host");
		assert(users[2] == User("nick!user@host"));
		assert(users[3] == User("nick!newuser@host"));
		assert(client.internalAddressList["nick"] == User("nick!newuser@host"));
		client.put(":nick!user@host CHGHOST newuser new.host.goes.here");
		assert(users[4] == User("nick!user@host"));
		assert(users[5] == User("nick!newuser@new.host.goes.here"));
		assert(client.internalAddressList["nick"] == User("nick!newuser@new.host.goes.here"));
		client.put(":tim!~toolshed@backyard CHGHOST b ckyard");
		assert(users[6] == User("tim!~toolshed@backyard"));
		assert(users[7] == User("tim!b@ckyard"));
		assert(client.internalAddressList["tim"] == User("tim!b@ckyard"));
		client.put(":tim!b@ckyard CHGHOST ~toolshed backyard");
		assert(users[8] == User("tim!b@ckyard"));
		assert(users[9] == User("tim!~toolshed@backyard"));
		assert(client.internalAddressList["tim"] == User("tim!~toolshed@backyard"));
	}
	{ //PING? PONG!
		auto client = spawnNoBufferClient();

		setupFakeConnection(client);
		client.put("PING :words");
		auto lineByLine = client.output.data.lineSplitter();
		assert(lineByLine.array[$-1] == "PONG :words");
	}
	{ //echo-message http://ircv3.net/specs/extensions/echo-message-3.2.html
		auto client = spawnNoBufferClient();
		Message[] messages;
		client.onMessage = (const User, const Target, const Message msg, const MessageMetadata) {
			messages ~= msg;
		};
		setupFakeConnection(client);
		client.msg("Attila", "hi");
		client.put(":"~testUser.text~" PRIVMSG Attila :hi");
		assert(messages.length > 0);
		assert(messages[0].isEcho);

		client.msg("#ircv3", "back from \x02lunch\x0F");
		client.put(":"~testUser.text~" PRIVMSG #ircv3 :back from lunch");
		assert(messages.length > 1);
		assert(messages[1].isEcho);
	}
	{ //Test self-tracking
		auto client = spawnNoBufferClient();
		setupFakeConnection(client);
		assert(client.me.nickname == testUser.nickname);
		client.changeNickname("Testface");
		client.put(":"~testUser.nickname~" NICK Testface");
		assert(client.me.nickname == "Testface");
	}
}
@system unittest {
	{ //QUIT and invalidation check
		import core.exception : AssertError;
		import std.exception : assertThrown;
		auto client = spawnNoBufferClient();

		setupFakeConnection(client);
		client.quit("I'm out");
		auto lineByLine = client.output.data.lineSplitter();
		assert(lineByLine.array[$-1] == "QUIT :I'm out");
		client.put(":"~testUser.nickname~" QUIT");
		assert(!client.isValid);
		assertThrown!AssertError(client.put("PING :hahahaha"));
	}
}
@safe unittest {
	{ //NAMES
		auto client = spawnNoBufferClient();
		NamesReply[] replies;
		client.onNamesReply = (const NamesReply reply, const MessageMetadata) {
			replies ~= reply;
		};

		setupFakeConnection(client);

		client.names();
		client.put(":localhost 353 someone = #channel :User1 User2 @User3 +User4");
		client.put(":localhost 353 someone @ #channel2 :User5 User2 @User6 +User7");
		client.put(":localhost 353 someone * #channel3 :User1 User2 @User3 +User4");
		client.put(":localhost 366 someone :End of NAMES list");
		assert(replies.length == 3);
		assert(replies[0].chanFlag == NamReplyFlag.public_);
		assert(replies[1].chanFlag == NamReplyFlag.secret);
		assert(replies[2].chanFlag == NamReplyFlag.private_);
	}
	{ //WATCH stuff
		auto client = spawnNoBufferClient();
		User[] users;
		SysTime[] times;
		client.onUserOnline = (const User user, const SysTime time, const MessageMetadata) {
			users ~= user;
			times ~= time;
		};
		setupFakeConnection(client);
		client.put(":localhost 600 someone someoneElse someIdent example.net 911248013 :logged on");

		assert(users.length == 1);
		assert(users[0] == User("someoneElse!someIdent@example.net"));
		assert(times.length == 1);
		assert(times[0] == SysTime(DateTime(1998, 11, 16, 20, 26, 53), UTC()));
	}
	{ //LUSER stuff
		auto client = spawnNoBufferClient();
		bool lUserMeReceived;
		bool lUserChannelsReceived;
		bool lUserOpReceived;
		bool lUserClientReceived;
		LUserMe lUserMe;
		LUserClient lUserClient;
		LUserOp lUserOp;
		LUserChannels lUserChannels;
		client.onLUserMe = (const LUserMe param, const MessageMetadata) {
			assert(!lUserMeReceived);
			lUserMeReceived = true;
			lUserMe = param;
		};
		client.onLUserChannels = (const LUserChannels param, const MessageMetadata) {
			assert(!lUserChannelsReceived);
			lUserChannelsReceived = true;
			lUserChannels = param;
		};
		client.onLUserOp = (const LUserOp param, const MessageMetadata) {
			assert(!lUserOpReceived);
			lUserOpReceived = true;
			lUserOp = param;
		};
		client.onLUserClient = (const LUserClient param, const MessageMetadata) {
			assert(!lUserClientReceived);
			lUserClientReceived = true;
			lUserClient = param;
		};
		setupFakeConnection(client);
		client.lUsers();
		client.put(":localhost 251 someone :There are 8 users and 0 invisible on 2 servers");
		client.put(":localhost 252 someone 1 :operator(s) online");
		client.put(":localhost 254 someone 1 :channels formed");
		client.put(":localhost 255 someone :I have 1 clients and 1 servers");

		assert(lUserMeReceived);
		assert(lUserChannelsReceived);
		assert(lUserOpReceived);
		assert(lUserClientReceived);

		assert(lUserMe.message == "I have 1 clients and 1 servers");
		assert(lUserClient.message == "There are 8 users and 0 invisible on 2 servers");
		assert(lUserOp.numOperators == 1);
		assert(lUserOp.message == "operator(s) online");
		assert(lUserChannels.numChannels == 1);
		assert(lUserChannels.message == "channels formed");
	}
	{ //PRIVMSG and NOTICE stuff
		auto client = spawnNoBufferClient();
		Tuple!(const User, "user", const Target, "target", const Message, "message")[] messages;
		client.onMessage = (const User user, const Target target, const Message msg, const MessageMetadata) {
			messages ~= tuple!("user", "target", "message")(user, target, msg);
		};

		setupFakeConnection(client);

		client.put(":someoneElse!somebody@somewhere PRIVMSG someone :words go here");
		assert(messages.length == 1);
		with (messages[0]) {
			assert(user == User("someoneElse!somebody@somewhere"));
			assert(!target.isChannel);
			assert(target.isNickname);
			assert(target == User("someone"));
			assert(message == "words go here");
			assert(message.isReplyable);
			assert(!message.isEcho);
		}
		client.put(":ohno!it's@me PRIVMSG #someplace :more words go here");
		assert(messages.length == 2);
		with (messages[1]) {
			assert(user == User("ohno!it's@me"));
			assert(target.isChannel);
			assert(!target.isNickname);
			assert(target == Channel("#someplace"));
			assert(message == "more words go here");
			assert(message.isReplyable);
			assert(!message.isEcho);
		}

		client.put(":someoneElse2!somebody2@somewhere2 NOTICE someone :words don't go here");
		assert(messages.length == 3);
		with(messages[2]) {
			assert(user == User("someoneElse2!somebody2@somewhere2"));
			assert(!target.isChannel);
			assert(target.isNickname);
			assert(target == User("someone"));
			assert(message == "words don't go here");
			assert(!message.isReplyable);
			assert(!message.isEcho);
		}

		client.put(":ohno2!it's2@me4 NOTICE #someplaceelse :more words might go here");
		assert(messages.length == 4);
		with(messages[3]) {
			assert(user == User("ohno2!it's2@me4"));
			assert(target.isChannel);
			assert(!target.isNickname);
			assert(target == Channel("#someplaceelse"));
			assert(message == "more words might go here");
			assert(!message.isReplyable);
			assert(!message.isEcho);
		}

		client.put(":someoneElse2!somebody2@somewhere2 NOTICE someone :\x01ACTION did the thing\x01");
		assert(messages.length == 5);
		with(messages[4]) {
			assert(user == User("someoneElse2!somebody2@somewhere2"));
			assert(!target.isChannel);
			assert(target.isNickname);
			assert(target == User("someone"));
			assert(message.isCTCP);
			assert(message.ctcpArgs == "did the thing");
			assert(message.ctcpCommand == "ACTION");
			assert(!message.isReplyable);
			assert(!message.isEcho);
		}

		client.put(":ohno2!it's2@me4 NOTICE #someplaceelse :\x01ACTION did not do the thing\x01");
		assert(messages.length == 6);
		with(messages[5]) {
			assert(user == User("ohno2!it's2@me4"));
			assert(target.isChannel);
			assert(!target.isNickname);
			assert(target == Channel("#someplaceelse"));
			assert(message.isCTCP);
			assert(message.ctcpArgs == "did not do the thing");
			assert(message.ctcpCommand == "ACTION");
			assert(!message.isReplyable);
			assert(!message.isEcho);
		}

		client.msg("#channel", "ohai");
		client.notice("#channel", "ohi");
		client.msg("someoneElse", "ohay");
		client.notice("someoneElse", "ohello");
		Target channelTarget;
		channelTarget.channel = Channel("#channel");
		Target userTarget;
		userTarget.user = User("someoneElse");
		client.msg(channelTarget, Message("ohai"));
		client.notice(channelTarget, Message("ohi"));
		client.msg(userTarget, Message("ohay"));
		client.notice(userTarget, Message("ohello"));
		auto lineByLine = client.output.data.lineSplitter();
		foreach (i; 0..5) //skip the initial handshake
			lineByLine.popFront();
		assert(lineByLine.array == ["PRIVMSG #channel :ohai", "NOTICE #channel :ohi", "PRIVMSG someoneElse :ohay", "NOTICE someoneElse :ohello", "PRIVMSG #channel :ohai", "NOTICE #channel :ohi", "PRIVMSG someoneElse :ohay", "NOTICE someoneElse :ohello"]);
	}
	{ //PING? PONG!
		auto client = spawnNoBufferClient();

		setupFakeConnection(client);
		client.ping("hooray");
		client.put(":localhost PONG localhost :hooray");

		client.put(":localhost PING :hoorah");

		auto lineByLine = client.output.data.lineSplitter();
		assert(lineByLine.array[$-2] == "PING :hooray");
		assert(lineByLine.array[$-1] == "PONG :hoorah");
	}
	{ //Mode change test
		auto client = spawnNoBufferClient();
		Tuple!(const User, "user", const Target, "target", const ModeChange, "change")[] changes;

		client.onMode = (const User user, const Target target, const ModeChange mode, const MessageMetadata) {
			changes ~= tuple!("user", "target", "change")(user, target, mode);
		};

		setupFakeConnection(client);
		client.join("#test");
		client.put(":"~testUser.text~" JOIN #test "~testUser.nickname);
		client.put(":someone!ident@host JOIN #test");
		client.put(":someoneElse!user@host2 MODE #test +s");
		client.put(":someoneElse!user@host2 MODE #test -s");
		client.put(":someoneElse!user@host2 MODE #test +kp 2");
		client.put(":someoneElse!user@host2 MODE someone +r");
		client.put(":someoneElse!user@host2 MODE someone +k");

		assert(changes.length == 6);
		with (changes[0]) {
			assert(target == Channel("#test"));
			assert(user == User("someoneElse!user@host2"));
		}
		with (changes[1]) {
			assert(target == Channel("#test"));
			assert(user == User("someoneElse!user@host2"));
		}
		with (changes[2]) {
			assert(target == Channel("#test"));
			assert(user == User("someoneElse!user@host2"));
		}
		with (changes[3]) {
			assert(target == Channel("#test"));
			assert(user == User("someoneElse!user@host2"));
		}
		with (changes[4]) {
			assert(target == User("someone"));
			assert(user == User("someoneElse!user@host2"));
		}
		with (changes[5]) {
			assert(target == User("someone"));
			assert(user == User("someoneElse!user@host2"));
		}
	}
	{ //client join stuff
		auto client = spawnNoBufferClient();
		client.join("#test");
		assert(client.output.data.lineSplitter.array[$-1] == "JOIN #test");
		client.join(Channel("#test2"));
		assert(client.output.data.lineSplitter.array[$-1] == "JOIN #test2");
		client.join("#test3", "key");
		assert(client.output.data.lineSplitter.array[$-1] == "JOIN #test3 key");
		client.join("#test4", "key2");
		assert(client.output.data.lineSplitter.array[$-1] == "JOIN #test4 key2");
	}
	{ //account-tag examples from http://ircv3.net/specs/extensions/account-tag-3.2.html
		auto client = spawnNoBufferClient();
		User[] privmsgUsers;
		client.onMessage = (const User user, const Target, const Message, const MessageMetadata) {
			privmsgUsers ~= user;
		};
		setupFakeConnection(client);

		client.put(":user PRIVMSG #atheme :Hello everyone.");
		client.put(":user ACCOUNT hax0r");
		client.put("@account=hax0r :user PRIVMSG #atheme :Now I'm logged in.");
		client.put("@account=hax0r :user ACCOUNT bob");
		client.put("@account=bob :user PRIVMSG #atheme :I switched accounts.");
		with(privmsgUsers[0]) {
			assert(account.isNull);
		}
		with(privmsgUsers[1]) {
			assert(account.get == "hax0r");
		}
		with(privmsgUsers[2]) {
			assert(account.get == "bob");
		}
		assert(client.internalAddressList["user"].account == "bob");
	}
	{ //account-notify - http://ircv3.net/specs/extensions/account-notify-3.1.html
		auto client = spawnNoBufferClient();
		setupFakeConnection(client);
		client.put(":nick!user@host ACCOUNT accountname");
		assert(client.internalAddressList["nick"].account.get == "accountname");
		client.put(":nick!user@host ACCOUNT *");
		assert(client.internalAddressList["nick"].account.isNull);
	}
	{ //monitor - http://ircv3.net/specs/core/monitor-3.2.html
		auto client = spawnNoBufferClient();
		initializeWithCaps(client, [Capability("MONITOR")]);

		assert(client.monitorIsEnabled);

		client.monitorAdd([User("Someone")]);
		client.monitorRemove([User("Someone")]);
		client.monitorClear();
		client.monitorList();
		client.monitorStatus();

		const lineByLine = client.output.data.lineSplitter().drop(5).array;
		assert(lineByLine == ["MONITOR + Someone", "MONITOR - Someone", "MONITOR C", "MONITOR L", "MONITOR S"]);
	}
	{ //No MOTD test
		auto client = spawnNoBufferClient();
		bool errorReceived;
		client.onError = (const IRCError error, const MessageMetadata) {
			assert(!errorReceived);
			errorReceived = true;
			assert(error.type == ErrorType.noMOTD);
		};
		setupFakeConnection(client);
		client.put("422 someone :MOTD File is missing");
		assert(errorReceived);
	}
	{ //NICK tests
		auto client = spawnNoBufferClient();
		Tuple!(const User, "old", const User, "new_")[] nickChanges;
		client.onNick = (const User old, const User new_, const MessageMetadata) {
			nickChanges ~= tuple!("old", "new_")(old, new_);
		};

		setupFakeConnection(client);
		client.put(":WiZ JOIN #testchan");
		client.put(":dan- JOIN #testchan");


		client.put(":WiZ NICK Kilroy");

		assert(nickChanges.length == 1);
		with(nickChanges[0]) {
			assert(old.nickname == "WiZ");
			assert(new_.nickname == "Kilroy");
		}

		assert("Kilroy" in client.internalAddressList);
		assert("Kilroy" in client.channels["#testchan"].users);
		assert("WiZ" !in client.channels["#testchan"].users);

		client.put(":dan-!d@localhost NICK Mamoped");

		assert(nickChanges.length == 2);
		with(nickChanges[1]) {
			assert(old.nickname == "dan-");
			assert(new_.nickname == "Mamoped");
		}

		assert("Mamoped" in client.internalAddressList);
		assert("Mamoped" in client.channels["#testchan"].users);
		assert("dan-" !in client.channels["#testchan"].users);

		//invalid, so we shouldn't see anything
		client.put(":a NICK");
		assert(nickChanges.length == 2);
	}
	{ //QUIT tests
		auto client = spawnNoBufferClient();

		Tuple!(const User, "user", string, "message")[] quits;
		client.onQuit = (const User user, const string msg, const MessageMetadata) {
			quits ~= tuple!("user", "message")(user, msg);
		};

		setupFakeConnection(client);

		client.put(":dan-!d@localhost QUIT :Quit: Bye for now!");
		assert(quits.length == 1);
		with (quits[0]) {
			assert(user == User("dan-!d@localhost"));
			assert(message == "Quit: Bye for now!");
		}
		client.put(":nomessage QUIT");
		assert(quits.length == 2);
		with(quits[1]) {
			assert(user == User("nomessage"));
			assert(message == "");
		}
	}
	{ //Batch stuff
		auto client = spawnNoBufferClient();

		Tuple!(const User, "user", const MessageMetadata, "metadata")[] quits;
		client.onQuit = (const User user, const string, const MessageMetadata metadata) {
			quits ~= tuple!("user", "metadata")(user, metadata);
		};

		setupFakeConnection(client);

		client.put(`:irc.host BATCH +yXNAbvnRHTRBv netsplit irc.hub other.host`);
		client.put(`@batch=yXNAbvnRHTRBv :aji!a@a QUIT :irc.hub other.host`);
		client.put(`@batch=yXNAbvnRHTRBv :nenolod!a@a QUIT :irc.hub other.host`);
		client.put(`:nick!user@host PRIVMSG #channel :This is not in batch, so processed immediately`);
		client.put(`@batch=yXNAbvnRHTRBv :jilles!a@a QUIT :irc.hub other.host`);

		assert(quits.length == 0);

		client.put(`:irc.host BATCH -yXNAbvnRHTRBv`);

		assert(quits.length == 3);
		with(quits[0]) {
			assert(metadata.batch.type == "netsplit");
		}
	}
	{ //INVITE tests
		auto client = spawnNoBufferClient();

		Tuple!(const User, "inviter", const User, "invited",  const Channel, "channel")[] invites;
		client.onInvite = (const User inviter, const User invited, const Channel channel, const MessageMetadata) {
			invites ~= tuple!("inviter", "invited", "channel")(inviter, invited, channel);
		};

		setupFakeConnection(client);

		//Ensure the internal address list gets used for invited users as well
		client.internalAddressList.update(User("Wiz!ident@host"));

		client.put(":Angel INVITE Wiz #Dust");
		assert(invites.length == 1);
		with(invites[0]) {
			assert(inviter.nickname == "Angel");
			assert(invited.nickname == "Wiz");
			assert(invited.host == "host");
			assert(channel == Channel("#Dust"));
		}

		client.put(":ChanServ!ChanServ@example.com INVITE Attila #channel");
		assert(invites.length == 2);
		with(invites[1]) {
			assert(inviter.nickname == "ChanServ");
			assert(invited.nickname == "Attila");
			assert(channel == Channel("#channel"));
		}
	}
	{ //VERSION tests
		auto client = spawnNoBufferClient();

		VersionReply[] replies;
		client.onVersionReply = (const VersionReply reply, const MessageMetadata) {
			replies ~= reply;
		};

		setupFakeConnection(client);

		client.version_();
		client.put(format!":localhost 351 %s example-1.0 localhost :not a beta"(testUser.nickname));
		with (replies[0]) {
			assert(version_ == "example-1.0");
			assert(server == "localhost");
			assert(comments == "not a beta");
		}
		client.version_("*.example");
		client.put(format!":localhost 351 %s example-1.0 test.example :not a beta"(testUser.nickname));
		with (replies[1]) {
			assert(version_ == "example-1.0");
			assert(server == "test.example");
			assert(comments == "not a beta");
		}
	}
	{ //SASL test
		auto client = spawnNoBufferClient();
		client.saslMechs = [new SASLPlain("jilles", "jilles", "sesame")];
		client.put(":localhost CAP * LS :sasl");
		client.put(":localhost CAP whoever ACK :sasl");
		client.put("AUTHENTICATE +");
		client.put(":localhost 900 "~testUser.nickname~" "~testUser.text~" "~testUser.nickname~" :You are now logged in as "~testUser.nickname);
		client.put(":localhost 903 "~testUser.nickname~" :SASL authentication successful");

		assert(client.output.data.canFind("AUTHENTICATE amlsbGVzAGppbGxlcwBzZXNhbWU="));
		assert(client.isAuthenticated == true);
		assert(client.me.account.get == testUser.nickname);
	}
	{ //SASL 3.2 test
		auto client = spawnNoBufferClient();
		client.saslMechs = [new SASLPlain("jilles", "jilles", "sesame")];
		client.put(":localhost CAP * LS :sasl=UNKNOWN,PLAIN,EXTERNAL");
		client.put(":localhost CAP whoever ACK :sasl");
		client.put("AUTHENTICATE +");
		client.put(":localhost 900 "~testUser.nickname~" "~testUser.text~" "~testUser.nickname~" :You are now logged in as "~testUser.nickname);
		client.put(":localhost 903 "~testUser.nickname~" :SASL authentication successful");

		assert(client.output.data.canFind("AUTHENTICATE amlsbGVzAGppbGxlcwBzZXNhbWU="));
		assert(client.isAuthenticated == true);
		assert(client.me.account.get == testUser.nickname);
	}
	{ //SASL 3.2 test
		auto client = spawnNoBufferClient();
		client.saslMechs = [new SASLExternal];
		client.put(":localhost CAP * LS :sasl=UNKNOWN,EXTERNAL");
		client.put(":localhost CAP whoever ACK :sasl");
		client.put("AUTHENTICATE +");
		client.put(":localhost 900 "~testUser.nickname~" "~testUser.text~" "~testUser.nickname~" :You are now logged in as "~testUser.nickname);
		client.put(":localhost 903 "~testUser.nickname~" :SASL authentication successful");

		assert(client.output.data.canFind("AUTHENTICATE +"));
		assert(client.isAuthenticated == true);
		assert(client.me.account.get == testUser.nickname);
	}
	{ //SASL 3.2 test (bogus)
		auto client = spawnNoBufferClient();
		client.saslMechs = [new SASLPlain("jilles", "jilles", "sesame")];
		client.put(":localhost CAP * LS :sasl=UNKNOWN,EXTERNAL");
		client.put(":localhost CAP whoever ACK :sasl");
		client.put("AUTHENTICATE +");
		client.put(":localhost 900 "~testUser.nickname~" "~testUser.text~" "~testUser.nickname~" :You are now logged in as "~testUser.nickname);
		client.put(":localhost 903 "~testUser.nickname~" :SASL authentication successful");

		assert(!client.output.data.canFind("AUTHENTICATE amlsbGVzAGppbGxlcwBzZXNhbWU="));
		assert(client.isAuthenticated == false);
		//assert(client.me.account.get.isNull);
	}
	{ //SASL post-registration test
		auto client = spawnNoBufferClient();
		client.saslMechs = [new SASLExternal()];
		setupFakeConnection(client);
		client.capList();
		client.put(":localhost CAP * LIST :sasl=UNKNOWN,PLAIN,EXTERNAL");
	}
	{ //KICK tests
		auto client = spawnNoBufferClient();
		Tuple!(const User, "kickedBy", const User, "kicked",  const Channel, "channel", string, "message")[] kicks;
		client.onKick = (const User kickedBy, const Channel channel, const User kicked, const string message, const MessageMetadata) {
			kicks ~= tuple!("kickedBy", "kicked", "channel", "message")(kickedBy, kicked, channel, message);
		};
		setupFakeConnection(client);
		client.kick(Channel("#test"), User("Example"), "message");
		auto lineByLine = client.output.data.lineSplitter();
		assert(lineByLine.array[$-1] == "KICK #test Example :message");

		client.put(":WiZ KICK #Finnish John");

		assert(kicks.length == 1);
		with(kicks[0]) {
			assert(kickedBy == User("WiZ"));
			assert(channel == Channel("#Finnish"));
			assert(kicked == User("John"));
			assert(message == "");
		}

		client.put(":Testo KICK #example User :Now with kick message!");

		assert(kicks.length == 2);
		with(kicks[1]) {
			assert(kickedBy == User("Testo"));
			assert(channel == Channel("#example"));
			assert(kicked == User("User"));
			assert(message == "Now with kick message!");
		}

		client.put(":WiZ!jto@tolsun.oulu.fi KICK #Finnish John");

		assert(kicks.length == 3);
		with(kicks[2]) {
			assert(kickedBy == User("WiZ!jto@tolsun.oulu.fi"));
			assert(channel == Channel("#Finnish"));
			assert(kicked == User("John"));
			assert(message == "");
		}

		client.put(":User KICK");
		assert(kicks.length == 3);

		client.put(":User KICK #channel");
		assert(kicks.length == 3);
	}
	{ //REHASH tests
		auto client = spawnNoBufferClient();
		RehashingReply[] replies;
		client.onServerRehashing = (const RehashingReply reply, const MessageMetadata) {
			replies ~= reply;
		};
		IRCError[] errors;
		client.onError = (const IRCError error, const MessageMetadata) {
			errors ~= error;
		};

		setupFakeConnection(client);
		client.rehash();
		auto lineByLine = client.output.data.lineSplitter();
		assert(lineByLine.array[$-1] == "REHASH");
		client.put(":localhost 382 Someone ircd.conf :Rehashing config");

		assert(replies.length == 1);
		with (replies[0]) {
			import virc.common : User;
			assert(me == User("Someone"));
			assert(configFile == "ircd.conf");
			assert(message == "Rehashing config");
		}

		client.put(":localhost 382 Nope");

		assert(replies.length == 1);

		client.put(":localhost 723 Someone rehash :Insufficient oper privileges");
		client.put(":localhost 723 Someone");
		assert(errors.length == 2);
		with(errors[0]) {
			assert(type == ErrorType.noPrivs);
		}
		with(errors[1]) {
			assert(type == ErrorType.malformed);
		}
	}
	{ //ISON tests
		auto client = spawnNoBufferClient();
		const(User)[] users;
		client.onIsOn = (const User user, const MessageMetadata) {
			users ~= user;
		};
		setupFakeConnection(client);

		client.isOn("phone", "trillian", "WiZ", "jarlek", "Avalon", "Angel", "Monstah");

		client.put(":localhost 303 Someone :trillian");
		client.put(":localhost 303 Someone :WiZ");
		client.put(":localhost 303 Someone :jarlek");
		client.put(":localhost 303 Someone :Angel");
		client.put(":localhost 303 Someone :Monstah");

		assert(users.length == 5);
		assert(users[0].nickname == "trillian");
		assert(users[1].nickname == "WiZ");
		assert(users[2].nickname == "jarlek");
		assert(users[3].nickname == "Angel");
		assert(users[4].nickname == "Monstah");
	}
	{ //OPER tests
		auto client = spawnNoBufferClient();
		bool received;
		client.onYoureOper = (const MessageMetadata) {
			received = true;
		};
		setupFakeConnection(client);

		client.oper("foo", "bar");
		auto lineByLine = client.output.data.lineSplitter();
		assert(lineByLine.array[$-1] == "OPER foo bar");
		client.put(":localhost 381 Someone :You are now an IRC operator");
		assert(received);
	}
	{ //SQUIT tests
		auto client = spawnNoBufferClient();
		IRCError[] errors;
		client.onError = (const IRCError error, const MessageMetadata) {
			errors ~= error;
		};
		setupFakeConnection(client);

		client.squit("badserver.example.net", "Bad link");
		auto lineByLine = client.output.data.lineSplitter();
		assert(lineByLine.array[$-1] == "SQUIT badserver.example.net :Bad link");
		client.put(":localhost 481 Someone :Permission Denied- You're not an IRC operator");
		client.put(":localhost 402 Someone badserver.example.net :No such server");
		client.put(":localhost 402 Someone");
		assert(errors.length == 3);
		with(errors[0]) {
			assert(type == ErrorType.noPrivileges);
		}
		with(errors[1]) {
			assert(type == ErrorType.noSuchServer);
		}
		with(errors[2]) {
			assert(type == ErrorType.malformed);
		}
	}
	{ //AWAY tests
		auto client = spawnNoBufferClient();
		Tuple!(const User, "user", string, "message")[] aways;
		client.onOtherUserAwayReply = (const User awayUser, const string msg, const MessageMetadata) {
			aways ~= tuple!("user", "message")(awayUser, msg);
		};
		bool unAwayReceived;
		client.onUnAwayReply = (const User, const MessageMetadata) {
			unAwayReceived = true;
		};
		bool awayReceived;
		client.onAwayReply = (const User, const MessageMetadata) {
			awayReceived = true;
		};
		setupFakeConnection(client);

		client.away("Laughing at salads");
		client.put(":localhost 306 Someone :You have been marked as being away");
		assert(client.isAway);
		assert(awayReceived);

		client.away();
		client.put(":localhost 305 Someone :You are no longer marked as being away");
		assert(!client.isAway);
		assert(unAwayReceived);

		client.put(":localhost 301 Someone AwayUser :User on fire");

		assert(aways.length == 1);
		with (aways[0]) {
			assert(user == User("AwayUser"));
			assert(message == "User on fire");
		}
	}
	{ //ADMIN tests
		auto client = spawnNoBufferClient();

		setupFakeConnection(client);

		client.admin("localhost");
		client.admin();
		auto lineByLine = client.output.data.lineSplitter();
		assert(lineByLine.array[$-2] == "ADMIN localhost");
		assert(lineByLine.array[$-1] == "ADMIN");
		client.put(":localhost 256 Someone :Administrative info for localhost");
		client.put(":localhost 257 Someone :Name     - Admin");
		client.put(":localhost 258 Someone :Nickname - Admin");
		client.put(":localhost 259 Someone :E-Mail   - Admin@localhost");
	}
	{ //WHOIS tests
		auto client = spawnNoBufferClient();
		const(WhoisResponse)[] responses;
		client.onWhois = (const User, const WhoisResponse whois) {
			responses ~= whois;
		};
		setupFakeConnection(client);
		client.whois("someoneElse");

		client.put(":localhost 276 Someone someoneElse :has client certificate 0");
		client.put(":localhost 311 Someone someoneElse someUsername someHostname * :Some Real Name");
		client.put(":localhost 312 Someone someoneElse example.net :The real world is out there");
		client.put(":localhost 313 Someone someoneElse :is an IRC operator");
		client.put(":localhost 317 Someone someoneElse 1000 1500000000 :seconds idle, signon time");
		client.put(":localhost 319 Someone someoneElse :+#test #test2");
		client.put(":localhost 330 Someone someoneElse someoneElseAccount :is logged in as");
		client.put(":localhost 378 Someone someoneElse :is connecting from someoneElse@127.0.0.5 127.0.0.5");
		client.put(":localhost 671 Someone someoneElse :is using a secure connection");
		client.put(":localhost 379 Someone someoneElse :is using modes +w");
		client.put(":localhost 307 Someone someoneElse :is a registered nick");

		assert(responses.length == 0);
		client.put(":localhost 318 Someone someoneElse :End of /WHOIS list");

		assert(responses.length == 1);
		with(responses[0]) {
			assert(isSecure);
			assert(isOper);
			assert(isRegistered);
			assert(username.get == "someUsername");
			assert(hostname.get == "someHostname");
			assert(realname.get == "Some Real Name");
			assert(connectedTime.get == SysTime(DateTime(2017, 7, 14, 2, 40, 0), UTC()));
			assert(idleTime.get == 1000.seconds);
			assert(connectedTo.get == "example.net");
			assert(account.get == "someoneElseAccount");
			assert(channels.length == 2);
			assert("#test" in channels);
			assert(channels["#test"].prefix == "+");
			assert("#test2" in channels);
			assert(channels["#test2"].prefix == "");
		}
	}
	{ //RESTART tests
		auto client = spawnNoBufferClient();
		setupFakeConnection(client);

		client.restart();
		auto lineByLine = client.output.data.lineSplitter();
		assert(lineByLine.array[$-1] == "RESTART");
	}
	{ //WALLOPS tests
		auto client = spawnNoBufferClient();
		string[] messages;
		client.onWallops = (const User, const string msg, const MessageMetadata) {
			messages ~= msg;
		};
		setupFakeConnection(client);

		client.wallops("Test message!");
		auto lineByLine = client.output.data.lineSplitter();
		assert(lineByLine.array[$-1] == "WALLOPS :Test message!");

		client.put(":OtherUser!someone@somewhere WALLOPS :Test message reply!");
		assert(messages.length == 1);
		assert(messages[0] == "Test message reply!");

	}
	{ //CTCP tests
		auto client = spawnNoBufferClient();
		setupFakeConnection(client);
		client.ctcp(Target(User("test")), "ping");
		client.ctcp(Target(User("test")), "action", "does the thing.");
		client.ctcpReply(Target(User("test")), "ping", "1000000000");

		auto lineByLine = client.output.data.lineSplitter();
		assert(lineByLine.array[$-3] == "PRIVMSG test :\x01ping\x01");
		assert(lineByLine.array[$-2] == "PRIVMSG test :\x01action does the thing.\x01");
		assert(lineByLine.array[$-1] == "NOTICE test :\x01ping 1000000000\x01");
	}
	{ //TOPIC tests
		auto client = spawnNoBufferClient();
		Tuple!(const User, "user", const Channel, "channel", string, "message")[] topics;
		IRCError[] errors;
		client.onTopicChange = (const User user, const Channel channel, const string msg, const MessageMetadata) {
			topics ~= tuple!("user", "channel", "message")(user, channel, msg);
		};
		client.onError = (const IRCError error, const MessageMetadata) {
			errors ~= error;
		};

		setupFakeConnection(client);
		client.changeTopic(Target(Channel("#test")), "This is a new topic");
		client.put(":"~testUser.text~" TOPIC #test :This is a new topic");
		client.put(":"~testUser.text~" TOPIC #test"); //Malformed
		client.put(":"~testUser.text~" TOPIC"); //Malformed

		auto lineByLine = client.output.data.lineSplitter();
		assert(lineByLine.array[$-1] == "TOPIC #test :This is a new topic");
		assert(topics.length == 1);
		with(topics[0]) {
			assert(channel == Channel("#test"));
			assert(message == "This is a new topic");
		}
		assert(errors.length == 2);
		assert(errors[0].type == ErrorType.malformed);
		assert(errors[1].type == ErrorType.malformed);
	}
	//Request capabilities (IRC v3.2) - Missing prefix
	{
		auto client = spawnNoBufferClient();
		client.put("CAP * LS :multi-prefix sasl");
		client.put("CAP * ACK :multi-prefix sasl");

		auto lineByLine = client.output.data.lineSplitter;
		lineByLine.popFront();
		lineByLine.popFront();
		lineByLine.popFront();
		//sasl not yet supported
		assert(lineByLine.front == "CAP REQ :multi-prefix sasl");
		lineByLine.popFront();
		assert(!lineByLine.empty);
		assert(lineByLine.front == "CAP END");
	}
	{ //METADATA tests
		auto client = spawnNoBufferClient();
		IRCError[] errors;
		client.onError = (const IRCError error, const MessageMetadata md) {
			errors ~= error;
		};
		string[] subs;
		client.onMetadataSubList = (const string str, const MessageMetadata) {
			subs ~= str;
		};
		initializeWithCaps(client, [Capability("draft/metadata-2", "foo,maxsub=50,maxkey=25,bar"), Capability("draft/metadata-notify-2")]);


		assert(client.state.maxMetadataSubscriptions == 50);
		assert(client.state.maxMetadataSelfKeys == 25);

		client.setMetadata("url", "http://www.example.com");
		assert(client.output.data.lineSplitter().array[$-1] == "METADATA * SET url :http://www.example.com");
		client.put(":irc.example.com 761 * url * :http://www.example.com");
		assert(client.ownMetadata["url"] == "http://www.example.com");

		client.setMetadata("url", "http://www.example.com");
		client.put("FAIL METADATA LIMIT_REACHED :Metadata limit reached");
		assert(errors.length == 1);
		with(errors[0]) {
			assert(type == ErrorType.standardFail);
		}

		client.setMetadata(User("user1"), "url", "http://www.example.com");
		assert(client.output.data.lineSplitter().array[$ - 1] == "METADATA user1 SET url :http://www.example.com");
		client.put("FAIL METADATA KEY_NO_PERMISSION url user1 :You do not have permission to set 'url' on 'user1'");
		assert(errors.length == 2);
		with(errors[1]) {
			assert(type == ErrorType.standardFail);
		}

		client.setMetadata(Channel("#example"), "url", "http://www.example.com");
		assert(client.output.data.lineSplitter().array[$ - 1] == "METADATA #example SET url :http://www.example.com");
		client.put(":irc.example.com 761 #example url * :http://www.example.com");
		assert(client.channelMetadata[Channel("#example")]["url"] == "http://www.example.com");

		client.setMetadata(User("$a:user"), "url", "http://www.example.com");
		client.put("FAIL METADATA INVALID_TARGET $a:user :Invalid target.");
		assert(errors.length == 3);
		with(errors[2]) {
			assert(type == ErrorType.standardFail);
		}

		client.setMetadata(User("user1"), "$url$", "http://www.example.com");
		client.put("FAIL METADATA INVALID_KEY $url$ user1 :Invalid key.");
		assert(errors.length == 4);
		with(errors[3]) {
			assert(type == ErrorType.standardFail);
		}

		client.setMetadata("url", "http://www.example.com");
		client.put("FAIL METADATA RATE_LIMIT url 5 :Rate-limit reached. You're going too fast! Try again in 5 seconds.");
		assert(errors.length == 5);
		with(errors[4]) {
			assert(type == ErrorType.standardFail);
		}

		client.setMetadata("url", "http://www.example.com");
		client.put("FAIL METADATA RATE_LIMIT url * :Rate-limit reached. You're going too fast!");
		assert(errors.length == 6);
		with(errors[5]) {
			assert(type == ErrorType.standardFail);
		}

		client.put(":irc.example.com METADATA user1 account * :user1");
		assert(client.userMetadata[User("user1")]["account"] == "user1");

		client.put(":user1!~user@somewhere.example.com METADATA #example url * :http://www.example.com");
		assert(client.channelMetadata[Channel("#example")]["url"] == "http://www.example.com");

		client.put(":irc.example.com METADATA #example wiki-url * :http://wiki.example.com");
		assert(client.channelMetadata[Channel("#example")]["wiki-url"] == "http://wiki.example.com");

		client.listMetadata(User("user1"));
		client.put(":irc.example.com BATCH +VUN2ot metadata");
		client.put("@batch=VUN2ot :irc.example.com 761 user1 url * :http://www.example.com");
		client.put("@batch=VUN2ot :irc.example.com 761 user1 im.xmpp * :user1@xmpp.example.com");
		client.put("@batch=VUN2ot :irc.example.com 761 user1 bot-likeliness-score visible-only-for-admin :42");
		client.put(":irc.example.com BATCH -VUN2ot");
		assert(client.userMetadata[User("user1")]["url"] == "http://www.example.com");
		assert(client.userMetadata[User("user1")]["im.xmpp"] == "user1@xmpp.example.com");
		assert(client.userMetadata[User("user1")]["bot-likeliness-score"] == "42");

		client.userMetadata.remove(User("user1"));

		client.getMetadata(User("user1"), "blargh", "splot", "im.xmpp");
		client.put(":irc.example.com BATCH +gWkCiV metadata");
		client.put("@batch=gWkCiV 766 user1 blargh :No matching key");
		client.put("@batch=gWkCiV 766 user1 splot :No matching key");
		client.put("@batch=gWkCiV :irc.example.com 761 user1 im.xmpp * :user1@xmpp.example.com");
		client.put(":irc.example.com BATCH -gWkCiV");
		assert("blargh" !in client.userMetadata[User("user1")]);
		assert("splot" !in client.userMetadata[User("user1")]);
		assert(client.userMetadata[User("user1")]["im.xmpp"] == "user1@xmpp.example.com");
		assert(errors.length == 8);
		with(errors[6]) {
			assert(type == ErrorType.keyNotSet);
		}
		with(errors[7]) {
			assert(type == ErrorType.keyNotSet);
		}

		client.join(Channel("#smallchan"));
		client.put(":modernclient!modernclient@example.com JOIN #smallchan");
		client.put(":irc.example.com 353 modernclient @ #smallchan :user1 user2 user3 user4 user5 ...");
		client.put(":irc.example.com 353 modernclient @ #smallchan :user51 user52 user53 user54 ...");
		client.put(":irc.example.com 353 modernclient @ #smallchan :user101 user102 user103 user104 ...");
		client.put(":irc.example.com 353 modernclient @ #smallchan :user151 user152 user153 user154 ...");
		client.put(":irc.example.com 366 modernclient #smallchan :End of /NAMES list.");
		client.put(":irc.example.com BATCH +UwZ67M metadata");
		client.put("@batch=UwZ67M :irc.example.com METADATA user2 bar * :second example value ");
		client.put("@batch=UwZ67M :irc.example.com METADATA user1 foo * :third example value");
		client.put("@batch=UwZ67M :irc.example.com METADATA user1 bar * :this is another example value");
		client.put("@batch=UwZ67M :irc.example.com METADATA user3 website * :www.example.com");
		client.put(":irc.example.com BATCH -UwZ67M");
		assert(client.userMetadata[User("user1")]["foo"] == "third example value");
		assert(client.userMetadata[User("user1")]["bar"] == "this is another example value");
		assert(client.userMetadata[User("user2")]["bar"] == "second example value ");
		assert(client.userMetadata[User("user3")]["website"] == "www.example.com");

		client.join(Channel("#bigchan"));
		client.put(":modernclient!modernclient@example.com JOIN #bigchan");
		client.put(":irc.example.com 353 modernclient @ #bigchan :user1 user2 user3 user4 user5 ...");
		client.put(":irc.example.com 353 modernclient @ #bigchan :user51 user52 user53 user54 ...");
		client.put(":irc.example.com 353 modernclient @ #bigchan :user101 user102 user103 user104 ...");
		client.put(":irc.example.com 353 modernclient @ #bigchan :user151 user152 user153 user154 ...");
		client.put(":irc.example.com 366 modernclient #bigchan :End of /NAMES list.");
		client.put(":irc.example.com 774 modernclient #bigchan 4");
		assert(errors.length == 9);
		with(errors[8]) {
			assert(type == ErrorType.waitAndRetry);
		}

		client.syncMetadata(Channel("#bigchan"));
		client.put(":irc.example.com 774 modernclient #bigchan 6");
		assert(errors.length == 10);
		with(errors[9]) {
			assert(type == ErrorType.waitAndRetry);
		}

		client.syncMetadata(Channel("#bigchan"));
		client.put(":irc.example.com BATCH +O5J6rk metadata");
		client.put("@batch=O5J6rk :irc.example.com METADATA user52 foo * :example value 1");
		client.put("@batch=O5J6rk :irc.example.com METADATA user2 bar * :second example value ");
		client.put("@batch=O5J6rk :irc.example.com METADATA user1 foo * :third example value");
		client.put("@batch=O5J6rk :irc.example.com METADATA user1 bar * :this is another example value");
		client.put("@batch=O5J6rk :irc.example.com METADATA user152 baz * :Lorem ipsum");
		client.put("@batch=O5J6rk :irc.example.com METADATA user3 website * :www.example.com");
		client.put("@batch=O5J6rk :irc.example.com METADATA user152 bar * :dolor sit amet");
		client.put(":irc.example.com BATCH -O5J6rk");
		assert(client.userMetadata[User("user1")]["foo"] == "third example value");
		assert(client.userMetadata[User("user1")]["bar"] == "this is another example value");
		assert(client.userMetadata[User("user2")]["bar"] == "second example value ");
		assert(client.userMetadata[User("user3")]["website"] == "www.example.com");
		assert(client.userMetadata[User("user52")]["foo"] == "example value 1");
		assert(client.userMetadata[User("user152")]["baz"] == "Lorem ipsum");
		assert(client.userMetadata[User("user152")]["bar"] == "dolor sit amet");

		client.subscribeMetadata("avatar", "website", "foo", "bar");
		client.put(":irc.example.com 770 modernclient :avatar website foo bar");
		assert(client.isSubscribed("avatar"));
		assert(client.isSubscribed("website"));
		assert(client.isSubscribed("foo"));
		assert(client.isSubscribed("bar"));
		client.unsubscribeMetadata("foo", "bar");
		client.put(":irc.example.com 771 modernclient :bar foo");
		assert(!client.isSubscribed("foo"));
		assert(!client.isSubscribed("bar"));

		client.subscribeMetadata("avatar", "website", "foo", "bar", "baz");
		client.put(":irc.example.com 770 modernclient :avatar website");
		client.put(":irc.example.com 770 modernclient :foo");
		client.put(":irc.example.com 770 modernclient :bar baz");
		assert(client.isSubscribed("avatar"));
		assert(client.isSubscribed("website"));
		assert(client.isSubscribed("foo"));
		assert(client.isSubscribed("bar"));
		assert(client.isSubscribed("baz"));

		client.subscribeMetadata("foo", "$url", "bar");
		client.put(":irc.example.com 770 modernclient :foo bar");
		client.put("FAIL METADATA INVALID_KEY $url :Invalid key");
		assert(errors.length == 11);
		with(errors[10]) {
			assert(type == ErrorType.standardFail);
		}

		// uh oh zone
		client.state.metadataSubscribedKeys = [];
		client.subscribeMetadata("website", "avatar", "foo", "bar", "baz");
		client.put(":irc.example.com 770 modernclient :website avatar foo bar baz");
		client.subscribeMetadata("email", "city");
		client.put("FAIL METADATA TOO_MANY_SUBS email :Too many subscriptions!");
		client.listSubscribedMetadata();
		client.put(":irc.example.com 772 modernclient :website avatar foo bar baz");
		assert(errors.length == 12);
		with(errors[11]) {
			assert(type == ErrorType.standardFail);
		}
		assert(client.isSubscribed("website"));
		assert(client.isSubscribed("avatar"));
		assert(client.isSubscribed("foo"));
		assert(client.isSubscribed("bar"));
		assert(client.isSubscribed("baz"));
		assert(!client.isSubscribed("email"));
		assert(!client.isSubscribed("city"));

		client.state.metadataSubscribedKeys = [];
		client.subscribeMetadata("website", "avatar", "foo");
		client.put(":irc.example.com 770 modernclient :website avatar foo");
		client.subscribeMetadata("email", "city", "country", "bar", "baz");
		client.put("FAIL METADATA TOO_MANY_SUBS country :Too many subscriptions!");
		client.put(":irc.example.com 770 modernclient :email city");
		client.listSubscribedMetadata();
		client.put(":irc.example.com 772 modernclient :website avatar city foo email");
		assert(errors.length == 13);
		with(errors[12]) {
			assert(type == ErrorType.standardFail);
		}
		assert(client.isSubscribed("website"));
		assert(client.isSubscribed("avatar"));
		assert(client.isSubscribed("foo"));
		assert(client.isSubscribed("email"));
		assert(client.isSubscribed("city"));
		assert(!client.isSubscribed("country"));
		assert(!client.isSubscribed("bar"));
		assert(!client.isSubscribed("baz"));

		client.state.metadataSubscribedKeys = [];
		client.subscribeMetadata("avatar", "website");
		client.put(":irc.example.com 770 modernclient :avatar website");
		client.subscribeMetadata("foo", "avatar", "website");
		client.put("FAIL METADATA TOO_MANY_SUBS website :Too many subscriptions!");
		client.put(":irc.example.com 770 modernclient :foo");
		client.listSubscribedMetadata();
		client.put(":irc.example.com 772 modernclient :avatar foo website");
		assert(errors.length == 14);
		with(errors[13]) {
			assert(type == ErrorType.standardFail);
		}
		assert(client.isSubscribed("avatar"));
		assert(client.isSubscribed("foo"));
		assert(client.isSubscribed("website"));
		assert(!client.isSubscribed("country"));
		assert(!client.isSubscribed("bar"));
		assert(!client.isSubscribed("baz"));

		client.state.metadataSubscribedKeys = [];
		client.subscribeMetadata("website", "avatar", "foo", "bar", "baz");
		client.put(":irc.example.com 770 modernclient :website avatar foo bar baz");
		client.listSubscribedMetadata();
		client.put(":irc.example.com 772 modernclient :avatar bar baz foo website");
		assert(client.isSubscribed("avatar"));
		assert(client.isSubscribed("foo"));
		assert(client.isSubscribed("website"));
		assert(client.isSubscribed("bar"));
		assert(client.isSubscribed("baz"));

		client.state.metadataSubscribedKeys = [];
		client.subscribeMetadata("website", "avatar", "foo", "bar", "baz");
		client.put(":irc.example.com 770 modernclient :website avatar foo bar baz");
		client.listSubscribedMetadata();
		client.put(":irc.example.com 772 modernclient :avatar");
		client.put(":irc.example.com 772 modernclient :bar baz");
		client.put(":irc.example.com 772 modernclient :foo website");
		assert(client.isSubscribed("avatar"));
		assert(client.isSubscribed("foo"));
		assert(client.isSubscribed("website"));
		assert(client.isSubscribed("bar"));
		assert(client.isSubscribed("baz"));

		client.state.metadataSubscribedKeys = [];
		client.listSubscribedMetadata();

		client.state.metadataSubscribedKeys = [];
		client.subscribeMetadata("website", "avatar", "foo", "bar", "baz");
		client.put(":irc.example.com 770 modernclient :website avatar foo bar baz");
		client.listSubscribedMetadata();
		client.put(":irc.example.com 772 modernclient :avatar bar baz foo website");
		client.unsubscribeMetadata("bar", "foo", "baz");
		client.put(":irc.example.com 771 modernclient :baz foo bar");
		client.listSubscribedMetadata();
		client.put(":irc.example.com 772 modernclient :avatar website");
		assert(client.isSubscribed("avatar"));
		assert(client.isSubscribed("website"));

		client.state.metadataSubscribedKeys = [];
		client.subscribeMetadata("website", "avatar", "foo", "bar", "baz");
		client.put(":irc.example.com 770 modernclient :website avatar foo bar baz");
		client.listSubscribedMetadata();
		client.put(":irc.example.com 772 modernclient :avatar bar baz foo website");
		client.subscribeMetadata("avatar", "website");
		client.put(":irc.example.com 770 modernclient :avatar website");
		client.listSubscribedMetadata();
		client.put(":irc.example.com 772 modernclient :avatar bar baz foo website");
		assert(client.isSubscribed("avatar"));
		assert(client.isSubscribed("website"));
		assert(client.isSubscribed("foo"));
		assert(client.isSubscribed("bar"));
		assert(client.isSubscribed("baz"));

		client.state.metadataSubscribedKeys = [];
		client.subscribeMetadata("avatar", "avatar");
		client.put(":irc.example.com 770 modernclient :avatar");
		client.listSubscribedMetadata();
		client.put(":irc.example.com 772 modernclient :avatar");
		assert(client.isSubscribed("avatar"));

		client.state.metadataSubscribedKeys = [];
		client.subscribeMetadata("avatar", "avatar");
		client.put(":irc.example.com 770 modernclient :avatar avatar");
		client.listSubscribedMetadata();
		client.put(":irc.example.com 772 modernclient :avatar");
		assert(client.isSubscribed("avatar"));

		client.state.metadataSubscribedKeys = [];
		client.listSubscribedMetadata();
		client.unsubscribeMetadata("website");
		client.put(":irc.example.com 771 modernclient :website");
		assert(!client.isSubscribed("website"));
		client.listSubscribedMetadata();
		client.subscribeMetadata("website");
		client.put(":irc.example.com 770 modernclient :website");
		client.listSubscribedMetadata();
		client.put(":irc.example.com 772 modernclient :website");
		assert(client.isSubscribed("website"));

		client.state.metadataSubscribedKeys = [];
		client.listSubscribedMetadata();
		client.put(":irc.example.com 772 modernclient :website");
		client.unsubscribeMetadata("website", "website");
		client.put(":irc.example.com 771 modernclient :website");
		assert(!client.isSubscribed("website"));

		client.state.metadataSubscribedKeys = [];
		client.listSubscribedMetadata();
		client.put(":irc.example.com 772 modernclient :website");
		client.unsubscribeMetadata("website", "website");
		client.put(":irc.example.com 771 modernclient :website website");
		assert(!client.isSubscribed("website"));

		client.state.metadataSubscribedKeys = [];
		client.subscribeMetadata("avatar", "secretkey", "website");
		client.put("FAIL METADATA KEY_NO_PERMISSION secretkey modernclient :You do not have permission to do that.");
		client.put(":irc.example.com 770 modernclient :avatar website");
		client.listSubscribedMetadata();
		client.put(":irc.example.com 772 modernclient :avatar website");
		assert(!client.isSubscribed("secretkey"));
		assert(client.isSubscribed("website"));
		assert(client.isSubscribed("avatar"));
		assert(errors.length == 15);
		with(errors[14]) {
			assert(type == ErrorType.standardFail);
		}

		client.state.metadataSubscribedKeys = [];
		client.subscribeMetadata("$invalid1", "secretkey1", "$invalid2", "secretkey2", "website");
		client.put("FAIL METADATA KEY_NO_PERMISSION secretkey1 modernclient :You do not have permission to do that.");
		client.put("FAIL METADATA KEY_INVALID $invalid1 modernclient :Invalid key");
		client.put("FAIL METADATA KEY_NO_PERMISSION secretkey2 modernclient :You do not have permission to do that.");
		client.put("FAIL METADATA KEY_INVALID $invalid2 modernclient :Invalid key");
		client.put(":irc.example.com 770 modernclient :website");
		client.listSubscribedMetadata();
		client.put(":irc.example.com 772 modernclient :website");
		assert(!client.isSubscribed("$invalid1"));
		assert(!client.isSubscribed("secretkey1"));
		assert(!client.isSubscribed("$invalid2"));
		assert(!client.isSubscribed("secretkey2"));
		assert(client.isSubscribed("website"));
		assert(errors.length == 19);
		with(errors[15]) {
			assert(type == ErrorType.standardFail);
		}
		with(errors[16]) {
			assert(type == ErrorType.standardFail);
		}
		with(errors[17]) {
			assert(type == ErrorType.standardFail);
		}
		with(errors[18]) {
			assert(type == ErrorType.standardFail);
		}

		// end of uh oh zone

	}
}
