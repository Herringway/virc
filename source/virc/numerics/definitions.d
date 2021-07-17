/++
+
+/
module virc.numerics.definitions;

import std.meta : AliasSeq;

///
enum Numeric {
	//RFC1459 Command responses: https://tools.ietf.org/html/rfc1459#section-6.2
	///
	RPL_TRACELINK = "200",
	///
	RPL_TRACECONNECTING = "201",
	///
	RPL_TRACEHANDSHAKE = "202",
	///
	RPL_TRACEUNKNOWN = "203",
	///
	RPL_TRACEOPERATOR = "204",
	///
	RPL_TRACEUSER = "205",
	///
	RPL_TRACESERVER = "206",
	///
	RPL_TRACENEWTYPE = "208",
	///
	RPL_STATSLINKINFO = "211",
	///
	RPL_STATSCOMMANDS = "212",
	///
	RPL_STATSCLINE = "213",
	///
	RPL_STATSNLINE = "214",
	///
	RPL_STATSILINE = "215",
	///
	RPL_STATSKLINE = "216",
	///
	RPL_STATSYLINE = "218",
	///
	RPL_ENDOFSTATS = "219",
	///
	RPL_STATSLLINE = "241",
	///
	RPL_STATSUPTIME = "242",
	///
	RPL_STATSOLINE = "243",
	///
	RPL_STATSHLINE = "244",
	///
	RPL_UMODEIS = "221",
	///
	RPL_LUSERCLIENT = "251",
	///
	RPL_LUSEROP = "252",
	///
	RPL_LUSERUNKNOWN = "253",
	///
	RPL_LUSERCHANNELS = "254",
	///
	RPL_LUSERME = "255",
	///
	RPL_ADMINME = "256",
	///
	RPL_ADMINLOC1 = "257",
	///
	RPL_ADMINLOC2 = "258",
	///
	RPL_ADMINEMAIL = "259",
	///
	RPL_TRACELOG = "261",
	///
	RPL_NONE = "300",
	///
	RPL_AWAY = "301",
	///
	RPL_USERHOST = "302",
	///
	RPL_ISON = "303",
	///
	RPL_UNAWAY = "305",
	///
	RPL_NOWAWAY = "306",
	///
	RPL_WHOISUSER = "311",
	///
	RPL_WHOISSERVER = "312",
	///
	RPL_WHOISOPERATOR = "313",
	///
	RPL_WHOWASUSER = "314",
	///
	RPL_ENDOFWHO = "315",
	///
	RPL_WHOISIDLE = "317",
	///
	RPL_ENDOFWHOIS = "318",
	///
	RPL_WHOISCHANNELS = "319",
	///
	RPL_LISTSTART = "321",
	///
	RPL_LIST = "322",
	///
	RPL_LISTEND = "323",
	///
	RPL_CHANNELMODEIS = "324",
	///
	RPL_NOTOPIC = "331",
	///
	RPL_TOPIC = "332",
	///
	RPL_INVITING = "341",
	///
	RPL_SUMMONING = "342",
	///
	RPL_VERSION = "351",
	///
	RPL_WHOREPLY = "352",
	///
	RPL_NAMREPLY = "353",
	///
	RPL_LINKS = "364",
	///
	RPL_ENDOFLINKS = "365",
	///
	RPL_ENDOFNAMES = "366",
	///
	RPL_BANLIST = "367",
	///
	RPL_ENDOFBANLIST = "368",
	///
	RPL_ENDOFWHOWAS = "369",
	///
	RPL_INFO = "371",
	///
	RPL_MOTD = "372",
	///
	RPL_ENDOFINFO = "374",
	///
	RPL_MOTDSTART = "375",
	///
	RPL_ENDOFMOTD = "376",
	///
	RPL_YOUREOPER = "381",
	///
	RPL_REHASHING = "382",
	///
	RPL_TIME = "391",
	///
	RPL_USERSSTART = "392",
	///
	RPL_USERS = "393",
	///
	RPL_ENDOFUSERS = "394",
	///
	RPL_NOUSERS = "395",
	//RFC1459 Errors: https://tools.ietf.org/html/rfc1459#section-6.1
	///
	ERR_NOSUCHNICK = "401",
	///
	ERR_NOSUCHSERVER = "402",
	///
	ERR_NOSUCHCHANNEL = "403",
	///
	ERR_CANNOTSENDTOCHAN = "404",
	///
	ERR_TOOMANYCHANNELS = "405",
	///
	ERR_WASNOSUCHNICK = "406",
	///
	ERR_TOOMANYTARGETS = "407",
	///
	ERR_NOORIGIN = "409",
	///
	ERR_NORECIPIENT = "411",
	///
	ERR_NOTEXTTOSEND = "412",
	///
	ERR_NOTOPLEVEL = "413",
	///
	ERR_WILDTOPLEVEL = "414",
	///
	ERR_UNKNOWNCOMMAND = "421",
	///
	ERR_NOMOTD = "422",
	///
	ERR_NOADMININFO = "423",
	///
	ERR_FILEERROR = "424",
	///
	ERR_NONICKNAMEGIVEN = "431",
	///
	ERR_ERRONEUSNICKNAME = "432",
	///
	ERR_NICKNAMEINUSE = "433",
	///
	ERR_NICKCOLLISION = "436",
	///
	ERR_USERNOTINCHANNEL = "441",
	///
	ERR_NOTONCHANNEL = "442",
	///
	ERR_USERONCHANNEL = "443",
	///
	ERR_NOLOGIN = "444",
	///
	ERR_SUMMONDISABLED = "445",
	///
	ERR_USERSDISABLED = "446",
	///
	ERR_NOTREGISTERED = "451",
	///
	ERR_NEEDMOREPARAMS = "461",
	///
	ERR_ALREADYREGISTRED = "462",
	///
	ERR_NOPERMFORHOST = "463",
	///
	ERR_PASSWDMISMATCH = "464",
	///
	ERR_YOUREBANNEDCREEP = "465",
	///
	ERR_KEYSET = "467",
	///
	ERR_CHANNELISFULL = "471",
	///
	ERR_UNKNOWNMODE = "472",
	///
	ERR_INVITEONLYCHAN = "473",
	///
	ERR_BANNEDFROMCHAN = "474",
	///
	ERR_BADCHANNELKEY = "475",
	///
	ERR_NOPRIVILEGES = "481",
	///
	ERR_CHANOPRIVSNEEDED = "482",
	///
	ERR_CANTKILLSERVER = "483",
	///
	ERR_NOOPERHOST = "491",
	///
	ERR_UMODEUNKNOWNFLAG = "501",
	///
	ERR_USERSDONTMATCH = "502",
	//RFC1459 Reserved: https://tools.ietf.org/html/rfc1459#section-6.3
	//Obsolete or reserved for "future use"
	///
	RPL_STATSQLINE = "217",
	///
	RPL_SERVICEINFO = "231",
	///
	RPL_ENDOFSERVICES = "232",
	///
	RPL_SERVICE = "233",
	///
	RPL_WHOISCHANOP = "316",
	///
	RPL_KILLDONE = "361",
	///
	RPL_CLOSING = "362",
	///
	RPL_CLOSEEND = "363",
	///
	RPL_INFOSTART = "373",
	///
	RPL_MYPORTIS = "384",
	///
	ERR_NOSERVICEHOST = "492",
	//RFC2812 Command responses: https://tools.ietf.org/html/rfc2812#section-5.1
	///<client> :Welcome to the Internet Relay Network <nick>!<user>@<host>
	RPL_WELCOME = "001",
	///<client> :Your host is <servername>, running version <version>
	RPL_YOURHOST = "002",
	///<client> :This server was created <date>
	RPL_CREATED = "003",
	///<client> <server_name> <version> <usermodes> <chanmodes> [chanmodes_with_a_parameter]
	RPL_MYINFO = "004",
	///<client> :Try server <server_name>, port <port_number>
	RPL_BOUNCE = "005",
	///<client> Service <class> <name> <type> <active_type>
	RPL_TRACESERVICE = "207",
	///<client> Class <class> <count>
	RPL_TRACECLASS = "209",
	///<client> <name> <server> <mask> <type> <hopcount> <info>
	RPL_SERVLIST = "234",
	///<client> <mask> <type> :<info>
	RPL_SERVLISTEND = "235",
	///???
	RPL_TRACEEND = "262",
	///<client> <server_name> <version>[.<debug_level>] :<info>
	RPL_TRYAGAIN = "263",
	///<client> <channel> <nickname>
	RPL_UNIQOPIS = "325",
	///<client> <channel> <invitemask>
	RPL_INVITELIST = "346",
	///<client> <channel> :<info>
	RPL_ENDOFINVITELIST = "347",
	///<client> <channel> <exceptionmask> [<who> <set-ts>]
	RPL_EXCEPTLIST = "348",
	///<client> <channel> :<info>
	RPL_ENDOFEXCEPTLIST = "349",
	//RFC2812 Errors: https://tools.ietf.org/html/rfc2812#section-5.2
	///
	ERR_NOSUCHSERVICE = "408",
	///
	ERR_BADMASK = "415",
	///
	ERR_TOOMANYMATCHES = "416", //Errata
	///
	ERR_UNAVAILRESOURCE = "437",
	///
	ERR_YOUWILLBEBANNED = "466",
	///
	ERR_BADCHANMASK = "476",
	///
	ERR_NOCHANMODES = "477",
	///
	ERR_BANLISTFULL = "478",
	///
	ERR_RESTRICTED = "484",
	///
	ERR_UNIQOPPRIVSNEEDED = "485",
	//RFC2812 Reserved: https://tools.ietf.org/html/rfc2812#section-5.3
	///
	RPL_STATSVLINE = "240",
	///
	RPL_STATSSLINE = "245", //244 in original doc, 245 in errata
	///
	RPL_STATSPING = "246",
	///
	RPL_STATSBLINE = "247",
	///
	RPL_STATSDLINE = "250",
	//Monitor: http://ircv3.net/specs/core/monitor-3.2.html
	///
	RPL_MONONLINE = "730",
	///
	RPL_MONOFFLINE = "731",
	///
	RPL_MONLIST = "732",
	///
	RPL_ENDOFMONLIST = "733",
	///
	ERR_MONLISTFULL = "734",
	//Metadata: WIP
	///	<Target> <Key> <Visibility> :<Value>
	RPL_WHOISKEYVALUE = "760",
	///	<Target> <Key> <Visibility>[ :<Value>]
	RPL_KEYVALUE = "761",
	///	:end of metadata
	RPL_METADATAEND = "762",
	///	<Target> :metadata limit reached
	ERR_METADATALIMIT = "764",
	///	<Target> :invalid metadata target
	ERR_TARGETINVALID = "765",
	///	<Target> <Key> :no matching key
	ERR_NOMATCHINGKEY = "766",
	///	<InvalidKey>
	ERR_KEYINVALID = "767",
	///	<Target> <Key> :key not set
	ERR_KEYNOTSET = "768",
	///	<Target> <Key> :permission denied
	ERR_KEYNOPERMISSION = "769",
	/// :<Key1> [<Key2> ...]
	RPL_METADATASUBOK = "770",
	/// :<Key1> [<Key2> ...]
	RPL_METADATAUNSUBOK = "771",
	/// :<Key1> [<Key2> ...]
	RPL_METADATASUBS = "772",
	/// <Key>
	ERR_METADATATOOMANYSUBS = "773",
	///	<Target> [<RetryAfter>]
	ERR_METADATASYNCLATER = "774",
	///	<Target> <Key> <RetryAfter> :<Value>
	ERR_METADATARATELIMIT = "775",
	//SASL: http://ircv3.net/specs/extensions/sasl-3.1.html
	///
	RPL_LOGGEDIN = "900",
	///
	RPL_LOGGEDOUT = "901",
	///
	ERR_NICKLOCKED = "902",
	///
	RPL_SASLSUCCESS = "903",
	///
	ERR_SASLFAIL = "904",
	///
	ERR_SASLTOOLONG = "905",
	///
	ERR_SASLABORTED = "906",
	///
	ERR_SASLALREADY = "907",
	///
	RPL_SASLMECHS = "908",
	//STARTTLS: http://ircv3.net/specs/extensions/tls-3.1.html
	///
	RPL_STARTTLS = "670",
	///
	ERR_STARTTLS = "691",
	//IRCX: http://tools.ietf.org/id/draft-pfenning-irc-extensions-04.txt
	//Pretty uncommon, but included for completeness
	///
	IRCRPL_IRCX = "800",
	///
	IRCRPL_ACCESSADD = "801",
	///
	IRCRPL_ACCESSDELETE = "802",
	///
	IRCRPL_ACCESSSTART = "803",
	///
	IRCRPL_ACCESSLIST = "804",
	///
	IRCRPL_ACCESSEND = "805",
	///
	IRCRPL_EVENTADD = "806",
	///
	IRCRPL_EVENTDEL = "807",
	///
	IRCRPL_EVENTSTART = "808",
	///
	IRCRPL_EVENTLIST = "809",
	///
	IRCRPL_EVENTEND = "810",
	///
	IRCRPL_LISTXSTART = "811",
	///
	IRCRPL_LISTXLIST = "812",
	///
	IRCRPL_LISTXPICS = "813",
	///
	IRCRPL_LISTXTRUNC = "816",
	///
	IRCRPL_LISTXEND = "817",
	///
	IRCRPL_PROPLIST = "818",
	///
	IRCRPL_PROPEND = "819",
	///
	IRCERR_BADCOMMAND = "900",
	///
	IRCERR_TOOMANYARGUMENTS = "901",
	///
	IRCERR_BADFUNCTION = "902",
	///
	IRCERR_BADLEVEL = "903",
	///
	IRCERR_BADTAG = "904",
	///
	IRCERR_BADPROPERTY = "905",
	///
	IRCERR_BADVALUE = "906",
	///
	IRCERR_RESOURCE = "907",
	///
	IRCERR_SECURITY = "908",
	///
	IRCERR_ALREADYAUTHENTICATED = "909",
	///
	IRCERR_AUTHENTICATIONFAILED = "910",
	///
	IRCERR_AUTHENTICATIONSUSPENDED = "911",
	///
	IRCERR_UNKNOWNPACKAGE = "912",
	///
	IRCERR_NOACCESS = "913",
	///
	IRCERR_DUPACCESS = "914",
	///
	IRCERR_MISACCESS = "915",
	///
	IRCERR_TOOMANYACCESSES = "916",
	///
	IRCERR_EVENTDUP = "918",
	///
	IRCERR_EVENTMIS = "919",
	///
	IRCERR_NOSUCHEVENT = "920",
	///
	IRCERR_TOOMANYEVENTS = "921",
	///
	IRCERR_NOWHISPER = "923",
	///
	IRCERR_NOSUCHOBJECT = "924",
	///
	IRCERR_NOTSUPPORTED = "925",
	///
	IRCERR_CHANNELEXIST = "926",
	///
	IRCERR_ALREADYONCHANNEL = "927",
	///
	IRCERR_UNKNOWNERROR = "999",
	//WATCH: https://github.com/grawity/irc-docs/blob/master/client/draft-meglio-irc-watch-00.txt
	///
	RPL_GONEAWAY = "598",
	///
	RPL_NOTAWAY = "599",
	///
	RPL_LOGON = "600",
	///
	RPL_LOGOFF = "601",
	///
	RPL_WATCHOFF = "602",
	///
	RPL_WATCHSTAT = "603",
	///
	RPL_NOWON = "604",
	///
	RPL_NOWOFF = "605",
	///
	RPL_WATCHLIST = "606",
	///
	RPL_ENDOFWATCHLIST = "607",
	///
	RPL_CLEARWATCH = "608",
	///
	RPL_NOWISAWAY = "609",
	//Misc
	///
	RPL_TEXT = "304",
	//Unknown origin, but in use
	///
	RPL_YOURID = "042",
	///
	RPL_LOCALUSERS = "265",
	///
	RPL_GLOBALUSERS = "266",
	/// <nick> :has client certificate fingerprint <fingerprint>
	RPL_WHOISCERTFP = "276",
	///
	RPL_WHOISREGNICK = "307",
	///
	RPL_WHOISACCOUNT = "330",
	///
	RPL_TOPICWHOTIME = "333",
	///
	RPL_WHOISHOST = "378",
	/// <nick> :is using modes <modestring>
	RPL_WHOISMODE = "379",
	///
	RPL_HOSTHIDDEN = "396",
	///
	RPL_WHOISSECURE = "671",
	///
	ERR_NOPRIVS = "723",
	//ISUPPORT: http://www.irc.org/tech_docs/draft-brocklesby-irc-isupport-03.txt
	///
	RPL_ISUPPORT = "005"
}
alias noInformationNumerics = AliasSeq!(
	Numeric.RPL_WELCOME,
	Numeric.RPL_YOURHOST,
	Numeric.RPL_CREATED,

	Numeric.RPL_YOURID,
	Numeric.RPL_LOCALUSERS,
	Numeric.RPL_GLOBALUSERS,
	Numeric.RPL_HOSTHIDDEN,

	listEndNumerics,
	listStartNumerics
);
alias listStartNumerics =AliasSeq!(
	Numeric.RPL_LISTSTART
);
alias listEndNumerics =AliasSeq!(
	Numeric.RPL_LISTEND,
	Numeric.RPL_ENDOFNAMES,
	Numeric.RPL_ENDOFMONLIST
);