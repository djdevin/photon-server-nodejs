// Photon Protocol Constants

/**
 * ENet command types used by Photon's reliable-UDP transport.
 * These appear as the first byte of each command inside a UDP packet.
 */
const ENET_COMMANDS = {
    ACKNOWLEDGE: 1,
    CONNECT: 2,
    VERIFY_CONNECT: 3,
    DISCONNECT: 4,
    PING: 5,
    SEND_RELIABLE: 6,
    SEND_UNRELIABLE: 7,
    SEND_FRAGMENT: 8,
    FETCH_SERVER_TIMESTAMP: 12
};

// Legacy alias (older code referred to these as PHOTON_COMMANDS)
const PHOTON_COMMANDS = {
    ACKNOWLEDGE: 1,
    CONNECT: 2,
    VERIFY_CONNECT: 3,
    DISCONNECT: 4,
    PING: 5,
    SEND_RELIABLE: 6,
    SEND_UNRELIABLE: 7,
    FRAGMENT: 8,
    SEND_UNRELIABLE_FRAGMENT: 9,
    SEND_RELIABLE_FRAGMENT: 10,
    FETCH_SERVER_TIMESTAMP: 12,
    SEND_NEXT_RELIABLE: 13,
    SEND_FRAGMENT: 14
};

/**
 * GpBinary message types. Messages travel inside reliable/unreliable
 * commands and always start with 0xF3 followed by one of these.
 */
const MESSAGE_TYPES = {
    INIT: 0,
    INIT_RESPONSE: 1,
    OPERATION_REQUEST: 2,
    OPERATION_RESPONSE: 3,
    EVENT: 4,
    INTERNAL_OPERATION_REQUEST: 6,
    INTERNAL_OPERATION_RESPONSE: 7,
    MESSAGE: 8,
    RAW_MESSAGE: 9
};

const MESSAGE_SIGNATURE = 0xF3;

const PHOTON_PEER_STATE = {
    DISCONNECTED: 0,
    CONNECTING: 1,
    CONNECTED: 2,
    CONNECTION_LOST: 3,
    DISCONNECTING: 4
};

/** GpBinaryV16 wire type markers */
const PHOTON_TYPES = {
    NULL: 0x2A,
    DICTIONARY: 0x44,
    STRING_ARRAY: 0x61,
    BYTE: 0x62,
    CUSTOM_DATA: 0x63,
    DOUBLE: 0x64,
    EVENT_DATA: 0x65,
    FLOAT: 0x66,
    HASH_TABLE: 0x68,
    INTEGER: 0x69,
    SHORT: 0x6B,
    LONG: 0x6C,
    INT_ARRAY: 0x6E,
    BOOLEAN: 0x6F,
    OPERATION_RESPONSE: 0x70,
    OPERATION_REQUEST: 0x71,
    STRING: 0x73,
    BYTE_ARRAY: 0x78,
    ARRAY: 0x79,
    OBJECT_ARRAY: 0x7A
};

/**
 * LoadBalancing (PUN / Realtime) operation codes.
 * These are what real Photon clients send.
 */
const PHOTON_OPERATIONS = {
    GET_GAME_LIST: 217,
    SERVER_SETTINGS: 218,
    WEB_RPC: 219,
    GET_REGIONS: 220,
    JOIN_RANDOM_GAME: 225,
    JOIN_GAME: 226,
    CREATE_GAME: 227,
    LEAVE_LOBBY: 228,
    JOIN_LOBBY: 229,
    AUTHENTICATE: 230,
    AUTHENTICATE_ONCE: 231,
    CHANGE_GROUPS: 248,
    EXCHANGE_KEYS_FOR_ENCRYPTION: 250,
    GET_PROPERTIES: 251,
    SET_PROPERTIES: 252,
    RAISE_EVENT: 253,
    LEAVE: 254,
    JOIN: 255,

    // Legacy aliases used elsewhere in this codebase
    JOIN_ROOM: 226,
    CREATE_ROOM: 227,
    JOIN_RANDOM_ROOM: 225,
    LEAVE_ROOM: 254,
    CHANGE_PROPERTIES: 252,
    GET_ROOMS: 217,
    GET_ROOM_LIST: 217
};

/** Internal operation codes (message type 6/7) */
const INTERNAL_OPERATIONS = {
    INIT_ENCRYPTION: 0,
    PING: 1
};

/**
 * LoadBalancing parameter codes (byte keys of operation/event parameters).
 */
const PHOTON_PARAMS = {
    GAME_ID: 255,            // room name
    ACTOR_NR: 254,
    TARGET_ACTOR_NR: 253,
    ACTORS: 252,             // int[]
    PROPERTIES: 251,
    BROADCAST: 250,
    ACTOR_PROPERTIES: 249,
    GAME_PROPERTIES: 248,
    CACHE: 247,
    RECEIVER_GROUP: 246,
    DATA: 245,               // event data / custom event content
    CODE: 244,               // event code (RaiseEvent)
    CLEANUP_CACHE_ON_LEAVE: 241,
    GROUP: 240,
    REMOVE_GROUPS: 239,
    ADD_GROUPS: 238,
    SUPPRESS_ROOM_EVENTS: 237,
    EMPTY_ROOM_TTL: 236,
    PLAYER_TTL: 235,
    PLUGINS: 204,
    MASTER_CLIENT_ID: 203,
    NICKNAME: 202,
    PUBLISH_USER_ID: 239,
    ADDRESS: 230,            // game server address returned by master
    PEER_COUNT: 229,
    GAME_COUNT: 228,
    MASTER_PEER_COUNT: 227,
    USER_ID: 225,
    APPLICATION_ID: 224,
    POSITION: 223,
    MATCHMAKING_TYPE: 223,
    GAME_LIST: 222,
    SECRET: 221,             // auth token
    APP_VERSION: 220,
    CLIENT_AUTHENTICATION_TYPE: 217,
    CLIENT_AUTHENTICATION_PARAMS: 216,
    JOIN_MODE: 215,          // 0 join, 1 create-if-not-exists, 2 rejoin...
    CLIENT_AUTHENTICATION_DATA: 214,
    LOBBY_NAME: 213,
    LOBBY_TYPE: 212,
    LOBBY_STATS: 211,
    REGION: 210,
    EXPECTED_VALUES: 231,
    ROOM_OPTION_FLAGS: 191
};

/** Well-known game property keys (byte keys inside GameProperties hashtable) */
const GAME_PROPERTY_KEYS = {
    MAX_PLAYERS: 255,
    IS_OPEN: 254,
    IS_VISIBLE: 253,
    PROPS_LISTED_IN_LOBBY: 250,
    CLEANUP_CACHE_ON_LEAVE: 249,
    MASTER_CLIENT_ID: 248,
    EXPECTED_USERS: 247,
    PLAYER_TTL: 246,
    EMPTY_ROOM_TTL: 245
};

/** Well-known actor property keys */
const ACTOR_PROPERTY_KEYS = {
    NICKNAME: 255,
    USER_ID: 254,
    IS_INACTIVE: 253
};

/** LoadBalancing event codes */
const PHOTON_EVENTS = {
    JOIN: 255,
    LEAVE: 254,
    PROPERTIES_CHANGED: 253,
    ERROR_INFO: 251,
    CACHE_SLICE_CHANGED: 250,
    AUTH_EVENT: 223,
    LOBBY_STATS: 224,
    GAME_LIST: 230,
    GAME_LIST_UPDATE: 229,
    MASTER_CLIENT_SWITCHED: 208,
    ROOM_LIST_UPDATE: 229
};

/** Event caching options (RaiseEvent parameter 247) */
const EVENT_CACHING = {
    DO_NOT_CACHE: 0,
    MERGE_CACHE: 1,
    REPLACE_CACHE: 2,
    REMOVE_CACHE: 3,
    ADD_TO_ROOM_CACHE: 4,
    ADD_TO_ROOM_CACHE_GLOBAL: 5,
    SLICE_INC_INDEX: 6,
    SLICE_SET_INDEX: 7,
    REMOVE_FROM_ROOM_CACHE: 8
};

/** Event receiver groups (RaiseEvent parameter 246) */
const RECEIVER_GROUPS = {
    OTHERS: 0,
    ALL: 1,
    MASTER_CLIENT: 2
};

const PHOTON_RETURN_CODES = {
    OK: 0,
    OPERATION_INVALID: -3,
    OPERATION_NOT_ALLOWED_IN_CURRENT_STATE: -4,
    INVALID_OPERATION: -2,
    INTERNAL_SERVER_ERROR: -1,
    INVALID_AUTHENTICATION: 32767,
    GAME_ID_ALREADY_EXISTS: 32766,
    GAME_FULL: 32765,
    GAME_CLOSED: 32764,
    NO_RANDOM_MATCH_FOUND: 32760,
    GAME_DOES_NOT_EXIST: 32758,
    ROOM_NOT_FOUND: 32758,
    ROOM_FULL: 32765,
    ROOM_CLOSED: 32764,
    ALREADY_JOINED: 32760,
    PLUGIN_REPORTED_ERROR: 32757,
    PLUGIN_MISMATCH: 32756,
    JOIN_FAILED_PEER_ALREADY_JOINED: 32750,
    JOIN_FAILED_FOUND_INACTIVE_JOINER: 32749,
    JOIN_FAILED_WITH_REJOIN_NOT_ALLOWED: 32748,
    JOIN_FAILED_FOUND_EXCLUDED_USER_ID: 32747,
    JOIN_FAILED_FOUND_ACTIVE_JOINER: 32746
};

// Legacy TCP-framing signature kept for backwards compatibility with old code
const PHOTON_SIGNATURE = 0xFB17;

const DEFAULT_SERVER_CONFIG = {
    port: 5055,
    host: '0.0.0.0',
    publicAddress: null,       // ip[:port] advertised to clients as the game server
    maxConnections: 1000,
    pingInterval: 30000,
    connectionTimeout: 60000,
    cleanupInterval: 60000,
    emptyRoomTtl: 300000
};

const DEFAULT_PEER_CONFIG = {
    timeout: 60000,
    pingInterval: 30000,
    maxReliableCommands: 1000,
    enableCompression: false,
    retransmitInterval: 300,   // initial reliable retransmit delay (ms)
    maxRetransmits: 10
};

module.exports = {
    ENET_COMMANDS,
    PHOTON_COMMANDS,
    MESSAGE_TYPES,
    MESSAGE_SIGNATURE,
    INTERNAL_OPERATIONS,
    PHOTON_PEER_STATE,
    PHOTON_TYPES,
    PHOTON_OPERATIONS,
    PHOTON_PARAMS,
    GAME_PROPERTY_KEYS,
    ACTOR_PROPERTY_KEYS,
    PHOTON_EVENTS,
    EVENT_CACHING,
    RECEIVER_GROUPS,
    PHOTON_RETURN_CODES,
    PHOTON_SIGNATURE,
    DEFAULT_SERVER_CONFIG,
    DEFAULT_PEER_CONFIG
};
