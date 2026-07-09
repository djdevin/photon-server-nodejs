const crypto = require('crypto');
const gp = require('../protocol/gpbinary');
const logger = require('../utils/logger');
const {
    PHOTON_OPERATIONS: OPS,
    PHOTON_PARAMS: P,
    PHOTON_EVENTS: EV,
    GAME_PROPERTY_KEYS: GPK,
    ACTOR_PROPERTY_KEYS: APK,
    EVENT_CACHING,
    RECEIVER_GROUPS,
    PHOTON_RETURN_CODES: RC
} = require('../protocol/constants');

const { T, raw } = gp;

/**
 * Handles LoadBalancing operations from Photon clients.
 *
 * This server plays both LoadBalancing roles at one address: clients first
 * authenticate against it as the "master server"; when they create/join a
 * room the response points them at the game server — the same address —
 * and they reconnect and re-authenticate (carrying the token in parameter
 * 221) before actually entering the room.
 */
class OperationHandler {
    /**
     * @param {PhotonServer} server - The Photon server instance
     */
    constructor(server) {
        if (!server) {
            throw new Error('Server instance is required');
        }
        this.server = server;
    }

    /**
     * Process an operation request message from a peer.
     * @param {PhotonPeer} peer
     * @param {Object} message - {operationCode, parameters}
     */
    async handleOperation(peer, message) {
        const opCode = message.operationCode;
        const params = message.parameters || {};

        logger.debug('Operation received', {
            peerId: peer.peerId,
            opCode,
            paramCodes: Object.keys(params)
        });

        try {
            switch (opCode) {
                case OPS.AUTHENTICATE: return this._authenticate(peer, params);
                case OPS.JOIN_LOBBY: return this._joinLobby(peer, params);
                case OPS.LEAVE_LOBBY: return this._leaveLobby(peer, params);
                case OPS.CREATE_GAME: return this._createOrJoinGame(peer, OPS.CREATE_GAME, params);
                case OPS.JOIN_GAME: return this._createOrJoinGame(peer, OPS.JOIN_GAME, params);
                case OPS.JOIN_RANDOM_GAME: return this._joinRandomGame(peer, params);
                case OPS.LEAVE: return this._leave(peer, params);
                case OPS.RAISE_EVENT: return this._raiseEvent(peer, params);
                case OPS.SET_PROPERTIES: return this._setProperties(peer, params);
                case OPS.GET_PROPERTIES: return this._getProperties(peer, params);
                case OPS.GET_REGIONS: return this._getRegions(peer, params);
                case OPS.GET_GAME_LIST: return this._getGameList(peer, params);
                case OPS.SERVER_SETTINGS: return this._serverSettings(peer, params);
                default:
                    logger.warn('Unknown operation', { peerId: peer.peerId, opCode });
                    peer.sendOperationResponse(opCode, RC.OPERATION_INVALID, {},
                        `Unknown operation code: ${opCode}`);
            }
        } catch (error) {
            logger.error('Operation failed', {
                peerId: peer.peerId,
                opCode,
                error: error.message,
                stack: error.stack
            });
            peer.sendOperationResponse(opCode, RC.INTERNAL_SERVER_ERROR, {},
                'Internal server error');
        }
    }

    // ------------------------------------------------------------------
    // Authentication
    // ------------------------------------------------------------------

    _authenticate(peer, params) {
        const appVersion = raw(params[P.APP_VERSION]);
        const userId = raw(params[P.USER_ID]) || `user_${peer.peerId}`;
        const secret = raw(params[P.SECRET]);

        // A token in the auth request means this is the game-server phase
        // of the connect flow (client reconnected after our redirect).
        peer.authenticate('', userId, {
            appVersion,
            authType: raw(params[P.CLIENT_AUTHENTICATION_TYPE]),
            authParams: raw(params[P.CLIENT_AUTHENTICATION_PARAMS]),
            authData: raw(params[P.CLIENT_AUTHENTICATION_DATA])
        }, secret || null);

        const responseParams = {
            [P.USER_ID]: T.string(peer.userId),
            [P.SECRET]: T.string(secret || this._makeToken(peer))
        };

        logger.info('Peer authenticated', {
            peerId: peer.peerId,
            userId: peer.userId,
            appVersion,
            phase: peer.onGameServer ? 'game-server' : 'master'
        });

        peer.sendOperationResponse(OPS.AUTHENTICATE, RC.OK, responseParams);
    }

    _makeToken(peer) {
        return crypto.randomBytes(16).toString('hex');
    }

    // ------------------------------------------------------------------
    // Lobby
    // ------------------------------------------------------------------

    _joinLobby(peer, params) {
        peer.sendOperationResponse(OPS.JOIN_LOBBY, RC.OK);

        // Send the current room list as a GameList event
        const gameList = new Map();
        for (const room of this.server.getVisibleRooms()) {
            gameList.set(room.name, this._roomListEntry(room));
        }
        peer.sendEvent(EV.GAME_LIST, { [P.GAME_LIST]: T.hashtable(gameList) });
    }

    _leaveLobby(peer, params) {
        peer.sendOperationResponse(OPS.LEAVE_LOBBY, RC.OK);
    }

    _roomListEntry(room) {
        const entry = new Map();
        entry.set(GPK.MAX_PLAYERS, T.byte(room.maxPlayers));
        entry.set(GPK.IS_OPEN, room.isOpen);
        entry.set(GPK.IS_VISIBLE, room.isVisible);
        entry.set(APK.USER_ID, T.byte(room.getPeerCount())); // PlayerCount key 252? kept simple
        for (const [key, value] of Object.entries(room.customProperties || {})) {
            entry.set(key, value);
        }
        return T.hashtable(entry);
    }

    _getGameList(peer, params) {
        const gameList = new Map();
        for (const room of this.server.getVisibleRooms()) {
            gameList.set(room.name, this._roomListEntry(room));
        }
        peer.sendOperationResponse(OPS.GET_GAME_LIST, RC.OK, {
            [P.GAME_LIST]: T.hashtable(gameList)
        });
    }

    _getRegions(peer, params) {
        peer.sendOperationResponse(OPS.GET_REGIONS, RC.OK, {
            [P.REGION]: T.stringArray(['us']),
            [P.ADDRESS]: T.stringArray([this.server.getPublicAddress()])
        });
    }

    _serverSettings(peer, params) {
        peer.sendOperationResponse(OPS.SERVER_SETTINGS, RC.OK);
    }

    // ------------------------------------------------------------------
    // Room create / join
    // ------------------------------------------------------------------

    _createOrJoinGame(peer, opCode, params) {
        if (!peer.isAuthenticated()) {
            peer.sendOperationResponse(opCode, RC.OPERATION_NOT_ALLOWED_IN_CURRENT_STATE, {},
                'Authenticate first');
            return;
        }

        const roomName = raw(params[P.GAME_ID]) ||
            `Room_${crypto.randomBytes(4).toString('hex')}`;
        const joinMode = raw(params[P.JOIN_MODE]) || 0;
        const createIfNotExists = opCode === OPS.CREATE_GAME || joinMode >= 1;

        // Master phase: validate and redirect to the game server (ourselves)
        if (!peer.onGameServer) {
            const room = this.server.getRoom(roomName);

            if (opCode === OPS.JOIN_GAME && !room && !createIfNotExists) {
                peer.sendOperationResponse(opCode, RC.GAME_DOES_NOT_EXIST, {},
                    'Game does not exist');
                return;
            }
            if (opCode === OPS.CREATE_GAME && room && joinMode === 0) {
                peer.sendOperationResponse(opCode, RC.GAME_ID_ALREADY_EXISTS, {},
                    'A game with this name already exists');
                return;
            }
            if (room && (!room.isOpen || room.isFull())) {
                peer.sendOperationResponse(opCode,
                    room.isOpen ? RC.GAME_FULL : RC.GAME_CLOSED, {},
                    room.isOpen ? 'Game full' : 'Game closed');
                return;
            }

            peer.sendOperationResponse(opCode, RC.OK, {
                [P.GAME_ID]: T.string(roomName),
                [P.ADDRESS]: T.string(this.server.getPublicAddress()),
                [P.SECRET]: T.string(this._makeToken(peer))
            });

            logger.info('Redirecting peer to game server', {
                peerId: peer.peerId,
                roomName,
                address: this.server.getPublicAddress()
            });
            return;
        }

        // Game-server phase: actually enter the room
        this._enterRoom(peer, opCode, roomName, params, createIfNotExists);
    }

    _enterRoom(peer, opCode, roomName, params, createIfNotExists) {
        if (peer.room) {
            peer.sendOperationResponse(opCode, RC.ALREADY_JOINED, {}, 'Already in a room');
            return;
        }

        let room = this.server.getRoom(roomName);

        if (!room) {
            if (!createIfNotExists) {
                peer.sendOperationResponse(opCode, RC.GAME_DOES_NOT_EXIST, {},
                    'Game does not exist');
                return;
            }
            room = this.server.createRoom(roomName, this._roomOptionsFromParams(params));
        } else if (opCode === OPS.CREATE_GAME && (raw(params[P.JOIN_MODE]) || 0) === 0) {
            peer.sendOperationResponse(opCode, RC.GAME_ID_ALREADY_EXISTS, {},
                'A game with this name already exists');
            return;
        }

        // Actor properties sent by the client (nickname etc.)
        const actorProps = raw(params[P.ACTOR_PROPERTIES]);
        if (actorProps instanceof Map) {
            peer.actorProperties = actorProps;
            const nick = raw(actorProps.get(APK.NICKNAME));
            if (typeof nick === 'string') peer.setNickname(nick);
        }

        if (!room.addPeer(peer)) {
            peer.sendOperationResponse(opCode,
                room.isFull() ? RC.GAME_FULL : RC.GAME_CLOSED, {},
                'Unable to join game');
            return;
        }

        // Merge game properties provided on create
        const gameProps = raw(params[P.GAME_PROPERTIES]);
        if (gameProps instanceof Map) {
            this._applyWellKnownGameProps(room, gameProps);
        }

        const actors = this._actorNumbers(room);

        peer.sendOperationResponse(opCode, RC.OK, {
            [P.ACTOR_NR]: T.int(peer.actorNr),
            [P.ACTORS]: T.intArray(actors),
            [P.ACTOR_PROPERTIES]: T.hashtable(this._actorPropertiesTable(room)),
            [P.GAME_PROPERTIES]: T.hashtable(this._gamePropertiesTable(room))
        });

        // Join event to everyone in the room (including the joiner)
        const joinEvent = {
            [P.ACTOR_NR]: T.int(peer.actorNr),
            [P.ACTORS]: T.intArray(actors),
            [P.ACTOR_PROPERTIES]: T.hashtable(peer.actorProperties || new Map())
        };
        for (const member of room.getPeers()) {
            member.sendEvent(EV.JOIN, joinEvent);
        }

        // Replay cached events to the new joiner
        room.replayCachedEvents(peer);

        logger.info('Peer entered room', {
            peerId: peer.peerId,
            actorNr: peer.actorNr,
            roomName,
            playerCount: room.getPeerCount()
        });
    }

    _joinRandomGame(peer, params) {
        if (!peer.isAuthenticated()) {
            peer.sendOperationResponse(OPS.JOIN_RANDOM_GAME, RC.OPERATION_NOT_ALLOWED_IN_CURRENT_STATE,
                {}, 'Authenticate first');
            return;
        }

        const filter = raw(params[P.GAME_PROPERTIES]);
        const candidates = this.server.getVisibleRooms().filter((room) =>
            room.isOpen && !room.isFull() && this._matchesFilter(room, filter));

        if (candidates.length === 0) {
            peer.sendOperationResponse(OPS.JOIN_RANDOM_GAME, RC.NO_RANDOM_MATCH_FOUND, {},
                'No match found');
            return;
        }

        const room = candidates[Math.floor(Math.random() * candidates.length)];
        peer.sendOperationResponse(OPS.JOIN_RANDOM_GAME, RC.OK, {
            [P.GAME_ID]: T.string(room.name),
            [P.ADDRESS]: T.string(this.server.getPublicAddress()),
            [P.SECRET]: T.string(this._makeToken(peer))
        });
    }

    _matchesFilter(room, filter) {
        if (!(filter instanceof Map) || filter.size === 0) return true;
        const props = room.customProperties || {};
        for (const [key, value] of filter.entries()) {
            if (props[key] !== raw(value)) return false;
        }
        return true;
    }

    _roomOptionsFromParams(params) {
        const options = { maxPlayers: 0, customProperties: {} };

        const gameProps = raw(params[P.GAME_PROPERTIES]);
        if (gameProps instanceof Map) {
            for (const [key, value] of gameProps.entries()) {
                switch (key) {
                    case GPK.MAX_PLAYERS: options.maxPlayers = raw(value); break;
                    case GPK.IS_OPEN: options.isOpen = !!raw(value); break;
                    case GPK.IS_VISIBLE: options.isVisible = !!raw(value); break;
                    case GPK.PROPS_LISTED_IN_LOBBY: break;
                    default:
                        if (typeof key === 'string') options.customProperties[key] = value;
                }
            }
        }

        const playerTtl = raw(params[P.PLAYER_TTL]);
        const emptyRoomTtl = raw(params[P.EMPTY_ROOM_TTL]);
        if (typeof playerTtl === 'number') options.playerTtl = Math.max(0, playerTtl);
        if (typeof emptyRoomTtl === 'number' && emptyRoomTtl > 0) options.emptyRoomTtl = emptyRoomTtl;
        if (!options.maxPlayers || options.maxPlayers <= 0) options.maxPlayers = 100;

        return options;
    }

    _applyWellKnownGameProps(room, gameProps) {
        const custom = {};
        for (const [key, value] of gameProps.entries()) {
            if (typeof key === 'string') custom[key] = value;
        }
        if (Object.keys(custom).length > 0) {
            room.setCustomProperties(custom, false);
        }
    }

    _actorNumbers(room) {
        return room.getPeers().map(p => p.actorNr).sort((a, b) => a - b);
    }

    _actorPropertiesTable(room) {
        const table = new Map();
        for (const member of room.getPeers()) {
            const props = new Map(member.actorProperties || []);
            if (member.playerName && !props.has(APK.NICKNAME)) {
                props.set(APK.NICKNAME, member.playerName);
            }
            table.set(T.int(member.actorNr), T.hashtable(props));
        }
        return table;
    }

    _gamePropertiesTable(room) {
        const table = new Map();
        table.set(GPK.MAX_PLAYERS, T.byte(Math.min(255, room.maxPlayers)));
        table.set(GPK.IS_OPEN, !!room.isOpen);
        table.set(GPK.IS_VISIBLE, !!room.isVisible);
        table.set(GPK.MASTER_CLIENT_ID, T.int(this._masterActorNr(room)));
        for (const [key, value] of Object.entries(room.customProperties || {})) {
            table.set(key, value);
        }
        return table;
    }

    _masterActorNr(room) {
        const actors = this._actorNumbers(room);
        return actors.length > 0 ? actors[0] : 0;
    }

    // ------------------------------------------------------------------
    // Leave
    // ------------------------------------------------------------------

    _leave(peer, params) {
        if (!peer.room) {
            peer.sendOperationResponse(OPS.LEAVE, RC.OPERATION_NOT_ALLOWED_IN_CURRENT_STATE,
                {}, 'Not in a room');
            return;
        }

        const roomName = peer.room.name;
        const wasEmpty = peer.leaveRoom('Client left');
        peer.sendOperationResponse(OPS.LEAVE, RC.OK);

        if (wasEmpty) {
            this.server.removeRoom(roomName);
        }
    }

    // ------------------------------------------------------------------
    // RaiseEvent
    // ------------------------------------------------------------------

    _raiseEvent(peer, params) {
        const room = peer.room;
        if (!room) {
            peer.sendOperationResponse(OPS.RAISE_EVENT, RC.OPERATION_NOT_ALLOWED_IN_CURRENT_STATE,
                {}, 'Not in a room');
            return;
        }

        const eventCode = raw(params[P.CODE]);
        if (typeof eventCode !== 'number') {
            peer.sendOperationResponse(OPS.RAISE_EVENT, RC.OPERATION_INVALID, {},
                'Missing event code');
            return;
        }

        const cache = raw(params[P.CACHE]) || 0;
        const receiverGroup = raw(params[P.RECEIVER_GROUP]) || RECEIVER_GROUPS.OTHERS;
        const targetActors = raw(params[P.ACTORS]);

        const eventParams = { [P.ACTOR_NR]: T.int(peer.actorNr) };
        if (params[P.DATA] !== undefined) {
            eventParams[P.DATA] = params[P.DATA]; // typed, round-trips exactly
        }

        // Event cache for late joiners
        switch (cache) {
            case EVENT_CACHING.ADD_TO_ROOM_CACHE:
            case EVENT_CACHING.ADD_TO_ROOM_CACHE_GLOBAL:
            case EVENT_CACHING.MERGE_CACHE:
            case EVENT_CACHING.REPLACE_CACHE:
                room.cacheRoomEvent(peer.actorNr, eventCode, eventParams,
                    cache === EVENT_CACHING.ADD_TO_ROOM_CACHE_GLOBAL);
                break;
            case EVENT_CACHING.REMOVE_CACHE:
            case EVENT_CACHING.REMOVE_FROM_ROOM_CACHE:
                room.removeCachedEvents(peer.actorNr, eventCode);
                break;
        }

        // Route
        let targets;
        if (Array.isArray(targetActors) && targetActors.length > 0) {
            const set = new Set(targetActors);
            targets = room.getPeers().filter(p => set.has(p.actorNr));
        } else if (receiverGroup === RECEIVER_GROUPS.ALL) {
            targets = room.getPeers();
        } else if (receiverGroup === RECEIVER_GROUPS.MASTER_CLIENT) {
            const masterNr = this._masterActorNr(room);
            targets = room.getPeers().filter(p => p.actorNr === masterNr);
        } else {
            targets = room.getPeers().filter(p => p !== peer);
        }

        for (const target of targets) {
            target.sendEvent(eventCode, eventParams);
        }

        // RaiseEvent has no operation response on success.
    }

    // ------------------------------------------------------------------
    // Properties
    // ------------------------------------------------------------------

    _setProperties(peer, params) {
        const room = peer.room;
        if (!room) {
            peer.sendOperationResponse(OPS.SET_PROPERTIES, RC.OPERATION_NOT_ALLOWED_IN_CURRENT_STATE,
                {}, 'Not in a room');
            return;
        }

        const properties = raw(params[P.PROPERTIES]);
        const targetActorNr = raw(params[P.ACTOR_NR]);
        const broadcast = params[P.BROADCAST] === undefined ? true : !!raw(params[P.BROADCAST]);

        if (!(properties instanceof Map)) {
            peer.sendOperationResponse(OPS.SET_PROPERTIES, RC.OPERATION_INVALID, {},
                'Missing properties');
            return;
        }

        if (typeof targetActorNr === 'number' && targetActorNr > 0) {
            // Actor properties
            const target = room.getPeers().find(p => p.actorNr === targetActorNr);
            if (!target) {
                peer.sendOperationResponse(OPS.SET_PROPERTIES, RC.OPERATION_INVALID, {},
                    'Actor not found');
                return;
            }
            for (const [key, value] of properties.entries()) {
                target.actorProperties.set(key, value);
                if (key === APK.NICKNAME) target.setNickname(raw(value));
            }
        } else {
            // Game properties
            this._applyWellKnownGameProps(room, properties);
            const maxPlayers = properties.get(GPK.MAX_PLAYERS);
            if (maxPlayers !== undefined) room.setMaxPlayers?.(raw(maxPlayers));
        }

        peer.sendOperationResponse(OPS.SET_PROPERTIES, RC.OK);

        if (broadcast) {
            const eventParams = {
                [P.ACTOR_NR]: T.int(peer.actorNr),
                [P.TARGET_ACTOR_NR]: T.int(typeof targetActorNr === 'number' ? targetActorNr : 0),
                [P.PROPERTIES]: T.hashtable(properties)
            };
            for (const member of room.getPeers()) {
                if (member !== peer) member.sendEvent(EV.PROPERTIES_CHANGED, eventParams);
            }
        }
    }

    _getProperties(peer, params) {
        const room = peer.room;
        if (!room) {
            peer.sendOperationResponse(OPS.GET_PROPERTIES, RC.OPERATION_NOT_ALLOWED_IN_CURRENT_STATE,
                {}, 'Not in a room');
            return;
        }

        peer.sendOperationResponse(OPS.GET_PROPERTIES, RC.OK, {
            [P.ACTOR_PROPERTIES]: T.hashtable(this._actorPropertiesTable(room)),
            [P.GAME_PROPERTIES]: T.hashtable(this._gamePropertiesTable(room))
        });
    }
}

module.exports = OperationHandler;
