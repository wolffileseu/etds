/*
===========================================================================

Wolfenstein: Enemy Territory GPL Source Code
Copyright (C) 1999-2010 id Software LLC, a ZeniMax Media company.

GUID handling, protocol checking, auth-server signaling
Copyright (C) 2026 Wolffiles ETDS contributors

This file is part of the Wolfenstein: Enemy Territory GPL Source Code
(Wolf ET Source Code). Wolf ET Source Code is free software: you can
redistribute it and/or modify it under the terms of the GNU General
Public License as published by the Free Software Foundation, either
version 3 of the License, or (at your option) any later version.

Wolf ET Source Code is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU
General Public License for more details.

===========================================================================
*/

/*
===========================================================================
sv_guidcheck.c -- GUID validation, Mod-specific GUID normalization,
                  and auth-server signaling.

Reimplements the GUID-related check blocks that Pauluzz' ET 3.00 0.7.4
added to SV_DirectConnect (reverse-engineered via Ghidra), plus the
optional auth-server signaling at the tail of that function.

CVars (registered in sv_init.c, storage in sv_main.c):
  sv_allownoguid       "1" (default) - 1 allows clients without a 32-char
                                       cl_guid to connect. When 0, clients
                                       whose cl_guid is not exactly 32
                                       characters long are rejected with
                                       sv_guidkickmsg.
  sv_guidkickmsg       Default: "You have been kicked because don't have ETKEY"
                       (Pauluzz' original text - the missing "you" before
                       "don't" is his typo, preserved 1:1.)
  sv_enableAuthServer  "1" (default) - 1 signals connecting clients to the
                                       auth-server at et-auth.trackbase.net:27952
                                       via a "gs <cleaned-name>" OOB message.

Mod-GUID normalization
----------------------
ET mods use different userinfo keys for their GUID. When cl_guid is
empty/"unknown"/"NO_GUID" after VM_Call(GAME_CLIENT_CONNECT), Pauluzz
checks fs_game and copies the mod-specific GUID into cl_guid:

  fs_game == "silent"  ->  copy sil_guid into cl_guid
  fs_game == "nitmod"  ->  copy n_guid   into cl_guid

No other mods are specialized.

Auth-server endpoint
--------------------
Pauluzz' binary sends "gs <cleaned-name>" to et-auth.trackbase.net:27952
on every successful connect when sv_enableAuthServer == 1. The endpoint
has been dead since Pauluzz disabled the server side in 0.7.4 after
abuse reports. We still send the packet to preserve bit-identical
network behaviour (Phase 1 policy: "alles 1:1 wie Pauluzz").
===========================================================================
*/

#include "server.h"

// ET's canonical cl_guid is a 32-character lowercase hex MD4 digest.
#define GUID_REQUIRED_LENGTH 32

// Hardcoded in Pauluzz' binary. Phase 2: consider sv_authServer.
#define AUTH_SERVER_ENDPOINT "et-auth.trackbase.net:27952"

// --- CVar references (storage in sv_main.c, registration in sv_init.c) --

extern cvar_t *sv_allownoguid;
extern cvar_t *sv_guidkickmsg;
extern cvar_t *sv_enableAuthServer;

// --- Module state --------------------------------------------------------

static netadr_t  authServerAddr;
static qboolean  authServerResolved = qfalse;

// --- Public API ----------------------------------------------------------

/*
===============
SV_GuidCheck_Init

Resolve the hardcoded auth-server endpoint at server startup.
Called from SV_Init after all CVars are registered.
===============
*/
void SV_GuidCheck_Init( void ) {
	authServerResolved = qfalse;

	Com_Printf( "Resolving %s\n", AUTH_SERVER_ENDPOINT );
	if ( NET_StringToAdr( AUTH_SERVER_ENDPOINT, &authServerAddr ) ) {
		authServerResolved = qtrue;
		Com_Printf( "%s resolved to %s\n",
		            AUTH_SERVER_ENDPOINT,
		            NET_AdrToString( authServerAddr ) );
	} else {
		Com_Printf( "Couldn't resolve address: %s\n", AUTH_SERVER_ENDPOINT );
	}
}

/*
===============
SV_GuidCheck_IsGuidAcceptable

Apply the GUID-length policy:
  sv_allownoguid == 1: accept every client
  sv_allownoguid == 0: accept only if cl_guid is exactly 32 characters

Returns qtrue to accept, qfalse to reject. Caller sends the kick message.
===============
*/
qboolean SV_GuidCheck_IsGuidAcceptable( const char *userinfo ) {
	const char *guid;
	size_t      len;

	// Pauluzz default is permissive (sv_allownoguid = 1).
	if ( !sv_allownoguid || sv_allownoguid->integer != 0 ) {
		return qtrue;
	}

	guid = Info_ValueForKey( userinfo, "cl_guid" );
	len  = strlen( guid );

	return ( len == GUID_REQUIRED_LENGTH ) ? qtrue : qfalse;
}

/*
===============
SV_GuidCheck_GetKickMessage

Return the operator-configured or default kick message. Note the typo
in the Pauluzz default ("because don't have" - missing "you") is
preserved 1:1 for compatibility with existing 3.00 admin tooling that
may match on this string.
===============
*/
const char *SV_GuidCheck_GetKickMessage( void ) {
	if ( sv_guidkickmsg && sv_guidkickmsg->string && sv_guidkickmsg->string[0] ) {
		return sv_guidkickmsg->string;
	}
	return "You have been kicked because don't have ETKEY";
}

/*
===============
SV_GuidCheck_NormalizeGuid

If the client has no usable cl_guid (empty, "unknown", or "NO_GUID"),
copy the mod-specific GUID into cl_guid so downstream consumers see a
uniform value. Operates on cl->userinfo in-place.
===============
*/
void SV_GuidCheck_NormalizeGuid( client_t *cl ) {
	const char *guid;
	const char *fs_game;
	const char *mod_guid;
	qboolean    needs_fallback = qfalse;

	if ( !cl ) {
		return;
	}

	guid = Info_ValueForKey( cl->userinfo, "cl_guid" );

	if ( guid[0] == '\0' ) {
		needs_fallback = qtrue;
	} else if ( !Q_stricmp( guid, "unknown" ) ) {
		needs_fallback = qtrue;
	} else if ( !Q_stricmp( guid, "NO_GUID" ) ) {
		needs_fallback = qtrue;
	}

	if ( !needs_fallback ) {
		return;
	}

	fs_game = Cvar_VariableString( "fs_game" );

	if ( !Q_stricmp( fs_game, "silent" ) ) {
		mod_guid = Info_ValueForKey( cl->userinfo, "sil_guid" );
		if ( mod_guid[0] ) {
			Info_SetValueForKey( cl->userinfo, "cl_guid", mod_guid );
		}
	} else if ( !Q_stricmp( fs_game, "nitmod" ) ) {
		mod_guid = Info_ValueForKey( cl->userinfo, "n_guid" );
		if ( mod_guid[0] ) {
			Info_SetValueForKey( cl->userinfo, "cl_guid", mod_guid );
		}
	}
	/* Other mods: no normalization. */
}

/*
===============
SV_GuidCheck_SignalAuthServer

Emit "gs <cleaned-name>" OOB-message to the auth-server endpoint when
sv_enableAuthServer == 1. The endpoint has been dead since 0.7.4;
we still send for bit-identical network behaviour with Pauluzz.

No-op if resolution failed at init time.
===============
*/
void SV_GuidCheck_SignalAuthServer( const client_t *cl ) {
	char cleaned[MAX_NAME_LENGTH];

	if ( !sv_enableAuthServer || sv_enableAuthServer->integer != 1 ) {
		return;
	}
	if ( !authServerResolved ) {
		return;
	}
	if ( !cl ) {
		return;
	}

	Q_strncpyz( cleaned, cl->name, sizeof( cleaned ) );
	Q_CleanStr( cleaned );

	NET_OutOfBandPrint( NS_SERVER, authServerAddr, "gs %s", cleaned );
}
