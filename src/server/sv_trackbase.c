/*
===========================================================================

Wolfenstein: Enemy Territory GPL Source Code
Copyright (C) 1999-2010 id Software LLC, a ZeniMax Media company.

TrackBase (TB) integration + Chat Relay
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
sv_trackbase.c -- TrackBase.net integration + local Chat Relay.

Reimplements the TB_* event-reporting subsystem from Pauluzz' ET 3.00
0.7.4 (reverse-engineered via Ghidra), plus the sv_chatRelay local
admin chat-mitlese feature.

CVars:
  sv_tbCommands  Forward server events to et-tracker.trackbase.net.
                 Default 0 (off).
  sv_chatRelay   Mirror all player chat to the server console so
                 admins can passively read chat. Default 0 (off).

PRIVACY: enabling sv_tbCommands forwards chat + stats to a third-party
tracker (et-tracker.trackbase.net). Operators in privacy-regulated
jurisdictions (GDPR etc.) must inform players and have a legal basis.

Phase 1 (this file): bit-faithful port of Pauluzz 0.7.4, hardcoded
trackbase.net endpoints, default-off, simplified makeClientInfo
(score/ready zeroed - QVM access deferred to Phase 2).
Phase 2 (future): configurable sv_tbHost, sv_tbAllowRemoteCommand,
QVM round-trip for score/ready, sv_protocolcheck integration.

Wire protocol (UDP OOB to et-tracker.trackbase.net):
  Primary  (:4444): start, stop, map, mapend, maprestart, connect,
                    disconnect, name, team, p, wsc, ws
  Control  (:4445): chat, cc; receives 'tbc' replies
===========================================================================
*/

#include "server.h"

#define TB_HOST_PRIMARY         "et-tracker.trackbase.net:4444"
#define TB_HOST_CONTROL         "et-tracker.trackbase.net:4445"
#define TB_HEARTBEAT_SECONDS    20    // Pauluzz' 'waittime' = 0x14
#define TB_OLDCLIENT_WARN_EVERY 9
#define TB_MSG_BUF_SIZE         32768

extern cvar_t *sv_tbCommands;
extern cvar_t *sv_chatRelay;

static netadr_t   tb_addr;
static netadr_t   tb_addrC;
static qboolean   tb_resolved_primary = qfalse;
static qboolean   tb_resolved_control = qfalse;

static time_t     tb_last_heartbeat   = 0;
static int        tb_expectnum        = 0;
static int        tb_querycl          = -1;
static int        tb_modulo           = 0;
static qboolean   tb_catchBot         = qfalse;
static int        tb_catchBotNum      = 0;
static qboolean   tb_maprunning       = qfalse;

static char       tb_expect[32];
static char       tb_umsg1[128];
static char       tb_umsg2[128];

static int TB_ClientSlot( const client_t *cl ) {
	return (int)( cl - svs.clients );
}

static void TB_Printf_OOB_ToAddr( netadr_t to, const char *fmt, va_list ap ) {
	char buf[TB_MSG_BUF_SIZE];

	Q_vsnprintf( buf, sizeof( buf ), fmt, ap );
	NET_OutOfBandPrint( NS_SERVER, to, "%s ", buf );
}

static const char *TB_getGUID( const client_t *cl ) {
	const char *g;

	g = Info_ValueForKey( cl->userinfo, "cl_guid" );
	if ( g[0] && Q_stricmp( g, "unknown" ) != 0 ) {
		return g;
	}
	g = Info_ValueForKey( cl->userinfo, "n_guid" );
	if ( g[0] ) {
		return g;
	}
	g = Info_ValueForKey( cl->userinfo, "sil_guid" );
	if ( g[0] ) {
		return g;
	}
	return "unknown";
}

/*
===============
TB_makeClientInfo

Build "<score>\<ping>\<team>\<ready>\<n>" for stats packets. Phase 1
emits zeros for score and ready (those live in QVM-side playerState_t
and need a sysCall to fetch safely - deferred to Phase 2).
===============
*/
static const char *TB_makeClientInfo( int slot ) {
	client_t   *cl;
	const char *teamstr;
	char        team_c = '?';

	if ( slot < 0 || slot >= sv_maxclients->integer ) {
		return "0\\0\\?\\0\\unknown";
	}

	cl = &svs.clients[slot];

	teamstr = Info_ValueForKey( Cvar_InfoString( CVAR_SYSTEMINFO ), "Players" );
	if ( teamstr && (int)strlen( teamstr ) > slot ) {
		team_c = teamstr[slot];
	}

	return va( "%i\\%i\\%c\\%i\\%s",
	           0,             /* score - Phase 2 */
	           cl->ping,
	           team_c,
	           0,             /* ready - Phase 2 */
	           cl->name );
}

static void TB_Send( const char *fmt, ... ) {
	va_list ap;

	if ( !sv_tbCommands || !sv_tbCommands->integer ) {
		return;
	}
	if ( !tb_resolved_primary ) {
		return;
	}
	va_start( ap, fmt );
	TB_Printf_OOB_ToAddr( tb_addr, fmt, ap );
	va_end( ap );
}

static void TB_SendX( const char *fmt, ... ) {
	va_list ap;

	if ( !sv_tbCommands || !sv_tbCommands->integer ) {
		return;
	}
	if ( !tb_resolved_control ) {
		return;
	}
	va_start( ap, fmt );
	TB_Printf_OOB_ToAddr( tb_addrC, fmt, ap );
	va_end( ap );
}

void SV_TrackBase_ServerStart( void ) {
	TB_Send( "start" );
}

void SV_TrackBase_ServerStop( void ) {
	TB_Send( "stop" );
}

void SV_TrackBase_Map( const char *mapname ) {
	TB_Send( "map %s", mapname );
	tb_maprunning = qtrue;
}

void SV_TrackBase_MapEnd( void ) {
	TB_Send( "mapend" );
	SV_TrackBase_RequestWeaponStats();
	tb_maprunning = qfalse;
}

void SV_TrackBase_MapRestart( void ) {
	TB_Send( "maprestart" );
	tb_maprunning = qtrue;
}

void SV_TrackBase_ClientConnect( const client_t *cl ) {
	TB_Send( "connect %i %s %s",
	         TB_ClientSlot( cl ),
	         TB_getGUID( cl ),
	         cl->name );
}

void SV_TrackBase_ClientDisconnect( const client_t *cl ) {
	TB_Send( "disconnect %i", TB_ClientSlot( cl ) );
}

void SV_TrackBase_ClientName( const client_t *cl ) {
	if ( !cl->name[0] ) {
		return;
	}
	TB_Send( "name %i %s %s",
	         TB_ClientSlot( cl ),
	         TB_getGUID( cl ),
	         cl->name );
}

void SV_TrackBase_ClientTeam( const client_t *cl ) {
	int         slot = TB_ClientSlot( cl );
	const char *teamstr;
	char        team_c = '?';

	teamstr = Info_ValueForKey( Cvar_InfoString( CVAR_SYSTEMINFO ), "Players" );
	if ( teamstr && (int)strlen( teamstr ) > slot ) {
		team_c = teamstr[slot];
	}
	// Phase 2: fetch persistant[PERS_TEAM] via QVM sysCall.
	TB_Send( "team %i %i %i %s",
	         slot,
	         team_c,
	         0,
	         cl->name );
}

void SV_TrackBase_TeamSwitch( const client_t *cl ) {
	TB_Send( "team %i", TB_ClientSlot( cl ) );
}

void SV_TrackBase_CatchBotConnect( int slot ) {
	tb_catchBot    = qtrue;
	tb_catchBotNum = slot;
}

void SV_TrackBase_CatchChat( const client_t *cl, const char *text ) {
	TB_SendX( "chat %i %s %s",
	          TB_ClientSlot( cl ),
	          cl->name,
	          text );
}

void SV_TrackBase_Frame( void ) {
	time_t now;
	int    i;

	if ( !sv_tbCommands || !sv_tbCommands->integer ) {
		return;
	}

	if ( tb_catchBot ) {
		if ( tb_catchBotNum >= 0 && tb_catchBotNum < sv_maxclients->integer ) {
			client_t *cl = &svs.clients[tb_catchBotNum];
			TB_Send( "connect %i %s %s",
			         tb_catchBotNum,
			         TB_getGUID( cl ),
			         cl->name );
		}
		tb_catchBot = qfalse;
	}

	now = time( NULL );
	if ( tb_last_heartbeat >= now - TB_HEARTBEAT_SECONDS ) {
		return;
	}

	TB_Send( "p" );
	tb_expectnum = 0;
	SV_TrackBase_RequestWeaponStats();
	tb_last_heartbeat = now;
	tb_modulo++;

	if ( tb_modulo >= TB_OLDCLIENT_WARN_EVERY ) {
		tb_modulo = 0;

		// Phase 1: send to ALL active clients. Phase 2 will gate on
		// a real protocol-mismatch flag (see feature #5).
		for ( i = 0; i < sv_maxclients->integer; i++ ) {
			client_t *cl = &svs.clients[i];
			if ( cl->state != CS_ACTIVE ) {
				continue;
			}
			SV_SendServerCommand( cl, "%s", tb_umsg1 );
			SV_SendServerCommand( cl, "%s", tb_umsg2 );
		}
	}
}

void SV_TrackBase_RequestWeaponStats( void ) {
	int       i;
	client_t *query_cl = NULL;

	if ( !tb_maprunning ) {
		return;
	}
	if ( !sv_tbCommands || !sv_tbCommands->integer ) {
		return;
	}

	Q_strncpyz( tb_expect, "ws", sizeof( tb_expect ) );

	tb_expectnum = 0;
	for ( i = 0; i < sv_maxclients->integer; i++ ) {
		if ( svs.clients[i].state == CS_ACTIVE ) {
			tb_expectnum++;
			if ( !query_cl ) {
				query_cl   = &svs.clients[i];
				tb_querycl = i;
			}
		}
	}

	if ( tb_expectnum <= 0 || !query_cl ) {
		tb_expectnum = 0;
		tb_querycl   = -1;
		return;
	}

	TB_Send( "wsc %i", tb_expectnum );
	for ( i = 0; i < sv_maxclients->integer; i++ ) {
		if ( svs.clients[i].state == CS_ACTIVE ) {
			TB_Send( "ws %i 0 0 0\\%s", i, TB_makeClientInfo( i ) );
		}
	}

	SV_ExecuteClientCommand( query_cl, "statsall", qtrue, qfalse );
}

qboolean SV_TrackBase_CatchServerCommand( client_t *cl, const char *cmd ) {
	int  slot = 0;
	char trimmed[MAX_STRING_CHARS];
	int  len;

	if ( !sv_tbCommands || !sv_tbCommands->integer ) {
		return qfalse;
	}
	if ( TB_ClientSlot( cl ) != tb_querycl || tb_expectnum <= 0 ) {
		return qfalse;
	}
	if ( !tb_expect[0] || Q_strncmp( cmd, tb_expect, strlen( tb_expect ) ) != 0 ) {
		return qfalse;
	}

	Q_strncpyz( trimmed, cmd, sizeof( trimmed ) );
	len = (int)strlen( trimmed );
	if ( len > 0 && trimmed[len - 1] == '\n' ) {
		trimmed[len - 1] = '\0';
	}

	if ( Q_strncmp( "ws", trimmed, 2 ) != 0 ) {
		return qfalse;
	}

	tb_expectnum--;
	if ( tb_expectnum <= 0 ) {
		tb_expect[0] = '\0';
		tb_querycl   = -1;
	}

	sscanf( trimmed, "ws %i", &slot );
	TB_Send( "%s\\%s", trimmed, TB_makeClientInfo( slot ) );
	return qtrue;
}

qboolean SV_TrackBase_ClientCommand( client_t *cl, const char *cmd_text ) {
	int         argc, i;
	char        args[1024];
	const char *cmd_name;

	if ( Q_strncmp( cmd_text, "tb_", 3 ) != 0 ) {
		return qfalse;
	}

	if ( !sv_tbCommands || !sv_tbCommands->integer ) {
		SV_SendServerCommand( cl,
		    "print\n\"TB Commands are not enabled on this server!\n\"" );
		return qtrue;
	}

	Cmd_TokenizeString( cmd_text );
	cmd_name = Cmd_Argv( 0 );
	argc     = Cmd_Argc();

	args[0] = '\0';
	for ( i = 1; i < argc; i++ ) {
		Q_strcat( args, sizeof( args ), "\\" );
		Q_strcat( args, sizeof( args ), Cmd_Argv( i ) );
	}

	TB_SendX( "cc %i %s %s%s",
	          TB_ClientSlot( cl ),
	          cmd_name,
	          cl->name,
	          args );
	return qtrue;
}

/*
===============
SV_TrackBase_HandleControlPacket

SECURITY (Phase 1): source-IP only, trivially spoofable via UDP.
Phase 2: add sv_tbAllowRemoteCommand (default 0) as a second gate.
===============
*/
void SV_TrackBase_HandleControlPacket( netadr_t from, const char *payload ) {
	int         slot = 0, broadcast = 0, type = 0;
	const char *p;
	char        text[1024];
	char        out[1024];
	int         text_len, i;

	if ( !sv_tbCommands || !sv_tbCommands->integer ) {
		return;
	}
	if ( !tb_resolved_control ) {
		return;
	}
	if ( !NET_CompareBaseAdr( from, tb_addrC ) ) {
		return;
	}

	Com_Printf( "%s", payload );

	if ( sscanf( payload, "tbc %d %d %d", &slot, &broadcast, &type ) != 3 ) {
		return;
	}

	p = strchr( payload, '\\' );
	if ( !p ) {
		return;
	}
	p += 1;

	Q_strncpyz( text, p, sizeof( text ) );
	text_len = (int)strlen( text );

	for ( i = 0; i < text_len; i++ ) {
		text[i] = (char)( (unsigned char)text[i] - 1 );
		if ( text[i] == '\t' ) {
			text[i] = '\n';
		}
	}

	if ( slot < 0 || slot >= sv_maxclients->integer ) {
		return;
	}
	if ( slot > 0 && svs.clients[slot].state != CS_ACTIVE ) {
		return;
	}

	switch ( type ) {
	case 1:
		Com_sprintf( out, sizeof( out ), "chat \"%s\"\r\n", text );
		break;
	case 2:
		Com_sprintf( out, sizeof( out ), "cpm \"%s\"\r\n", text );
		break;
	case 3:
		Com_sprintf( out, sizeof( out ), "cp \"%s\"\r\n", text );
		break;
	case 4:
		Com_sprintf( out, sizeof( out ), "bp \"%s\"\r\n", text );
		break;
	default:
		Com_sprintf( out, sizeof( out ), "print\r\n\"%s\r\n\"\r\n", text );
		break;
	}

	if ( broadcast == 0 ) {
		SV_SendServerCommand( &svs.clients[slot], "%s", out );
	} else {
		SV_SendServerCommand( NULL, "%s", out );
	}
}

void SV_ChatRelay_Mirror( const client_t *cl, const char *cmd, const char *text ) {
	if ( !sv_chatRelay || !sv_chatRelay->integer ) {
		return;
	}
	if ( !cl || !text || !text[0] ) {
		return;
	}

	if ( cmd && !Q_stricmp( cmd, "say_team" ) ) {
		Com_Printf( "[CHAT-TEAM] %s: %s\n", cl->name, text );
	} else if ( cmd && !Q_stricmp( cmd, "tell" ) ) {
		Com_Printf( "[CHAT-TELL] %s: %s\n", cl->name, text );
	} else {
		Com_Printf( "[CHAT] %s: %s\n", cl->name, text );
	}
}

static void TB_ObfuscateDecode( char *buf, int shift ) {
	int i;
	for ( i = 0; buf[i] != '\0'; i++ ) {
		buf[i] = (char)( (unsigned char)buf[i] + shift );
	}
}

void SV_TrackBase_Init( void ) {
	tb_resolved_primary = qfalse;
	tb_resolved_control = qfalse;
	tb_last_heartbeat   = time( NULL );
	tb_expectnum        = 0;
	tb_querycl          = -1;
	tb_modulo           = 0;
	tb_catchBot         = qfalse;
	tb_catchBotNum      = 0;
	tb_maprunning       = qfalse;
	tb_expect[0]        = '\0';

	Com_Printf( "Resolving %s\n", TB_HOST_PRIMARY );
	if ( NET_StringToAdr( TB_HOST_PRIMARY, &tb_addr ) ) {
		tb_resolved_primary = qtrue;
		Com_Printf( "%s resolved to %s\n", TB_HOST_PRIMARY, NET_AdrToString( tb_addr ) );
	} else {
		Com_Printf( "Couldn't resolve address: %s\n", TB_HOST_PRIMARY );
	}

	Com_Printf( "Resolving %s\n", TB_HOST_CONTROL );
	if ( NET_StringToAdr( TB_HOST_CONTROL, &tb_addrC ) ) {
		tb_resolved_control = qtrue;
		Com_Printf( "%s resolved to %s\n", TB_HOST_CONTROL, NET_AdrToString( tb_addrC ) );
	} else {
		Com_Printf( "Couldn't resolve address: %s\n", TB_HOST_CONTROL );
	}

	// umsg1 plain:  cpm "^7You are running an ^1old ET version^7!"
	{
		static const char src1[] =
		    ".rp\"_9[qw\"ctg\"twppkpi\"cp\"_3qnf\"GV\"xgtukqp_9#\"";
		Q_strncpyz( tb_umsg1, src1, sizeof( tb_umsg1 ) );
		TB_ObfuscateDecode( tb_umsg1, -2 );
	}
	// umsg2 plain:  cpm "Please update at ^3http://et.trackbase.net/update"
	{
		static const char src2[] =
		    "dqn!Qmfbtf!vqebuf!bu!_4iuuq;00fu/usbdlcbtf/ofu0vqebuf#";
		Q_strncpyz( tb_umsg2, src2, sizeof( tb_umsg2 ) );
		TB_ObfuscateDecode( tb_umsg2, -1 );
	}
}

void SV_TrackBase_Shutdown( void ) {
	SV_TrackBase_ServerStop();
	tb_maprunning = qfalse;
}
