/*
===========================================================================

Wolfenstein: Enemy Territory GPL Source Code
Copyright (C) 1999-2010 id Software LLC, a ZeniMax Media company.

Quiet game-log filter (Phase 2: console-spam suppression)
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
sv_quietlog.c -- Filter for noisy qagame console output.

The game VM (qagame.mp.i386.so) emits a steady stream of per-client and
per-frame log lines via the G_PRINT syscall: ClientConnect, ClientBegin,
ClientUserinfoChanged, Userinfo, Omnibot init/Goals, mapscript autospawn
warnings, etc. On a busy server with bots and per-map reloads, this drowns
the operator's console. The logfile (g_log / games_mp.log) is unaffected
because the qagame writes that via trap_FS_Write, not via G_PRINT.

This module is consulted from sv_game.c's G_PRINT handler. When
sv_quietGameLog is non-zero and the incoming string matches a known or
operator-defined prefix pattern, the line is dropped before reaching
Com_Printf.

CVars:
  sv_quietGameLog       0 = all qagame output reaches console (Pauluzz
                            default, preserves 0.7.4 behaviour)
                        1 = drop the built-in pattern set (per-client
                            spam: ClientConnect, ClientBegin,
                            ClientDisconnect, ClientUserinfoChanged,
                            Userinfo)
                        2 = also drop mapscript / Omnibot init noise
                            (Omni-bot, Goals Loaded, Setting Allied/Axis
                            autospawn, setstate warnings)
  sv_quietGamePatterns  ';'-separated list of additional case-sensitive
                        prefix patterns to drop. Leading color codes
                        (^X) on the incoming message are skipped before
                        matching, so patterns can be written as
                        "Goals Loaded" rather than "^2Goals Loaded".

Patterns are matched as PREFIX, after stripping leading ^X color codes.
This keeps the filter cheap (one Q_strncmp per pattern) and predictable.

The match is intentionally one-directional: lines are either fully
suppressed or fully passed. We do not attempt to selectively keep parts
of multi-line strings because the qagame already issues one G_PRINT call
per logical line.

Phase 2 / 3 notes
-----------------
- Consider a "passthrough to log file" mode (write filtered lines to a
  separate ringbuffer the operator can inspect on demand).
- Consider per-client suppression keyed on cl_guid so we can keep human
  ClientConnect lines and only drop bot ones (cl_guid starting with
  OMNIBOT). Currently the filter is content-only.
===========================================================================
*/

#include "server.h"

extern cvar_t *sv_quietGameLog;
extern cvar_t *sv_quietGamePatterns;

/*
===============
Built-in pattern sets

Indexed by sv_quietGameLog level. Level 1 covers per-client noise (the
overwhelming majority of console spam in practice). Level 2 adds the
boot-time / map-load noise that, while less frequent, still clutters
the console on every map change.

Order does not affect correctness, but more-specific patterns first
short-circuits faster on the hot path. ClientConnect and Userinfo
together account for ~80% of bot-server traffic.
===============
*/
static const char *quiet_patterns_level1[] = {
	"ClientConnect:",
	"Userinfo:",
	"ClientUserinfoChanged:",
	"ClientBegin:",
	"ClientDisconnect:",
	NULL
};

static const char *quiet_patterns_level2[] = {
	"Omni-bot",
	"Goals Loaded",
	"Setting Allied autospawn",
	"Setting Axis autospawn",
	"Warning: setstate",
	NULL
};

/*
===============
SkipColorCodes

Advance past any leading ^X color codes. Mirrors the prefix-stripping
behaviour of Q_CleanStr but only at the head of the string and without
modifying anything. Returns a pointer into the original buffer.
===============
*/
static const char *SkipColorCodes( const char *s ) {
	while ( Q_IsColorString( s ) ) {
		s += 2;
	}
	return s;
}

/*
===============
MatchAny

Return qtrue if the cleaned string starts with any entry in the
NULL-terminated pattern array. Empty / NULL patterns are skipped.
===============
*/
static qboolean MatchAny( const char *cleaned, const char **patterns ) {
	const char *p;
	size_t      len;
	int         i;

	for ( i = 0; patterns[i] != NULL; i++ ) {
		p = patterns[i];
		if ( !p[0] ) {
			continue;
		}
		len = strlen( p );
		if ( !Q_strncmp( cleaned, p, len ) ) {
			return qtrue;
		}
	}
	return qfalse;
}

/*
===============
MatchCustomPatterns

Parse sv_quietGamePatterns on every call. The cvar is operator-edited
and rarely changes; the parse cost is one strcpy + one tokenise per
G_PRINT call, which is bounded by the cvar buffer length (small) and
not a concern at typical qagame print rates.

If the cvar string is empty or NULL, returns qfalse immediately.
===============
*/
static qboolean MatchCustomPatterns( const char *cleaned ) {
	char  buf[1024];
	char *start, *p;
	size_t len;

	if ( !sv_quietGamePatterns || !sv_quietGamePatterns->string ||
	     !sv_quietGamePatterns->string[0] ) {
		return qfalse;
	}

	Q_strncpyz( buf, sv_quietGamePatterns->string, sizeof( buf ) );
	start = buf;
	p     = buf;

	while ( 1 ) {
		qboolean at_end;

		if ( *p != ';' && *p != '\0' ) {
			p++;
			continue;
		}

		at_end = ( *p == '\0' );
		*p     = '\0';

		// Trim leading whitespace
		while ( *start == ' ' || *start == '\t' ) {
			start++;
		}

		if ( *start ) {
			len = strlen( start );
			if ( !Q_strncmp( cleaned, start, len ) ) {
				return qtrue;
			}
		}

		if ( at_end ) {
			break;
		}

		p++;
		start = p;
	}

	return qfalse;
}

/*
===============
SV_QuietGameLog_ShouldDrop

Public entry point consulted from sv_game.c case G_PRINT. Returns qtrue
when the line should be silently dropped, qfalse to pass through to
Com_Printf as before.

Cheap when disabled: a single integer comparison.
===============
*/
qboolean SV_QuietGameLog_ShouldDrop( const char *msg ) {
	const char *cleaned;
	int         level;

	if ( !sv_quietGameLog || sv_quietGameLog->integer == 0 ) {
		return qfalse;
	}

	if ( !msg || !msg[0] ) {
		return qfalse;
	}

	cleaned = SkipColorCodes( msg );
	level   = sv_quietGameLog->integer;

	if ( MatchAny( cleaned, quiet_patterns_level1 ) ) {
		return qtrue;
	}

	if ( level >= 2 && MatchAny( cleaned, quiet_patterns_level2 ) ) {
		return qtrue;
	}

	if ( MatchCustomPatterns( cleaned ) ) {
		return qtrue;
	}

	return qfalse;
}
