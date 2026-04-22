/*
===========================================================================

Wolfenstein: Enemy Territory GPL Source Code
Copyright (C) 1999-2010 id Software LLC, a ZeniMax Media company.

RCON IP filter (whitelist) extension
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
sv_rconfilter.c -- RCON source-IP whitelist.

Purpose
-------
Restrict rcon-command execution to a set of whitelisted source IPs,
even when the rcon password is correct. Useful to lock the admin
surface down to a fixed set of office/VPN IPs so that a leaked
password alone is not enough to run rcon.

Configuration
-------------
  sv_rconfilter  0/1   Master switch. 0 = filter off (id-Software default
                       behaviour), 1 = only whitelisted IPs may use rcon.

  sv_rcon1..sv_rcon5   Up to five whitelist entries. Each may contain a
                       single IPv4 pattern; empty entries are skipped.

Pattern syntax (matches Pauluzz' ET 3.00 0.7.4 exactly):
  "A.B.C.D"   - exact IPv4 match
  "A.B.C.*"   - last octet wildcard
  "A.B.*.*"   - last two octets wildcard
  "A.*.*.*"   - last three octets wildcard

Mixed wildcards (e.g. "A.*.C.D") are NOT supported; they silently
won't match anything. This is by design to stay compatible with
Pauluzz' behaviour and with existing ET 3.00 server configurations.

Relation to Pauluzz' ET 3.00
----------------------------
Reimplementation based on the SVC_RemoteCommand modifications observed
in Pauluzz' ET 3.00 0.7.4 Linux binary (reverse-engineered via Ghidra).
The CVar names, pattern syntax, default values and error message
("You are not able to use rcon") match the original so that existing
ET 3.00 server configurations work without any changes.

The original inlined the whole check into SVC_RemoteCommand with
five hand-unrolled CVar reads and four hand-unrolled wildcard
variants per CVar (20 strcmp call sites in total). We factor the
logic out into a tight loop over an array of CVar pointers and a
helper for the wildcard match, which is functionally identical but
an order of magnitude smaller and much easier to audit.
===========================================================================
*/

#include "server.h"

// CVar references -- storage and registration live in sv_main.c / sv_init.c.
extern cvar_t *sv_rconfilter;
extern cvar_t *sv_rcon1;
extern cvar_t *sv_rcon2;
extern cvar_t *sv_rcon3;
extern cvar_t *sv_rcon4;
extern cvar_t *sv_rcon5;

/*
===============
SV_RconFilter_PatternMatches

Returns qtrue if `pattern` matches the address in `from`. The pattern
must be one of the four Pauluzz-style forms documented at the top of
this file; any other pattern returns qfalse.

An empty or NULL pattern never matches (so empty sv_rconN CVars are
harmless).
===============
*/
static qboolean SV_RconFilter_PatternMatches( const char *pattern, const netadr_t *from ) {
	unsigned int a, b, c, d;
	char         candidate[32];

	if ( !pattern || !pattern[0] ) {
		return qfalse;
	}

	a = from->ip[0];
	b = from->ip[1];
	c = from->ip[2];
	d = from->ip[3];

	// Try each of the four wildcard forms. Order doesn't matter for
	// correctness -- the pattern either matches one form exactly or
	// it matches none.

	Com_sprintf( candidate, sizeof( candidate ), "%u.%u.%u.%u", a, b, c, d );
	if ( !strcmp( pattern, candidate ) ) {
		return qtrue;
	}

	Com_sprintf( candidate, sizeof( candidate ), "%u.%u.%u.*", a, b, c );
	if ( !strcmp( pattern, candidate ) ) {
		return qtrue;
	}

	Com_sprintf( candidate, sizeof( candidate ), "%u.%u.*.*", a, b );
	if ( !strcmp( pattern, candidate ) ) {
		return qtrue;
	}

	Com_sprintf( candidate, sizeof( candidate ), "%u.*.*.*", a );
	if ( !strcmp( pattern, candidate ) ) {
		return qtrue;
	}

	return qfalse;
}

/*
===============
SV_RconFilter_IsAllowed

Called from SVC_RemoteCommand after the rcon password has been
verified. Returns qtrue if the source IP is on the whitelist (or if
the filter is disabled); qfalse if the request should be rejected.

Mirrors Pauluzz' behaviour: the check only runs once sv_rconfilter
is set to 1. With the filter disabled, rcon remains open to anyone
who knows the password, matching id-Software default behaviour.
===============
*/
qboolean SV_RconFilter_IsAllowed( const netadr_t *from ) {
	const cvar_t *entries[5];
	int          i;

	if ( !sv_rconfilter || sv_rconfilter->integer != 1 ) {
		return qtrue;  // filter disabled, allow everyone
	}

	entries[0] = sv_rcon1;
	entries[1] = sv_rcon2;
	entries[2] = sv_rcon3;
	entries[3] = sv_rcon4;
	entries[4] = sv_rcon5;

	for ( i = 0; i < 5; i++ ) {
		if ( !entries[i] ) {
			continue;
		}
		if ( SV_RconFilter_PatternMatches( entries[i]->string, from ) ) {
			return qtrue;
		}
	}

	return qfalse;
}
