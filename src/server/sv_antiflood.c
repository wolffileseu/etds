/*
===========================================================================

Wolfenstein: Enemy Territory GPL Source Code
Copyright (C) 1999-2010 id Software LLC, a ZeniMax Media company.

Anti-Flood extension (getstatus reflective-DDoS mitigation)
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
sv_antiflood.c -- Reflective getstatus-flood protection.

Purpose
-------
UDP getstatus/getinfo responses are a common amplification vector for
reflective DDoS attacks: an attacker spoofs a victim's IP as the source
of a getstatus packet, and the server blasts a much larger response at
the victim. By rate-limiting responses per source IP at the application
layer, we remove the amplification.

Algorithm
---------
A dynamically-grown table tracks observed source addresses. For each IP:

  - A sliding 60-second window counts incoming getstatus/getinfo requests.
  - When the window expires (no traffic for 60s), the counter resets and
    the entry becomes "released" again.
  - If the counter exceeds sv_maxGetstatusPerMinute within the window,
    further requests from that IP are silently dropped ("flagged" state).
  - If the counter additionally exceeds sv_maxGetstatusBeforeIPTABLES, the
    entry is marked "blocked" for the rest of the session (no log spam).
  - Entries inactive for >30 minutes are recycled (LRU).

Relation to Pauluzz' ET 3.00
----------------------------
Inspired by the anti-flood mechanism observed in Pauluzz' ET 3.00 0.7.4
Linux binary (reverse-engineered via Ghidra). The core rate-limiting
idea and the 60s / 30min time constants match the original behaviour.

The original's system("iptables -A INPUT ...") firewall invocation is
intentionally omitted here: shelling out to a privileged tool from a
user-space game server is a security and portability anti-pattern
(requires root, Linux-only, persists outside the server lifecycle,
no rollback on crash). Application-layer dropping is sufficient and
safe. The CVar name is kept as sv_maxGetstatusBeforeIPTABLES for 1:1
compatibility with Pauluzz ET 3.00 0.7.4 server configs, even though
our implementation does not actually invoke iptables.

The CVars are registered in sv_init.c (SV_Init). They are referenced
here via `extern` from sv_main.c.
===========================================================================
*/

#include "server.h"

// --- Tuning constants -----------------------------------------------------

// Size of the sliding rate-limit window, in seconds.
#define ANTIFLOOD_WINDOW_SECONDS     60

// After this many seconds of inactivity, an entry becomes eligible for
// recycling (LRU reclaim).
#define ANTIFLOOD_ENTRY_TTL_SECONDS  1800

// Initial capacity of the tracking table. Grown by ANTIFLOOD_GROWTH_STEP
// whenever full.
#define ANTIFLOOD_INITIAL_CAPACITY   128
#define ANTIFLOOD_GROWTH_STEP        128

// --- CVar references ------------------------------------------------------
// Declared and Cvar_Get()-registered in sv_main.c / sv_init.c.

extern cvar_t *sv_maxGetstatusCheck;
extern cvar_t *sv_maxGetstatusPerMinute;
extern cvar_t *sv_maxGetstatusBeforeIPTABLES;

// --- Types ----------------------------------------------------------------

typedef enum {
	FLOOD_STATE_NORMAL  = 0,    // tracked, not over threshold
	FLOOD_STATE_FLAGGED = 1,    // soft threshold crossed, packets are dropped
	FLOOD_STATE_BLOCKED = 2     // hard threshold crossed, session-wide block
} floodState_t;

typedef struct {
	netadr_t     addr;
	unsigned int packet_count;
	time_t       window_start;
	floodState_t state;
} floodEntry_t;

// --- Module state ---------------------------------------------------------

static floodEntry_t *flood_table    = NULL;
static int           flood_capacity = 0;
static int           flood_used     = 0;

// --- Helpers --------------------------------------------------------------

/*
===============
SV_AntiFlood_FindOrAllocateEntry

Three-pass lookup:
  1. exact match for the given address (returns existing entry)
  2. stale-slot recycling (an entry older than the TTL is reused in place)
  3. table growth via realloc, then append

Returns a pointer to the resulting entry, or NULL if the table was full
and realloc() failed. Callers must treat NULL as "fail open" (do not
block the request we cannot track).
===============
*/
static floodEntry_t *SV_AntiFlood_FindOrAllocateEntry( const netadr_t *from, time_t now ) {
	int i;

	// 1. Exact match
	for ( i = 0; i < flood_used; i++ ) {
		if ( NET_CompareBaseAdr( flood_table[i].addr, *from ) ) {
			return &flood_table[i];
		}
	}

	// 2. Recycle a stale slot
	for ( i = 0; i < flood_used; i++ ) {
		if ( ( now - flood_table[i].window_start ) > ANTIFLOOD_ENTRY_TTL_SECONDS ) {
			memset( &flood_table[i], 0, sizeof( floodEntry_t ) );
			flood_table[i].addr         = *from;
			flood_table[i].window_start = now;
			return &flood_table[i];
		}
	}

	// 3. Grow the table
	if ( flood_used >= flood_capacity ) {
		int new_capacity = flood_capacity + ANTIFLOOD_GROWTH_STEP;
		floodEntry_t *new_table = realloc( flood_table, new_capacity * sizeof( floodEntry_t ) );
		if ( !new_table ) {
			Com_Printf( "[ANTI-FLOOD] Memory allocation failed for flood table, cannot track this request\n" );
			return NULL;
		}
		memset( &new_table[flood_capacity], 0, ANTIFLOOD_GROWTH_STEP * sizeof( floodEntry_t ) );
		flood_table    = new_table;
		flood_capacity = new_capacity;

		Com_Printf( "[ANTI-FLOOD] Flood table grown to %d entries\n", flood_capacity );
	}

	// Append new entry at the tail
	memset( &flood_table[flood_used], 0, sizeof( floodEntry_t ) );
	flood_table[flood_used].addr         = *from;
	flood_table[flood_used].window_start = now;
	return &flood_table[flood_used++];
}

// --- Public API -----------------------------------------------------------

/*
===============
SV_CheckForFlood

Call this before responding to a getstatus-style OOB request (SVC_Status,
SVC_Info, etc.). It updates per-IP tracking and decides whether to answer.

Returns qtrue  -> drop the packet, do not respond
        qfalse -> allow the packet, respond normally

Fails open on any internal error (OOM, table-allocation failure): returns
qfalse so that a memory hiccup never makes the server unresponsive to
legitimate clients.
===============
*/
qboolean SV_CheckForFlood( const netadr_t *from ) {
	floodEntry_t *entry;
	time_t        now;
	int           threshold;
	int           block_threshold;

	// Feature disabled: pass everything through.
	if ( !sv_maxGetstatusCheck || !sv_maxGetstatusCheck->integer ) {
		return qfalse;
	}

	// LAN clients (admin polling, local monitoring, bot frameworks on the
	// same box) are never rate-limited.
	if ( Sys_IsLANAddress( *from ) ) {
		return qfalse;
	}

	// Lazy allocation of the tracking table on first use.
	if ( !flood_table ) {
		flood_table = calloc( ANTIFLOOD_INITIAL_CAPACITY, sizeof( floodEntry_t ) );
		if ( !flood_table ) {
			return qfalse;  // OOM, fail open
		}
		flood_capacity = ANTIFLOOD_INITIAL_CAPACITY;
		flood_used     = 0;
	}

	now   = time( NULL );
	entry = SV_AntiFlood_FindOrAllocateEntry( from, now );
	if ( !entry ) {
		return qfalse;  // table full, realloc failed -- fail open
	}

	// Sliding window reset: if the last activity was more than one window
	// ago, start counting fresh. Previously-flagged/blocked IPs get a
	// clean slate so that well-behaved operators are not punished forever.
	if ( ( now - entry->window_start ) > ANTIFLOOD_WINDOW_SECONDS ) {
		if ( entry->packet_count > 0 ) {
			Com_Printf( "[ANTI-FLOOD] %s is released and can getstatus again\n",
			            NET_AdrToString( *from ) );
		}
		entry->packet_count = 0;
		entry->window_start = now;
		entry->state        = FLOOD_STATE_NORMAL;
		return qfalse;
	}

	entry->packet_count++;
	threshold       = sv_maxGetstatusPerMinute   ? sv_maxGetstatusPerMinute->integer   : 0;
	block_threshold = sv_maxGetstatusBeforeIPTABLES ? sv_maxGetstatusBeforeIPTABLES->integer : 0;

	if ( threshold > 0 && (int)entry->packet_count > threshold ) {
		// Log once when the soft threshold is first crossed.
		if ( entry->state == FLOOD_STATE_NORMAL ) {
			int remaining = (int)( ANTIFLOOD_WINDOW_SECONDS - ( now - entry->window_start ) );
			if ( remaining < 0 ) {
				remaining = 0;
			}
			Com_Printf( "[ANTI-FLOOD] %s was flooding the server with getstatus packets (%u/%d), release in %d seconds\n",
			            NET_AdrToString( *from ),
			            entry->packet_count,
			            threshold,
			            remaining );
			entry->state = FLOOD_STATE_FLAGGED;
		}

		// Escalate to a session-wide block if the hard threshold is also
		// crossed. Log once, then stay quiet to avoid filling the console.
		if ( block_threshold > 0 &&
		     (int)entry->packet_count > block_threshold &&
		     entry->state != FLOOD_STATE_BLOCKED ) {
			Com_Printf( "[ANTI-FLOOD] %s crossed the block threshold (%u packets), blocking for this session\n",
			            NET_AdrToString( *from ),
			            entry->packet_count );
			entry->state = FLOOD_STATE_BLOCKED;
		}

		return qtrue;  // drop this packet
	}

	return qfalse;
}

/*
===============
SV_AntiFlood_Shutdown

Release the tracking table. Called from SV_Shutdown (sv_init.c).
Safe to call multiple times.
===============
*/
void SV_AntiFlood_Shutdown( void ) {
	if ( flood_table ) {
		free( flood_table );
		flood_table    = NULL;
		flood_capacity = 0;
		flood_used     = 0;
	}
}