/*
===========================================================================

Wolfenstein: Enemy Territory GPL Source Code
Copyright (C) 1999-2010 id Software LLC, a ZeniMax Media company.

Defence-log extension (DDoS / abuse event logging)
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
sv_defence.c -- Defence-log sink for DDoS / abuse events.

Reimplements Pauluzz' SV_WriteDefenceLog from ET 3.00 0.7.4. Called from
SVC_Status (over-long challenge strings), SVC_Info (same), and future
abuse-detection paths. Events are timestamped and appended to the file
named by sv_defenceLog; if sv_defence == 0 or sv_defenceLog is empty
the call is a no-op.

CVars:
  sv_defence     0 = logging disabled (default), 1 = enabled
  sv_defenceLog  Path to log file (relative to fs_basepath or absolute).
                 Default "" = disabled even if sv_defence == 1.

The log format is plain text, one event per line:
  [YYYY-MM-DD HH:MM:SS] <message>
The caller is responsible for including the source address in the
message if desired. No log rotation is performed; operators must
manage the file externally (logrotate, etc.).

Phase 2 notes
-------------
- Consider switching to FS_FOpenFileAppend so logs land in fs_homepath
  rather than CWD.
- Consider a rate-limit on log writes (currently unbounded).
- Consider structured format (JSON) for easier machine parsing.
===========================================================================
*/

#include "server.h"

extern cvar_t *sv_defence;
extern cvar_t *sv_defenceLog;

/*
===============
SV_WriteDefenceLog

Append a timestamped line to the defence log file. No-op when the
feature is disabled or no log path is configured. Best-effort: if
the file cannot be opened, silently give up (we don't want log
failures to spam the server console, which would itself be a DoS
amplification vector).

Called from hot paths (every dropped getstatus, etc.), so we keep
the implementation small and don't touch CVars beyond the initial
gate checks.
===============
*/
void SV_WriteDefenceLog( const char *message ) {
	FILE      *fp;
	time_t     now;
	struct tm *tm_info;
	char       stamp[32];

	if ( !sv_defence || sv_defence->integer == 0 ) {
		return;
	}
	if ( !sv_defenceLog || !sv_defenceLog->string || !sv_defenceLog->string[0] ) {
		return;
	}
	if ( !message || !message[0] ) {
		return;
	}

	fp = fopen( sv_defenceLog->string, "a" );
	if ( !fp ) {
		return;  // silently give up (see comment above)
	}

	now = time( NULL );
	tm_info = localtime( &now );
	if ( tm_info ) {
		strftime( stamp, sizeof( stamp ), "%Y-%m-%d %H:%M:%S", tm_info );
	} else {
		Q_strncpyz( stamp, "????-??-?? ??:??:??", sizeof( stamp ) );
	}

	fprintf( fp, "[%s] %s\n", stamp, message );
	fclose( fp );
}
