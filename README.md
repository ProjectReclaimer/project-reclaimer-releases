# Project Reclaimer

Ready-built downloads of Project Reclaimer, a free, non-commercial multiplayer
client for Halo 3 from Halo: The Master Chief Collection. This repository
holds only the releases; the source code isn't published.

## Download

To play, get the **game client** from the
[latest release](https://github.com/ProjectReclaimer/project-reclaimer-releases/releases/latest).
Future releases name it `project-reclaimer-client-v<version>.exe`, with the
release's version in the filename. The `project-reclaimer-dedicated-...exe`
download runs servers only; it cannot start the game.

Older releases name the game client `project-reclaimer-v<version>.exe` or
`project-reclaimer.exe`.

Check your download against that release's `SHA256SUMS.txt` before running it.
In PowerShell, replace the example below with your downloaded file's exact name:

```powershell
Get-FileHash '.\project-reclaimer-client-v<version>.exe' -Algorithm SHA256
```

You need your own Steam copy of Halo: The Master Chief Collection with Halo 3
Campaign and Multiplayer installed; no game files are included. Double-click
the client executable to start the game.

When updating from an older client that cannot install the renamed download
from its menu, open the release page and download the client executable.

## Dedicated servers

For Windows servers, download `project-reclaimer-dedicated-v<version>.exe`.
Each release also publishes the Linux server image
`ghcr.io/projectreclaimer/project-reclaimer-dedicated`. See
[hosting a dedicated server](https://projectreclaimer.dev/host).

## Community and custom game modes

The [game-mode guide](https://projectreclaimer.dev/modes) explains how to write
JSON or Megalo modes and check them with the game client's `mode-check` command.
A valid file still needs a playtest with another player before it is shared.

For project questions and bug reports, use the Discord linked from the
[official website](https://projectreclaimer.dev/).

## About

More at [projectreclaimer.dev](https://projectreclaimer.dev).

Project Reclaimer is not affiliated with, endorsed, sponsored or approved by
Microsoft, Xbox Game Studios, Halo Studios, 343 Industries, Bungie or
Activision. Halo, Halo: The Master Chief Collection and Xbox are trademarks of
the Microsoft group of companies.
