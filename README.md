# Project Reclaimer

Ready-built downloads of Project Reclaimer, a free, non-commercial multiplayer
client for Halo 3 from Halo: The Master Chief Collection. This repository
holds only the releases; the source code isn't published.

## Download

Get `project-reclaimer.exe` from the
[latest release](https://github.com/ProjectReclaimer/project-reclaimer-releases/releases/latest)
and check it against that release's `SHA256SUMS.txt` before running it:

```powershell
Get-FileHash project-reclaimer.exe -Algorithm SHA256
```

You need your own Steam copy of Halo: The Master Chief Collection with Halo 3
installed; no game files are included. Start the client with:

```powershell
project-reclaimer.exe game-client
```

## Dedicated servers

Each release also publishes the server image
`ghcr.io/projectreclaimer/project-reclaimer-dedicated`. See
[hosting a dedicated server](https://projectreclaimer.dev/host).

## About

More at [projectreclaimer.dev](https://projectreclaimer.dev).

Project Reclaimer is not affiliated with, endorsed, sponsored or approved by
Microsoft, Xbox Game Studios, Halo Studios, 343 Industries, Bungie or
Activision. Halo, Halo: The Master Chief Collection and Xbox are trademarks of
the Microsoft group of companies.
