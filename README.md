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

## Linux via Proton (community-tested, unofficial)

The player client is published for Windows; Linux is not an officially supported
client platform. One community-tested way to try it on Linux is with Steam Play:

1. Install Halo: The Master Chief Collection from Steam, including both **Halo 3
   Campaign** and **Halo 3 Multiplayer**. Wait for Steam to finish installing them.
2. Add the Project Reclaimer client executable from the latest release to Steam
   as a **Non-Steam Game**.
3. In that shortcut's **Properties → Compatibility**, enable **Force the use of
   a specific Steam Play compatibility tool** and select **Proton Experimental**.
4. Keep Steam running and start Project Reclaimer from the shortcut. If the
   client asks for the MCC folder, choose the installed
   `Halo The Master Chief Collection` directory in the file picker; Proton
   exposes Linux files through its `Z:` drive.

This is an experimental community workaround, not an official Linux support
commitment; behavior may vary with Proton versions and Linux systems. Linux
dedicated-server support through Docker is a separate, documented setup.

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
