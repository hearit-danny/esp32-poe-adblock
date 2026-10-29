#pragma once
// HTTP admin UI on port 80: status page, /stats JSON, blocklist upload,
// block-mode toggle and firmware update.

void admin_begin();
// Runs a pending reboot after a firmware update; call from loop().
void admin_loop();
