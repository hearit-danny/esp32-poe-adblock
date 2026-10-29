# PlatformIO pre-build script: passes the admin password into the firmware as
# ADMIN_PASSWORD, read from the ADBLOCK_ADMIN_PASSWORD environment variable so
# it never lands in the repo. The build stops if it is unset, because a build
# without it would leave the blocklist upload and firmware update open.
import os
import sys

Import("env")  # noqa: F821 (provided by PlatformIO)

password = os.environ.get("ADBLOCK_ADMIN_PASSWORD", "")
if not password:
    sys.stderr.write(
        "ADBLOCK_ADMIN_PASSWORD is not set. Set it before building, for example:\n"
        '  setx ADBLOCK_ADMIN_PASSWORD "choose-a-password"   (then open a new shell)\n'
    )
    env.Exit(1)  # noqa: F821
env.Append(CPPDEFINES=[("ADMIN_PASSWORD", env.StringifyMacro(password))])  # noqa: F821
