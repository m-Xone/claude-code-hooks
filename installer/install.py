"""cchooks installer. Normally launched by install.sh / install.ps1, which
pick the Python interpreter; you can also run it directly with the Python
you want the hooks to use:

    python3 installer/install.py [--scope user|project] [--project DIR]
                                 [--mode warn|enforce] [--statusline] [--retention-days N]
    python3 installer/install.py --hooks-only        # ignore any starter template
    python3 installer/install.py --uninstall [--keep-data]
    python3 installer/install.py --doctor
"""

import argparse
import os
import sys

if sys.version_info < (3, 9):
    sys.exit("cchooks needs Python 3.9 or newer; %s is %s." % (sys.executable, sys.version.split()[0]))

REPO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, os.path.join(REPO, "src"))

from cchooks import installer  # noqa: E402


def main():
    p = argparse.ArgumentParser(description="Install the cchooks Claude Code hook suite.")
    p.add_argument("--scope", choices=("user", "project"), default="user",
                   help="user: ~/.claude/settings.json (default). project: <project>/.claude/settings.json")
    p.add_argument("--project", help="project directory for --scope project (default: cwd)")
    p.add_argument("--mode", choices=("warn", "enforce"),
                   help="set every check to this mode (default: keep per-check defaults)")
    p.add_argument("--statusline", action="store_true", help="also install the cchooks status line")
    p.add_argument("--template", metavar="DIR",
                   help="starter ~/.claude to deploy first: settings.json is merged (your values win, lists "
                        "unioned); other existing files are backed up to .bak-<timestamp> and replaced")
    p.add_argument("--dry-run", action="store_true", help="show what would change, change nothing")
    p.add_argument("--retention-days", type=int, metavar="N",
                   help="auto-delete per-session data after N days unused; 0 = never. Asked interactively "
                        "if omitted (default: current setting, or 30)")
    p.add_argument("--hooks-only", action="store_true",
                   help="install only the hooks: ignore --template, touch nothing in ~/.claude except the hook "
                        "entries in settings.json (backed up first) and cchooks' own folder")
    p.add_argument("--uninstall", action="store_true",
                   help="remove everything cchooks added: hook entries, status line, /cchooks-report and "
                        "~/.claude/cchooks (code, config, state, logs)")
    p.add_argument("--keep-data", action="store_true", help="with --uninstall: keep config, logs and state")
    p.add_argument("--doctor", action="store_true", help="health check and self-test")
    a = p.parse_args()
    if a.uninstall:
        return installer.uninstall(keep_data=a.keep_data)
    if a.doctor:
        return installer.doctor()
    return installer.install(REPO, scope=a.scope, project=a.project, mode=a.mode, statusline=a.statusline,
                             template=None if a.hooks_only else a.template, dry_run=a.dry_run,
                             retention_days=a.retention_days)


if __name__ == "__main__":
    sys.exit(main())
