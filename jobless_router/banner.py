"""
Startup banner. Uses pyfiglet for real ASCII-art block lettering with an
ANSI color gradient, falling back to a plain text banner if pyfiglet isn't
installed -- the tool must never refuse to start just because the banner
can't render fancy.
"""
SUBTITLE = "Reincarnated in a Tier-1 Scrubbing Center to Master BGP Flowspec"

_RESET = "\033[0m"
_BOLD = "\033[1m"
_DIM = "\033[2m"
# A cool-to-warm gradient, cycled top-to-bottom across the art's lines --
# cyan/blue at the top fading toward magenta, a fairly standard "hacker
# tool" palette that reads well on both light and dark terminals.
_GRADIENT = ["\033[96m", "\033[96m", "\033[94m", "\033[95m", "\033[95m", "\033[91m"]


def _plain_fallback() -> str:
    return f"\n   JOBLESS-ROUTER\n   {SUBTITLE}\n"


def render_banner() -> str:
    try:
        import pyfiglet
        art = pyfiglet.figlet_format("JOBLESS-ROUTER", font="slant", width=200)
    except Exception:
        return _plain_fallback()

    lines = art.rstrip("\n").split("\n")
    if not any(line.strip() for line in lines):
        return _plain_fallback()

    colored_lines = []
    for i, line in enumerate(lines):
        color = _GRADIENT[i % len(_GRADIENT)]
        colored_lines.append(f"{color}{_BOLD}{line}{_RESET}")

    subtitle_line = f"{_DIM}   \u21b3 {SUBTITLE}{_RESET}"
    return "\n" + "\n".join(colored_lines) + "\n" + subtitle_line + "\n"
