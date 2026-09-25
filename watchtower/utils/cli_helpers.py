def parse_program_filter(raw_arg: str) -> list | None:
    """Parses a comma-separated string of program names into a clean list."""
    if not raw_arg:
        return None
    programs = [p.strip() for p in raw_arg.split(',') if p.strip()]
    return programs if programs else None