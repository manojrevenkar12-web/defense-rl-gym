fix.py: resolves the name with realpath inside support.DOCS and returns 404 for anything that resolves outside it (../, absolute paths, symlinks, NUL bytes).
