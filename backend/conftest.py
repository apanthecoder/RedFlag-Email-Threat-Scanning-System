"""Empty on purpose: its presence makes pytest add backend/ to sys.path,
so `import config`, `from services...`, `from utils...` etc. resolve the
same way they do when Flask runs the app.
"""
