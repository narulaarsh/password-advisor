"""Hosted entry point for the G1-G4 study only (no vault). Deploy with docs/DEPLOY_STUDY.md."""
import os
import runpy
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

import streamlit as st  # noqa: E402


def drop_stale_project_modules():
    """After a git-push redeploy the server process can keep old copies of project modules
    (vault.*, modules.*) while the page script is new. Drop any whose source file changed
    since import, so the next import loads the current code."""
    for name, module in list(sys.modules.items()):
        if not (name == 'vault' or name.startswith(('vault.', 'modules'))):
            continue
        path = getattr(module, '__file__', None)
        loaded = getattr(module, '__project_mtime__', None)
        if not path or not os.path.exists(path):
            continue
        current = os.path.getmtime(path)
        if loaded is None:
            module.__project_mtime__ = current
        elif current != loaded:
            del sys.modules[name]


drop_stale_project_modules()
st.set_page_config(page_title='Password feedback study', layout='centered', initial_sidebar_state='collapsed')
runpy.run_path(str(ROOT / 'pages' / '7_Controlled_Study.py'), run_name='__main__')
