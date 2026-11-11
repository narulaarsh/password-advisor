"""Hosted entry point for the G1-G4 study only (no vault). Deploy with docs/DEPLOY_STUDY.md."""
import runpy
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

import streamlit as st  # noqa: E402

# A git-push redeploy can leave old copies of this project's modules (vault.*, modules.*)
# in the server process while the page script is new. Always load them fresh: they are
# small, and participants' progress lives in st.session_state, not in these modules.
for _name in [n for n in sys.modules if n == 'vault' or n.startswith(('vault.', 'modules'))]:
    del sys.modules[_name]

st.set_page_config(page_title='Password feedback study', layout='centered', initial_sidebar_state='collapsed')
runpy.run_path(str(ROOT / 'pages' / '7_Controlled_Study.py'), run_name='__main__')
