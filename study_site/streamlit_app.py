"""Hosted entry point for the G1-G4 study only (no vault). Deploy with docs/DEPLOY_STUDY.md."""
import runpy
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

import streamlit as st  # noqa: E402

st.set_page_config(page_title='Password feedback study', layout='centered', initial_sidebar_state='collapsed')
runpy.run_path(str(ROOT / 'pages' / '7_Controlled_Study.py'), run_name='__main__')
