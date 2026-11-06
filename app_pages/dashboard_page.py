from __future__ import annotations

import streamlit as st

from app_pages.common import current_events, page_header
from dashboard import render_dashboard

page_header("Security dashboard", "A clear view of activity that may deserve a closer look.")
render_dashboard(current_events())
