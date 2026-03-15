"""
Web-only state wrapper
"""
from ui.tui.state import UIState


web_state = UIState()
web_state.stop = False
web_state.paused = False
web_state.stopped = False
