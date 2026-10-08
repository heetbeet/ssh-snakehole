"""Full-screen fixture using Textual's native terminal driver."""

import sys
from pathlib import Path

from textual.app import App, ComposeResult
from textual.widgets import Label, TextArea


class Editor(App):
    CSS = """
    #title { height: 1; color: red; text-style: bold; }
    TextArea { height: 1fr; border: none; }
    #size { height: 1; }
    """
    BINDINGS = [("ctrl+q", "finish", "Finish")]

    def compose(self) -> ComposeResult:
        yield Label("FULL-SCREEN é 汉 🐍", id="title")
        yield TextArea()
        yield Label(id="size")

    def on_resize(self, event):
        self.query_one("#size", Label).update(
            f"SIZE({event.size.width}, {event.size.height})"
        )

    def on_mount(self):
        self.query_one(TextArea).focus()
        self.query_one("#title", Label).update("READY FULL-SCREEN é 汉 🐍")

    def action_finish(self):
        Path(sys.argv[1]).write_text(self.query_one(TextArea).text, encoding="utf-8")
        self.exit()


Editor().run()
print("APP-DONE", flush=True)
