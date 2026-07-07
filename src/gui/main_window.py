import customtkinter as ctk

from src.gui.components.sidebar import Sidebar
from src.gui.pages.dashboard import Dashboard


class MainWindow(ctk.CTkFrame):
    def __init__(self, parent):
        super().__init__(parent)

        self.pack(fill="both", expand=True)

        self.sidebar = Sidebar(self)
        self.sidebar.pack(side="left", fill="y")

        self.dashboard = Dashboard(self)
        self.dashboard.pack(
            side="right",
            fill="both",
            expand=True
        )