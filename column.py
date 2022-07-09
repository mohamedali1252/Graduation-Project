from PyQt6 import QtWidgets, QtCore, QtGui
import global_var


class Column(QtWidgets.QLabel):
    def __init__(self, title: str, info: list[str]):
        super().__init__()
        self.info = info
        self.titlefont = QtGui.QFont("Arial", 13, 1000)
        self.customfont = QtGui.QFont("Arial", 12, 700)
        self.init_ui(title)
        self.populate()

    def init_ui(self, title: str):
        """Init the UI

        Args:
            title (str): The title of the column
        """
        # Since the column is technicly a QLabel we have to use this trick to fully display it
        self.setMinimumHeight(len(self.info)*35)
        self.setStyleSheet(
            f"background-color:{global_var.COLUMN_COLOR};border-radius:10px")
        # Thanks to this, the app respond well to different size !
        self.setSizePolicy(QtWidgets.QSizePolicy.Policy.Expanding,
                           QtWidgets.QSizePolicy.Policy.Expanding)
        title_display = QtWidgets.QLabel(title)
        title_display.setAlignment(QtCore.Qt.AlignmentFlag.AlignCenter)
        title_display.setFont(self.titlefont)

        self.lay = QtWidgets.QVBoxLayout()
        self.lay.setAlignment(QtCore.Qt.AlignmentFlag.AlignTop)
        self.lay.setSpacing(5)

        self.lay.addWidget(title_display)

        self.setLayout(self.lay)

    def add_item(self, item: str):
        """Add the given item to the column

        Args:
            item (str): A string to be added
        """

        item_display = QtWidgets.QLabel(item)
        item_display.setFont(self.customfont)
        item_display.setAlignment(QtCore.Qt.AlignmentFlag.AlignCenter)
        item_display.setFixedHeight(30)

        color = ""
        if item == "PASSED":
            color = global_var.PASSED_COLOR
        elif item == "BLOCKED":
            color = global_var.BLOCKED_COLOR

        item_display.setStyleSheet(
            f"background:{color};border-radius:6px;color:white")
        self.lay.addWidget(item_display)

    def populate(self):
        """add the different item from info into the column
        """
        for item in self.info:
            self.add_item(item)
