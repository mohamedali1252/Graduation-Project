from PyQt6 import QtWidgets, QtCore, QtGui

from column import Column
from reader import CSV_Reader
from scrollArea import Scroll_area
import global_var


class Window(QtWidgets.QMainWindow):
    def __init__(self):
        super().__init__()
        self.init_ui()
        self.start_checker()

    def init_ui(self) -> None:
        """Init the UI of the obect.
        """
        self.setWindowTitle("Intelligence Honeypot on SDN")

        self.setMinimumSize(QtCore.QSize(1100, 150))

        central_widget = QtWidgets.QWidget()
        self.main_layout = QtWidgets.QVBoxLayout()
        title = QtWidgets.QLabel("Intelligence Honeypot on SDN")
        title.setFont(QtGui.QFont("Arial", 20, 1000))
        title.setAlignment(QtCore.Qt.AlignmentFlag.AlignCenter)

        central_widget.setLayout(self.main_layout)
        self.setCentralWidget(central_widget)

        self.main_layout.addWidget(title)

        self.show()

    def start_checker(self):
        """Start the checking of the CSV file
        """
        # We create our reader
        self.reader = CSV_Reader(self)

        # This will call our reader every second
        self.checker = QtCore.QTimer(self)
        self.checker.timeout.connect(
            lambda: self.reader.read_csv(global_var.CSV_PATH))
        self.checker.start(1000)

    def populate(self, infos: list[list[str]]):
        """Put all the column in the app

        Args:
            info (list[list[str]]): A list of list containing the info, each inner list is for 1 info type
        """
        # Each time this method is called the previous Scroll_area (and its children) is replaced with a new one
        # The old one will be garbage collect
        # This is way quicker then keeping the old column and replacing each item in it

        if self.main_layout.count() > 1:
            self.main_layout.itemAt(1).widget().setParent(None)

        scroll = Scroll_area()
        self.main_layout.addWidget(scroll)

        titles = ["date", "time", "source IP", "destination IP",
                  "attack type", "protocol type", "action taken"]

        for index, title in enumerate(titles):
            corresponding_info = infos[index]
            column = Column(title, corresponding_info)
            scroll.add_child(column)


if __name__ == "__main__":
    import sys

    app = QtWidgets.QApplication(sys.argv)
    window = Window()
    sys.exit(app.exec())
