from PyQt6 import QtWidgets, QtCore, QtGui


class Scroll_area(QtWidgets.QScrollArea):
    """An object representing a 'scroll area' with his appearance and logic.

    Args:
        main_object (QMainWindow): A QMainWindow object. Use to acces method of the main window.
    """

    def __init__(self):
        super().__init__()
        self.init_ui()

    def init_ui(self) -> None:
        """Init the UI of the object.
        """
        self.setWidgetResizable(True)
        content_holder = QtWidgets.QWidget()

        self.content_holder_layout = QtWidgets.QHBoxLayout()
        self.content_holder_layout.setAlignment(
            QtCore.Qt.AlignmentFlag.AlignTop)
        content_holder.setLayout(self.content_holder_layout)

        self.setWidget(content_holder)

    def add_child(self, child) -> None:
        """Add a Child_cell object at the end of the scroll area.
        """
        self.content_holder_layout.addWidget(child)
