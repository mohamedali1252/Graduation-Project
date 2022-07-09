from PyQt6 import QtWidgets
import global_var


class CSV_Reader:
    def __init__(self, main_window: QtWidgets.QMainWindow) -> None:
        self.main_window = main_window
        self.previous_lines = []

    def filter_lines(self, lines: list[str]) -> list[list[str]]:
        """Filter each lines and put each item in a specific info list

        Args:
            lines (list[str]): A list of string, each string is a line

        Returns:
            list[list[str]]: A list of list containing the info, each inner list is for 1 info type
        """
        # We create a list containing 7 empty list for sorting the different info
        returning_infos = [[] for _ in range(7)]

        for line in lines:
            if line != "":
                info = line.split(global_var.CSV_DELIMITER)
                # This will place each item in the correct corresponding list
                for index, item in enumerate(info):
                    returning_infos[index].append(item)

                    # There we check the attack type
                    if index == 4:
                        if item.strip().lower() == "normal":
                            new_item = ("PASSED")
                        else:
                            new_item = ("BLOCKED")
                        returning_infos[6].append(new_item)

        return returning_infos

    def read_csv(self, path: str):
        """Read the CSV file

        Args:
            path (str): A path to the csv file
        """
        with open(path, "r") as csv_file:
            # Here we remove the line break "symbol" at the end of a line to have "pure" info
            lines = "".join(csv_file.readlines())
            lines = lines.splitlines()

        # There's no need to update the UI if the CSV hasn't change !
        if self.previous_lines != lines:
            self.previous_lines = lines
            infos = self.filter_lines(lines)
            self.main_window.populate(infos)
