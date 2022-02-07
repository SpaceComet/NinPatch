from binaryninja import *

import binaryninjaui
from binaryninjaui import (getMonospaceFont, UIAction, UIActionHandler, Menu, UIContext)
if "qt_major_version" in binaryninjaui.__dict__ and binaryninjaui.qt_major_version == 6:
    from PySide6.QtWidgets import (QLineEdit, QPushButton, QApplication, QWidget,
         QVBoxLayout, QHBoxLayout, QDialog, QFileSystemModel, QTreeView, QLabel, QSplitter,
         QInputDialog, QMessageBox, QHeaderView, QKeySequenceEdit, QCheckBox)
    from PySide6.QtCore import (QDir, Qt, QFileInfo, QItemSelectionModel, QSettings, QUrl)
    from PySide6.QtGui import (QFontMetrics, QDesktopServices, QKeySequence, QIcon)
else:
    from PySide2.QtWidgets import (QLineEdit, QPushButton, QApplication, QWidget,
         QVBoxLayout, QHBoxLayout, QDialog, QFileSystemModel, QTreeView, QLabel, QSplitter,
         QInputDialog, QMessageBox, QHeaderView, QKeySequenceEdit, QCheckBox)
    from PySide2.QtCore import (QDir, Qt, QFileInfo, QItemSelectionModel, QSettings, QUrl)
    from PySide2.QtGui import (QFontMetrics, QDesktopServices, QKeySequence, QIcon)

class Binpatch(QDialog):

    def __init__(self, context, parent=None):
        super(Binpatch, self).__init__(parent)
        # Create widgets
        self.setWindowFlags(self.windowFlags() & ~Qt.WindowContextHelpButtonHint)
        self.title = QLabel(self.tr("Binpatch"))
        self.saveButton = QPushButton(self.tr("&Save"))
        self.saveButton.setShortcut(QKeySequence(self.tr("Ctrl+S")))
        self.closeButton = QPushButton(self.tr("Close"))
        self.setWindowTitle(self.title.text())

        # Add signals
        self.saveButton.clicked.connect(self.saveClicked)
        self.closeButton.clicked.connect(self.close)

        # Create layout and add widgets
        optionsAndButtons = QVBoxLayout()

        buttons = QHBoxLayout()
        buttons.addWidget(self.closeButton)
        buttons.addWidget(self.saveButton)

        optionsAndButtons.addLayout(buttons)

        vlayoutWidget = QWidget()
        vlayout = QVBoxLayout()
        vlayout.addLayout(optionsAndButtons)
        vlayoutWidget.setLayout(vlayout)

        hsplitter = QSplitter()
        hsplitter.addWidget(vlayoutWidget)

        hlayout = QHBoxLayout()
        hlayout.addWidget(hsplitter)

        # Set dialog layout
        self.setLayout(hlayout)

    def saveClicked(self):
        print("Click!")


def bp_patch(bv,function):
	patchesList = []
	tmpValues = bv.read(function, bv.get_instruction_length(function)).hex()

	try:
		patchesList = bv.query_metadata("binpatch-patches")
		patchesList.append(tmpValues)
		bv.store_metadata("binpatch-patches", patchesList)
	except:
		bv.store_metadata("binpatch-patches", [tmpValues])

	show_message_box("Do Nothing", str(hex(function)), MessageBoxButtonSet.OKButtonSet, MessageBoxIcon.ErrorIcon)


def bp_view(bv,function):
	tmpVal = bv.query_metadata("binpatch-patches")
	show_message_box("View Patches", ', '.join(tmpVal)+"\n\n", MessageBoxButtonSet.OKButtonSet, MessageBoxIcon.ErrorIcon)

PluginCommand.register_for_address(
	"NinPatch\\Patch\\Patch01", "Patch this", bp_patch
)

PluginCommand.register_for_address(
	"NinPatch\\View\\View Patches", "View all Patches", bp_view
)

binpatch = None

def launchPlugin(context):
    global binpatch
    if not binpatch:
        binpatch = Binpatch(context, parent=context.widget)
    binpatch.show()

if __name__ == '__main__':
    app = QApplication(sys.argv)
    binpatch = Binpatch(None)
    binpatch.show()
    sys.exit(app.exec_())
else:
    UIAction.registerAction("NinPatch\\View Patches")
    UIActionHandler.globalActions().bindAction("NinPatch\\View Patches", UIAction(launchPlugin))
    Menu.mainMenu("Tools").addAction("NinPatch\\View Patches", "NinPatch")