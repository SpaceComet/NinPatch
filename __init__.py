#from binaryninja import *
from binaryninja import (PluginCommand, show_message_box, MessageBoxButtonSet, MessageBoxIcon)

import binaryninjaui
from binaryninjaui import (getMonospaceFont, UIAction, UIActionHandler, Menu, UIContext)
if "qt_major_version" in binaryninjaui.__dict__ and binaryninjaui.qt_major_version == 6:
    from PySide6.QtWidgets import (QLineEdit, QPushButton, QApplication, QWidget,
         QVBoxLayout, QHBoxLayout, QDialog, QFileSystemModel, QTreeView, QLabel, QSplitter,
         QInputDialog, QMessageBox, QHeaderView, QKeySequenceEdit, QCheckBox, QGroupBox, QSizePolicy, QScrollArea,
         QSpacerItem, QListView)
    from PySide6.QtCore import (QDir, Qt, QFileInfo, QItemSelectionModel, QSettings, QUrl, QRect)
    from PySide6.QtGui import (QFontMetrics, QDesktopServices, QKeySequence, QIcon, QStandardItemModel, QStandardItem)
else:
    from PySide2.QtWidgets import (QLineEdit, QPushButton, QApplication, QWidget,
         QVBoxLayout, QHBoxLayout, QDialog, QFileSystemModel, QTreeView, QLabel, QSplitter,
         QInputDialog, QMessageBox, QHeaderView, QKeySequenceEdit, QCheckBox, QGroupBox, QSizePolicy, QScrollArea,
         QSpacerItem, QListView)
    from PySide2.QtCore import (QDir, Qt, QFileInfo, QItemSelectionModel, QSettings, QUrl, QRect)
    from PySide2.QtGui import (QFontMetrics, QDesktopServices, QKeySequence, QIcon, QStandardItemModel, QStandardItem)


def getPatchesInMetadata(bv):
    rVal = None

    try:
        tmpPatches = bv.query_metadata("ninpatch-patches")
        if (type(tmpPatches) is list):
            if (len(tmpPatches) > 0):
                rVal = tmpPatches
    except:
        rVal = False

    return(rVal)

class Ninpatch(QDialog):

    def __init__(self, context, parent=None):
        super(Ninpatch, self).__init__(parent)

        # Create widgets
        self.setWindowFlags(self.windowFlags() & ~Qt.WindowContextHelpButtonHint)
        self.title = QLabel(self.tr("Ninpatch"))
        self.setWindowTitle(self.title.text())
        self.resize(419, 530)

        # ----
        self.groupBox = QGroupBox(self.tr("&Patches"))
        sizePolicy = QSizePolicy(QSizePolicy.Preferred, QSizePolicy.Expanding)
        sizePolicy.setHorizontalStretch(0)
        sizePolicy.setVerticalStretch(0)
        sizePolicy.setHeightForWidth(self.groupBox.sizePolicy().hasHeightForWidth())
        self.groupBox.setSizePolicy(sizePolicy)

        # ---- 
        self.bv = context.binaryView
        self.patches = []
        self.listOfPatches = QListView(self.groupBox)
        self.listOfPatchesModel = QStandardItemModel()
        
        # Get the patches list
        self.patches = getPatchesInMetadata(self.bv)

        # Build list of patches
        if (self.patches):
            for nPatch in self.patches:
                if (len(nPatch) >= 4):
                    item = QStandardItem("@{0}: {1} -> {2}".format(hex(nPatch[1]), nPatch[2], nPatch[3]))
                    item.setCheckable(True)
                    check = Qt.Checked if nPatch[0] else Qt.Unchecked
                    item.setCheckState(check)
                    self.listOfPatchesModel.appendRow(item)
                else:
                    # the metadata is corrupted
                    # TODO: Show Error Msg
                    break
        else:
            item = QStandardItem("There are not patches")
            self.listOfPatchesModel.appendRow(item)

        
        self.listOfPatches.setModel(self.listOfPatchesModel)

        # ----
        self.buttonSelect = QPushButton(self.groupBox.tr("&Select All"))
        self.buttonDeselect = QPushButton(self.groupBox.tr("&Deselect All"))
        self.hLayoutSeclection = QHBoxLayout()
        self.hLayoutSeclection.addWidget(self.buttonSelect)
        self.hLayoutSeclection.addWidget(self.buttonDeselect)

        # ----
        self.verticalLayout = QVBoxLayout(self.groupBox)
        self.verticalLayout.addWidget(self.listOfPatches)
        self.verticalLayout.addLayout(self.hLayoutSeclection)

        # ----
        self.buttonPatch = QPushButton(self.tr("&Patch File"))
        self.hLayoutIO = QHBoxLayout()
        self.buttonImportPacthes = QPushButton(self.tr("&Import Patches"))
        self.buttonExportPatches = QPushButton(self.tr("&Export Patches"))
        self.hLayoutIO.addWidget(self.buttonImportPacthes)
        self.hLayoutIO.addWidget(self.buttonExportPatches)

        # ----
        self.hLayoutClose = QHBoxLayout()
        self.horizontalSpacer = QSpacerItem(40, 20, QSizePolicy.Expanding, QSizePolicy.Minimum)
        self.buttonClose = QPushButton(self.tr("&Close"))
        self.hLayoutClose.addItem(self.horizontalSpacer)
        self.hLayoutClose.addWidget(self.buttonClose)

        # ----
        self.vLayoutButtons = QVBoxLayout()
        self.vLayoutButtons.addWidget(self.buttonPatch)
        self.vLayoutButtons.addLayout(self.hLayoutIO)
        self.vLayoutButtons.addLayout(self.hLayoutClose)

        self.vLayoutPatches = QVBoxLayout()
        self.vLayoutPatches.addWidget(self.groupBox)
        self.vLayoutPatches.addLayout(self.vLayoutButtons)

        self.verticalLayout_3 = QVBoxLayout()
        self.verticalLayout_3.addLayout(self.vLayoutPatches)

        #self.saveButton = QPushButton(self.tr("&Save"))
        #self.saveButton.setShortcut(QKeySequence(self.tr("Ctrl+S")))

        # Add signals
        self.buttonPatch.clicked.connect(self.saveClicked)
        self.buttonClose.clicked.connect(self.close)

        # Set dialog layout
        self.setLayout(self.verticalLayout_3)

    def saveClicked(self):
        print("Click!")

ninpatch = None

def np_patch(bv, cuAddr):
    patchesList = []
    cpCuOpcode = bv.arch.assemble((bv.get_disassembly( cuAddr ))).hex()
    cpPaOpcode = bv.arch.convert_to_nop(bytes.fromhex(cpCuOpcode)).hex()

    # Patch's format
    # [Check, address, current opcode, patched opcode]
    currentPatch = [True, cuAddr, cpCuOpcode, cpPaOpcode]

    patchesList = getPatchesInMetadata(bv)
    if (patchesList):
        # If there are patches in the metadata already then add the new patch
        patchesList.append(currentPatch)
        bv.store_metadata("ninpatch-patches", patchesList)
    else:
        # If not then make the metadata and add the first patch
        bv.store_metadata("ninpatch-patches", [currentPatch])

    #show_message_box("Do Nothing", str(hex(cuAddr)), MessageBoxButtonSet.OKButtonSet, MessageBoxIcon.ErrorIcon)


def np_view(bv, cuAddr):
    tmpVal = bv.query_metadata("ninpatch-patches")
    print(tmpVal)
    show_message_box("View Patches", str(tmpVal)+"\n\n", MessageBoxButtonSet.OKButtonSet, MessageBoxIcon.ErrorIcon)

PluginCommand.register_for_address(
	"NinPatch\\Patch\\Patch01", "Patch this", np_patch
)

PluginCommand.register_for_address(
	"NinPatch\\View\\View Patches", "View all Patches", np_view
)

def launchPlugin(context):
    global ninpatch
    #if not ninpatch:
    #    ninpatch = Ninpatch(context, parent=context.widget)

    # Rebuild the window every time because I don't know how to update it... yet.
    ninpatch = Ninpatch(context, parent=context.widget)
    ninpatch.show()

if __name__ == '__main__':
    app = QApplication(sys.argv)
    ninpatch = Ninpatch(None)
    ninpatch.show()
    sys.exit(app.exec_())
else:
    UIAction.registerAction("NinPatch\\View Patches")
    UIActionHandler.globalActions().bindAction("NinPatch\\View Patches", UIAction(launchPlugin))
    Menu.mainMenu("Tools").addAction("NinPatch\\View Patches", "NinPatch")