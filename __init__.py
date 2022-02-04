from binaryninja import *

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
	"BinPatch\\Patch\\Patch01", "Patch this", bp_patch
)

PluginCommand.register_for_address(
	"BinPatch\\View\\View Patches", "View all Patches", bp_view
)