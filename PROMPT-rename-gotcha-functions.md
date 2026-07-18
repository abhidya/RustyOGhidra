You are connected to Ghidra through OGhidraMCP. The active program should be Gotcha Force `boot.dol` from a GameCube ISO decomp project.

Goal: rename poorly named functions using evidence from decompilation, callers/callees, strings, data references, and nearby symbols.

Workflow:
1. Confirm the active Ghidra instance and program with `instances_list` and switch to the `boot.dol` instance if needed.
2. List functions and prioritize default/unknown names such as `FUN_*`, `sub_*`, `func_*`, `thunk_*`, or address-only names.
3. Work in batches of 20 functions. For each function, inspect decompiled code, xrefs/callers, strings, and obvious data references before renaming.
4. Rename only when there is concrete evidence. Prefer `rename_function_by_address(function_address, new_name)` so the exact target is unambiguous.
5. Use lower_snake_case names. Use domain prefixes when useful, such as `battle_`, `borg_`, `camera_`, `effect_`, `input_`, `menu_`, `model_`, `render_`, `sound_`, `ui_`, or `gf_`.
6. Do not rename imports, compiler/library stubs, thunks, or functions whose behavior is still unclear. Leave uncertain functions unchanged and explain what evidence is missing.
7. After each successful rename, add a short decompiler comment at the function entry explaining the evidence.
8. Stop after the batch and report a table with: address, old name, new name, confidence, and reason.

Start now with a first batch of high-confidence function renames. Apply the renames directly in Ghidra.
