## 800715f8 zz_00715f8_
OLD=initializeSubsystemContext  NEW=initBorgFlightVectorAndDispatchAction

**Function Analysis:**
The function `zz_00715f8_` acts as a state-transition handler for a Borg instance, specifically focusing on the initialization of movement vectors and the triggering of specific action states.
1.  **Input Check & Vector Initialization**: It first checks byte `0x1d0f` (likely an input flag or trigger condition). If true, it computes a new facing angle by subtracting `0x8000` (128 degrees offset, likely for a specific facing mode or reverse direction) from the current heading at `0x72` and stores it in `0x5ae`. Crucially, it then copies four global floats (`FLOAT_80437768`, `FLOAT_80437748`, `FLOAT_804376e4`, `FLOAT_804376e0`) into the Borg's struct at offsets `0x44`, `0x4c`, `0x48`, and `0x50`. In the Borg struct, these offsets typically correspond to velocity components (`velX`, `velY`, `velZ`) or flight direction vectors, suggesting this function sets a specific flight vector or "dash" direction based on global state.
2.  **State Cue Dispatch**: It calls `zz_006dbe0_` (a known helper for processing action cues/animation states) with parameters `(param_1, 2, 1, 1)`. This likely attempts to transition the Borg to a specific internal state (possibly related to movement or action ID 2).
3.  **Conditional Action Execution**: If the state transition is successful (`iVar6 != 0`), it reads the current action/state ID from `0x1000` (a common offset for the active action enum in Borg structs) and dispatches specific sub-actions via `zz_007db5c_` (likely a helper for playing specific animations, sounds, or effects):
    *   If state is `0`: Calls `zz_007db5c_(..., 0)`.
    *   If state is `3`: Calls `zz_007db5c_(..., 1)`, and if `0x7c8` (likely an upper-body state or combo flag) is set, also calls `zz_007db5c_(..., 2)`.
    *   If state is `10`: Calls `zz_007db5c_(..., 3)`.

This pattern indicates a "pre-flight" or "action-initiation" routine that sets up physics vectors and then triggers the corresponding visual/auditory cues for specific Borg actions.

**Behavior Summary:**
This function initializes a Borg's flight vector based on a global reference and current heading, then transitions the Borg into a specific action state. Depending on the resulting action ID, it triggers specific animation or effect cues associated with that state, effectively bridging the gap between movement setup and action execution.

**Suggested Name:** initBorgFlightVectorAndDispatchAction
**Rationale:** The name captures the two primary phases: setting the flight/velocity vector (via the global float copies and heading calculation) and then dispatching the relevant action cues based on the state ID. It avoids generic terms like "update" or "handle" in favor of "init" and "dispatch," which accurately reflect the one-time setup nature of the vector assignment and the event-driven nature of the `zz_007db5c_` calls. It references the domain object "Borg" and the specific subsystems "Flight" (movement) and "Action" (state machine/animations).

---
## 8006facc invokeDispatchTableEntry
OLD=executeIndexedDispatchCallback  NEW=dispatchBorgActionState

**Function Analysis:**
The function `invokeDispatchTableEntry` acts as a generic dispatcher for the Borg instance state machine. It takes a pointer to a specific Borg instance (`param_1`) as input. The core logic accesses an offset `0x580` within that Borg struct (`*(char *)(param_1 + 0x580)`). Based on the provided context notes, offset `0x544` is the main state/action enum, but `0x580` is likely a derived index or a specific sub-state/action selector used for the dispatch table lookup. This index is used to retrieve a function pointer from the global `PTR_dispatchStateCallback_802d3b68` array. The retrieved function pointer is then immediately invoked. This pattern is characteristic of a virtual dispatch or switch-case implementation where the state determines which specific behavior routine (e.g., idle, attack, hit, death) is executed for that Borg instance in the current frame. It does not modify data itself but delegates control flow to the appropriate state handler.

**Behavior Summary:**
This function retrieves a function pointer from a global dispatch table using an index derived from the Borg instance's offset `0x580`, and then executes that function. It serves as the core loop mechanism for transitioning and executing the current action state of a Borg character, effectively driving the Borg's behavioral logic based on its internal state data.

**Suggested Name:** dispatchBorgActionState
**Rationale:** The name accurately reflects the function's role: it `dispatches` a callback to handle the current `Borg` `Action` `State`. The offset `0x580` is interpreted as the source of the action/state index used to look up the correct handler in `PTR_dispatchStateCallback_`. This aligns with the domain-specific requirement to use action verbs like "dispatch" and include the domain object "Borg", distinguishing it from generic state updates or movement calculations.

---
## 80071598 zz_0071598_
OLD=dispatchViaIndexTable  NEW=dispatchBorgSubStateAction

**Function Analysis:**
The function `zz_0071598_` acts as a simple indirect call dispatcher (a trampoline). It takes a pointer to a Borg instance (`param_1`) as its argument. It accesses memory at `param_1 + 0x581`, which corresponds to a byte-sized state or action index within the Borg instance struct. This index is used to look up a function pointer from a global table located at `PTR_zz_00115d4__802d3c48` (specifically `&PTR_zz_00115d4__802d3c48[0x802d3c48 + index]`, though the syntax `&PTR...[*(char...)]` implies the table base is at `0x802d3c48` and the offset is the byte value). The retrieved function pointer is then executed.

In the context of *Gotcha Force*, the offset `0x581` is likely part of the Borg's action or sub-state machine data (distinct from the main state at `0x544` or status flags at `0x5e0`). The table at `0x802d3c48` serves as a jump table for specific actions or states that this Borg is currently undergoing. This pattern is typical for dispatching logic based on a dynamic sub-state index, such as specific attack animations, hit reactions, or special ability phases that are not covered by the main state machine's coarse switch. It does not modify data but merely redirects control flow based on the current sub-state.

**Behavior Summary:**
This function retrieves a function pointer from a global dispatch table using an index stored at the Borg instance offset `0x581`, then immediately calls that function. It serves as an indirect call site for executing state-specific or action-specific logic determined by the Borg's current sub-state index.

**Suggested Name:** dispatchBorgSubStateAction
**Rationale:** The name accurately reflects the function's role as a dispatcher (`dispatch`) for a Borg instance's (`Borg`) specific sub-state or action logic (`SubStateAction`). The offset `0x581` is identified as the sub-state index source, and the global table at `0x802d3c48` acts as the action dispatch table. This aligns with the requirement to use specific domain objects and action verbs, distinguishing it from the main state machine update loop.

---
