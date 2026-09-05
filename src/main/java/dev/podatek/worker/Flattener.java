package dev.podatek.worker;

import org.objectweb.asm.Opcodes;
import org.objectweb.asm.Type;
import org.objectweb.asm.tree.AbstractInsnNode;
import org.objectweb.asm.tree.FieldInsnNode;
import org.objectweb.asm.tree.FrameNode;
import org.objectweb.asm.tree.IincInsnNode;
import org.objectweb.asm.tree.InsnList;
import org.objectweb.asm.tree.InsnNode;
import org.objectweb.asm.tree.IntInsnNode;
import org.objectweb.asm.tree.JumpInsnNode;
import org.objectweb.asm.tree.LabelNode;
import org.objectweb.asm.tree.LdcInsnNode;
import org.objectweb.asm.tree.LineNumberNode;
import org.objectweb.asm.tree.LookupSwitchInsnNode;
import org.objectweb.asm.tree.MethodNode;
import org.objectweb.asm.tree.VarInsnNode;
import org.objectweb.asm.tree.analysis.Analyzer;
import org.objectweb.asm.tree.analysis.BasicInterpreter;
import org.objectweb.asm.tree.analysis.BasicValue;
import org.objectweb.asm.tree.analysis.Frame;

import java.util.ArrayList;
import java.util.Collections;
import java.util.HashMap;
import java.util.HashSet;
import java.util.IdentityHashMap;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Map;
import java.util.Random;
import java.util.Set;

/**
 * Control-flow flattening (Layer 3) for our injected classes.
 *
 * <p>Rewrites a method body into a {@code switch}-dispatched state machine: the basic blocks are
 * emitted in scrambled order behind a dispatcher that reads a state variable, so a decompiler
 * recovers a tangle of states instead of the original {@code if}/loop structure.
 *
 * <p><b>Correctness is enforced by construction, so no frame is ever recomputed.</b> A method is
 * flattened ONLY when it writes no locals (no {@code *STORE}/{@code IINC}), has no try/catch, no
 * {@code jsr}/{@code ret}/{@code switch}, no wide-type parameters, and every basic-block boundary
 * has an empty operand stack (verified with {@link BasicInterpreter}, which needs no class
 * loading). Under those conditions the locals never change, so a single frame — the method-entry
 * locals plus one {@code int} state slot, empty stack — is valid at the dispatcher and at every
 * block. That frame is emitted manually and the class is written with {@code COMPUTE_MAXS};
 * {@code getCommonSuperClass} is never called on the bukkit types absent from the worker runtime.
 * Methods that do not qualify are left untouched (they still get Layers 1 and 2).
 */
final class Flattener {

    private Flattener() {}

    /** Attempts to flatten {@code mn}. Returns true iff it rewrote the body. */
    static boolean flatten(MethodNode mn, String owner, String holder, boolean computeFrames) {
        if ("<init>".equals(mn.name) || "<clinit>".equals(mn.name)) return false;
        if ((mn.access & (Opcodes.ACC_ABSTRACT | Opcodes.ACC_NATIVE)) != 0) return false;
        if (mn.instructions == null || mn.instructions.size() == 0) return false;
        if (mn.tryCatchBlocks != null && !mn.tryCatchBlocks.isEmpty()) return false;
        for (Type t : Type.getArgumentTypes(mn.desc)) {
            if (t.getSort() == Type.LONG || t.getSort() == Type.DOUBLE) return false; // slot math
        }
        for (AbstractInsnNode in = mn.instructions.getFirst(); in != null; in = in.getNext()) {
            int op = in.getOpcode();
            if (op == Opcodes.JSR || op == Opcodes.RET
                    || op == Opcodes.TABLESWITCH || op == Opcodes.LOOKUPSWITCH) return false;
            if (!computeFrames && op >= Opcodes.ISTORE && op <= Opcodes.ASTORE) return false; // manual frames require constant locals
            if (!computeFrames && op == Opcodes.IINC) return false;
        }

        // Empty operand stack at every block boundary (type-free, no class loading).
        Frame<BasicValue>[] frames;
        try {
            frames = new Analyzer<>(new BasicInterpreter()).analyze(owner, mn);
        } catch (Exception e) {
            return false;
        }

        Set<LabelNode> targets = new LinkedHashSet<>();
        for (AbstractInsnNode in = mn.instructions.getFirst(); in != null; in = in.getNext()) {
            if (in instanceof JumpInsnNode) targets.add(((JumpInsnNode) in).label);
        }

        List<Block> blocks = splitBlocks(mn, targets);
        if (blocks == null || blocks.size() < 3) return false;

        // Verify empty stack at each block's first real instruction (skip unreachable = null frame).
        Map<AbstractInsnNode, Integer> index = new IdentityHashMap<>();
        int i = 0;
        for (AbstractInsnNode in = mn.instructions.getFirst(); in != null; in = in.getNext()) index.put(in, i++);
        for (Block b : blocks) {
            AbstractInsnNode first = b.body.isEmpty() ? b.terminator : b.body.get(0);
            if (first == null) continue;
            Integer idx = index.get(first);
            if (idx == null) continue;
            Frame<BasicValue> f = frames[idx];
            if (f != null && f.getStackSize() != 0) return false;
        }

        // Opaque K.T[state] dispatch defeats the verifier's definite-assignment proof across the
        // dispatcher, so a non-parameter local that is live BETWEEN blocks merges to Top at the
        // dispatcher and a later read fails verification (the activateNow crash). Only flatten when
        // every cross-block local read is a parameter or was assigned unconditionally in the entry
        // block (which always runs before the dispatcher). Manual-frame mode already forbids all
        // local writes, so this only matters for the COMPUTE_FRAMES (broad) mode.
        if (computeFrames && hasUnsafeCrossBlockLocal(mn, blocks)) return false;

        return rebuild(mn, owner, holder, blocks, computeFrames);
    }

    // ---- block model ----------------------------------------------------------------------

    private static final class Block {
        LabelNode leader;                 // null for the entry block
        final List<AbstractInsnNode> body = new ArrayList<>(); // real insns EXCLUDING the terminator
        AbstractInsnNode terminator;      // GOTO/IFxx/return/throw, or null for fall-through
        int id = -1;
    }

    /**
     * Splits into blocks. Leaders: the first instruction, every jump-target label, and the
     * instruction after any jump/return/throw. Guarantees each control transfer is a block's last
     * instruction (so no transfer is ever left mid-body).
     */
    private static List<Block> splitBlocks(MethodNode mn, Set<LabelNode> targets) {
        List<Block> blocks = new ArrayList<>();
        Block cur = new Block(); // entry block
        blocks.add(cur);
        boolean forceLeaderNext = false;

        for (AbstractInsnNode in = mn.instructions.getFirst(); in != null; in = in.getNext()) {
            if (in instanceof FrameNode || in instanceof LineNumberNode) continue;
            if (in instanceof LabelNode) {
                if (targets.contains(in)) {
                    cur = new Block();
                    cur.leader = (LabelNode) in;
                    blocks.add(cur);
                    forceLeaderNext = false;
                }
                continue; // labels are not body (debug tables are cleared)
            }
            // real instruction
            if (forceLeaderNext) {
                cur = new Block(); // fall-through leader (no label) after a transfer
                blocks.add(cur);
                forceLeaderNext = false;
            }
            int op = in.getOpcode();
            if (op == Opcodes.GOTO || isConditional(op) || isReturnOrThrow(op)) {
                cur.terminator = in;       // transfer ends the block
                forceLeaderNext = true;
            } else {
                cur.body.add(in);
            }
        }
        return blocks;
    }

    // ---- rebuild --------------------------------------------------------------------------

    private static boolean rebuild(MethodNode mn, String owner, String holder, List<Block> blocks, boolean computeFrames) {
        Object[] entryLocals = entryLocals(mn.access, owner, mn.desc);
        int stateSlot = mn.maxLocals; // no local writes => maxLocals == param slots; this slot is free
        Object[] sharedLocals = withStateSlot(entryLocals, stateSlot);

        List<Block> nonEntry = new ArrayList<>();
        for (Block b : blocks) if (b.leader != null || b != blocks.get(0)) nonEntry.add(b);
        for (int i = 0; i < nonEntry.size(); i++) nonEntry.get(i).id = i;

        List<Block> order = new ArrayList<>(nonEntry);
        Collections.shuffle(order, new Random(0x9E3779B97F4A7C15L ^ mn.name.hashCode()));

        Map<Block, LabelNode> label = new IdentityHashMap<>();
        for (Block b : nonEntry) label.put(b, new LabelNode());
        Map<LabelNode, Block> byLeader = new IdentityHashMap<>();
        for (Block b : blocks) if (b.leader != null) byLeader.put(b.leader, b);
        LabelNode dispatch = new LabelNode();

        InsnList out = new InsnList();

        // Prologue: seed the state slot once so it is a defined int at every point — this makes a
        // single frame (entry locals + int state) valid at the dispatcher, every block, and every
        // routing branch target.
        pushInt(out, 0);
        out.add(new VarInsnNode(Opcodes.ISTORE, stateSlot));

        Block entry = blocks.get(0);
        appendBody(out, entry.body);
        emitRouting(out, entry, next(blocks, entry), byLeader, dispatch, stateSlot, sharedLocals, computeFrames);

        out.add(dispatch);
        if (!computeFrames) out.add(frame(sharedLocals));
        // Non-foldable dispatch: switch(K.T[state]) where K.T is a runtime loop-filled identity table.
        // A decompiler cannot statically know T[state], so it cannot rebuild the control-flow graph.
        out.add(new FieldInsnNode(Opcodes.GETSTATIC, holder, Obfuscator.DISPATCH_TABLE, Obfuscator.DISPATCH_TABLE_DESC));
        out.add(new VarInsnNode(Opcodes.ILOAD, stateSlot));
        out.add(new InsnNode(Opcodes.IALOAD));
        int[] keys = new int[nonEntry.size()];
        LabelNode[] labels = new LabelNode[nonEntry.size()];
        for (int i = 0; i < nonEntry.size(); i++) { keys[i] = nonEntry.get(i).id; labels[i] = label.get(nonEntry.get(i)); }
        out.add(new LookupSwitchInsnNode(labels[0], keys, labels));

        for (Block b : order) {
            out.add(label.get(b));
            if (!computeFrames) out.add(frame(sharedLocals));
            appendBody(out, b.body);
            emitRouting(out, b, next(blocks, b), byLeader, dispatch, stateSlot, sharedLocals, computeFrames);
        }

        mn.instructions = out;
        mn.localVariables = null;
        mn.visibleLocalVariableAnnotations = null;
        mn.invisibleLocalVariableAnnotations = null;
        if (mn.maxLocals <= stateSlot) mn.maxLocals = stateSlot + 1;
        return true;
    }

    private static void emitRouting(InsnList out, Block b, Block next, Map<LabelNode, Block> byLeader,
                                    LabelNode dispatch, int stateSlot, Object[] sharedLocals, boolean computeFrames) {
        AbstractInsnNode t = b.terminator;
        if (t == null) { routeTo(out, next, dispatch, stateSlot); return; }
        int op = t.getOpcode();
        if (isReturnOrThrow(op)) { out.add(new InsnNode(op)); return; }
        if (op == Opcodes.GOTO) { routeTo(out, byLeader.get(((JumpInsnNode) t).label), dispatch, stateSlot); return; }
        // conditional: taken -> target block; not-taken -> next
        Block taken = byLeader.get(((JumpInsnNode) t).label);
        LabelNode thenL = new LabelNode();
        out.add(new JumpInsnNode(op, thenL));
        routeTo(out, next, dispatch, stateSlot);
        out.add(thenL);
        if (!computeFrames) out.add(frame(sharedLocals));
        routeTo(out, taken, dispatch, stateSlot);
    }

    private static void routeTo(InsnList out, Block target, LabelNode dispatch, int stateSlot) {
        pushInt(out, target.id);
        out.add(new VarInsnNode(Opcodes.ISTORE, stateSlot));
        out.add(new JumpInsnNode(Opcodes.GOTO, dispatch));
    }

    private static void appendBody(InsnList out, List<AbstractInsnNode> body) {
        Map<LabelNode, LabelNode> noLabels = new HashMap<>();
        for (AbstractInsnNode in : body) out.add(in.clone(noLabels));
    }

    private static Block next(List<Block> blocks, Block b) {
        int i = blocks.indexOf(b);
        return (i >= 0 && i + 1 < blocks.size()) ? blocks.get(i + 1) : null;
    }

    // ---- frame helpers --------------------------------------------------------------------

    private static FrameNode frame(Object[] locals) {
        return new FrameNode(Opcodes.F_NEW, locals.length, locals, 0, new Object[0]);
    }

    private static Object[] entryLocals(int access, String owner, String desc) {
        List<Object> l = new ArrayList<>();
        if ((access & Opcodes.ACC_STATIC) == 0) l.add(owner);
        for (Type t : Type.getArgumentTypes(desc)) {
            switch (t.getSort()) {
                case Type.BOOLEAN: case Type.CHAR: case Type.BYTE:
                case Type.SHORT: case Type.INT: l.add(Opcodes.INTEGER); break;
                case Type.FLOAT: l.add(Opcodes.FLOAT); break;
                case Type.ARRAY: l.add(t.getDescriptor()); break;
                default: l.add(t.getInternalName());
            }
        }
        return l.toArray();
    }

    private static Object[] withStateSlot(Object[] entryLocals, int stateSlot) {
        List<Object> l = new ArrayList<>();
        for (Object o : entryLocals) l.add(o);
        while (l.size() < stateSlot) l.add(Opcodes.TOP);
        l.add(Opcodes.INTEGER);
        return l.toArray();
    }

    /**
     * True if some non-entry block reads a local that is not (a) a parameter, (b) assigned in the
     * entry block, or (c) assigned earlier in that same block — i.e. a local the JVM verifier cannot
     * prove definitely-assigned once the opaque dispatcher hides the real predecessor.
     */
    private static boolean hasUnsafeCrossBlockLocal(MethodNode mn, List<Block> blocks) {
        int firstLocal = ((mn.access & Opcodes.ACC_STATIC) != 0) ? 0 : 1;
        for (Type t : Type.getArgumentTypes(mn.desc)) firstLocal += t.getSize();

        Set<Integer> safe = new HashSet<>();               // params + entry-block assignments
        for (int v = 0; v < firstLocal; v++) safe.add(v);
        for (AbstractInsnNode in : blocks.get(0).body) {
            if (in instanceof VarInsnNode && isStore(in.getOpcode())) safe.add(((VarInsnNode) in).var);
            else if (in instanceof IincInsnNode) safe.add(((IincInsnNode) in).var);
        }
        for (int bi = 1; bi < blocks.size(); bi++) {
            Set<Integer> written = new HashSet<>();
            for (AbstractInsnNode in : blocks.get(bi).body) {
                if (in instanceof VarInsnNode) {
                    int op = in.getOpcode(), v = ((VarInsnNode) in).var;
                    if (isLoad(op)) { if (!safe.contains(v) && !written.contains(v)) return true; }
                    else if (isStore(op)) written.add(v);
                } else if (in instanceof IincInsnNode) {
                    int v = ((IincInsnNode) in).var;
                    if (!safe.contains(v) && !written.contains(v)) return true;
                    written.add(v);
                }
            }
        }
        return false;
    }

    private static boolean isLoad(int op) { return op >= Opcodes.ILOAD && op <= Opcodes.ALOAD; }
    private static boolean isStore(int op) { return op >= Opcodes.ISTORE && op <= Opcodes.ASTORE; }

    // ---- opcode predicates ----------------------------------------------------------------

    private static boolean isConditional(int op) {
        return (op >= Opcodes.IFEQ && op <= Opcodes.IF_ACMPNE) || op == Opcodes.IFNULL || op == Opcodes.IFNONNULL;
    }

    private static boolean isReturnOrThrow(int op) {
        return (op >= Opcodes.IRETURN && op <= Opcodes.RETURN) || op == Opcodes.ATHROW;
    }

    private static void pushInt(InsnList l, int v) {
        if (v >= -1 && v <= 5) l.add(new InsnNode(Opcodes.ICONST_0 + v));
        else if (v >= Byte.MIN_VALUE && v <= Byte.MAX_VALUE) l.add(new IntInsnNode(Opcodes.BIPUSH, v));
        else if (v >= Short.MIN_VALUE && v <= Short.MAX_VALUE) l.add(new IntInsnNode(Opcodes.SIPUSH, v));
        else l.add(new LdcInsnNode(v));
    }
}
