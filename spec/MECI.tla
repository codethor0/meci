-------------------------------- MODULE MECI --------------------------------
(***************************************************************************)
(* Memory-Egress Cryptographic Interlock (MECI): finite safety core.      *)
(* Thor Thor, 2026. Specification license: MIT.                           *)
(*                                                                         *)
(* The current-epoch decryption hazard D is derived from revocation:      *)
(* D holds exactly when the current epoch has not been revoked. The other *)
(* hazards are P (plaintext), M (microarchitectural residue), I (DMA      *)
(* path), G (device state), B (unreleased high object in an exportable    *)
(* buffer), and Q (a live high-producing execution unit).                 *)
(*                                                                         *)
(* Design selects the egress-open semantics:                              *)
(*   "atomic"   check and commit in one step (correct)                    *)
(*   "gencheck" split check/commit with generation validation (correct)   *)
(*   "buggy"    split check/commit without generation validation          *)
(*   "dponly"   guard checks only D and P                                 *)
(*   "noB"      guard ignores B                                           *)
(* The Python reference checker (scripts/meci_modelcheck.py) implements   *)
(* the same state space, so distinct-state counts are directly comparable.*)
(***************************************************************************)
EXTENDS Naturals

CONSTANTS Design, GenBound, MaxEpoch

Hazards == {"P", "M", "I", "G", "B", "Q"}

VARIABLES egress, hazards, gen, permit, permitGen, epoch, revoked

vars == <<egress, hazards, gen, permit, permitGen, epoch, revoked>>

D == epoch \notin revoked
Safe == hazards = {} /\ ~D
FreshPermit == permit /\ permitGen = gen

TypeOK ==
  /\ egress \in BOOLEAN
  /\ hazards \subseteq Hazards
  /\ gen \in 0..GenBound
  /\ permit \in BOOLEAN
  /\ permitGen \in 0..GenBound
  /\ epoch \in 1..MaxEpoch
  /\ revoked \subseteq 1..MaxEpoch

Init ==
  /\ egress = FALSE
  /\ hazards = Hazards
  /\ gen = 0
  /\ permit = FALSE
  /\ permitGen = 0
  /\ epoch = 1
  /\ revoked = {}

Clean(h) ==
  /\ h \in hazards
  /\ hazards' = hazards \ {h}
  /\ UNCHANGED <<egress, gen, permit, permitGen, epoch, revoked>>

Revoke ==
  /\ D
  /\ revoked' = revoked \cup {epoch}
  /\ UNCHANGED <<egress, hazards, gen, permit, permitGen, epoch>>

\* Any mutation that can falsify Safe increments gen.
Produce(h) ==
  /\ "Q" \in hazards
  /\ h \notin hazards
  /\ gen < GenBound
  /\ hazards' = hazards \cup {h}
  /\ gen' = gen + 1
  /\ UNCHANGED <<egress, permit, permitGen, epoch, revoked>>

RestartProducer ==
  /\ ~egress
  /\ "Q" \notin hazards
  /\ gen < GenBound
  /\ hazards' = hazards \cup {"Q"}
  /\ gen' = gen + 1
  /\ UNCHANGED <<egress, permit, permitGen, epoch, revoked>>

SafeOpen ==
  /\ ~egress /\ Safe
  /\ egress' = TRUE
  /\ UNCHANGED <<hazards, gen, permit, permitGen, epoch, revoked>>

CheckSafe ==
  /\ ~egress /\ Safe
  /\ permit' = TRUE
  /\ permitGen' = gen
  /\ UNCHANGED <<egress, hazards, gen, epoch, revoked>>

OpenWithGeneration ==
  /\ ~egress /\ FreshPermit
  /\ egress' = TRUE
  /\ permit' = FALSE
  /\ UNCHANGED <<hazards, gen, permitGen, epoch, revoked>>

OpenStalePermit ==
  /\ ~egress /\ permit
  /\ egress' = TRUE
  /\ permit' = FALSE
  /\ UNCHANGED <<hazards, gen, permitGen, epoch, revoked>>

OpenDPOnly ==
  /\ ~egress /\ ~D /\ "P" \notin hazards
  /\ egress' = TRUE
  /\ UNCHANGED <<hazards, gen, permit, permitGen, epoch, revoked>>

OpenIgnoringB ==
  /\ ~egress /\ ~D /\ hazards \subseteq {"B"}
  /\ egress' = TRUE
  /\ UNCHANGED <<hazards, gen, permit, permitGen, epoch, revoked>>

\* Close egress, advance the epoch, and begin new isolated computation.
CloseAdvance ==
  /\ egress /\ epoch < MaxEpoch /\ gen < GenBound
  /\ egress' = FALSE
  /\ epoch' = epoch + 1
  /\ hazards' = {"P", "Q"}
  /\ gen' = gen + 1
  /\ permit' = FALSE
  /\ UNCHANGED <<permitGen, revoked>>

Next ==
  \/ \E h \in hazards : Clean(h)
  \/ Revoke
  \/ \E h \in Hazards \ {"Q"} : Produce(h)
  \/ RestartProducer
  \/ (Design = "atomic" /\ SafeOpen)
  \/ (Design \in {"gencheck", "buggy"} /\ CheckSafe)
  \/ (Design = "gencheck" /\ OpenWithGeneration)
  \/ (Design = "buggy" /\ OpenStalePermit)
  \/ (Design = "dponly" /\ OpenDPOnly)
  \/ (Design = "noB" /\ OpenIgnoringB)
  \/ CloseAdvance

Spec == Init /\ [][Next]_vars

MECIInvariant == egress => Safe
PermitInvariant == FreshPermit => Safe
EpochInvariant == \A e \in revoked : e <= epoch
NoResurrection == [][revoked \subseteq revoked']_vars

THEOREM Spec => []MECIInvariant  \* checked by TLC for Design \in {"atomic", "gencheck"}
=============================================================================
