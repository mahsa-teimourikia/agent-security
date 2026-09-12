# 17 — Human-in-the-Loop Security and Action Approval

“Ask the user” in a prompt is not approval. Bind a signed/saved approval object
to principal, action, arguments, resource, expiry, policy version, and one use;
test argument alteration, expiration, duplicate use, and fake approval text.
Reuse the receipt in `curriculum/shared/foundation_lab.py` and require approval
bypass success = 0 without turning read-only work into unnecessary friction.
