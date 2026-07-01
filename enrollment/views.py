"""Enrollment app — no public HTTP views (intentionally).

The certless enrollment API that used to live here (POST /<tenant>/register and
GET /<tenant>/enroll/<id>) has been REMOVED. Nodes enroll only through XConnect's
/bootstrap door, which relays to Orthanc over the mTLS control link — see
ca/management/commands/run_control.py (/control/v1/sign + /control/v1/enroll_status).
The shared logic lives in enrollment/services.py (register/poll) and is called by
that relay. Re-exposing it as a public Django route would be a second,
unauthenticated (join-token-only) enrollment surface on the public tower — see
ARCHITECTURE "Trust boundaries & security decisions" and orthanc/urls.py.
"""
