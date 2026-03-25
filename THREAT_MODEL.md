# Threat model

## Primary risk

The Docker socket is effectively root-equivalent operational authority over the host's containers.

If you hand that socket to an agent, web app, or automation system directly, you hand it ambient power.

## safe-docker goal

Reduce that ambient power into explicit, reviewable policy:
- who can call
- what service names exist
- what actions are allowed
- what happened

## In scope

- accidental misuse by trusted internal callers
- overpowered agents/tools needing only narrow Docker operations
- API-key compromise with constrained policy blast radius
- auditability of lifecycle operations

## Out of scope

- hostile root on the Docker host
- kernel/container escape vulnerabilities
- replacement for full platform authz systems
- safe exposure to the public Internet without surrounding controls

## Main design controls

1. deny by default
2. no raw Docker passthrough
3. no exec or shell endpoints
4. explicit service alias mapping
5. explicit per-action authorization
6. strict config validation
7. structured audit logs
8. startup Docker verification

## Residual risk

A valid API key still grants the actions explicitly allowed to it by deployment policy.
That is intentional. The point is to make the granted power small, visible, and auditable.
