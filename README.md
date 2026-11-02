# Reusable Workflow

## Failed init tasks

The ECS deployment workflow reports the exact failed init task's stop reason, container exit codes and a bounded application log excerpt (at most 100 events / 12,000 characters). It reads the `awslogs` group, region and stream prefix from the rendered task definition and uses the task ARN returned by the deploy action. It does not search other tasks, skip migrations or turn a failed deployment green. Diagnostic failures leave the original deployment failure intact.

The existing deploy role needs `logs:GetLogEvents` on the relevant application streams, for example `arn:aws:logs:eu-central-1:ACCOUNT:log-group:ecs/kraken-staging:log-stream:ecs/app/*`. No secret-read, log-unmasking or log-write permission is needed. Without that grant, task metadata is still reported and the log excerpt is unavailable.

Known credential values from the runner/task environment, including their JSON-escaped forms, and common credential patterns are redacted. URL userinfo is masked with or without a password. Authorization values are masked through their closing quote or, for unquoted headers, the end of the line. Log text is printed with GitHub workflow-command interpretation disabled. Redaction is best effort; application logging must still avoid secrets and private payloads. Excerpts inherit the calling repository's Actions-log visibility and retention. No separate log artifact is uploaded.

Run `python3 -m unittest discover -s tests -v` to exercise the exact inline diagnostic code with mocked AWS responses. Tests do not require AWS credentials or run deployments.
