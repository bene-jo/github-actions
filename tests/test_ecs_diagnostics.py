"""Exercise the exact inline diagnostic step without AWS access."""
import contextlib
import io
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import textwrap
import unittest
from unittest.mock import patch

WORKFLOW = Path(__file__).parents[1] / '.github/workflows/task-definition-deploy.yml'
TEXT = WORKFLOW.read_text()
SCRIPT = textwrap.dedent(TEXT.split("          python3 - <<'PY'\n", 1)[1].split('\n          PY', 1)[0])
TASK = 'arn:aws:ecs:eu-central-1:123:task/staging/exact-task-id'


class DiagnosticsTest(unittest.TestCase):
    def run_diagnostics(self, *, exit_code=1, status='STOPPED', driver='awslogs', logs=None, denied=False, password='known-password'):
        calls = []
        definition = {'containerDefinitions': [{
            'name': 'app', 'environment': [{'name': 'DB_PASSWORD', 'value': password}],
            'logConfiguration': {'logDriver': driver, 'options': {
                'awslogs-group': 'ecs/kraken-staging', 'awslogs-region': 'eu-central-1',
                'awslogs-stream-prefix': 'ecs',
            }},
        }]}
        def aws(command, **kwargs):
            calls.append(command)
            if command[1] == 'ecs':
                result = {'tasks': [{'taskArn': TASK, 'lastStatus': status,
                    'stopCode': 'EssentialContainerExited', 'stoppedReason': 'Essential container in task exited',
                    'containers': [{'name': 'app', 'exitCode': exit_code}]}]}
            elif denied:
                return subprocess.CompletedProcess(command, 1, '', 'secret stderr must not be printed')
            else:
                result = {'events': [{'message': line} for line in (logs or ['PG::Error: migration failed'])]}
            return subprocess.CompletedProcess(command, 0, json.dumps(result), '')

        with tempfile.TemporaryDirectory() as directory:
            task_file = Path(directory) / 'task.json'
            task_file.write_text(json.dumps(definition))
            env = {'TASK_ARNS': json.dumps([TASK]), 'TASK_DEFINITION': str(task_file),
                   'CLUSTER': 'staging', 'CONTAINER': 'app', 'AWS_SESSION_TOKEN': 'session-secret'}
            output = io.StringIO()
            with patch.dict(os.environ, env, clear=True), patch('subprocess.run', side_effect=aws), contextlib.redirect_stdout(output):
                exec(compile(SCRIPT, str(WORKFLOW), 'exec'), {})
            return output.getvalue(), calls

    def test_failed_migration_reads_only_exact_task_stream(self):
        output, calls = self.run_diagnostics()
        self.assertIn('EssentialContainerExited', output)
        self.assertIn('"exitCode": 1', output)
        self.assertIn('PG::Error: migration failed', output)
        self.assertEqual(calls[0][1:7], ['ecs', 'describe-tasks', '--cluster', 'staging', '--tasks', TASK])
        args = calls[1]
        self.assertEqual(args[args.index('--log-stream-name') + 1], 'ecs/app/exact-task-id')
        self.assertEqual(args[args.index('--log-group-name') + 1], 'ecs/kraken-staging')
        self.assertIn('--no-paginate', args)
        self.assertEqual(args[args.index('--limit') + 1], '100')
        self.assertNotIn('--unmask', args)

    def test_successful_task_does_not_read_logs(self):
        output, calls = self.run_diagnostics(exit_code=0)
        self.assertEqual(output, '')
        self.assertEqual(len(calls), 1)

    def test_running_task_does_not_read_logs(self):
        output, calls = self.run_diagnostics(status='RUNNING', exit_code=None)
        self.assertEqual(output, '')
        self.assertEqual(len(calls), 1)

    def test_credentials_and_workflow_commands_are_not_executed(self):
        output, _ = self.run_diagnostics(logs=[
            'known-password session-secret', 'postgres://user:database-password@host/db',
            'Authorization: Bearer abc.def.xyz', 'password="quoted password" api_key=unknown-key',
            'AWS key AKIA1234567890123456', '::error::untrusted log instruction',
        ])
        for secret in ['known-password', 'session-secret', 'database-password', 'abc.def.xyz', 'quoted password', 'unknown-key', 'AKIA1234567890123456']:
            self.assertNotIn(secret, output)
        marker = output.splitlines()[0].removeprefix('::stop-commands::')
        self.assertTrue(output.rstrip().endswith(f'::{marker}::'))
        self.assertIn('::error::untrusted log instruction', output)

    def test_log_denial_keeps_task_failure_evidence_without_stderr(self):
        output, _ = self.run_diagnostics(denied=True)
        self.assertIn('"exitCode": 1', output)
        self.assertIn('Application logs unavailable', output)
        self.assertNotIn('secret stderr', output)

    def test_json_escaped_known_credentials_are_redacted_in_message_fields(self):
        password = 'synthetic-"quote\\backslash-ü'
        for ensure_ascii in (True, False):
            with self.subTest(ensure_ascii=ensure_ascii):
                message = json.dumps({'message': password}, ensure_ascii=ensure_ascii)
                output, _ = self.run_diagnostics(password=password, logs=[message, password])
                logged_json = next(line for line in output.splitlines() if line.startswith('{"message":'))
                self.assertEqual(json.loads(logged_json)['message'], '[REDACTED]')
                self.assertNotIn(password, output)

    def test_credential_fields_consume_escaped_quotes_in_unknown_values(self):
        for key in ('password', 'DB_PASSWORD', 'api key', 'aws.secret_access_key'):
            with self.subTest(key=key):
                output, _ = self.run_diagnostics(logs=[
                    json.dumps({key: 'unknown-"suffix\\tail'}),
                    f"{key}='unknown-\\'suffix\\\\tail'",
                ])
                self.assertNotIn('unknown-', output)
                self.assertNotIn('suffix', output)
                self.assertNotIn('tail', output)
                self.assertIn('[REDACTED]', output)

    def test_unsupported_log_driver_is_not_queried(self):
        output, calls = self.run_diagnostics(driver='awsfirelens')
        self.assertIn('does not use awslogs', output)
        self.assertEqual(len(calls), 1)

    def test_log_excerpt_is_bounded(self):
        output, _ = self.run_diagnostics(logs=['x' * 20000])
        self.assertIn('x' * 12000, output)
        self.assertNotIn('x' * 12001, output)

    def test_large_log_redaction_finishes_without_exposing_credentials(self):
        code = """
from test_ecs_diagnostics import DiagnosticsTest
output, _ = DiagnosticsTest().run_diagnostics(logs=[
    'a' * 250000, 'postgres://user:' + 'a:' * 100000,
    'secret' * 40000,
    'postgres://user:still-secret@host/db',
])
assert 'still-secret' not in output
assert 'postgres://[REDACTED]@host/db' in output
"""
        subprocess.run([sys.executable, '-B', '-c', code], cwd=Path(__file__).parent,
                       capture_output=True, text=True, check=True, timeout=5)

    def test_failure_only_step_preserves_migration_gate(self):
        self.assertIn("failure() && steps.deploy-service.outcome == 'failure'", TEXT)
        self.assertIn("run-task: ${{ inputs.skip-init-task != 'true' }}", TEXT)
        step = TEXT.split('      - name: Report failed init task', 1)[1].split('  deploy-sidecars:', 1)[0]
        self.assertIn('continue-on-error: true', step)
        self.assertIn('timeout-minutes: 2', step)
        deploy = TEXT.split('      - name: Deploy to Amazon ECS service', 1)[1].split('      - name: Report failed init task', 1)[0]
        self.assertNotIn('continue-on-error', deploy)


if __name__ == '__main__':
    unittest.main()
