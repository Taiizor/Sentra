/**
 * Example inputs for the snippet scanner. They are code only: no expected rule ids, severities
 * or results are attached, because the only source of results is the scan itself.
 */
export interface StudioExample {
  id: string
  label: string
  fileName: string
  code: string
}

export const STUDIO_EXAMPLES: readonly StudioExample[] = [
  {
    id: 'ts-sql-concat',
    label: 'SQL string built from request input (TypeScript)',
    fileName: 'snippet.ts',
    code: [
      "import express from 'express'",
      '',
      'const app = express()',
      '',
      "app.get('/users', async (req, res) => {",
      '  const name = req.query.name',
      `  const rows = await db.query("SELECT * FROM users WHERE name = '" + name + "'")`,
      '  res.json(rows)',
      '})',
    ].join('\n'),
  },
  {
    id: 'py-shell',
    label: 'Shell command built from request input (Python)',
    fileName: 'snippet.py',
    code: [
      'import subprocess',
      'from flask import request',
      '',
      '',
      'def list_dir():',
      '    target = request.args.get("dir")',
      '    return subprocess.check_output("ls " + target, shell=True)',
    ].join('\n'),
  },
  {
    id: 'rs-unsafe',
    label: 'Raw pointer read in an unsafe block (Rust)',
    fileName: 'snippet.rs',
    code: [
      'fn read_raw(ptr: *const u8, len: usize) -> Vec<u8> {',
      '    unsafe { std::slice::from_raw_parts(ptr, len).to_vec() }',
      '}',
    ].join('\n'),
  },
  {
    id: 'yml-workflow',
    label: 'Workflow step interpolating pull request data (YAML)',
    fileName: 'ci.yml',
    code: [
      'on: pull_request_target',
      'jobs:',
      '  greet:',
      '    runs-on: ubuntu-latest',
      '    steps:',
      '      - uses: actions/checkout@v4',
      '        with:',
      '          ref: ${{ github.event.pull_request.head.sha }}',
      '      - run: echo "Title: ${{ github.event.pull_request.title }}"',
    ].join('\n'),
  },
  {
    id: 'dockerfile-root',
    label: 'Remote install script piped to a shell (Dockerfile)',
    fileName: 'Dockerfile',
    code: ['FROM node:latest', 'USER root', 'RUN curl -sSL https://example.com/install.sh | sh'].join('\n'),
  },
]
