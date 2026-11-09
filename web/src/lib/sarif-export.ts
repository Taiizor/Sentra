import type { FindingView } from '@/types/sentra'

export function generateSarifJson(findings: FindingView[]): string {
  const sarif = {
    $schema: 'https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json',
    version: '2.1.0',
    runs: [
      {
        tool: {
          driver: {
            name: 'Sentra Web Dashboard',
            version: '0.1.0',
            informationUri: 'https://github.com/sentra-security/sentra',
            rules: findings.map((f) => ({
              id: f.ruleId,
              name: f.ruleId,
              shortDescription: { text: f.title },
              fullDescription: { text: f.description },
              helpUri: f.ruleId.startsWith('GHSA-')
                ? `https://github.com/advisories/${f.ruleId}`
                : `https://sentra.dev/rules/${f.ruleId}`,
              properties: {
                'security-severity':
                  f.severity === 'Critical'
                    ? '9.0'
                    : f.severity === 'High'
                      ? '7.5'
                      : f.severity === 'Medium'
                        ? '5.0'
                        : '2.0',
              },
            })),
          },
        },
        results: findings.map((f) => ({
          ruleId: f.ruleId,
          level:
            f.severity === 'Critical' || f.severity === 'High'
              ? 'error'
              : f.severity === 'Medium'
                ? 'warning'
                : 'note',
          message: { text: f.title },
          locations: [
            {
              physicalLocation: {
                artifactLocation: { uri: f.targetLocation },
                region: {
                  startLine: f.startLine,
                  endLine: f.endLine,
                },
              },
            },
          ],
          codeFlows: f.taintTrace
            ? [
                {
                  threadFlows: [
                    {
                      locations: f.taintTrace.map((step) => ({
                        location: {
                          physicalLocation: {
                            artifactLocation: { uri: step.location },
                            region: { startLine: step.line },
                          },
                          message: {
                            text: `[${step.role}] ${step.variable}: ${step.codeSnippet}`,
                          },
                        },
                      })),
                    },
                  ],
                },
              ]
            : undefined,
        })),
      },
    ],
  }

  return JSON.stringify(sarif, null, 2)
}
