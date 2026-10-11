# fivedrisk - 5D Risk Governance Plugin

A deployment consultant for per-action AI-agent risk governance. Start with a redacted
system prompt or a description of the agent's goals and likely actions. The skill helps
you confirm deployment facts, design a 5D profile, compare deterministic-only governance
with observer-LLM or TypeSafe Jev designs, configure a supported runtime adapter, and
verify the real execution boundary. The profile is not runtime configuration, and no
observer runtime is bundled.

The plugin manifest version follows the bundled package/repository release. The
setup skill has its own independently managed artifact version.

## Choose the right artifact

Both release ZIPs are deterministic builds of the same immutable Git commit and contain
the same consultant skill, references, examples, and installation/verification helpers.

| Artifact | Purpose | Enforcement boundary |
|---|---|---|
| `fivedrisk-plugin-public-0.7.1.zip` | Hooks-free ChatGPT/Codex public-directory submission candidate | Advisory only; no automatic host enforcement |
| `fivedrisk-plugin-manual-0.7.1.zip` | Manually reviewed local integration | Includes the reviewed Claude-specific hooks; requires verified runtime setup |

Skill execution is advisory and does not intercept tool calls. In ChatGPT, Codex, and
other compatible hosts, installing the public artifact does not install the Python
runtime, configure a live agent, or make its tools safe. A supported runtime adapter must
sit on the actual execution path before you claim enforcement. If the host cannot access
that environment, use the consultation and configuration artifacts, and have the operator
run the checks there.

Manually installed Codex desktop plugins and Claude Code plugins can use host-specific
lifecycle hooks when available. Hook protocols are not interchangeable: this release's
reviewed integration is Claude-specific, not a Codex hook implementation. Do not enable
the Claude launcher in Codex. Any ZIP containing lifecycle hooks is **not eligible for the public plugin directory**;
submit only the `public` ZIP. GitHub publication is not OpenAI directory approval.

The root `plugin.json` is the portable manifest. OpenAI presentation metadata and
`onboardingSkill` live under `extensions.com.openai`; the onboarding path resolves to the
packaged `./skills/fivedrisk-setup/SKILL.md`. `.codex-plugin/plugin.json` is the compatibility
projection. Root OpenAI settings replace, rather than merge with, the compatibility
settings. Both identify the same one auto-discovered skill: `fivedrisk-setup`.

## Start the consultation

After installing the advisory package in a compatible host, run its setup action or ask:
“Use fivedrisk-setup to design a 5D risk profile for my agent.” Provide only a redacted
prompt or goals/boundaries description—never credentials, customer data, or unnecessary
proprietary content. Confirm the extracted facts before generating runtime policy.

For manual hook installation, review `manual/README.md` inside the manual ZIP or the
[manual integration guide](https://github.com/theDoc001/fivedrisk/tree/main/fivedrisk-plugin/manual).
The source directory contains that manual integration; do not upload the whole directory
to a public-directory portal. No Claude marketplace entry is claimed.

Public directory submission still requires publisher-owned listing/privacy information,
host installation/onboarding checks, and portal review. The manifest does not invent
privacy/terms URLs or claim that those human publication steps have already happened.

## License

Apache-2.0 — Authored by Loren, March 2026.
